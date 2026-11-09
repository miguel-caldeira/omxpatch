"""Linha de comandos do agente.

    omxpatch-agent enroll --server https://omxpatch.exemplo.pt --token omxe_… [--pin-sha256 AB:CD:…] [--ca-file ca.pem]
    omxpatch-agent run            (ciclo contínuo; é o que corre como serviço)
    omxpatch-agent once           (um contacto e execução das tarefas recebidas)
    omxpatch-agent inventory      (mostra o inventário que seria enviado)
    omxpatch-agent status
    omxpatch-agent install-service | uninstall-service
"""
from __future__ import annotations

import argparse
import json
import os
import logging
import random
import sys
import time

from . import __version__, collectors, compat, config, executor, service, trust, update
from . import client as client_mod
from .client import Client, ServerError
from urllib.parse import urlsplit

log = logging.getLogger("omxpatch.agent")
INVENTORY_EVERY = 24 * 3600


def cmd_enroll(args) -> int:
    urls = client_mod.split_urls(args.server)
    cfg = {"server_url": ",".join(urls), "pin_sha256": client_mod.normalize_pin(args.pin_sha256 or ""), "ca_file": args.ca_file or ""}
    if not urls or not all(u.startswith("https://") for u in urls):
        print("AVISO: o servidor deve usar HTTPS.", file=sys.stderr)
    if cfg["pin_sha256"] and client_mod.pin_algorithm(cfg["pin_sha256"]) is None:
        print("Impressão digital inválida: use o SHA-256 (64 hex) ou o thumbprint SHA-1 (40 hex).", file=sys.stderr)
        return 2
    if any(client_mod.is_ip_host(urlsplit(u).hostname or "") for u in urls) and not (cfg["pin_sha256"] or cfg["ca_file"]):
        print("Para falar com a consola por IP é obrigatório indicar a impressão digital do certificado (--pin-sha256) ou um CA (--ca-file).", file=sys.stderr)
        return 2
    existing = config.load()
    if existing.get("agent_key") and not args.force:
        print(f"Este equipamento já está registado na organização «{existing.get('tenant_name', '?')}» "
              f"({existing.get('server_url')}). Use --force para o registar de novo (só é aceite na mesma organização).", file=sys.stderr)
        return 3
    info = collectors.base_info()
    info["version"] = __version__
    try:
        data = Client(cfg).enroll(args.token, info)
    except ServerError as exc:
        print(f"Registo recusado: {exc}", file=sys.stderr)
        return 2
    t = data.get("trust") or {}
    cfg.update({"agent_id": data.get("agent_id"), "task_keys": [k for k in t.get("task_keys", []) if isinstance(k, str)][:3]})
    cfg.update({"agent_key": data["agent_key"], "poll_seconds": data.get("poll_seconds", 300),
                "tenant": data.get("tenant", {}).get("slug", ""), "tenant_name": data.get("tenant", {}).get("name", "")})
    path = config.save(cfg)
    print(f"Agente registado ({info['hostname']}) na organização «{cfg['tenant_name']}». Configuração em {path}")
    if args.install_service:
        print(service.install())
    return 0


def _client() -> Client:
    cfg = config.load()
    if not cfg.get("agent_key"):
        sys.exit("Agente não registado: execute 'omxpatch-agent enroll'")
    return Client(cfg)


def send_inventory(client: Client) -> None:
    info = collectors.collect()
    res = client.inventory({**{k: v for k, v in info.items() if k not in ("hostname", "machine_id")}, "version": __version__,
                            "runtime": compat.runtime()})
    log.info("Inventário enviado: %s", res)


def _adopt_servers(client: Client, urls) -> None:
    """A consola pode publicar os seus endereços (ex.: novo IP). Só se aceitam https e só com a impressão digital fixada."""
    cfg = config.load()
    if not isinstance(urls, list) or not cfg.get("pin_sha256"):
        return
    new = [u.rstrip("/") for u in urls if isinstance(u, str) and u.startswith("https://") and len(u) < 200][:6]
    if new and new != client_mod.split_urls(cfg.get("server_url", "")):
        cfg["server_url"] = ",".join(new)
        config.save(cfg)
        client.bases = new
        client.base = new[0]
        log.info("Endereços da consola atualizados: %s", cfg["server_url"])


def _adopt_trust(client: Client, resp: dict) -> dict:
    """Impressões digitais (rotação), chaves de assinatura e identificador, publicados pela consola por TLS já fixado."""
    t = resp.get("trust") or {}
    cfg = config.load()
    if t and cfg.get("agent_key") and trust.adopt(cfg, t, getattr(client.s, "matched_pin", "")):
        config.save(cfg)
        if cfg.get("pin_sha256") and hasattr(client.s, "pins"):
            client.s.pins = [p for p in cfg["pin_sha256"].split(",") if p]
            client.s.pin = cfg["pin_sha256"]
        log.info("Confiança atualizada (impressões digitais/chaves de assinatura)")
    return cfg


def cycle(client: Client, state: dict) -> int:
    """Um contacto: inventário (se pedido/periódico) e execução das tarefas. Devolve o n.º de tarefas."""
    try:
        from . import isolation
        if isolation.release_if_expired():
            log.warning("Isolamento expirado: ativo libertado")
    except Exception as exc:  # noqa: BLE001
        log.warning("Verificação do isolamento: %s", exc)
    resp = client.poll()
    _adopt_servers(client, resp.get("server_urls"))
    cfg = _adopt_trust(client, resp)
    offer = update.check(cfg, resp.get("trust") or {})
    if offer and not state.get("update_failed") == offer["version"]:
        try:
            log.info("A atualizar o agente para %s", offer["version"])
            update.apply(client, offer)
            update.restart_self()
        except Exception as exc:  # noqa: BLE001 - uma atualização falhada nunca impede o trabalho normal
            log.warning("Atualização falhou (mantém a versão atual): %s", exc)
            state["update_failed"] = offer["version"]
    if resp.get("inventory_requested") or time.time() - state.get("last_inventory", 0) > INVENTORY_EVERY:
        try:
            send_inventory(client)
            state["last_inventory"] = time.time()
        except Exception as exc:  # noqa: BLE001
            log.warning("Inventário falhou: %s", exc)
    try:                                              # descoberta periódica de atualizações (com reenvio garantido)
        from .updates import sync
        sync.run_and_upload(client, hours=float((resp.get("updates") or {}).get("scan_hours") or 6))
    except Exception as exc:  # noqa: BLE001 - nunca impede o resto do ciclo
        log.warning("Descoberta de atualizações: %s", exc)
    for task in resp.get("tasks", []):
        log.info("Tarefa %s (%s)", task["id"], task["type"])
        valid, why = trust.verify_task(cfg, task, cfg.get("agent_id"))
        if not valid:
            log.error("Tarefa %s recusada: %s", task["id"], why)
            report = {"status": "failed", "output": f"Recusada pelo agente: {why}", "rejected": True}
        else:
            report = executor.execute(client, task)
        try:
            client.task_result(task["id"], report)
        except Exception as exc:  # noqa: BLE001 - o servidor repõe a tarefa na fila se não houver resposta
            log.error("Não foi possível enviar o resultado da tarefa %s: %s", task["id"], exc)
    state["poll"] = int(resp.get("poll_seconds") or 300)
    return len(resp.get("tasks", []))


def cmd_run(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    client, state = _client(), {}
    while True:
        try:
            n = cycle(client, state)
            wait = 5 if n else state.get("poll", 300)
        except ServerError as exc:
            log.warning("Sem contacto com o servidor: %s", exc)
            wait = 60
        time.sleep(wait + random.randint(0, max(1, wait // 10)))


def cmd_once(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    print(f"{cycle(_client(), {})} tarefa(s) executada(s)")
    return 0


def cmd_inventory(args) -> int:
    print(json.dumps(collectors.collect(), indent=2, ensure_ascii=False)[:200000])
    return 0


def cmd_selftest(args) -> int:
    res = compat.selftest()
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        rt = res["runtime"]
        print(f"Python {rt['python']} ({rt['implementation']}) · OpenSSL {rt['openssl']} · nível: {rt['level']}")
        for d in rt["degraded"]:
            print("  aviso:", d)
        for st in res["steps"]:
            print(f"  [{'OK' if st['status'] == 'ok' else 'FALHA'}] {st['name']}: {st['detail']}")
        print("Autoteste:", "tudo OK" if res["ok"] else "com falhas")
    return 0 if res["ok"] else 1


def cmd_validate(args) -> int:
    """Validação no sistema real (ver ``omxpatch_agent/validate.py``). Código de saída 1 se alguma verificação falhar."""
    from . import validate as v
    if args.level == "lab" and not args.yes_lab:
        print("O nível «lab» faz alterações reversíveis (firewall de teste, endurecimento aplicado e revertido). Use só em VM/equipamento de laboratório e confirme com --yes-lab.", file=sys.stderr)
        return 2
    if args.with_isolation and not (args.level == "lab" and args.server):
        print("--with-isolation exige --level lab e --server (o isolamento corta a rede exceto a consola).", file=sys.stderr)
        return 2
    rep = v.validate(args.level, args.server or "", args.pin or "", args.with_isolation, redact=not args.no_redact)
    md = v.to_markdown(rep)
    if args.json:
        open(args.json, "w", encoding="utf-8").write(json.dumps(rep, indent=1, ensure_ascii=False))
    if args.report:
        open(args.report, "w", encoding="utf-8").write(md)
    print(md if not args.quiet else f"Resultado: {rep['summary']['counts']}")
    summ = os.environ.get("GITHUB_STEP_SUMMARY")
    if summ:
        open(summ, "a", encoding="utf-8").write(md)
    return 0 if rep["summary"]["ok"] else 1


def cmd_updates(args) -> int:
    """Diagnóstico local: corre a descoberta, mostra o resultado por origem e (com --send) envia-o à consola."""
    from . import updates as upd
    rep = upd.discover(refresh=not args.no_refresh)
    print(f"Plataforma: {rep['platform']} — {len(rep['updates'])} atualização(ões) descoberta(s)")
    if not rep["sources"]:
        print("Nenhuma origem aplicável encontrada neste equipamento (apt/dnf/zypper/WUA/winget/choco/softwareupdate/brew).")
    for name, s in rep["sources"].items():
        print(f"  {name:14} {'OK ' if s['ok'] else 'ERRO'} {s['count']:4} item(s) {s.get('error') or s.get('note') or ''}")
    for u in rep["updates"][:args.limit]:
        print(f"  - {u.get('name')} {u.get('current_version') or ''} -> {u.get('new_version') or ''} [{u.get('severity')}]")
    if args.send:
        from .updates import sync
        res = sync.run_and_upload(_client(), force=True)
        print("Enviado à consola:" , "sim" if res.get("sent") else f"NÃO ({res.get('error', '')})")
        return 0 if res.get("sent") else 1
    return 0


def cmd_status(args) -> int:
    cfg = config.load()
    print(f"Agente {__version__} — organização: {cfg.get('tenant_name', '(não registado)')} — servidor: {cfg.get('server_url', '-')} — configuração: {config.config_path()}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="omxpatch-agent")
    sub = p.add_subparsers(dest="cmd")
    e = sub.add_parser("enroll"); e.add_argument("--server", required=True); e.add_argument("--token", required=True)
    e.add_argument("--pin-sha256"); e.add_argument("--ca-file"); e.add_argument("--install-service", action="store_true"); e.add_argument("--force", action="store_true"); e.set_defaults(fn=cmd_enroll)
    for name, fn in (("run", cmd_run), ("once", cmd_once), ("inventory", cmd_inventory), ("status", cmd_status)):
        sub.add_parser(name).set_defaults(fn=fn)
    va = sub.add_parser("validate"); va.add_argument("--level", choices=["read", "lab"], default="read"); va.add_argument("--yes-lab", action="store_true")
    va.add_argument("--with-isolation", action="store_true"); va.add_argument("--server"); va.add_argument("--pin"); va.add_argument("--json"); va.add_argument("--report")
    va.add_argument("--no-redact", action="store_true"); va.add_argument("--quiet", action="store_true"); va.set_defaults(fn=cmd_validate)
    up = sub.add_parser("updates"); up.add_argument("--send", action="store_true"); up.add_argument("--no-refresh", action="store_true"); up.add_argument("--limit", type=int, default=20); up.set_defaults(fn=cmd_updates)
    st = sub.add_parser("selftest"); st.add_argument("--json", action="store_true"); st.set_defaults(fn=cmd_selftest)
    sub.add_parser("install-service").set_defaults(fn=lambda a: print(service.install()) or 0)
    sub.add_parser("uninstall-service").set_defaults(fn=lambda a: print(service.uninstall()) or 0)
    args = p.parse_args(argv)
    if not getattr(args, "fn", None):
        p.print_help()
        return 1
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
