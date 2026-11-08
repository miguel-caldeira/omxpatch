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
import logging
import random
import sys
import time

from . import __version__, collectors, compat, config, executor, service
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


def cycle(client: Client, state: dict) -> int:
    """Um contacto: inventário (se pedido/periódico) e execução das tarefas. Devolve o n.º de tarefas."""
    resp = client.poll()
    _adopt_servers(client, resp.get("server_urls"))
    if resp.get("inventory_requested") or time.time() - state.get("last_inventory", 0) > INVENTORY_EVERY:
        try:
            send_inventory(client)
            state["last_inventory"] = time.time()
        except Exception as exc:  # noqa: BLE001
            log.warning("Inventário falhou: %s", exc)
    for task in resp.get("tasks", []):
        log.info("Tarefa %s (%s)", task["id"], task["type"])
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
