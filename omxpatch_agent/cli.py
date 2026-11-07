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

from . import __version__, collectors, config, executor, service
from .client import Client, ServerError

log = logging.getLogger("omxpatch.agent")
INVENTORY_EVERY = 24 * 3600


def cmd_enroll(args) -> int:
    cfg = {"server_url": args.server.rstrip("/"), "pin_sha256": args.pin_sha256 or "", "ca_file": args.ca_file or ""}
    if not cfg["server_url"].startswith("https://"):
        print("AVISO: o servidor deve usar HTTPS.", file=sys.stderr)
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
    res = client.inventory({**{k: v for k, v in info.items() if k not in ("hostname", "machine_id")}, "version": __version__})
    log.info("Inventário enviado: %s", res)


def cycle(client: Client, state: dict) -> int:
    """Um contacto: inventário (se pedido/periódico) e execução das tarefas. Devolve o n.º de tarefas."""
    resp = client.poll()
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
    sub.add_parser("install-service").set_defaults(fn=lambda a: print(service.install()) or 0)
    sub.add_parser("uninstall-service").set_defaults(fn=lambda a: print(service.uninstall()) or 0)
    args = p.parse_args(argv)
    if not getattr(args, "fn", None):
        p.print_help()
        return 1
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
