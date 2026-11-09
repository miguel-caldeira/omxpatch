"""Descoberta + envio à consola com garantia de entrega: o relatório fica em disco até a consola confirmar a receção
(*store-and-forward*): se a consola estiver em baixo, reenvia no contacto seguinte sem repetir o varrimento."""
from __future__ import annotations

import json
import logging
import os
import time

from .. import config

log = logging.getLogger("omxpatch.agent.updates")


def _pending_path():
    return config.config_dir() / "updates_pending.json"


def _state_path():
    return config.config_dir() / "updates_state.json"


def _read(p, default):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _write(p, data) -> None:
    config.config_dir().mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, p)


RETRY_FAILED_MINUTES = 30


def due(hours: float, now: float | None = None) -> bool:
    """Nova descoberta quando passou o intervalo — ou em 30 min se a última teve origens com erro (não espera 6 h por uma correção)."""
    st = _read(_state_path(), {})
    wait = min(hours * 3600, RETRY_FAILED_MINUTES * 60) if st.get("had_errors") else hours * 3600
    return (now or time.time()) - float(st.get("last_scan", 0)) >= wait


def flush_pending(client) -> dict | None:
    """Reenvia o relatório guardado, se existir. Devolve a confirmação da consola ou None."""
    p = _pending_path()
    report = _read(p, None)
    if not report:
        return None
    ack = client.updates(report)
    if ack.get("ok"):
        try:
            p.unlink()
        except OSError:
            pass
        _write(_state_path(), {"last_scan": report.get("scanned_at", time.time()), "last_ack": time.time(), "scan_id": report.get("scan_id"),
                                 "had_errors": any(v.get("ok") is False for v in (report.get("sources") or {}).values())})
    return ack


def run_and_upload(client, force: bool = False, hours: float = 6) -> dict:
    """Garante que a consola recebeu uma descoberta recente: reenvia o pendente e/ou faz um varrimento novo quando é altura."""
    from . import discover
    ack = None
    try:
        ack = flush_pending(client)
    except Exception as exc:  # noqa: BLE001 - mantém-se em disco para a próxima tentativa
        log.warning("Reenvio da descoberta falhou: %s", exc)
    if not force and not due(hours):
        return {"sent": bool(ack), "scanned": False, "ack": ack}
    report = discover(refresh=True)
    _write(_pending_path(), report)
    try:
        ack = flush_pending(client)
    except Exception as exc:  # noqa: BLE001
        log.warning("Envio da descoberta falhou (fica guardada e é reenviada): %s", exc)
        return {"sent": False, "scanned": True, "total": len(report["updates"]), "error": str(exc)[:200], "sources": report["sources"]}
    return {"sent": bool(ack and ack.get("ok")), "scanned": True, "total": len(report["updates"]), "ack": ack, "sources": report["sources"]}
