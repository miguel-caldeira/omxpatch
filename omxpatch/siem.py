"""Envio da auditoria para um SIEM por syslog (UDP / TCP), formato RFC 5424 ou JSON, em segundo plano."""
from __future__ import annotations

import json
import logging
import queue
import threading
from datetime import datetime, timezone

from sqlalchemy import event

from .connectors.outbound import syslog_send
from .models import AuditLog

log = logging.getLogger("omxpatch.siem")
_q: "queue.Queue[dict]" = queue.Queue(maxsize=5000)
_app = None
_thread: threading.Thread | None = None


def build(cfg, ev: dict) -> str:
    if str(cfg.get("SYSLOG_FORMAT")) == "json":
        return json.dumps(ev, ensure_ascii=False, default=str)
    pri = int(cfg.get("SYSLOG_FACILITY", 16)) * 8 + 6
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sd = f'[omxpatch@0 tenant="{ev.get("tenant_id") or ""}" ip="{ev.get("ip", "")}"]'
    return f"<{pri}>1 {ts} omxpatch omxpatch - {ev.get('action')} {sd} {str(ev.get('detail', '')).replace(chr(10), ' ')}"


def _worker() -> None:
    while True:
        ev = _q.get()
        try:
            with _app.app_context():
                cfg = _app.config
                if cfg.get("SYSLOG_ENABLED") and cfg.get("SYSLOG_HOST"):
                    syslog_send(cfg["SYSLOG_HOST"], int(cfg["SYSLOG_PORT"]), str(cfg["SYSLOG_PROTOCOL"]).lower(), build(cfg, ev))
        except Exception as exc:  # noqa: BLE001 - o SIEM nunca bloqueia a aplicação
            log.warning("Syslog: %s", exc)


def _ensure_thread() -> None:
    global _thread
    if _thread is None or not _thread.is_alive():
        _thread = threading.Thread(target=_worker, daemon=True, name="omxpatch-syslog")
        _thread.start()


@event.listens_for(AuditLog, "after_insert")
def _inserted(mapper, connection, target):  # noqa: ANN001
    cfg = _app.config if _app is not None else {}
    if cfg.get("SYSLOG_ENABLED") and cfg.get("SYSLOG_HOST"):
        try:
            _q.put_nowait({"action": target.action, "detail": target.detail, "tenant_id": target.tenant_id,
                           "ip": target.ip, "user_id": target.user_id})
        except queue.Full:
            pass
        _ensure_thread()


def init_app(app) -> None:
    global _app
    _app = app
