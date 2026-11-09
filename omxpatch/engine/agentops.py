"""Operação remota dos agentes a partir da consola: depuração, reinício, atualização, pedido de registos; e receção dos registos."""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

from flask import current_app

from ..extensions import db
from ..models import Agent, AgentLog, Task, utcnow

ACTIONS = {"restart": "Reiniciar o agente", "update": "Atualizar o agente", "debug_on": "Ativar depuração completa",
           "debug_off": "Desativar depuração", "logs": "Pedir envio imediato dos registos"}
KINDS = ("operation", "audit", "debug")
LEVELS = ("debug", "info", "warning", "error")
_SECRET = re.compile(r"(omx[ae]_[A-Za-z0-9_\-]{6,}|(?i:bearer)\s+[A-Za-z0-9._\-]{8,}|(?i:(?:password|passwd|palavra-passe|secret|token|agent_key|api[_-]?key))\s*[=:]\s*\S+)")


def record(agent: Agent, kind: str, message: str, level: str = "info", source: str = "console", data: dict | None = None, ts: datetime | None = None) -> None:
    db.session.add(AgentLog(tenant_id=agent.tenant_id, agent_id=agent.id, ts=ts or utcnow(), kind=kind, level=level, source=source,
                            message=_SECRET.sub("[removido]", message)[:2000], data=json.dumps(data, default=str)[:4000] if data else ""))


def command(agent: Agent, action: str, user=None, minutes: int | None = None) -> Task | None:
    """Pede uma ação ao agente (tarefa assinada; o agente recolhe-a no próximo contacto, de 5 em 5 min por defeito)."""
    if action not in ACTIONS:
        raise ValueError("ação desconhecida")
    cfg = current_app.config
    who = getattr(user, "email", "") or "consola"
    if action in ("debug_on", "debug_off"):
        if action == "debug_on":
            mins = max(1, min(int(minutes or cfg["AGENT_DEBUG_DEFAULT_MINUTES"]), 1440))
            agent.debug_until = utcnow() + timedelta(minutes=mins)
            minutes = mins
        else:
            agent.debug_until = None
    record(agent, "audit", f"{ACTIONS[action]}" + (f" ({minutes} min)" if action == "debug_on" else "") + f" — pedido por {who}", source="console",
           data={"action": action, "by": who})
    if agent.asset_id is None:
        return None
    # a depuração é declarativa (vai no contacto); restart/update/logs são tarefas assinadas e rastreáveis
    if action in ("debug_on", "debug_off"):
        return None
    if Task.query.filter(Task.tenant_id == agent.tenant_id, Task.asset_id == agent.asset_id, Task.type == "agent_ctl",
                         Task.status.in_(("queued", "sent", "running")), Task.payload.contains(f'"action": "{action}"')).first():
        return None
    t = Task(tenant_id=agent.tenant_id, type="agent_ctl", asset_id=agent.asset_id, ring=agent.asset.ring if agent.asset else 4, mode="agent", status="queued",
             payload=json.dumps({"action": action, "requested_by": who}))
    db.session.add(t)
    return t


def agent_config(agent: Agent, now: datetime | None = None) -> dict:
    """Parâmetros entregues ao agente em cada contacto (todos editáveis na consola)."""
    cfg = current_app.config
    now = now or utcnow()
    secs = int((agent.debug_until - now).total_seconds()) if agent.debug_until and agent.debug_until > now else 0
    return {"giveup_minutes": int(cfg["AGENT_GIVEUP_MINUTES"]), "log_upload": bool(cfg["AGENT_LOG_UPLOAD"]), "log_level": str(cfg["AGENT_LOG_LEVEL"]),
            "log_max_batch": int(cfg["AGENT_LOG_MAX_BATCH"]), "debug_seconds": secs}


def ingest(agent: Agent, events: list) -> int:
    """Grava os eventos recebidos do agente (validados: tipos, níveis, tamanhos, data plausível)."""
    cfg = current_app.config
    if not cfg.get("AGENT_LOG_UPLOAD", True):
        return 0
    now = utcnow()
    n = 0
    for ev in events[: int(cfg["AGENT_LOG_MAX_BATCH"]) * 2]:
        if not isinstance(ev, dict):
            continue
        kind = ev.get("kind") if ev.get("kind") in KINDS else "operation"
        level = ev.get("level") if ev.get("level") in LEVELS else "info"
        try:
            ts = datetime.fromtimestamp(float(ev.get("ts")), tz=timezone.utc).replace(tzinfo=None)
        except (TypeError, ValueError, OverflowError, OSError):
            ts = now
        if not (now - timedelta(days=14) <= ts <= now + timedelta(hours=1)):
            ts = now
        data = ev.get("data") if isinstance(ev.get("data"), dict) else None
        record(agent, kind, str(ev.get("msg", "")), level, "agent", data, ts)
        n += 1
    return n
