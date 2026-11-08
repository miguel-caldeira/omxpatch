"""Confiança do agente na consola: impressões digitais (com rotação), chaves de assinatura de tarefas e verificação das tarefas.

* ``pin_sha256`` pode ser uma lista (separada por vírgula): o agente aceita o certificado atual **e** o seguinte; a consola publica a
  lista no contacto e o agente só a adota se contiver a impressão digital com que acabou de se ligar — assim a renovação do
  certificado não deixa a frota sem ligação.
* ``task_keys`` (Ed25519): fixadas no 1.º contacto (por TLS já fixado) e só substituíveis por uma lista que contenha uma já conhecida.
  Com chaves fixadas, uma tarefa sem assinatura válida e recente é recusada."""
from __future__ import annotations

import json
import time

from . import ed25519

TASK_MAX_AGE = 3600          # s: a tarefa tem de ter sido assinada há menos de 1 h (relógios dos postos incluídos)
FUTURE_SKEW = 600


def canonical(kind: str, data: dict) -> bytes:
    return b"OMXPatch-" + kind.encode() + b"\0" + json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_with(keys, kind: str, data: dict, sig_hex: str) -> bool:
    try:
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError):
        return False
    msg = canonical(kind, data)
    return any(ed25519.verify(bytes.fromhex(k), msg, sig) for k in keys if _is_hex(k, 64))


def _is_hex(v, n: int) -> bool:
    return isinstance(v, str) and len(v) == n and all(c in "0123456789abcdefABCDEF" for c in v)


def verify_task(cfg: dict, task: dict, agent_id, now: float | None = None) -> tuple[bool, str]:
    """(válida, motivo). Sem chaves fixadas (agente antigo/ainda sem 1.º contacto) aceita — comportamento anterior."""
    keys = cfg.get("task_keys") or []
    if not keys:
        return True, ""
    now = now or time.time()
    iat = task.get("iat")
    if not isinstance(iat, int) or not task.get("sig"):
        return False, "tarefa sem assinatura"
    if iat < now - TASK_MAX_AGE or iat > now + FUTURE_SKEW:
        return False, "assinatura fora de prazo (verifique o relógio do equipamento)"
    data = {"id": task.get("id"), "type": task.get("type"), "payload": task.get("payload"), "agent": agent_id, "iat": iat}
    if not verify_with(keys, "task", data, task["sig"]):
        return False, "assinatura inválida"
    return True, ""


def adopt(cfg: dict, trust: dict, matched_pin: str = "") -> bool:
    """Atualiza ``cfg`` (em memória) com o que a consola publicou; devolve True se mudou. Nunca aceita nada que quebre a continuidade."""
    changed = False
    pins = [p.replace(":", "").lower() for p in trust.get("pins") or [] if isinstance(p, str)]
    pins = [p for p in pins if len(p) in (40, 64) and _is_hex(p, len(p))][:4]
    current = [p for p in str(cfg.get("pin_sha256") or "").split(",") if p]
    if pins and current and (matched_pin in pins or set(pins) & set(current)) and pins != current:
        cfg["pin_sha256"] = ",".join(pins)
        changed = True
    if isinstance(trust.get("agent_id"), int) and not cfg.get("agent_id"):
        cfg["agent_id"] = trust["agent_id"]
        changed = True
    keys = [k.lower() for k in trust.get("task_keys") or [] if _is_hex(k, 64)][:3]
    have = cfg.get("task_keys") or []
    if keys and keys != have and (not have or set(keys) & set(have)):
        cfg["task_keys"] = keys
        changed = True
    return changed
