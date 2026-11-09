"""Registos do agente para a consola (operação, auditoria, depuração) e estado de execução persistente.

* Os eventos ficam num ficheiro local (``agent_events.jsonl``, limitado) até a consola confirmar a receção (store-and-forward).
* O modo de depuração é pedido pela consola, tem validade e sobrevive a reinícios; fora dele só se enviam eventos INFO ou acima.
* Segredos (chave do agente, tokens, palavras-passe) são removidos de tudo o que sai do equipamento.
* ``runtime.json`` guarda o que tem de sobreviver a reinícios: depuração, parâmetros recebidos da consola, início das falhas de contacto."""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import re
import threading
import time

from . import config

MAX_QUEUE_BYTES = 2 * 1024 * 1024        # o ficheiro de eventos pendentes nunca passa disto (descarta os mais antigos)
LEVELS = {"debug": 10, "info": 20, "warning": 30, "error": 40}
_lock = threading.Lock()
_SECRET = re.compile(r"(omx[ae]_[A-Za-z0-9_\-]{6,}|(?i:bearer)\s+[A-Za-z0-9._\-]{8,}|(?i:(?:password|passwd|palavra-passe|secret|token|agent_key|api[_-]?key))\s*[=:]\s*\S+)")


def redact(text) -> str:
    return _SECRET.sub("[removido]", str(text))


def _p(name: str):
    return config.config_dir() / name


# --------------------------------------------------------------------------- estado persistente


def runtime() -> dict:
    try:
        return json.loads(_p("runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_runtime(data: dict) -> None:
    config.config_dir().mkdir(parents=True, exist_ok=True)
    tmp = _p("runtime.json.tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, _p("runtime.json"))


def update_runtime(**kw) -> dict:
    with _lock:
        rt = runtime()
        rt.update(kw)
        for k in [k for k, v in rt.items() if v is None]:
            rt.pop(k)
        save_runtime(rt)
        return rt


def debug_active(now: float | None = None) -> bool:
    return float(runtime().get("debug_until", 0)) > (now or time.time())


def set_debug(seconds: int) -> bool:
    """Liga/desliga a depuração (segundos restantes; 0 desliga). Devolve True se o estado mudou."""
    was = debug_active()
    update_runtime(debug_until=(time.time() + seconds) if seconds > 0 else None)
    apply_log_level()
    now = debug_active()
    if now != was:
        audit("debug_on" if now else "debug_off", f"depuração {'ativada por ' + str(seconds // 60) + ' min' if now else 'desativada'} pela consola")
    return now != was


def adopt_server_config(ac: dict) -> None:
    """Parâmetros enviados pela consola no contacto (todos configuráveis na consola)."""
    if not isinstance(ac, dict):
        return
    keep = {}
    for k in ("giveup_minutes", "log_upload", "log_level", "log_max_batch"):
        if k in ac:
            keep[k] = ac[k]
    if keep:
        update_runtime(**keep)
    set_debug(int(ac.get("debug_seconds") or 0))


# --------------------------------------------------------------------------- eventos


def _append(ev: dict) -> None:
    line = json.dumps(ev, ensure_ascii=False, separators=(",", ":"))
    with _lock:
        p = _p("agent_events.jsonl")
        config.config_dir().mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        try:
            if p.stat().st_size > MAX_QUEUE_BYTES:
                lines = p.read_text(encoding="utf-8").splitlines()
                p.write_text("\n".join(lines[len(lines) // 2:]) + "\n", encoding="utf-8")
        except OSError:
            pass


def event(kind: str, level: str, msg: str, data: dict | None = None) -> None:
    if kind not in ("operation", "audit", "debug"):
        kind = "operation"
    ev = {"ts": round(time.time(), 3), "kind": kind, "level": level if level in LEVELS else "info", "msg": redact(msg)[:2000]}
    if data:
        ev["data"] = json.loads(redact(json.dumps(data, default=str)))
    try:
        _append(ev)
    except OSError:
        pass


def audit(action: str, detail: str = "", **data) -> None:
    event("audit", "info", f"{action}: {detail}" if detail else action, {"action": action, **data})


def pending(limit: int) -> tuple[list, int]:
    """Eventos por enviar (máximo ``limit``) e o n.º de linhas lidas (para os descartar depois da confirmação)."""
    try:
        lines = _p("agent_events.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], 0
    out, n = [], 0
    for line in lines[:limit]:
        n += 1
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out, n


def pending_count() -> int:
    try:
        with open(_p("agent_events.jsonl"), encoding="utf-8") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def drop(n: int) -> None:
    with _lock:
        p = _p("agent_events.jsonl")
        try:
            lines = p.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        rest = lines[n:]
        p.write_text(("\n".join(rest) + "\n") if rest else "", encoding="utf-8")


def flush(client) -> int:
    """Envia os eventos pendentes à consola (vários lotes); só os apaga depois da confirmação. Devolve o n.º enviado."""
    rt = runtime()
    if rt.get("log_upload", True) is False:
        drop(10 ** 9)
        return 0
    batch = max(10, min(int(rt.get("log_max_batch") or 200), 1000))
    sent = 0
    for _ in range(5):
        evs, n = pending(batch)
        if not n:
            break
        if not evs:
            drop(n)
            continue
        ack = client.logs(evs)
        if not ack.get("ok"):
            break
        drop(n)
        sent += len(evs)
    return sent


class _Handler(logging.Handler):
    """Encaminha os registos Python para a fila de eventos: INFO+ (ou o nível definido na consola) como «operação»; tudo em depuração."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            if record.name.startswith("omxpatch.agent.telemetry"):
                return
            rt = runtime()
            minimum = LEVELS.get(str(rt.get("log_level", "info")).lower(), 20)
            if record.levelno >= max(minimum, 20):
                event("operation", record.levelname.lower(), f"{record.name}: {record.getMessage()}")
            elif record.levelno >= 10 and debug_active():
                event("debug", "debug", f"{record.name}: {record.getMessage()}")
        except Exception:  # noqa: BLE001 - registar nunca pode partir o agente
            pass


_installed = False


def apply_log_level() -> None:
    logging.getLogger("omxpatch").setLevel(logging.DEBUG if debug_active() else logging.INFO)


def setup(console: bool = True) -> None:
    """Configura o registo: consola, ficheiro rotativo local e fila para a consola."""
    global _installed
    root = logging.getLogger("omxpatch")
    if _installed:
        apply_log_level()
        return
    _installed = True
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        root.addHandler(sh)
    try:
        config.config_dir().mkdir(parents=True, exist_ok=True)
        fh = logging.handlers.RotatingFileHandler(str(_p("agent.log")), maxBytes=1024 * 1024, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.addFilter(lambda r: True)
        root.addHandler(fh)
    except OSError:
        pass
    root.addHandler(_Handler())
    root.propagate = False
    apply_log_level()


# --------------------------------------------------------------------------- desistência (sem contacto durante muito tempo)


def contact_ok() -> None:
    rt = runtime()
    if "first_fail" in rt or "disconnected" in rt:
        update_runtime(first_fail=None, disconnected=None)


def contact_failed(now: float | None = None) -> float:
    """Regista a falha; devolve há quantos minutos o agente não consegue contactar a consola."""
    now = now or time.time()
    rt = runtime()
    first = float(rt.get("first_fail") or 0)
    if not first:
        first = now
        update_runtime(first_fail=first)
        audit("contact_lost", "sem contacto com a consola")
    return (now - first) / 60.0


def should_give_up(minutes_without_contact: float) -> bool:
    limit = float(runtime().get("giveup_minutes", 120))
    return limit > 0 and minutes_without_contact >= limit
