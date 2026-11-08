"""Métricas de pedidos em memória (por processo): taxa, latência (p50/p95/p99) e erros por grupo de rotas.

Alimentam a página «Capacidade e carga». São por processo web (o worker publica as suas num ficheiro, ver ``engine/capacity``)."""
from __future__ import annotations

import threading
import time
from collections import deque

START = time.time()
_lock = threading.Lock()
_GROUPS = ("agent_poll", "agent_other", "api", "console")
_samples: dict = {g: deque(maxlen=5000) for g in _GROUPS}
_inflight = 0


def group_of(path: str) -> str:
    if path.endswith("/agent/v1/poll"):
        return "agent_poll"
    if "/agent/v1/" in path:
        return "agent_other"
    if "/api/v1/" in path:
        return "api"
    return "console"


def begin() -> float:
    global _inflight
    with _lock:
        _inflight += 1
    return time.perf_counter()


def end(path: str, started: float, status: int) -> None:
    global _inflight
    ms = (time.perf_counter() - started) * 1000
    with _lock:
        _inflight = max(0, _inflight - 1)
        if "/static/" not in path:
            _samples[group_of(path)].append((time.time(), ms, status))


def _pct(values: list, p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return round(values[min(len(values) - 1, int(len(values) * p))], 1)


def summary(window: int = 300) -> dict:
    now = time.time()
    out: dict = {"uptime_s": int(now - START), "inflight": _inflight, "groups": {}}
    with _lock:
        snap = {g: list(d) for g, d in _samples.items()}
    for g, rows in snap.items():
        rows = [r for r in rows if now - r[0] <= window]
        lat = [r[1] for r in rows]
        span = max(1.0, min(window, now - rows[0][0])) if rows else 1.0
        out["groups"][g] = {"requests": len(rows), "rps": round(len(rows) / span, 2), "p50": _pct(lat, .5), "p95": _pct(lat, .95),
                            "p99": _pct(lat, .99), "errors": sum(1 for r in rows if r[2] >= 500)}
    return out


def reset() -> None:
    with _lock:
        for d in _samples.values():
            d.clear()
