"""Limitação de pedidos em memória (janela deslizante por chave). Por processo: com várias instâncias cada uma limita a sua parte."""
from __future__ import annotations

import threading
import time
from collections import deque

_lock = threading.Lock()
_hits: dict = {}


def hit(key: str, limit: int, window: int = 60) -> tuple[bool, int]:
    """Regista um pedido. Devolve (permitido, segundos até poder tentar de novo). ``limit`` ≤ 0 desativa."""
    if limit <= 0:
        return True, 0
    now = time.monotonic()
    with _lock:
        if len(_hits) > 20000:                                   # limita a memória: descarta chaves já expiradas
            for k in [k for k, d in _hits.items() if not d or now - d[-1] > window]:
                _hits.pop(k, None)
        d = _hits.setdefault(key, deque())
        while d and now - d[0] > window:
            d.popleft()
        if len(d) >= limit:
            return False, max(1, int(window - (now - d[0])) + 1)
        d.append(now)
        return True, 0


def peek(key: str, window: int = 60) -> int:
    """N.º de pedidos recentes (sem registar)."""
    now = time.monotonic()
    with _lock:
        return sum(1 for t in _hits.get(key, ()) if now - t <= window)


def reset() -> None:
    with _lock:
        _hits.clear()
