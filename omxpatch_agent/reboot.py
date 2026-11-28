"""Reinício do equipamento com aviso prévio (e cancelamento), igual nos três sistemas operativos."""
from __future__ import annotations

import sys

from .runner import run

MSG = "OMXPatch: reinício após a atualização. Guarde o seu trabalho."


def clamp(minutes) -> int:
    try:
        return max(1, min(int(minutes), 10080))
    except (TypeError, ValueError):
        return 2


def schedule(minutes, message: str = MSG) -> str:
    n = clamp(minutes)
    if sys.platform.startswith("win"):
        r = run(["shutdown", "/r", "/t", str(n * 60), "/c", message[:500]], 30)
    else:
        r = run(["shutdown", "-r", f"+{n}", message[:500]], 30)
    return f"Reinício agendado para daqui a {n} minuto(s)." + ("" if r.ok else f" (aviso: {r.out.strip()[:200]})")


def cancel() -> str:
    r = run(["shutdown", "/a"], 30) if sys.platform.startswith("win") else run(["shutdown", "-c"], 30)
    return "Reinício cancelado." if r.ok else f"Nada a cancelar ou falhou: {r.out.strip()[:200]}"
