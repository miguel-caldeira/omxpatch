"""Descoberta das atualizações **instaláveis** neste equipamento (sem instalar nada) para enviar à consola.

Cada origem devolve itens normalizados::

    {"uid", "source", "name", "title", "current_version", "new_version", "kb", "severity", "category", "cves": [], "size_bytes",
     "reboot", "download_url", "sha256", "installer", "package", "silent_args", "origin"}

e o estado da origem (``ok``/erro) — a consola só dá como resolvidas as atualizações de uma origem cujo varrimento terminou bem.
``download_url`` + ``sha256`` (quando a origem os fornece de forma verificável) permitem à consola descarregar o pacote
proativamente para o seu repositório."""
from __future__ import annotations

import time
import uuid

from ..config import platform_family

MAX_ITEMS = 2000


def _finish(updates: list) -> list:
    seen, out = set(), []
    for u in updates:
        key = (u["source"], u["uid"])
        if key in seen:
            continue
        seen.add(key)
        u.setdefault("cves", [])
        out.append(u)
    return out[:MAX_ITEMS]


def discover(refresh: bool = True) -> dict:
    """Varre todas as origens aplicáveis. Uma origem que falha não impede as outras."""
    fam = platform_family()
    if fam == "linux":
        from . import linux as mod
    elif fam == "windows":
        from . import windows as mod
    else:
        from . import macos as mod
    updates, sources = [], {}
    for name, fn in mod.SCANNERS:
        t0 = time.time()
        try:
            res = fn(refresh) if fn.__code__.co_argcount else fn()
            if res is None:                          # origem não disponível neste equipamento: não conta
                continue
            items, note = res
            for it in items:
                it.setdefault("source", name)
            updates += items
            sources[name] = {"ok": True, "count": len(items), "note": note, "seconds": round(time.time() - t0, 1)}
        except Exception as exc:  # noqa: BLE001 - cada origem é isolada
            sources[name] = {"ok": False, "count": 0, "error": f"{type(exc).__name__}: {exc}"[:300], "seconds": round(time.time() - t0, 1)}
    return {"scan_id": uuid.uuid4().hex, "scanned_at": time.time(), "platform": fam, "sources": sources, "updates": _finish(updates)}
