"""Versão instalada da consola e histórico de atualizações (``<dados>/version.json``), mostrados na consola e confirmados pelos scripts."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from . import __version__  # noqa: F401  (reexportado)

log = logging.getLogger("omxpatch.version")
MAX_HISTORY = 20


def _path(cfg) -> Path:
    return Path(cfg["DATA_DIR"]) / "version.json"


def read(cfg) -> dict:
    try:
        return json.loads(_path(cfg).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def record(cfg) -> dict:
    """Chamado no arranque: se a versão mudou, regista «anterior → atual» e a data."""
    info = read(cfg)
    if info.get("current") == __version__:
        return info
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    hist = list(info.get("history", []))
    if info.get("current"):
        hist.append({"from": info["current"], "to": __version__, "at": now})
    info = {"current": __version__, "previous": info.get("current", ""), "since": now, "history": hist[-MAX_HISTORY:]}
    try:
        p = _path(cfg)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(info, ensure_ascii=False, indent=1), encoding="utf-8")
    except OSError as exc:
        log.warning("Não foi possível gravar %s: %s", _path(cfg), exc)
    return info
