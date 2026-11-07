"""Configuração do agente (JSON, permissões 600) por sistema operativo."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def platform_family() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def config_dir() -> Path:
    env = os.environ.get("OMXPATCH_AGENT_DIR")
    if env:
        return Path(env)
    fam = platform_family()
    if fam == "windows":
        return Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "OMXPatchAgent"
    if fam == "macos":
        return Path("/Library/Application Support/OMXPatchAgent")
    return Path("/etc/omxpatch-agent")


def config_path() -> Path:
    return config_dir() / "agent.json"


def load() -> dict:
    p = config_path()
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def save(cfg: dict) -> Path:
    d = config_dir()
    d.mkdir(parents=True, exist_ok=True)
    p = config_path()
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    return p
