"""Aplicação de patches por sistema operativo (sem shell; argumentos validados)."""
from __future__ import annotations

import re

from ..config import platform_family

SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:@/=~-]{0,200}$")
KB_RE = re.compile(r"^KB\d{6,8}$", re.I)
SAFE_ARGS = re.compile(r"^[A-Za-z0-9 ._:/\\=\-\"'%,]{0,300}$")


class PatchError(RuntimeError):
    pass


def check_pkg(name: str) -> str:
    if not name or not SAFE_PKG.match(name):
        raise PatchError(f"Nome de pacote inválido: {name!r}")
    return name


SAFE_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._+\-()@:]{0,150}$")


def check_label(name: str) -> str:
    """Nome de atualização do macOS (``softwareupdate -l``): tem espaços («macOS Sonoma 14.5-23F79»). Vai sempre numa lista de
    argumentos (nunca por shell) e não pode começar por «-» (injeção de opções)."""
    if not name or not SAFE_LABEL.match(name):
        raise PatchError(f"Nome de atualização inválido: {name!r}")
    return name


def apply(payload: dict, download) -> dict:
    """``download(dest_suffix) -> caminho local`` obtém o ficheiro do repositório quando o patch o tem."""
    fam = platform_family()
    if fam == "windows":
        from . import windows as mod
    elif fam == "macos":
        from . import macos as mod
    else:
        from . import linux as mod
    return mod.apply(payload, download)


def simulate(payload: dict, stage) -> dict:
    """Dry-run por sistema operativo: {checks[], predicted{}} sem alterar o equipamento."""
    fam = platform_family()
    if fam == "windows":
        from . import windows as mod
    elif fam == "macos":
        from . import macos as mod
    else:
        from . import linux as mod
    return mod.simulate(payload, stage)
