"""Simulação prévia (pré-voo) de um patch: tudo o que se pode verificar **sem instalar**.

Verificações comuns — privilégios, espaço em disco, reinício pendente, aplicação em utilização, saúde do sistema — e o
*dry-run* do instalador (aplicabilidade, versões, dependências, assinatura, reinício previsto). Cada verificação devolve
``ok`` / ``info`` / ``warn`` / ``block``; o servidor decide o resultado global (pronto / com avisos / bloqueado / nada a fazer)."""
from __future__ import annotations

import os
import shutil

from . import health, staging
from .config import platform_family
from .patchers import PatchError, simulate as os_simulate
from .runner import powershell, run

MB = 1024 * 1024


def _chk(cid: str, label: str, status: str, detail: str = "") -> dict:
    return {"id": cid, "label": label, "status": status, "detail": detail}


def privileges() -> dict:
    fam = platform_family()
    if fam == "windows":
        r = powershell("([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent())"
                       ".IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)", 60)
        ok = r.out.strip().lower().endswith("true")
    else:
        ok = hasattr(os, "geteuid") and os.geteuid() == 0
    return _chk("privileges", "Privilégios de administrador", "ok" if ok else "block",
                "" if ok else "O agente não corre como administrador/root: não consegue instalar")


def disk_space(p: dict, predicted: dict) -> dict:
    root = "C:\\" if platform_family() == "windows" else "/"
    free = shutil.disk_usage(root).free
    size = int(p.get("size_bytes") or 0) or int((predicted.get("download_mb") or 0) * MB)
    need = max(1024 * MB, size * 3)
    gb = free / 1024 / MB
    if free < need:
        return _chk("disk_space", "Espaço em disco", "block", f"Livre {gb:.1f} GB; necessário ≥ {need / 1024 / MB:.1f} GB")
    if free < need * 2:
        return _chk("disk_space", "Espaço em disco", "warn", f"Livre {gb:.1f} GB (necessário ≥ {need / 1024 / MB:.1f} GB)")
    return _chk("disk_space", "Espaço em disco", "ok", f"Livre {gb:.1f} GB")


def pending_reboot() -> dict:
    fam = platform_family()
    try:
        if fam == "windows":
            from .collectors import windows as w
            pend = w._reboot_pending()
        elif fam == "linux":
            from .patchers.linux import reboot_required
            pend = reboot_required()
        else:
            pend = False
    except Exception:  # noqa: BLE001
        return _chk("pending_reboot", "Reinício pendente", "info", "não foi possível determinar")
    return _chk("pending_reboot", "Reinício pendente", "warn" if pend else "ok",
                "Há um reinício pendente: a instalação pode falhar ou ficar incompleta até reiniciar" if pend else "")


def in_use(p: dict) -> dict | None:
    token = (p.get("product") or p.get("package") or "").split(" ")[0].split(".")[-1].lower()
    if len(token) < 3 or p.get("installer") in ("wua", "msu", "cab"):
        return None
    try:
        if platform_family() == "windows":
            out = run(["tasklist", "/FO", "CSV", "/NH"], 60).out.lower()
        else:
            out = run(["ps", "-A", "-o", "comm="], 30).out.lower()
    except Exception:  # noqa: BLE001
        return None
    if token in out:
        return _chk("in_use", "Aplicação em execução", "warn", f"«{token}» está em execução: pode ser interrompida ou exigir reinício")
    return _chk("in_use", "Aplicação em execução", "ok", "")


def run_simulation(client, p: dict) -> dict:
    """Executa a simulação completa. Nunca lança: erros viram verificações *block*."""
    checks: list[dict] = [privileges()]
    predicted: dict = {}

    def stage(suffix: str) -> str:
        return staging.stage(client, p, suffix)

    try:
        res = os_simulate(p, stage)
        checks += res["checks"]
        predicted = res["predicted"]
    except PatchError as exc:
        checks.append(_chk("applicability", "Simulação do instalador", "block", str(exc)))
    except Exception as exc:  # noqa: BLE001 - p. ex. falha de descarregamento ou de verificação do SHA-256
        checks.append(_chk("applicability", "Simulação do instalador", "block", f"{exc.__class__.__name__}: {exc}"))
    if p.get("reboot_required") and "reboot" not in predicted:
        predicted["reboot"] = True
    checks.append(disk_space(p, predicted))
    checks.append(pending_reboot())
    iu = in_use(p)
    if iu:
        checks.append(iu)
    failed = health.failed_units()
    checks.append(_chk("health", "Saúde do sistema (linha de base)", "warn" if failed > 5 else "ok", f"{failed} serviço(s)/eventos com falha"))
    if predicted.get("reboot"):
        policy = p.get("reboot_policy", "if_needed")
        checks.append(_chk("reboot_prediction", "Reinício previsto", "warn" if policy == "none" else "info",
                           "O patch exige reinício; a política da campanha é «nunca» — ficará pendente" if policy == "none"
                           else f"O patch exige reinício (política: {policy})"))
    return {"status": "succeeded", "checks": checks, "predicted": predicted,
            "output": "; ".join(f"{c['id']}={c['status']}" for c in checks)}
