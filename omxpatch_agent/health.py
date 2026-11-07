"""Indicadores de saúde antes/depois do patch (crash rate e experiência do utilizador)."""
from __future__ import annotations

import shutil

from .config import platform_family
from .runner import powershell, run


def failed_units() -> int:
    fam = platform_family()
    if fam == "linux" and shutil.which("systemctl"):
        r = run(["systemctl", "--failed", "--no-legend", "--plain"], 30)
        return len([l for l in r.out.splitlines() if l.strip()])
    if fam == "windows":
        r = powershell("(Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=(Get-Date).AddMinutes(-15)} "
                       "-ErrorAction SilentlyContinue | Measure-Object).Count", 120)
        try:
            return int(r.out.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return 0
    return 0


def ux_score(duration_s: int, rebooted: bool, crashed: bool, failed: bool) -> int:
    """Heurística documentada: 100 − 40 (falha) − 30 (crash) − 15 (reinício forçado) − 10 (>15 min) − 5 (>5 min)."""
    s = 100 - (40 if failed else 0) - (30 if crashed else 0) - (15 if rebooted else 0)
    s -= 10 if duration_s > 900 else 5 if duration_s > 300 else 0
    return max(0, min(100, s))
