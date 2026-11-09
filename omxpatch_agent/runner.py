"""Execução de comandos sem shell, com tempo limite e saída limitada."""
from __future__ import annotations

import subprocess  # nosec B404
from dataclasses import dataclass


@dataclass
class Result:
    rc: int
    out: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def run(cmd: list[str], timeout: int = 3600, input_text: str | None = None, env: dict | None = None) -> Result:
    try:
        import os
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text,  # nosec B603
                           encoding="utf-8", errors="replace", env={**os.environ, **env} if env else None)
        return Result(p.returncode, ((p.stdout or "") + (p.stderr or ""))[-30000:])
    except FileNotFoundError:
        return Result(127, f"Comando não encontrado: {cmd[0]}")
    except subprocess.TimeoutExpired as exc:
        return Result(124, f"Tempo excedido ({timeout}s)\n{(exc.stdout or '')[-2000:] if isinstance(exc.stdout, str) else ''}")


def powershell(script: str, timeout: int = 3600) -> Result:
    """Executa o script com -EncodedCommand (UTF-16LE em base64): sem problemas de aspas/acentos na linha de comandos do Windows
    e com a saída em UTF-8."""
    import base64
    pre = "$ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    enc = base64.b64encode((pre + script).encode("utf-16-le")).decode("ascii")
    return run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc], timeout)
