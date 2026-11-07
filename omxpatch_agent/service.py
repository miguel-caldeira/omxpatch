"""Instalação do agente como serviço (systemd, launchd, Tarefa Agendada do Windows). Os playbooks Ansible usam o
mesmo mecanismo; este módulo serve a instalação manual (``omxpatch-agent install-service``)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import platform_family
from .runner import run

UNIT = """[Unit]
Description=OMXPatch Agent
After=network-online.target
Wants=network-online.target

[Service]
Environment=PYTHONPATH={root}
ExecStart={python} -m omxpatch_agent run
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
"""
PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>pt.oramix.omxpatch.agent</string>
<key>ProgramArguments</key><array><string>{python}</string><string>-m</string><string>omxpatch_agent</string><string>run</string></array>
<key>EnvironmentVariables</key><dict><key>PYTHONPATH</key><string>{root}</string></dict>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>/var/log/omxpatch-agent.log</string><key>StandardErrorPath</key><string>/var/log/omxpatch-agent.log</string>
</dict></plist>
"""


def package_root() -> Path:
    """Pasta que contém o pacote omxpatch_agent (o agente instalado por script não usa pip nem venv)."""
    return Path(__file__).resolve().parent.parent


def install() -> str:
    fam, py, root = platform_family(), sys.executable, package_root()
    if fam == "linux":
        Path("/etc/systemd/system/omxpatch-agent.service").write_text(UNIT.format(python=py, root=root))
        run(["systemctl", "daemon-reload"], 60)
        r = run(["systemctl", "enable", "--now", "omxpatch-agent"], 120)
        return "serviço systemd omxpatch-agent " + ("ativo" if r.ok else f"falhou: {r.out}")
    if fam == "macos":
        path = Path("/Library/LaunchDaemons/pt.oramix.omxpatch.agent.plist")
        path.write_text(PLIST.format(python=py, root=root))
        os.chmod(path, 0o644)
        r = run(["launchctl", "load", "-w", str(path)], 60)
        return "LaunchDaemon " + ("carregado" if r.ok else f"falhou: {r.out}")
    launcher = root / "run-agent.cmd"
    launcher.write_text(f'@echo off\r\nset PYTHONPATH={root}\r\n"{py}" -m omxpatch_agent run\r\n', encoding="ascii")
    r = run(["schtasks", "/Create", "/F", "/TN", "OMXPatchAgent", "/SC", "ONSTART", "/RU", "SYSTEM", "/RL", "HIGHEST",
             "/TR", f'"{launcher}"'], 60)
    if r.ok:
        run(["schtasks", "/Run", "/TN", "OMXPatchAgent"], 60)
    return "Tarefa agendada OMXPatchAgent " + ("criada e iniciada" if r.ok else f"falhou: {r.out}")


def uninstall() -> str:
    fam = platform_family()
    if fam == "linux":
        run(["systemctl", "disable", "--now", "omxpatch-agent"], 60)
        Path("/etc/systemd/system/omxpatch-agent.service").unlink(missing_ok=True)
        return "serviço removido"
    if fam == "macos":
        p = Path("/Library/LaunchDaemons/pt.oramix.omxpatch.agent.plist")
        run(["launchctl", "unload", "-w", str(p)], 60)
        p.unlink(missing_ok=True)
        return "LaunchDaemon removido"
    run(["schtasks", "/Delete", "/F", "/TN", "OMXPatchAgent"], 60)
    return "Tarefa agendada removida"
