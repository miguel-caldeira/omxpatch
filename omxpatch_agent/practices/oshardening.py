"""Endurecimento do sistema operativo (configurações incorretas detetadas): SSH (Linux) e SMBv1/RDP-NLA (Windows).

Mesmo contrato das restantes boas práticas: ``plan`` (só leitura, com ações e *diff*), ``apply`` (cópia de segurança → alterar → testar →
recarregar → verificar → **reverter sozinho** se falhar) e ``rollback``. Salvaguardas contra bloqueio: o SSH só desativa a palavra-passe
se existir pelo menos uma chave autorizada (e o pedido o indicar); o ficheiro é validado com ``sshd -t`` antes de recarregar."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil

from ..config import platform_family
from ..runner import powershell, run
from . import common

SSHD_MAIN = "/etc/ssh/sshd_config"
DROPIN = "/etc/ssh/sshd_config.d/99-omxpatch.conf"
OS_PRACTICES = ("ssh_hardening", "windows_hardening")


# --------------------------------------------------------------------------- SSH (Linux)


def _sshd_effective() -> dict:
    if shutil.which("sshd") and os.geteuid() == 0:
        txt = run(["sshd", "-T"], 20).out
    else:
        try:
            txt = open(SSHD_MAIN, encoding="utf-8", errors="replace").read()
        except OSError:
            txt = ""
    d = {}
    for line in txt.splitlines():
        p = line.strip().split(None, 1)
        if len(p) == 2 and not p[0].startswith("#"):
            d.setdefault(p[0].lower(), p[1].strip().lower())
    return d


def authorized_keys_present() -> bool:
    for f in ["/root/.ssh/authorized_keys"] + glob.glob("/home/*/.ssh/authorized_keys"):
        try:
            if os.path.getsize(f) > 0:
                return True
        except OSError:
            continue
    return False


def _has_include() -> bool:
    try:
        return bool(re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/", open(SSHD_MAIN, encoding="utf-8", errors="replace").read(), re.M | re.I))
    except OSError:
        return False


def _ssh_wanted(params: dict, eff: dict) -> tuple[dict, list]:
    wanted, checks = {}, []
    if eff.get("permitrootlogin", "") not in ("no",):
        wanted["PermitRootLogin"] = "no"
    if eff.get("permitemptypasswords", "no") == "yes":
        wanted["PermitEmptyPasswords"] = "no"
    if params.get("disable_password"):
        if authorized_keys_present():
            if eff.get("passwordauthentication", "yes") != "no":
                wanted["PasswordAuthentication"] = "no"
            checks.append({"id": "keys", "label": "Existe chave SSH autorizada (sem risco de bloqueio)", "status": "ok", "detail": ""})
        else:
            checks.append({"id": "keys", "label": "Existe chave SSH autorizada", "status": "block",
                           "detail": "sem authorized_keys: desativar a palavra-passe deixaria o ativo inacessível por SSH"})
    return wanted, checks


def _ssh_plan(params: dict) -> dict:
    if not shutil.which("sshd"):
        return {"info": None, "checks": [{"id": "server", "label": "OpenSSH servidor instalado", "status": "block", "detail": "sshd não encontrado"}], "actions": [], "edits": [], "predicted": {}}
    eff = _sshd_effective()
    wanted, checks = _ssh_wanted(params, eff)
    checks.insert(0, {"id": "server", "label": "OpenSSH servidor detetado", "status": "ok", "detail": f"porta {eff.get('port', '22')}"})
    checks.append({"id": "include", "label": "Configuração em ficheiro próprio (sshd_config.d)", "status": "ok" if _has_include() else "warn",
                   "detail": "" if _has_include() else "sshd_config não inclui sshd_config.d: o ficheiro principal será alterado"})
    edits = []
    if wanted:
        body = "# Gerido pelo OMXPatch (endurecimento SSH)\n" + "".join(f"{k} {v}\n" for k, v in wanted.items())
        if _has_include():
            old = open(DROPIN, encoding="utf-8").read() if os.path.exists(DROPIN) else None
            edits.append(common.Edit(DROPIN, old, body, "SSH: " + ", ".join(f"{k} {v}" for k, v in wanted.items())))
        else:
            old = open(SSHD_MAIN, encoding="utf-8").read()
            new = old
            for k, v in wanted.items():
                new, n = common.replace_directives(new, rf"{k}\b", f"{k} {v}")
                if not n:
                    new = f"{k} {v}\n" + new                      # a 1.ª ocorrência vence no sshd
            edits.append(common.Edit(SSHD_MAIN, old, new, "SSH: " + ", ".join(f"{k} {v}" for k, v in wanted.items())))
    return {"info": {"type": "ssh"}, "checks": checks, "edits": edits, "actions": [e.action() for e in edits if e.changed], "wanted": wanted,
            "predicted": {"compliant": not wanted, "changes": len(wanted), "reload": bool(wanted), "wanted": wanted}}


def _ssh_apply(params: dict, item: str) -> dict:
    p = _ssh_plan(params)
    blocks = [c for c in p["checks"] if c["status"] == "block"]
    if blocks:
        return {"status": "failed", "output": "Pré-requisitos falhados: " + "; ".join(f"{c['label']}: {c['detail']}" for c in blocks), "actions": [], "rolled_back": False}
    edits = [e for e in p["edits"] if e.changed]
    if not edits:
        return {"status": "succeeded", "output": "Já em conformidade: nada a alterar.", "actions": [], "rolled_back": False}
    common.save_backup(f"{item}-ssh", edits)
    for e in edits:
        common.write_atomic(e.path, e.new)

    def undo(why):
        common.restore_backup(f"{item}-ssh")
        _reload()
        return {"status": "failed", "output": f"{why}; alterações revertidas.", "actions": p["actions"], "rolled_back": True}
    t = run(["sshd", "-t"], 30)
    if not t.ok:
        return undo("sshd -t falhou: " + t.out.strip()[-200:])
    r = _reload()
    if not r.ok:
        return undo("recarga do SSH falhou: " + r.out.strip()[-200:])
    eff = _sshd_effective()
    bad = [k for k, v in p["wanted"].items() if eff.get(k.lower()) != v]
    if bad:
        return undo("verificação falhou (" + ", ".join(bad) + ")")
    return {"status": "succeeded", "output": f"{len(edits)} ficheiro(s) alterado(s); SSH recarregado e verificado", "actions": p["actions"], "rolled_back": False,
            "verification": {"ok": True, "detail": ", ".join(f"{k}={v}" for k, v in p["wanted"].items())}}


def _reload():
    for unit in ("ssh", "sshd"):
        r = run(["systemctl", "reload", unit], 60)
        if r.ok:
            return r
    return r


# --------------------------------------------------------------------------- Windows (SMBv1 e RDP NLA)

WIN_READ = r"""
$ErrorActionPreference='SilentlyContinue'
[pscustomobject]@{ smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol; nla = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1);
  rdp = ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 0) } | ConvertTo-Json -Compress
"""


def _win_state() -> dict:
    r = powershell(WIN_READ, 60)
    try:
        return json.loads(r.out[r.out.index("{"):])
    except (ValueError, IndexError):
        return {}


def _win_plan(params: dict) -> dict:
    st = _win_state()
    checks = [{"id": "server", "label": "Estado lido do Windows", "status": "ok" if st else "block", "detail": "" if st else "não foi possível ler o estado (PowerShell/permissões)"}]
    changes = []
    if st.get("smb1"):
        changes.append({"key": "smb1", "old": True, "new": False, "summary": "SMBv1: ativo → desativado", "script": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -Confirm:$false",
                        "revert": "Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -Confirm:$false"})
    if st.get("rdp") and not st.get("nla"):
        changes.append({"key": "nla", "old": False, "new": True, "summary": "RDP: autenticação ao nível da rede (NLA) desativada → ativada",
                        "script": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
                        "revert": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 0"})
    if changes:
        checks.append({"id": "clients", "label": "Impacto em clientes antigos", "status": "warn",
                       "detail": "SMBv1: equipamentos XP/2003 e impressoras antigas deixam de partilhar ficheiros; NLA: clientes RDP sem CredSSP deixam de ligar"})
    return {"info": {"type": "windows"}, "checks": checks, "changes": changes,
            "actions": [{"target": "Windows", "kind": "definição do Windows", "summary": c["summary"], "diff": "", "reversible": True} for c in changes],
            "predicted": {"compliant": not changes, "changes": len(changes), "reboot": False}}


def _win_apply(params: dict, item: str) -> dict:
    p = _win_plan(params)
    if any(c["status"] == "block" for c in p["checks"]):
        return {"status": "failed", "output": "Estado do Windows ilegível", "actions": [], "rolled_back": False}
    if not p["changes"]:
        return {"status": "succeeded", "output": "Já em conformidade: nada a alterar.", "actions": [], "rolled_back": False}
    d = common.backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{item}-win")
    d.mkdir(parents=True, exist_ok=True)
    (d / "win.json").write_text(json.dumps(p["changes"]))
    for c in p["changes"]:
        r = powershell(c["script"], 120)
        if not r.ok:
            _win_rollback(item)
            return {"status": "failed", "output": f"Falha em «{c['summary']}»; revertido.\n{r.out.strip()[-200:]}", "actions": p["actions"], "rolled_back": True}
    after = _win_state()
    ok = all((after.get(c["key"]) == c["new"]) for c in p["changes"])
    if not ok:
        _win_rollback(item)
        return {"status": "failed", "output": "Verificação falhou; revertido.", "actions": p["actions"], "rolled_back": True}
    return {"status": "succeeded", "output": f"{len(p['changes'])} definição(ões) aplicada(s) e verificada(s)", "actions": p["actions"], "rolled_back": False,
            "verification": {"ok": True, "detail": ", ".join(c["summary"] for c in p["changes"])}}


def _win_rollback(item: str) -> list[str]:
    f = common.backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{item}-win") / "win.json"
    done = []
    for c in reversed(json.loads(f.read_text())):
        powershell(c["revert"], 120)
        done.append(c["key"])
    return done


# --------------------------------------------------------------------------- contrato comum


def simulate(practice: str, params: dict) -> dict:
    fam = platform_family()
    if practice == "ssh_hardening":
        p = _ssh_plan(params) if fam in ("linux", "macos") else {"info": None, "checks": [{"id": "os", "label": "Linux/macOS", "status": "block", "detail": "o SSH só se endurece em Linux/macOS"}], "actions": [], "predicted": {}}
    else:
        p = _win_plan(params) if fam == "windows" else {"info": None, "checks": [{"id": "os", "label": "Windows", "status": "block", "detail": "SMBv1/NLA só se aplicam em Windows"}], "actions": [], "predicted": {}}
    noop = bool(p.get("predicted", {}).get("compliant"))
    return {"checks": p["checks"], "actions": p["actions"], "predicted": {**p.get("predicted", {}), "noop": noop,
            "summary": "Já em conformidade" if noop else f"{len(p['actions'])} alteração(ões)"}}


def apply(practice: str, params: dict, item: str) -> dict:
    return _ssh_apply(params, item) if practice == "ssh_hardening" else _win_apply(params, item)


def rollback(practice: str, item: str) -> dict:
    if practice == "ssh_hardening":
        done = common.restore_backup(f"{item}-ssh")
        _reload()
    else:
        done = _win_rollback(item)
    return {"status": "succeeded" if done else "failed", "output": f"{len(done)} elemento(s) restaurado(s)", "restored": done}
