"""IIS / Windows: TLS (Schannel + .NET) e cabeçalhos HTTP.

* ``tls_protocols`` — Schannel: SSL 2.0/3.0 e TLS 1.0/1.1 desativados, TLS 1.2 (e 1.3 onde o Windows o suporta: Server 2022 / Windows 11)
  ativados, mais ``SchUseStrongCrypto`` / ``SystemDefaultTlsVersions`` do .NET. É global ao equipamento (afeta RDP, SQL, etc.) e só
  passa a valer após **reiniciar**: o plano avisa e a verificação fica pendente.
* ``hsts`` / ``security_headers`` — cabeçalhos ao nível do servidor IIS (``system.webServer/httpProtocol/customHeaders``).
* ``hide_version`` — ``removeServerHeader``, ``X-Powered-By`` e ``X-AspNet-Version``.
Cada alteração guarda o valor anterior (cópia em JSON) e é reversível; o código usa o módulo WebAdministration."""
from __future__ import annotations

import json
import re

from .. import config
from ..runner import powershell
from . import common

SCHANNEL = r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
NET = (r"HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319", r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319",
       r"HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727", r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727")
HEADERS = (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "SAMEORIGIN"), ("Referrer-Policy", "same-origin"))
TLS13_MIN_BUILD = 20348            # Windows Server 2022 / Windows 11


def hsts_value(params: dict) -> str:
    v = f"max-age={int(params.get('max_age') or common.HSTS_DEFAULT_MAX_AGE)}"
    if params.get("include_subdomains", True):
        v += "; includeSubDomains"
    return v + ("; preload" if params.get("preload") else "")


def _ps_str(v: str) -> str:
    return "'" + v.replace("'", "''") + "'"


def _json(out: str):
    for line in reversed(out.strip().splitlines()):
        try:
            return json.loads(line)
        except ValueError:
            continue
    return None


def detect() -> dict | None:
    r = powershell(r"""
$svc = Get-Service W3SVC -ErrorAction SilentlyContinue
if (-not $svc) { exit 3 }
$v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue).VersionString
[pscustomobject]@{ status = "$($svc.Status)"; version = "$v"; build = [Environment]::OSVersion.Version.Build;
  webadmin = [bool](Get-Module -ListAvailable WebAdministration) } | ConvertTo-Json -Compress""", 60)
    d = _json(r.out) if r.ok else None
    if not d:
        return None
    return {"type": "iis", "version": (d.get("version") or "").replace("Version ", ""), "running": d.get("status") == "Running", "build": int(d.get("build") or 0),
            "webadmin": bool(d.get("webadmin")), "config": "IIS (applicationHost.config)", "ports": [443]}


def schannel_targets(params: dict, build: int) -> list[tuple[str, str, int]]:
    """[(chave, nome, valor desejado)]. ``scope=both`` inclui o lado cliente (afeta ligações de saída das aplicações)."""
    sides = ("Server", "Client") if params.get("scope") == "both" else ("Server",)
    out = []
    for proto in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"):
        for side in sides:
            out += [(rf"{SCHANNEL}\{proto}\{side}", "Enabled", 0), (rf"{SCHANNEL}\{proto}\{side}", "DisabledByDefault", 1)]
    protos = ["TLS 1.2"] + (["TLS 1.3"] if build >= TLS13_MIN_BUILD and params.get("tls13", "auto") not in (False, "false") else [])
    for proto in protos:
        for side in sides:
            out += [(rf"{SCHANNEL}\{proto}\{side}", "Enabled", 1), (rf"{SCHANNEL}\{proto}\{side}", "DisabledByDefault", 0)]
    for key in NET:
        out += [(key, "SchUseStrongCrypto", 1), (key, "SystemDefaultTlsVersions", 1)]
    return out


def read_registry(targets: list[tuple[str, str, int]]) -> dict[str, int | None]:
    items = ",".join(f"@({_ps_str(k)},{_ps_str(n)})" for k, n, _ in targets)
    r = powershell(f"""
$o = @{{}}
foreach ($t in @({items})) {{ $v = (Get-ItemProperty -Path $t[0] -Name $t[1] -ErrorAction SilentlyContinue).$($t[1]); $o[$t[0] + '|' + $t[1]] = $v }}
$o | ConvertTo-Json -Compress""", 120)
    return _json(r.out) or {}


def read_headers() -> dict[str, str]:
    r = powershell(r"""
Import-Module WebAdministration -ErrorAction SilentlyContinue
$h = @{}
Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -ErrorAction SilentlyContinue |
  ForEach-Object { $_.Collection } | ForEach-Object { $h[$_.name] = $_.value }
$rf = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.webServer/security/requestFiltering' -Name removeServerHeader -ErrorAction SilentlyContinue)
$h['__removeServerHeader'] = "$($rf)"
$an = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT' -Filter 'system.web/httpRuntime' -Name enableVersionHeader -ErrorAction SilentlyContinue)
$h['__enableVersionHeader'] = "$($an)"
$h | ConvertTo-Json -Compress""", 120)
    return _json(r.out) or {}


def _fmt(v) -> str:
    return "(ausente)" if v is None else str(v)


def plan(practice: str, params: dict) -> dict:
    info = detect()
    checks: list[dict] = []
    if info is None:
        return {"info": None, "checks": [{"id": "server", "label": "IIS instalado", "status": "block", "detail": "serviço W3SVC não encontrado"}],
                "actions": [], "predicted": {}, "changes": []}
    checks.append({"id": "server", "label": "IIS detetado", "status": "ok" if info["running"] else "warn",
                   "detail": f"{info['version']} (build do Windows {info['build']}){'' if info['running'] else ' — serviço parado'}"})
    changes: list[dict] = []
    actions: list[dict] = []
    if practice == "tls_protocols":
        want13 = params.get("tls13", "auto")
        if info["build"] < TLS13_MIN_BUILD:
            checks.append({"id": "tls13", "label": "TLS 1.3 suportado", "status": "block" if want13 in (True, "true") else "warn",
                           "detail": f"Windows build {info['build']} < {TLS13_MIN_BUILD}: só é configurado o TLS 1.2"})
        else:
            checks.append({"id": "tls13", "label": "TLS 1.3 suportado", "status": "ok", "detail": f"Windows build {info['build']}"})
        targets = schannel_targets(params, info["build"])
        cur = read_registry(targets)
        for key, name, want in targets:
            have = cur.get(f"{key}|{name}")
            if have is None or int(have) != want:
                changes.append({"type": "registry", "key": key, "name": name, "old": have, "new": want})
        checks.append({"id": "reboot", "label": "Reinício necessário", "status": "warn" if changes else "info",
                       "detail": "O Schannel só aplica as alterações após reiniciar o servidor" + ("; afeta todos os serviços do equipamento (RDP, SQL…)" if changes else "")})
        if params.get("scope") == "both":
            checks.append({"id": "client_side", "label": "Lado cliente do Schannel", "status": "warn",
                           "detail": "Desativar protocolos antigos no cliente pode quebrar ligações de saída de aplicações legadas"})
    else:
        if not info["webadmin"]:
            checks.append({"id": "webadmin", "label": "Módulo WebAdministration", "status": "block", "detail": "Função «Web Server (IIS) Management Tools» em falta"})
        cur = read_headers() if info["webadmin"] else {}
        if practice == "hsts":
            wanted = {"Strict-Transport-Security": hsts_value(params)}
        elif practice == "security_headers":
            wanted = dict(HEADERS)
        else:
            wanted = {}
        for name, val in wanted.items():
            if cur.get(name) != val:
                changes.append({"type": "header", "name": name, "old": cur.get(name), "new": val})
        if practice == "hide_version":
            for name in ("X-Powered-By",):
                if name in cur:
                    changes.append({"type": "header_remove", "name": name, "old": cur.get(name), "new": None})
            if cur.get("__removeServerHeader", "").lower() != "true":
                changes.append({"type": "iis_setting", "filter": "system.webServer/security/requestFiltering", "pspath": "MACHINE/WEBROOT/APPHOST",
                                "name": "removeServerHeader", "old": cur.get("__removeServerHeader") or None, "new": "true"})
            if cur.get("__enableVersionHeader", "").lower() != "false":
                changes.append({"type": "iis_setting", "filter": "system.web/httpRuntime", "pspath": "MACHINE/WEBROOT", "name": "enableVersionHeader",
                                "old": cur.get("__enableVersionHeader") or None, "new": "false"})
    for c in changes:
        if c["type"] == "registry":
            actions.append({"target": c["key"], "kind": "registo do Windows", "summary": f"{c['name']}: {_fmt(c['old'])} → {c['new']}", "diff": "", "reversible": True})
        elif c["type"] in ("header", "header_remove"):
            actions.append({"target": "IIS customHeaders", "kind": "cabeçalho HTTP", "summary": f"{c['name']}: {_fmt(c['old'])} → {_fmt(c['new'])}", "diff": "", "reversible": True})
        else:
            actions.append({"target": c["filter"], "kind": "definição do IIS", "summary": f"{c['name']}: {_fmt(c['old'])} → {c['new']}", "diff": "", "reversible": True})
    return {"info": info, "checks": checks, "actions": actions, "changes": changes,
            "predicted": {"compliant": not changes, "changes": len(changes), "reboot": practice == "tls_protocols" and bool(changes)}}


def change_script(c: dict) -> str:
    if c["type"] == "registry":
        v = "$null" if c["new"] is None else str(int(c["new"]))
        return (f"if (-not (Test-Path {_ps_str(c['key'])})) {{ New-Item -Path {_ps_str(c['key'])} -Force | Out-Null }}\n"
                f"New-ItemProperty -Path {_ps_str(c['key'])} -Name {_ps_str(c['name'])} -Value {v} -PropertyType DWord -Force | Out-Null")
    pre = "Import-Module WebAdministration\n"
    ap = "'MACHINE/WEBROOT/APPHOST'"
    if c["type"] == "header":
        flt = "'system.webServer/httpProtocol/customHeaders'"
        return (pre + f"$e = Get-WebConfigurationProperty -PSPath {ap} -Filter \"system.webServer/httpProtocol/customHeaders/add[@name={_ps_str(c['name'])}]\" -Name value -ErrorAction SilentlyContinue\n"
                f"if ($e) {{ Set-WebConfigurationProperty -PSPath {ap} -Filter \"system.webServer/httpProtocol/customHeaders/add[@name={_ps_str(c['name'])}]\" -Name value -Value {_ps_str(c['new'])} }}\n"
                f"else {{ Add-WebConfigurationProperty -PSPath {ap} -Filter {flt} -Name '.' -Value @{{name={_ps_str(c['name'])}; value={_ps_str(c['new'])}}} }}")
    if c["type"] == "header_remove":
        return pre + f"Remove-WebConfigurationProperty -PSPath {ap} -Filter 'system.webServer/httpProtocol/customHeaders' -Name '.' -AtElement @{{name={_ps_str(c['name'])}}}"
    return pre + f"Set-WebConfigurationProperty -PSPath '{c['pspath']}' -Filter '{c['filter']}' -Name '{c['name']}' -Value {_ps_str(c['new'])}"


def revert_script(c: dict) -> str:
    """Reposição do valor anterior de uma alteração."""
    inv = dict(c)
    if c["type"] == "registry":
        if c["old"] is None:
            return f"Remove-ItemProperty -Path {_ps_str(c['key'])} -Name {_ps_str(c['name'])} -ErrorAction SilentlyContinue"
        inv["new"] = c["old"]
        return change_script(inv)
    if c["type"] == "header":
        if c["old"] is None:
            return change_script({"type": "header_remove", "name": c["name"]})
        inv["new"] = c["old"]
        return change_script(inv)
    if c["type"] == "header_remove":
        return change_script({"type": "header", "name": c["name"], "new": c["old"]}) if c["old"] is not None else ""
    if c["old"] is None:
        return ""
    inv["new"] = c["old"]
    return change_script(inv)


def _store(item: str, changes: list[dict]) -> None:
    d = common.backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{item}-iis")
    d.mkdir(parents=True, exist_ok=True)
    (d / "iis.json").write_text(json.dumps(changes))


def rollback(item: str) -> list[str]:
    f = common.backup_root() / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{item}-iis") / "iis.json"
    done = []
    for c in reversed(json.loads(f.read_text())):
        script = revert_script(c)
        if script:
            powershell(script, 120)
            done.append(c.get("key") or c.get("name"))
    return done


def apply(practice: str, params: dict, item: str) -> dict:
    p = plan(practice, params)
    blocks = [c for c in p["checks"] if c["status"] == "block"]
    if blocks:
        return {"status": "failed", "output": "Pré-requisitos falhados: " + "; ".join(f"{c['label']}: {c['detail']}" for c in blocks), "actions": [], "rolled_back": False}
    if not p["changes"]:
        return {"status": "succeeded", "output": "Já em conformidade: nada a alterar.", "actions": [], "rolled_back": False}
    _store(item, p["changes"])
    done = []
    for c in p["changes"]:
        r = powershell(change_script(c), 120)
        if not r.ok:
            rollback(item)
            return {"status": "failed", "output": f"Falha numa alteração; revertido.\n{r.out.strip()[-300:]}", "actions": p["actions"], "rolled_back": True}
        done.append(c)
    reboot = practice == "tls_protocols"
    return {"status": "succeeded", "output": f"{len(done)} alteração(ões) aplicada(s)" + ("; reinicie o servidor para o Schannel as aplicar" if reboot else ""),
            "actions": p["actions"], "rolled_back": False, "reboot_pending": reboot,
            "verification": {"ok": None, "detail": "pendente de reinício (Schannel)" if reboot else "cabeçalhos aplicados ao nível do servidor"}}


__all__ = ["config"]
