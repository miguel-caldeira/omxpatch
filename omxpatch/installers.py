"""Scripts de auto-instalação dos agentes (Windows, Linux, macOS) e de remoção.

Cada script é gerado para **uma organização**: leva um token de registo dessa organização, o URL do servidor de agentes
(porta 4444) e a impressão digital SHA-256 do certificado ``omxpatchcli.oramix.local``. Descarrega o agente por TLS com
*pinning* (sem depender de CA, internet ou pip — o agente só usa a biblioteca padrão do Python 3), regista o equipamento
e instala o serviço. Podem ser executados localmente, por GPO/Intune/Jamf, por SSH/WinRM ou pelo playbook
``ansible/install_agent_script.yml``.
"""
from __future__ import annotations

import re

URL_RE = re.compile(r"^https?://[A-Za-z0-9.\-]+(:\d{1,5})?$")
PIN_RE = re.compile(r"^([0-9A-Fa-f]{2}:?){32}$")
TOKEN_RE = re.compile(r"^omxe_[A-Za-z0-9_\-]{10,80}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")
IP_RE = re.compile(r"^[0-9a-fA-F:.]{0,45}$")
OS_KINDS = {"windows": ("ps1", "Windows (PowerShell)"), "linux": ("sh", "Linux (shell)"), "macos": ("sh", "macOS (shell)")}

# Descarrega o agente por TLS com pinning do certificado, verifica o SHA-256 do zip e extrai-o. Só biblioteca padrão.
BOOT_PY = r'''import hashlib, http.client, io, os, shutil, socket, ssl, sys, zipfile
from urllib.parse import urlsplit
url, pin, token, dest = sys.argv[1], sys.argv[2].replace(":", "").lower(), sys.argv[3], sys.argv[4]
u = urlsplit(url)
host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
if u.scheme == "https":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    conn = http.client.HTTPSConnection(host, port, timeout=120, context=ctx)
    conn.connect()
    if pin and hashlib.sha256(conn.sock.getpeercert(True)).hexdigest() != pin:
        sys.exit("ERRO: o certificado do servidor não corresponde à impressão digital esperada")
else:
    conn = http.client.HTTPConnection(host, port, timeout=120)
conn.request("GET", "/agent/v1/bundle", headers={"X-Enrollment-Token": token})
r = conn.getresponse()
data = r.read()
if r.status != 200:
    sys.exit("ERRO: o servidor recusou a transferência do agente (HTTP %d): %s" % (r.status, data[:200]))
if hashlib.sha256(data).hexdigest() != r.getheader("X-Content-SHA256"):
    sys.exit("ERRO: integridade do agente não confirmada (SHA-256)")
os.makedirs(dest, exist_ok=True)
shutil.rmtree(os.path.join(dest, "omxpatch_agent"), ignore_errors=True)
with zipfile.ZipFile(io.BytesIO(data)) as z:
    for n in z.namelist():
        if n.startswith(("/", "\\")) or ".." in n.split("/") or not n.startswith("omxpatch_agent/"):
            sys.exit("ERRO: pacote inválido")
    z.extractall(dest)
print("Agente transferido e verificado para", dest)
'''

_SH = r'''#!/bin/sh
# OMXPatch Agent — instalação automática (@@OSLABEL@@) — organização: @@TENANT@@
# Gerado em @@WHEN@@. Contém um token de registo da organização: trate este ficheiro como credencial.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Execute como root:  sudo sh $0"; exit 1; }
URL='@@URL@@'; PIN='@@PIN@@'; TOKEN='@@TOKEN@@'; HOST='@@HOST@@'; SERVER_IP='@@IP@@'
DEST='@@DEST@@'
if [ -n "$SERVER_IP" ] && ! grep -q "[[:space:]]$HOST\$" /etc/hosts 2>/dev/null; then
  echo "$SERVER_IP $HOST" >> /etc/hosts
fi
PY="$(command -v python3 || true)"
if [ -z "$PY" ]; then
@@INSTALL_PY@@
  PY="$(command -v python3 || true)"
  [ -n "$PY" ] || { echo "Python 3 não está disponível e não foi possível instalá-lo."; exit 1; }
fi
mkdir -p "$DEST"
"$PY" - "$URL" "$PIN" "$TOKEN" "$DEST" <<'PYEOF'
@@BOOT@@PYEOF
PYTHONPATH="$DEST" "$PY" -m omxpatch_agent enroll --server "$URL" --token "$TOKEN" ${PIN:+--pin-sha256 "$PIN"} --install-service --force
echo "Instalação concluída."
'''
_INSTALL_LINUX = '''  if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q python3
  elif command -v yum >/dev/null 2>&1; then yum install -y -q python3
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install python3
  elif command -v apk >/dev/null 2>&1; then apk add --no-cache python3
  fi'''
_INSTALL_MAC = '''  xcode-select -p >/dev/null 2>&1 || { xcode-select --install 2>/dev/null || true; echo "Instale as Xcode Command Line Tools (Python 3) e volte a executar o script."; exit 1; }'''

_PS1 = r'''#Requires -RunAsAdministrator
# OMXPatch Agent — instalação automática (Windows) — organização: @@TENANT@@
# Gerado em @@WHEN@@. Contém um token de registo da organização: trate este ficheiro como credencial.
param([string]$PythonUrl = 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe', [string]$PythonSha256 = '')
$ErrorActionPreference = 'Stop'
$Url = '@@URL@@'; $Pin = '@@PIN@@'; $Token = '@@TOKEN@@'; $HostName = '@@HOST@@'; $ServerIp = '@@IP@@'
$Dest = 'C:\OMXPatchAgent'
if ($ServerIp) {
  $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
  if (-not (Select-String -Path $hosts -Pattern ([regex]::Escape($HostName) + '\s*$') -Quiet)) { Add-Content -Path $hosts -Value "$ServerIp $HostName" }
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Find-Python {
  $c = @('C:\Python312\python.exe', 'C:\Program Files\Python312\python.exe', 'C:\Program Files\Python313\python.exe', 'C:\Program Files\Python311\python.exe',
         "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:ProgramFiles\Python312\python.exe")
  foreach ($k in 'HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore', 'HKCU:\SOFTWARE\Python\PythonCore') {
    Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { $ip = (Get-ItemProperty "$($_.PSPath)\InstallPath" -ErrorAction SilentlyContinue).'(default)'; if ($ip) { $c += (Join-Path $ip 'python.exe') } }
  }
  foreach ($p in $c) { if ($p -and (Test-Path $p)) { try { if ((& $p -c 'import sys;print(sys.version_info>=(3,8))' 2>$null) -eq 'True') { return $p } } catch {} } }
  $g = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($g -and $g.Source -notlike '*WindowsApps*') { return $g.Source }
  return $null
}
function Install-Python([string]$Installer) {
  # 1.º todos os utilizadores; 2.º só o utilizador atual; 3.º winget. Mostra o registo se falhar.
  $log = Join-Path $env:TEMP 'omxpatch-python-install.log'
  foreach ($mode in @('InstallAllUsers=1', 'InstallAllUsers=0')) {
    $a = @('/quiet', $mode, 'PrependPath=0', 'Include_test=0', 'Include_pip=1', 'Include_launcher=0', "/log `"$log`"")
    if ($mode -eq 'InstallAllUsers=1') { $a += 'TargetDir=C:\Python312' }
    $p = Start-Process -FilePath $Installer -ArgumentList $a -Wait -PassThru
    Write-Host "Instalador do Python ($mode): código de saída $($p.ExitCode)"
    $py = Find-Python
    if ($py) { return $py }
  }
  if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
    Write-Host 'A tentar com o winget...'
    & winget.exe install --id Python.Python.3.12 -e --scope machine --silent --accept-package-agreements --accept-source-agreements | Out-Host
    $py = Find-Python
    if ($py) { return $py }
  }
  if (Test-Path $log) { Write-Host '--- fim do registo do instalador do Python ---'; Get-Content $log -Tail 15 | Out-Host }
  throw "Não foi possível instalar o Python 3 (registo: $log). Instale o Python 3.12 manualmente (python.org, «Add to PATH» opcional) e execute de novo."
}
$Py = Find-Python
if (-not $Py) {
  Write-Host 'A instalar o Python 3...'
  $inst = Join-Path $env:TEMP 'python-installer.exe'
  Invoke-WebRequest -Uri $PythonUrl -OutFile $inst -UseBasicParsing
  if ($PythonSha256 -and ((Get-FileHash $inst -Algorithm SHA256).Hash -ne $PythonSha256.ToUpper())) { throw 'SHA-256 do instalador do Python não confere' }
  $Py = Install-Python $inst
}
Write-Host "Python: $Py"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$boot = Join-Path $env:TEMP 'omxpatch-bootstrap.py'
@'
@@BOOT@@'@ | Set-Content -Path $boot -Encoding UTF8
& $Py $boot $Url $Pin $Token $Dest
if ($LASTEXITCODE -ne 0) { throw 'Falha ao transferir o agente.' }
Remove-Item $boot -Force
$env:PYTHONPATH = $Dest
$args2 = @('-m', 'omxpatch_agent', 'enroll', '--server', $Url, '--token', $Token, '--install-service', '--force')
if ($Pin) { $args2 += @('--pin-sha256', $Pin) }
& $Py @args2
if ($LASTEXITCODE -ne 0) { throw 'Falha no registo do agente.' }
Write-Host 'Instalação concluída.'
'''

_UN_SH = '''#!/bin/sh
# OMXPatch Agent — remoção (@@OSLABEL@@). Depois, revogue/elimine o agente em «Agentes» na consola.
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Execute como root"; exit 1; }
@@UNINSTALL@@
echo "Agente removido."
'''
_UN_LINUX = '''systemctl disable --now omxpatch-agent 2>/dev/null || true
rm -f /etc/systemd/system/omxpatch-agent.service; systemctl daemon-reload 2>/dev/null || true
rm -rf /opt/omxpatch-agent /etc/omxpatch-agent'''
_UN_MAC = '''launchctl unload -w /Library/LaunchDaemons/pt.oramix.omxpatch.agent.plist 2>/dev/null || true
rm -f /Library/LaunchDaemons/pt.oramix.omxpatch.agent.plist
rm -rf /Library/OMXPatchAgent "/Library/Application Support/OMXPatchAgent"'''
_UN_PS1 = r'''#Requires -RunAsAdministrator
# OMXPatch Agent — remoção (Windows). Depois, revogue/elimine o agente em «Agentes» na consola.
schtasks /End /TN OMXPatchAgent 2>$null | Out-Null
schtasks /Delete /F /TN OMXPatchAgent 2>$null | Out-Null
Remove-Item -Recurse -Force 'C:\OMXPatchAgent', "$env:ProgramData\OMXPatchAgent" -ErrorAction SilentlyContinue
Write-Host 'Agente removido.'
'''


def _check(url: str, pin: str, token: str, host: str, ip: str) -> None:
    if not URL_RE.match(url):
        raise ValueError("URL do servidor de agentes inválido")
    if pin and not PIN_RE.match(pin):
        raise ValueError("Impressão digital inválida")
    if not TOKEN_RE.match(token):
        raise ValueError("Token de registo inválido")
    if not HOST_RE.match(host) or not IP_RE.match(ip):
        raise ValueError("Nome ou IP do servidor inválido")


def render(os_kind: str, *, url: str, pin: str, token: str, tenant_name: str, host: str, server_ip: str = "",
           when: str = "") -> tuple[str, str]:
    """(nome do ficheiro, conteúdo) do script de instalação. Todos os valores são validados (sem injeção de comandos)."""
    if os_kind not in OS_KINDS:
        raise ValueError("Sistema operativo desconhecido")
    _check(url, pin, token, host, server_ip)
    label = tenant_name.replace("\n", " ").replace("'", "").replace("$", "")[:80]
    fields = {"URL": url, "PIN": pin.replace(":", "").lower() if pin else "", "TOKEN": token, "HOST": host, "IP": server_ip,
              "TENANT": label, "WHEN": when, "OSLABEL": OS_KINDS[os_kind][1], "BOOT": BOOT_PY}
    if os_kind == "windows":
        tpl = _PS1
    else:
        tpl = _SH.replace("@@INSTALL_PY@@", _INSTALL_LINUX if os_kind == "linux" else _INSTALL_MAC)
        fields["DEST"] = "/opt/omxpatch-agent" if os_kind == "linux" else "/Library/OMXPatchAgent"
    out = tpl
    for k, v in fields.items():
        out = out.replace(f"@@{k}@@", v)
    slug = re.sub(r"[^a-z0-9]+", "-", tenant_name.lower()).strip("-") or "org"
    name = f"omxpatch-install-{slug}-{os_kind}.{OS_KINDS[os_kind][0]}"
    return name, out.replace("\r\n", "\n") if os_kind != "windows" else out.replace("\n", "\r\n")


def render_uninstall(os_kind: str) -> tuple[str, str]:
    if os_kind not in OS_KINDS:
        raise ValueError("Sistema operativo desconhecido")
    if os_kind == "windows":
        return "omxpatch-uninstall-windows.ps1", _UN_PS1.replace("\n", "\r\n")
    body = _UN_SH.replace("@@OSLABEL@@", OS_KINDS[os_kind][1]).replace("@@UNINSTALL@@", _UN_LINUX if os_kind == "linux" else _UN_MAC)
    return f"omxpatch-uninstall-{os_kind}.sh", body
