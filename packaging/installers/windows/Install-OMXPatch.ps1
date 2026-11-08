#Requires -RunAsAdministrator
<#
  OMXPatch — instalação em Windows Server 2019/2022/2025 (ou Windows 10/11): centro de comando.
  Instala Python (se faltar), o ambiente virtual em C:\OMXPatch, a configuração e os dados em C:\ProgramData\OMXPatch,
  duas tarefas agendadas SYSTEM (web + worker) e regras de firewall para:
    4434/tcp  consola de gestão   (https://omxpatch.oramix.local:4434)      certificado autoassinado, 2 anos
    4444/tcp  agentes → consola   (https://omxpatchcli.oramix.local:4444)   certificado autoassinado, 2 anos
  Uso:  .\Install-OMXPatch.ps1 [-Hostname omxpatch.empresa.pt] [-AgentHostname omxpatchcli.empresa.pt] [-ServerIp 10.0.0.5]
        [-PythonSha256 <hash do instalador do Python>] [-WithAnsible]
  Pode ser executado de novo para atualizar (configuração e dados mantidos).
#>
param(
  [string]$Hostname = 'omxpatch.oramix.local', [string]$AgentHostname = 'omxpatchcli.oramix.local', [string]$ServerIp = '',
  [int]$Port = 4434, [int]$AgentPort = 4444, [switch]$WithAnsible, [switch]$NoFirewall,
  [string]$PythonUrl = 'https://www.python.org/ftp/python/3.12.8/python-3.12.8-amd64.exe', [string]$PythonSha256 = ''
)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$App = 'C:\OMXPatch'; $Data = 'C:\ProgramData\OMXPatch'; $Cfg = Join-Path $Data 'omxpatch.toml'
if ($Hostname -notmatch '^[A-Za-z0-9.\-]+$' -or $AgentHostname -notmatch '^[A-Za-z0-9.\-]+$') { throw 'Nome inválido' }
if ($ServerIp -and $ServerIp -notmatch '^[0-9a-fA-F:.]+$') { throw 'IP inválido' }
if (-not (Get-ChildItem (Join-Path $Here 'wheels') -Filter 'omxpatch-*.whl' -ErrorAction SilentlyContinue)) { throw "Pacote incompleto: faltam os wheels em $Here\wheels" }
Start-Transcript -Path (Join-Path $env:TEMP 'omxpatch-install.log') -Append | Out-Null
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Find-Python {
  $c = @('C:\Python312\python.exe', 'C:\Program Files\Python312\python.exe', 'C:\Program Files\Python313\python.exe', 'C:\Program Files\Python311\python.exe',
         "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:ProgramFiles\Python312\python.exe")
  foreach ($k in 'HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore', 'HKCU:\SOFTWARE\Python\PythonCore') {
    Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { $ip = (Get-ItemProperty "$($_.PSPath)\InstallPath" -ErrorAction SilentlyContinue).'(default)'; if ($ip) { $c += (Join-Path $ip 'python.exe') } }
  }
  foreach ($p in $c) { if ($p -and (Test-Path $p)) { try { if ((& $p -c 'import sys;print(sys.version_info>=(3,9))' 2>$null) -eq 'True') { return $p } } catch {} } }
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
Step 'Python'
$Py = Find-Python
if (-not $Py) {
  $inst = Join-Path $Here 'python-installer.exe'
  if (Test-Path $inst) {                                   # incluído no pacote (instalação offline)
    $shaFile = Join-Path $Here 'python-installer.sha256'
    if (-not $PythonSha256 -and (Test-Path $shaFile)) { $PythonSha256 = (Get-Content $shaFile -Raw).Trim() }
    Write-Host 'A usar o instalador do Python incluído no pacote.'
  } else {
    $inst = Join-Path $env:TEMP 'python-installer.exe'
    Write-Host "A descarregar o Python de $PythonUrl"
    Invoke-WebRequest -Uri $PythonUrl -OutFile $inst -UseBasicParsing
  }
  if ($PythonSha256 -and ((Get-FileHash $inst -Algorithm SHA256).Hash -ne $PythonSha256.ToUpper())) { throw 'SHA-256 do instalador do Python não confere' }
  $Py = Install-Python $inst
}
Write-Host "Python: $Py"

Step 'Aplicação (ambiente virtual)'
New-Item -ItemType Directory -Force -Path $App, $Data | Out-Null
& $Py -m venv "$App\venv"
$Pip = "$App\venv\Scripts\pip.exe"
& $Pip install --quiet --no-index --find-links "$Here\wheels" omxpatch
if ($LASTEXITCODE -ne 0) { Write-Warning 'Instalação offline incompatível; a usar o PyPI.'; & $Pip install --quiet --find-links "$Here\wheels" omxpatch; if ($LASTEXITCODE -ne 0) { throw 'Falha ao instalar o OMXPatch' } }
if ($WithAnsible) { & $Pip install --quiet pywinrm requests-credssp; Write-Warning 'O Ansible não corre nativamente no Windows: use WSL ou um controlador Linux para o modo sem agente.' }

Step 'Configuração'
if (-not (Test-Path $Cfg)) {
@"
data_dir = "$($Data -replace '\\','/')"

[server]
tls_enabled = true
tls_hostname = "$Hostname"
port = $Port
session_cookie_secure = true
embedded_worker = false

[agents]
tls_hostname = "$AgentHostname"
port = $AgentPort
server_ip = "$ServerIp"

[ansible]
enabled = false
"@ | Set-Content -Path $Cfg -Encoding UTF8
} else { Write-Host "Configuração existente mantida: $Cfg" }
icacls $Data /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

Step 'Certificados TLS (autoassinados, 2 anos)'
$env:OMXPATCH_CONFIG = $Cfg
& "$App\venv\Scripts\omxpatch.exe" tls info

Step 'Tarefas agendadas (SYSTEM)'
foreach ($t in @(@{n = 'OMXPatch'; a = 'serve --no-worker'}, @{n = 'OMXPatch-Worker'; a = 'worker'})) {
  $cmd = "$App\run-$($t.n).cmd"
  # ciclo: se o processo terminar (p.ex. «Reiniciar» na consola) volta a arrancar passados 5 s
  "@echo off`r`nset OMXPATCH_CONFIG=$Cfg`r`nset OMXPATCH_SUPERVISED=1`r`n:loop`r`n`"$App\venv\Scripts\omxpatch.exe`" $($t.a)`r`ntimeout /t 5 /nobreak >nul`r`ngoto loop`r`n" | Set-Content -Path $cmd -Encoding ASCII
  schtasks /End /TN $t.n 2>$null | Out-Null
  schtasks /Create /F /TN $t.n /SC ONSTART /RU SYSTEM /RL HIGHEST /TR "`"$cmd`"" | Out-Null
  schtasks /Run /TN $t.n | Out-Null
}

if (-not $NoFirewall) {
  Step 'Firewall'
  foreach ($r in @(@('OMXPatch consola', $Port), @('OMXPatch agentes', $AgentPort))) {
    Remove-NetFirewallRule -DisplayName $r[0] -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $r[0] -Direction Inbound -Action Allow -Protocol TCP -LocalPort $r[1] | Out-Null
  }
}

Step 'Super-administrador inicial'
Start-Sleep -Seconds 5
& "$App\venv\Scripts\omxpatch.exe" initial-password
Write-Host "`nConcluído.`n  Consola:  https://${Hostname}:$Port/`n  Agentes:  https://${AgentHostname}:$AgentPort/  (scripts de instalação em «Agentes»)"
Stop-Transcript | Out-Null
