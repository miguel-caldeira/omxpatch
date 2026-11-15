#Requires -RunAsAdministrator
<#
  OMXPatch - instalacao do AGENTE em Windows (10/11 e Server 2012 R2+). Instala os ficheiros em C:\OMXPatchAgent, encontra (ou instala,
  se o pacote trouxer python-installer.exe) um Python 3.8+ e, com os dados de inscricao, inscreve o agente e instala o servico.
  Uso:  .\Install-OMXPatchAgent.ps1 [-Server https://omxpatchcli.oramix.local:4444 -Token omxe_... [-Pin <SHA-256 ou thumbprint>]] [-Pause]
  Sem parametros usa C:\ProgramData\OMXPatchAgent\enroll.env (MDM: OMXPATCH_SERVER, OMXPATCH_TOKEN, OMXPATCH_PIN); se nao existir, so instala os ficheiros.
#>
param([string]$Server = '', [string]$Token = '', [string]$Pin = '', [switch]$Pause)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Dest = 'C:\OMXPatchAgent'; $Data = Join-Path $env:ProgramData 'OMXPatchAgent'
function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Find-Python {
  $c = @('C:\Python312\python.exe', 'C:\Python311\python.exe', 'C:\Program Files\Python312\python.exe', 'C:\Program Files\Python311\python.exe', 'C:\Program Files\Python313\python.exe')
  foreach ($k in 'HKLM:\SOFTWARE\Python\PythonCore', 'HKLM:\SOFTWARE\WOW6432Node\Python\PythonCore', 'HKCU:\SOFTWARE\Python\PythonCore') {
    Get-ChildItem $k -ErrorAction SilentlyContinue | ForEach-Object { $ip = (Get-ItemProperty "$($_.PSPath)\InstallPath" -ErrorAction SilentlyContinue).'(default)'; if ($ip) { $c += (Join-Path $ip 'python.exe') } }
  }
  foreach ($p in $c) { if ($p -and (Test-Path $p)) { try { if ((& $p -c 'import sys;print(sys.version_info>=(3,8))' 2>$null) -eq 'True') { return $p } } catch {} } }
  $g = Get-Command python.exe -ErrorAction SilentlyContinue
  if ($g -and $g.Source -notlike '*WindowsApps*') { try { if ((& $g.Source -c 'import sys;print(sys.version_info>=(3,8))' 2>$null) -eq 'True') { return $g.Source } } catch {} }
  return $null
}
try {
  Step 'Ficheiros do agente'
  New-Item -ItemType Directory -Force -Path $Dest, $Data | Out-Null
  if (Test-Path (Join-Path $Dest 'omxpatch_agent')) { Remove-Item -Recurse -Force (Join-Path $Dest 'omxpatch_agent') }
  Copy-Item -Recurse -Force (Join-Path $Here 'omxpatch_agent') $Dest
  Write-Host "Agente copiado para $Dest"
  if (-not $Server -or -not $Token) {
    $envf = Join-Path $Data 'enroll.env'
    if (Test-Path $envf) {
      Get-Content $envf | ForEach-Object { if ($_ -match '^\s*(OMXPATCH_SERVER|OMXPATCH_TOKEN|OMXPATCH_PIN)\s*=\s*(.*?)\s*$') { Set-Variable -Name ('E_' + $Matches[1]) -Value $Matches[2] } }
      if (-not $Server) { $Server = $E_OMXPATCH_SERVER }; if (-not $Token) { $Token = $E_OMXPATCH_TOKEN }; if (-not $Pin) { $Pin = $E_OMXPATCH_PIN }
    }
  }
  Step 'Python'
  $Py = Find-Python
  $inst = Join-Path $Here 'python-installer.exe'
  if (-not $Py -and (Test-Path $inst)) {
    Write-Host 'A instalar o Python (incluido no pacote)...'
    Start-Process -FilePath $inst -ArgumentList @('/quiet', 'InstallAllUsers=1', 'PrependPath=0', 'Include_test=0', 'Include_pip=0', 'Include_launcher=0') -Wait | Out-Null
    $Py = Find-Python
  }
  if (-not $Py) { throw 'Python 3.8+ nao encontrado e o pacote nao inclui o instalador. Instale o Python (python.org) e repita.' }
  Write-Host "Python: $Py"
  if ($Server -and $Token) {
    Step 'Inscricao e servico'
    $env:PYTHONPATH = $Dest
    $a = @('-m', 'omxpatch_agent', 'enroll', '--server', $Server, '--token', $Token, '--install-service')
    if ($Pin) { $a += @('--pin-sha256', $Pin) }
    & $Py @a
    if ($LASTEXITCODE -ne 0) { throw "A inscricao falhou (codigo $LASTEXITCODE)." }
    Remove-Item -Force (Join-Path $Data 'enroll.env') -ErrorAction SilentlyContinue
    Write-Host 'Agente inscrito e servico instalado.' -ForegroundColor Green
  } else {
    Write-Host "`nAgente instalado. Inscrever (PowerShell de administrador):" -ForegroundColor Yellow
    Write-Host "  `$env:PYTHONPATH='$Dest'; & '$Py' -m omxpatch_agent enroll --server https://omxpatchcli.oramix.local:4444 --token omxe_... --pin-sha256 <SHA-256> --install-service"
  }
} finally { if ($Pause) { Read-Host 'Prima Enter para fechar' | Out-Null } }
