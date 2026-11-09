#Requires -RunAsAdministrator
<#
  OMXPatch - atualiza uma instalacao existente (configuracao e dados mantidos).
  Uso (na pasta extraida do pacote novo):  .\Update-OMXPatch.ps1
#>
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$App = 'C:\OMXPatch'; $Data = 'C:\ProgramData\OMXPatch'; $Cfg = Join-Path $Data 'omxpatch.toml'
$Pip = "$App\venv\Scripts\pip.exe"
if (-not (Test-Path $Pip)) { throw "Instalacao nao encontrada em $App - use Install-OMXPatch.ps1" }
if (-not (Get-ChildItem (Join-Path $Here 'wheels') -Filter 'omxpatch-*.whl' -ErrorAction SilentlyContinue)) { throw 'Pacote incompleto: faltam os wheels' }
$New = if (Test-Path "$Here\VERSION") { (Get-Content "$Here\VERSION" -Raw).Trim() } else { '' }
function Cur { ((& $Pip show omxpatch) | Where-Object { $_ -like 'Version:*' } | ForEach-Object { $_.Substring(8).Trim() }) }
$Old = Cur
Write-Host "Versao instalada: $Old  ->  pacote: $New"
if (Test-Path $Cfg) { Copy-Item $Cfg "$Cfg.bak-$(Get-Date -Format yyyyMMddHHmmss)" }
& $Pip install --quiet --upgrade --no-index --find-links "$Here\wheels" omxpatch
if ($LASTEXITCODE -ne 0) { & $Pip install --quiet --upgrade --find-links "$Here\wheels" omxpatch }
$Cur = Cur
if ($New -and $Cur -ne $New) {
  Write-Host "A forcar a reinstalacao ($Cur != $New)..."
  & $Pip install --quiet --force-reinstall --no-deps --no-index --find-links "$Here\wheels" "omxpatch==$New"
  $Cur = Cur
}
if ($New -and $Cur -ne $New) { throw "A versao instalada continua $Cur (esperado $New)" }
foreach ($n in 'OMXPatch', 'OMXPatch-Worker') { schtasks /End /TN $n 2>$null | Out-Null }
Get-Process omxpatch -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
foreach ($n in 'OMXPatch', 'OMXPatch-Worker') { schtasks /Run /TN $n | Out-Null }
Write-Host "OMXPatch atualizado: $Old -> $Cur" -ForegroundColor Green
try {
  [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  Start-Sleep -Seconds 5
  $h = (New-Object Net.WebClient).DownloadString("https://127.0.0.1:4434/healthz") | ConvertFrom-Json
  Write-Host "Versao em execucao na consola: $($h.version)" -ForegroundColor Green
} catch { Write-Warning "Nao foi possivel confirmar a versao em execucao na consola (ainda a arrancar?)." }
