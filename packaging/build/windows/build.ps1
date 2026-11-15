<#
  Compila NO WINDOWS os instaladores Windows do OMXPatch (PowerShell 5.1+ ou 7; Python 3.9+ no PATH; Inno Setup 6 opcional):
    omxpatch-windows-<v>.zip / omxpatch-windows-setup-<v>.exe               centro de comando (Server 2019+, Windows 10/11; Python 3.12)
    omxpatch-windows2012r2-<v>.zip / omxpatch-windows2012r2-setup-<v>.exe   centro de comando para Windows Server 2012 R2 (Python 3.11)
    omxpatch-agent-windows-<v>.zip / omxpatch-agent-windows-setup-<v>.exe   agente
    omxpatch-validation-kit-<v>.zip, SHA256SUMS
  Os .exe usam o Inno Setup 6 (choco install innosetup -y); sem ele só se geram os .zip. O instalador do Python é descarregado de python.org
  e o seu SHA-256 fica em python-installer.sha256 (ou use -Python312Exe/-Python311Exe com ficheiros locais).
  Uso:  powershell -ExecutionPolicy Bypass -File packaging\build\windows\build.ps1 [-OutDir dist] [-Python python]
#>
param([string]$OutDir = '', [string]$Python = 'python', [string]$Python312Exe = '', [string]$Python311Exe = '', [switch]$NoSetupExe)
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
Set-Location $Root
if (-not $OutDir) { $OutDir = Join-Path $Root 'dist' }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null; $OutDir = (Resolve-Path $OutDir).Path
$Ver = [regex]::Match((Get-Content 'omxpatch\__init__.py' -Raw), '__version__ = "([^"]+)"').Groups[1].Value
if (-not $Ver) { throw 'Versao nao encontrada em omxpatch\__init__.py' }
$Stage = Join-Path ([IO.Path]::GetTempPath()) ("omxpatch-build-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Stage | Out-Null
Write-Host "OMXPatch $Ver - compilacao nativa Windows ($([Environment]::OSVersion.VersionString))" -ForegroundColor Cyan

function Run([string]$Exe, [string[]]$Arguments) { & $Exe @Arguments; if ($LASTEXITCODE -ne 0) { throw "Falhou ($LASTEXITCODE): $Exe $($Arguments -join ' ')" } }
function Zip([string]$Dir, [string]$Zip) { Run $Python @('packaging\build\zipdir.py', $Dir, $Zip) }
function Get-File([string]$Url, [string]$Dest) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  try { Invoke-WebRequest -Uri $Url -OutFile $Dest -UseBasicParsing -TimeoutSec 600; return $true } catch { Write-Warning "Nao foi possivel descarregar $Url : $_"; return $false }
}
function Add-Python([string]$Dir, [string]$Local, [string]$Full) {
  $dst = Join-Path $Dir 'python-installer.exe'
  if ($Local -and (Test-Path $Local)) { Copy-Item $Local $dst }
  else { if (-not (Get-File "https://www.python.org/ftp/python/$Full/python-$Full-amd64.exe" $dst)) { Remove-Item $dst -ErrorAction SilentlyContinue } }
  if (Test-Path $dst) { (Get-FileHash $dst -Algorithm SHA256).Hash.ToLower() | Set-Content -Path (Join-Path $Dir 'python-installer.sha256') -Encoding ascii }
  else { Write-Warning "Pacote sem python-installer.exe (use -Python$($Full.Substring(0,4).Replace('.',''))Exe ou instale o Python antes)." }
}
function Copy-Docs([string]$Dir) {
  $d = Join-Path $Dir 'docs'; New-Item -ItemType Directory -Force -Path $d | Out-Null
  Get-ChildItem (Join-Path $Root 'docs\build') -Filter "MANUAL-*-$Ver.pdf" -ErrorAction SilentlyContinue | Copy-Item -Destination $d
}
function Add-Bom([string]$Path) {
  $b = [IO.File]::ReadAllBytes($Path)
  if (-not ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB -and $b[2] -eq 0xBF)) { [IO.File]::WriteAllBytes($Path, (@(0xEF, 0xBB, 0xBF) + $b)) }
}
function Build-Setup([string]$Src, [string]$Mode, [string]$OutName) {
  if ($NoSetupExe) { return }
  $iscc = (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source
  if (-not $iscc) { foreach ($p in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe")) { if (Test-Path $p) { $iscc = $p } } }
  if (-not $iscc) { Write-Warning 'Inno Setup 6 nao encontrado (choco install innosetup -y): .exe nao gerado.'; return }
  Run $iscc @("/DAppVer=$Ver", "/DMode=$Mode", "/DSrc=$Src", "/DOut=$OutDir", "/DOutName=$OutName", '/Q', 'packaging\build\windows\omxpatch.iss')
}

# ---- wheel da aplicacao e dependencias (wheels win_amd64, SHA-256 verificados) -------------------------------------------------
Write-Host '==> wheel da aplicacao' -ForegroundColor Cyan
Run $Python @('-m', 'pip', 'wheel', '.', '--no-deps', '-q', '-w', (Join-Path $Stage 'app-wheel'))
function Add-Wheels([string]$Dir, [string]$PyVer) {
  $w = Join-Path $Dir 'wheels'; New-Item -ItemType Directory -Force -Path $w | Out-Null
  Copy-Item (Join-Path $Stage 'app-wheel\*.whl') $w
  Run $Python @('-m', 'pip', 'download', '-q', '-r', 'requirements.lock', '--require-hashes', '--only-binary=:all:', '--platform', 'win_amd64', '--python-version', $PyVer, '--implementation', 'cp', '-d', $w)
  & $Python -m pip download -q tzdata --only-binary=:all: -d $w 2>$null
}

# ---- centro de comando (Windows 10/11, Server 2019+) ---------------------------------------------------------------------------
Write-Host '==> centro de comando (Windows)' -ForegroundColor Cyan
$W = Join-Path $Stage "omxpatch-windows-$Ver"; New-Item -ItemType Directory -Force -Path $W | Out-Null
Add-Wheels $W '3.12'
Add-Python $W $Python312Exe '3.12.8'
Copy-Item 'packaging\installers\windows\*' $W; Set-Content (Join-Path $W 'VERSION') $Ver -Encoding ascii
Copy-Docs $W
Zip $W (Join-Path $OutDir "omxpatch-windows-$Ver.zip")
Build-Setup $W 'server' "omxpatch-windows-setup-$Ver"

# ---- centro de comando (Windows Server 2012 R2, Python 3.11) -------------------------------------------------------------------
Write-Host '==> centro de comando (Windows Server 2012 R2)' -ForegroundColor Cyan
$W2 = Join-Path $Stage "omxpatch-windows2012r2-$Ver"; New-Item -ItemType Directory -Force -Path $W2, (Join-Path $W2 'prereq') | Out-Null
Add-Wheels $W2 '3.11'
foreach ($f in 'Instalar.cmd', 'Atualizar.cmd', 'Update-OMXPatch.ps1', 'Uninstall-OMXPatch.ps1') { Copy-Item (Join-Path 'packaging\installers\windows' $f) $W2 }
Run $Python @('packaging\make_2012r2.py', 'packaging\installers\windows\Install-OMXPatch.ps1', (Join-Path $W2 'Install-OMXPatch.ps1'))
Copy-Item 'packaging\installers\windows2012r2\LEIA-ME.txt' $W2; Set-Content (Join-Path $W2 'VERSION') $Ver -Encoding ascii
Add-Python $W2 $Python311Exe '3.11.9'
Get-ChildItem $W2 -Filter '*.ps1' | ForEach-Object { Add-Bom $_.FullName }
Copy-Docs $W2
Zip $W2 (Join-Path $OutDir "omxpatch-windows2012r2-$Ver.zip")
Build-Setup $W2 'server' "omxpatch-windows2012r2-setup-$Ver"

# ---- agente -----------------------------------------------------------------------------------------------------------------------
Write-Host '==> agente (Windows)' -ForegroundColor Cyan
$A = Join-Path $Stage "omxpatch-agent-windows-$Ver"; New-Item -ItemType Directory -Force -Path $A | Out-Null
Copy-Item -Recurse 'omxpatch_agent' $A; Get-ChildItem $A -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
Copy-Item 'packaging\installers\windows-agent\Install-OMXPatchAgent.ps1' $A; Set-Content (Join-Path $A 'VERSION') $Ver -Encoding ascii
Add-Python $A $Python312Exe '3.12.8'
Zip $A (Join-Path $OutDir "omxpatch-agent-windows-$Ver.zip")
Build-Setup $A 'agent' "omxpatch-agent-windows-setup-$Ver"

# ---- kit de validacao ---------------------------------------------------------------------------------------------------------------
Write-Host '==> kit de validacao' -ForegroundColor Cyan
$K = Join-Path $Stage "omxpatch-validation-kit-$Ver"; New-Item -ItemType Directory -Force -Path $K | Out-Null
Copy-Item -Recurse 'omxpatch_agent' $K; Get-ChildItem $K -Recurse -Directory -Filter '__pycache__' | Remove-Item -Recurse -Force
Copy-Item 'packaging\validation-kit\*' $K; Set-Content (Join-Path $K 'VERSION') $Ver -Encoding ascii
Zip $K (Join-Path $OutDir "omxpatch-validation-kit-$Ver.zip")

# ---- somas de verificacao ---------------------------------------------------------------------------------------------------------
$lines = Get-ChildItem $OutDir -File | Where-Object { $_.Name -ne 'SHA256SUMS' -and $_.Name -like "*$Ver*" } | ForEach-Object { "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower())  $($_.Name)" }
[IO.File]::WriteAllLines((Join-Path $OutDir 'SHA256SUMS.windows'), [string[]]$lines)
$lines | ForEach-Object { Write-Host $_ }
Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
