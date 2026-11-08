<#
  OMXPatch — validação do agente em Windows (kit de teste).
  Uso (PowerShell):   .\validate-windows.ps1                       # só leitura (seguro)
                      .\validate-windows.ps1 -Level lab -YesLab    # + alterações reversíveis (SÓ em VM de laboratório; como Administrador)
                      .\validate-windows.ps1 -Server https://10.0.0.5:4444 -Pin <SHA-256 ou thumbprint>   # testa também a ligação à consola por IP + impressão digital
  Gera report-<data>.md e report-<data>.json nesta pasta (nome do equipamento e IP ocultados). Envie-os.
#>
param([ValidateSet('read', 'lab')][string]$Level = 'read', [switch]$YesLab, [string]$Server = '', [string]$Pin = '', [switch]$WithIsolation, [switch]$NoRedact)
$ErrorActionPreference = 'Stop'
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
function Find-Python {
  foreach ($p in @('C:\Python312\python.exe', 'C:\Python311\python.exe', 'C:\Program Files\Python312\python.exe', 'C:\Program Files\Python313\python.exe', 'C:\Program Files\Python311\python.exe', 'C:\Python38\python.exe', "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe")) { if (Test-Path $p) { return $p } }
  foreach ($n in @('python.exe', 'py.exe')) { $c = Get-Command $n -ErrorAction SilentlyContinue; if ($c -and $c.Source -notlike '*WindowsApps*') { return $c.Source } }
  return $null
}
$Py = Find-Python
if (-not $Py) { throw 'Python 3.8+ não encontrado. Instale o Python (python.org) ou copie o instalador para esta pasta e execute-o.' }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Python: $Py · Administrador: $admin · Nível: $Level"
if ($Level -eq 'lab' -and -not $admin) { Write-Warning 'Sem privilégios de Administrador: as verificações de alteração serão saltadas.' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$argsList = @('-m', 'omxpatch_agent', 'validate', '--level', $Level, '--report', (Join-Path $Here "report-$stamp.md"), '--json', (Join-Path $Here "report-$stamp.json"))
if ($YesLab) { $argsList += '--yes-lab' }
if ($Server) { $argsList += @('--server', $Server) }
if ($Pin) { $argsList += @('--pin', $Pin) }
if ($WithIsolation) { $argsList += '--with-isolation' }
if ($NoRedact) { $argsList += '--no-redact' }
$env:PYTHONPATH = $Here
Push-Location $Here
try { & $Py @argsList; $rc = $LASTEXITCODE } finally { Pop-Location }
Write-Host "`nRelatórios: report-$stamp.md / report-$stamp.json (código de saída $rc)"
exit $rc
