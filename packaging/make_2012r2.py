"""Gera o instalador do centro de comando para Windows Server 2012 R2 a partir do instalador principal.

Diferenças: Python 3.11 (o último com suporte oficial ao 2012 R2 — o 3.12 já não o suporta), verificações prévias
(PowerShell 4+, .NET 4.5+, KB2999226/UCRT, TLS 1.2) e wheelhouse cp311. Uso: make_2012r2.py <origem.ps1> <destino.ps1>"""
import re
import sys

src, dst = sys.argv[1:3]
s = open(src, encoding="utf-8-sig").read()

s = s.replace("instalação em Windows Server 2019/2022/2025 (ou Windows 10/11)", "instalação em Windows Server 2012 R2 (também 2012/2016 e Windows 8.1+)")
s = s.replace("python/3.12.8/python-3.12.8-amd64.exe", "python/3.11.9/python-3.11.9-amd64.exe")
s = s.replace("TargetDir=C:\\Python312", "TargetDir=C:\\Python311")
s = s.replace("Instale o Python 3.12 manualmente", "Instale o Python 3.11 manualmente")
s = s.replace("'C:\\Python312\\python.exe',", "'C:\\Python311\\python.exe', 'C:\\Python312\\python.exe',", 1)
s = s.replace('"$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe"', '"$env:LOCALAPPDATA\\Programs\\Python\\Python311\\python.exe", "$env:LOCALAPPDATA\\Programs\\Python\\Python312\\python.exe"')
s = s.replace("Python.Python.3.12", "Python.Python.3.11")

pre = r'''
# ---- Verificações prévias específicas do Windows Server 2012 R2 --------------------------------------------------------
Write-Host "`n==> Verificações prévias (Windows Server 2012 R2)" -ForegroundColor Cyan
$osv = [Environment]::OSVersion.Version
Write-Host "Windows $($osv.Major).$($osv.Minor) build $($osv.Build) · PowerShell $($PSVersionTable.PSVersion) · $([Environment]::Is64BitOperatingSystem)"
if (-not [Environment]::Is64BitOperatingSystem) { throw 'Requer Windows de 64 bits.' }
if ($osv.Major -lt 6 -or ($osv.Major -eq 6 -and $osv.Minor -lt 3)) { throw 'Requer Windows Server 2012 R2 (6.3) ou posterior.' }
if ($PSVersionTable.PSVersion.Major -lt 4) { throw 'Requer PowerShell 4.0 ou posterior (Windows Management Framework 4.0/5.1).' }
$rel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if (-not $rel -or $rel -lt 378389) { throw 'Requer .NET Framework 4.5 ou posterior.' }
if ($osv.Major -eq 6 -and -not (Get-HotFix -Id KB2999226 -ErrorAction SilentlyContinue)) {
  $msu = Get-ChildItem (Join-Path $Here 'prereq') -Filter '*KB2999226*.msu' -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($msu) {
    Write-Host "A instalar $($msu.Name) (Universal C Runtime, necessário ao Python 3.11)..."
    Start-Process wusa.exe -ArgumentList "`"$($msu.FullName)`"", '/quiet', '/norestart' -Wait
  } else {
    Write-Warning 'A atualização KB2999226 (Universal C Runtime) não está instalada: o instalador do Python pode falhar. Instale o Windows Update de abril de 2014 (KB2919355) e a KB2999226, ou coloque o .msu em prereq\ e repita.'
  }
}
# TLS 1.2 para o .NET/PowerShell neste sistema (o 2012 R2 usa TLS 1.0 por omissão nas aplicações .NET 4.5)
New-Item -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SchUseStrongCrypto -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name SystemDefaultTlsVersions -Value 1 -Type DWord
'''
# inserir depois da linha da transcrição/Step (antes de "Step 'Python'")
i = s.index("Step 'Python'")
s = s[:i] + pre.lstrip("\n") + s[i:]
open(dst, "w", encoding="utf-8-sig", newline="").write(s)
