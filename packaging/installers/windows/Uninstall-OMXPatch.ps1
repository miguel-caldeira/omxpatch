#Requires -RunAsAdministrator
# Remove o OMXPatch (tarefas e aplicação). Mantém C:\ProgramData\OMXPatch salvo -Purge.
param([switch]$Purge)
foreach ($t in 'OMXPatch', 'OMXPatch-Worker') { schtasks /End /TN $t 2>$null | Out-Null; schtasks /Delete /F /TN $t 2>$null | Out-Null }
Remove-NetFirewallRule -DisplayName 'OMXPatch consola', 'OMXPatch agentes' -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force 'C:\OMXPatch' -ErrorAction SilentlyContinue
if ($Purge) { Remove-Item -Recurse -Force 'C:\ProgramData\OMXPatch' -ErrorAction SilentlyContinue; Write-Host 'Removido, incluindo dados.' } else { Write-Host 'Removido. Dados mantidos em C:\ProgramData\OMXPatch (-Purge para apagar).' }
