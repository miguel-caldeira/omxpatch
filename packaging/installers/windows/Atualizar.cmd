@echo off
rem Duplo clique: atualiza a instalacao existente como administrador.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File ""%~dp0Update-OMXPatch.ps1""'"
