@echo off

setlocal

set "scriptName=Prepare-PC.ps1"
set "scriptLocation=%~dp0%scriptName%"
powershell.exe -WindowStyle Hidden -c "Start-Process 'powershell.exe' -ArgumentList '-ExecutionPolicy Bypass -c \". \\\"%scriptLocation%\\\" -f11 -l -a \\\"DEFAULT\\\"\"' -Verb RunAs -WindowStyle Maximized"