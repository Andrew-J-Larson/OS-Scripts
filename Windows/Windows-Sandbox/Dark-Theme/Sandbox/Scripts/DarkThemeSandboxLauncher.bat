@echo off
setlocal

REM Launches Windows Sandbox with dark theme, but prevents your eyes from being blinded by minimizing the window until theme is loaded.

start "" "..\Dark Theme.wsb"

REM Please make sure to copy the "Sandbox" folder to the correct location, at the root of the C: drive (see below)!
start /min powershell.exe -ExecutionPolicy Bypass -File ".\DarkThemeSandboxHandler.ps1"
