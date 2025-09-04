# Standalone Version

This version of the shortcut uses steganography to merge the shortcut and the script into one file, and the shortcut parameters have been tweaked to read the PowerShell code from within.

## Instructions

You can create it with the following steps:
1. Copy `Windows Sandbox.lnk` into this folder.
2. View the Properties of the link and modify the **Target** to be:
  - `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command "&{$x = (gci -Filter ((Get-Process -Id $PID).MainWindowTitle + '.lnk') | gc -Raw) ; iex $x.Substring($x.LastIndexOf('<# Copyright (C) '))}"` (this helps it find the code at the end of the .lnk shortcut)
3. Using the following command (in CMD) `copy /b ".\Windows Sandbox.lnk" + ..\ThemedSandbox.ps1 "Windows Sandbox (Standalone).lnk"` (this copies the script to the end of the shortcut file)

However, **most modern virus protection software will likely see this file as a threat, and quarantine it**, so that's why this version isn't as recommended (and removed from this repo).

Additional note, attempting to modify any of the properties on the shortcut will shed away the bundled script file, breaking the file. So, if you want to modify the properties, you'll have to recreate the shortcut like so:
- `copy /b "Windows Sandbox (Standalone).lnk" + ..\ThemedSandbox.ps1 "Windows Sandbox (Standalone) - Fixed.lnk"`
