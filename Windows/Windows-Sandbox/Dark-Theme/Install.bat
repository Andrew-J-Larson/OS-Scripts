@echo off
setlocal

set "batPath=%~dp0"
set "path=%batPath:~0,-1%"
set "destPath=C:\Sandbox"
set "shortcutPath=%destPath%\Windows Sandbox (Dark Theme).lnk"

REM Must be admin for install
net session >nul 2>&1
if %errorLevel% neq 0 (
  echo Install aborted, please run script as admin.
  echo.
  pause
  exit 1
)

REM Copy to root of C: drive
xcopy /y /e /s /q "%path%\Sandbox\*.*" "%destPath%\"
echo Successfully installed to "%destPath%".
echo Shortcut located at "%shortcutPath%".
echo.
pause
