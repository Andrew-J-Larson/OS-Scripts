@echo off

REM unzip <InputZip> <OutputFolder> (ItemInZip)
REM <> = required, () = optional

setlocal
set argCount=0
for %%x in (%*) do Set /A argCount+=1
if %argCount%==0 (
  echo Error: not enough arguments.
  exit /b 1
)
set "outputDir=%~n1"
if %argCount% gtr 1 set "outputDir=%~2"
if %argCount% gtr 3 (
  echo Error: too many arguments.
  exit /b 1
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a1") do if "%%B" neq "" (
  echo Error: the input, "%~1", is not a file.
  exit /b 1
) else if "%%A" neq "-" (
  echo Continuing>nul
) else (
  echo Error: the input file, "%~1", doesn't exist.
  exit /b 1
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a2") do if "%%B" neq "" (
  echo Adding onto folder>nul
) else if "%%A" neq "-" (
  echo Error: the output, "%~2", already exists as a file.
  exit /b 1
) else (
  mkdir "%outputDir%"
)
REM in case the arguments aren't using a full directory
set "tempCheck=%tmp%\zipunzipfoldername%RANDOM%.txt"
if exist "%tempCheck%" del /f /q "%tempCheck%"
REM 0 = both are paths, 1 = first isn't path, 2 = second isn't path, 3 = all aren't paths
FOR /F "tokens=* USEBACKQ" %%F IN (`where /r . "%~1"`) DO (
set inputZip=%%F
)
set "folderConstant= Directory of "
dir "%outputDir%"|findstr ":"|findstr "%folderConstant%">"%tempCheck%"
set /p outputDir=<"%tempCheck%"
if exist "%tempCheck%" del /f /q "%tempCheck%"
call set "outputDir=%%outputDir:%folderConstant%=%%"
set "unzip=%tmp%\unzip%RANDOM%.vbs"
if exist "%unzip%" del /f /q "%unzip%"
>"%unzip%" echo set Args = WScript.Arguments
>>"%unzip%" echo source = Args(0)
>>"%unzip%" echo target = Args(1)
>>"%unzip%" echo set fso = CreateObject("Scripting.FileSystemObject")
>>"%unzip%" echo if not fso.FolderExists(target) Then
>>"%unzip%" echo    fso.CreateFolder(target)
>>"%unzip%" echo End If
>>"%unzip%" echo set objShell = CreateObject("Shell.Application")
>>"%unzip%" echo set itemsInZip = objShell.NameSpace(source).items
>>"%unzip%" echo objShell.NameSpace(target).CopyHere(itemsInZip),4
>>"%unzip%" echo set fso = Nothing
>>"%unzip%" echo set objShell = Nothing
echo "%~1"|findstr "[:]">nul
set /a inputCheck=%ERRORLEVEL%
if %argCount% lss 3 (
  if %inputCheck% equ 1 (
    call :extractAll "%inputZip%" "%outputDir%"
  ) else (
    call :extractAll "%~1" "%outputDir%"
  )
)
if %argCount%==3 (
  if %inputCheck% equ 1 (
    call :extractItem "%inputZip%" "%outputDir%" "%~3"
  ) else (
    call :extractItem "%~1" "%outputDir%" "%~3"
  )
)
if exist "%unzip%" del /f /q "%unzip%"
endlocal
exit /b

:extractItem [not for user calls]
setlocal
set "tempItemDir=%tmp%\zipunzip%RANDOM%"
if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
if %inputCheck% equ 1 (
  cscript //nologo "%unzip%" "%inputZip%" "%tempItemDir%"
) else (
  cscript //nologo "%unzip%" "%~1" "%tempItemDir%"
)
cd "%tempItemDir%"
for /f "tokens=1,2 delims=d" %%A in ("-%~a3") do if "%%B" neq "" (
  REM Copying folder
  robocopy /E /J "%tempItemDir%\%~3" "%outputDir%\%~3">nul
) else if "%%A" neq "-" (
  REM Copying file
  robocopy /J "%tempItemDir%" "%outputDir%" "%~3">nul
) else (
  echo Error: file or folder didn't exist in zip file.
  if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
  exit /b 1
)
cd "%~dp0"
if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
endlocal
exit /b

:extractAll [not for user calls]
cscript //nologo "%unzip%" "%~1" "%~2%"
exit /b