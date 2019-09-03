@echo off

REM These are fully functional zip and unzip functions made entirely just for batch/cmd, and they can be added to any file and work. There is some error handling, for which you need to test yourself

REM I primarily created these with some resources online (zip and unzip I found online), however, unzipItem was created by entirely by hand
REM - TheAlienDrew

echo This batch file shows no examples (view the source code on how to use) & echo.
pause
exit



:unzip <InputZip> <OutputFolder> (ItemInZip)
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

:zip <InputFolder> <CompressTo>
REM <> = required, () = optional
setlocal
set argCount=0
for %%x in (%*) do Set /A argCount+=1
if not %argCount%==2 (
  if %argCount% lss 2 (
    echo Error: not enough arguments.
  ) else (
    echo Error: too many arguments.
  )
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a1") do if "%%B" neq "" (
  echo Continuing>nul
) else if "%%A" neq "-" (
  echo Error: the input, "%~1", is not a folder.
  exit /b 1
) else (
  echo Error: the input folder, "%~1", doesn't exist.
  exit /b 1
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a2") do if "%%B" neq "" (
  echo Error: the output, "%~2", already exists as a folder.
  exit /b 1
) else if "%%A" neq "-" (
  echo Overwriting "%~2"
) else (
  echo Continuing>nul
)
REM in case the arguments aren't using a full directory
set "tempCheck=%tmp%\zipunzipfoldername%RANDOM%.txt"
if exist "%tempCheck%" del /f /q "%tempCheck%"
set "folderConstant= Directory of "
dir "%~1"|findstr ":"|findstr "%folderConstant%">"%tempCheck%"
set /p inputDir=<"%tempCheck%"
if exist "%tempCheck%" del /f /q "%tempCheck%"
call set "inputDir=%%inputDir:%folderConstant%=%%"
REM fix ending slash issues
IF NOT "%inputDir:~-1%"=="\" SET "inputDir=%inputDir%\"
REM no colon in name means I need to create full dir
set "outputZip=%~2"
echo "%~2"|findstr ":">nul
if %ERRORLEVEL% equ 1 set "outputZip=%cd%\%~2"
REM don't allow same dir compressing
call set "outputCheck=%%outputZip:%inputDir%=%%"
if not "%outputCheck%" == "%outputZip%" (
	echo Error: Can't compress to the same directory.
	exit /b 1
)
set "zip=%tmp%\zip%RANDOM%.vbs"
if exist "%zip%" del /f /q "%zip%"
>"%zip%" echo set Args = WScript.Arguments
>>"%zip%" echo source = Args(0)
>>"%zip%" echo while Right(source, 1) = "\"
>>"%zip%" echo     source = Mid(source, 1, Len(source) - 1)
>>"%zip%" echo wend
>>"%zip%" echo target = Args(1)
>>"%zip%" echo set fso = CreateObject("Scripting.FileSystemObject")
>>"%zip%" echo set zip = fso.OpenTextFile(target, 2, vbtrue)
>>"%zip%" echo zip.Write "PK" ^& Chr(5) ^& Chr(6) ^& String(18, Chr(0))
>>"%zip%" echo zip.Close
>>"%zip%" echo set zip = nothing
>>"%zip%" echo set fso = nothing
>>"%zip%" echo set app = CreateObject("Shell.Application")
>>"%zip%" echo set sourceFolderObj = app.NameSpace(source)
>>"%zip%" echo set targetFolderObj = app.NameSpace(target)
>>"%zip%" echo for each item in sourceFolderObj.Items
>>"%zip%" echo   itemPath = source ^& "\" ^& item.Name
>>"%zip%" echo   copyItem = false
>>"%zip%" echo   if itemPath ^<^> target then
>>"%zip%" echo     if item.IsFolder then
>>"%zip%" echo       if item.GetFolder.Items().Count = 0 then
>>"%zip%" echo       else
>>"%zip%" echo         copyItem = true
>>"%zip%" echo       end if
>>"%zip%" echo     else
>>"%zip%" echo       copyItem = true
>>"%zip%" echo     end if
>>"%zip%" echo   end if
>>"%zip%" echo   if copyItem then
>>"%zip%" echo     targetFolderObj.CopyHere item,4
>>"%zip%" echo     while (targetFolderObj.ParseName(item.Name) is nothing)
>>"%zip%" echo       WScript.Sleep 1
>>"%zip%" echo     wend
>>"%zip%" echo   end If
>>"%zip%" echo next
>>"%zip%" echo set targetFolderObj = nothing
>>"%zip%" echo set sourceFolderObj = nothing
>>"%zip%" echo set app = nothing
cscript //nologo "%zip%" "%inputDir%" "%outputZip%"
if exist "%zip%" del /f /q "%zip%"
endlocal
exit /b
