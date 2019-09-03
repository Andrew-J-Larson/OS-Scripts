@echo off
setlocal

REM These are fully functional zip and unzip functions made entirely just for batch/cmd, and they can be added to any file and work. There is some error handling, for which you need to test yourself

REM I primarily created these with some resources online (zip and unzip I found online), however, unzipItem was created by entirely by hand
REM - TheAlienDrew

:unzip <InputZip> <OutputFolder>
for /f "tokens=1,2 delims=d" %%A in ("-%~a1") do if "%%B" neq "" (
  echo Error: the input, %1, is not a file.
  exit /b 1
) else if "%%A" neq "-" (
  echo Continuing>nul
) else (
  echo Error: the input file, %1, doesn't exist.
  exit /b 1
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a2") do if "%%B" neq "" (
  echo Adding onto folder>nul
) else if "%%A" neq "-" (
  echo Error: the output, %2, already exists as a file.
  exit /b 1
) else (
  echo Continuing>nul
)
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
cscript //nologo "%unzip%" "%~1" "%~2"
if exist "%unzip%" del /f /q "%unzip%"
exit /b

:unzipItem <InputZip> <ItemInZip> <OutputFolder>
for /f "tokens=1,2 delims=d" %%A in ("-%~a1") do if "%%B" neq "" (
  echo Error: the input, %1, is not a file.
  exit /b
) else if "%%A" neq "-" (
  echo Continuing>nul
) else (
  echo Error: the input file, "%~1", doesn't exist.
  exit /b
)
for /f "tokens=1,2 delims=d" %%A in ("-%~a3") do if "%%B" neq "" (
  echo Adding onto folder>nul
) else if "%%A" neq "-" (
  echo Error: the output, "%~3", already exists as a file.
  exit /b
) else (
  echo Continuing>nul
)
set "tempItemDir=%tmp%\zipunzip%RANDOM%"
if not exist "%tempItemDir%" mkdir "%tempItemDir%"
call :unzip "%~1" "%tempItemDir%"
if %ERRORLEVEL% equ 1 (
	echo Error: there were problems unzipping.
	if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
	exit /b 1
)
REM check item
cd "%tempItemDir%"
for /f "tokens=1,2 delims=d" %%A in ("-%~a2") do if "%%B" neq "" (
  REM Copying folder
  robocopy /E /J "%tempItemDir%\%~2" "%~3\%~2">nul
) else if "%%A" neq "-" (
  REM Copying file
  robocopy /J "%tempItemDir%" "%~3" "%~2">nul
) else (
  echo Error: file or folder didn't extract, so nothing was copied over.
  if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
  exit /b 1
)
cd "%~dp0"
if exist "%tempItemDir%" rmdir /q /s "%tempItemDir%"
exit /b

:zip <InputFolder> <CompressTo>
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
REM fix ending slash issues
set "checkDir1=%~1"
IF NOT "%checkDir1:~-1%"=="\" SET "checkDir1=%checkDir1%\"
set "checkDir2=%~2"
call set "checkDir3=%%checkDir2:%checkDir1%=%%"
REM don't allow same dir compressing
if not "%checkDir3%" == "%checkDir2%" (
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
cscript //nologo "%zip%" "%~1" "%~2"
if exist "%zip%" del /f /q "%zip%"
exit /b
