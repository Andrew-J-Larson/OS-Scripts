@echo off

:: BatchGotAdmin
::-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del /q "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
::--------------------------------------

REM Get true directory location
powershell "Get-Location | findstr \\ | Set-Content '.\pwd' -NoNewLine"
set /p resources=<".\pwd"
del ".\pwd"
cd \
cd "%resources%"

REM Set up variables for install/uninstall/temporary locations
set "usr=%HOMEDRIVE%\usr"
set "usrbin=%usr%\bin"
set "tempStore=%tmp%\sudo"
set install=1

REM All files to install "Size on disk" from bytes converted to kilobytes
set "size=2.41"
set "sizeOnDisk=4.09"

REM Check files
echo|set /p=Reading package lists...
if exist "%usrbin%\sudo.cmd" set install=0
if exist "%usrbin%\sudo.ps1" set install=0
echo  Done
echo Building dependency tree
if exist "%tempStore%" rmdir /Q/S "%tempStore%"
if not exist "%tempStore%" mkdir "%tempStore%"
echo|set /p=Reading state information...
powershell "(Get-Item -path 'C:\Windows\System32\SystemPropertiesAdvanced.exe').VersionInfo.ProductVersion | Set-Content '%tempStore%\StPrAd' -NoNewLine"
powershell "wmic os get Caption | findstr Windows | Set-Content '%tempStore%\Caption' -NoNewLine"
set /p Build=<"%tempStore%\StPrAd"
set /p Caption=<"%tempStore%\Caption"
set Caption=%Caption: =%
del "%tempStore%\StPrAd"
del "%tempStore%\Caption"
echo  Done
if %install%==0 goto uninstall

:install
echo The following NEW packages will be installed:
echo.  sudo
echo 0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.
choice /N /M "Do you want to continue? [Y/n] "
if ERRORLEVEL 2 goto abort
if not exist "%usrbin%" mkdir "%usrbin%"
echo Need to get %size% kB of archives.
echo After this operation, %sizeOnDisk% kB of additional disk space will be used.
echo Unpacking sudo (.cmd, .ps1, .txt) ...
copy /Y "%resources%\sudo*" "%usrbin%">nul
echo Setting up sudo ...
echo|set /p=Processing directories for system PATH environment (%sysEnvVer%%Caption%)
powershell "[Environment]::SetEnvironmentVariable('path', \""$([Environment]::GetEnvironmentVariable('path', 'machine'));%usrbin%\"",'Machine');"
goto :eof

:uninstall
set foldersize=0
echo The following packages will be REMOVED:
echo.  sudo
echo 0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
choice /N /M "Do you want to continue? [Y/n] "
if ERRORLEVEL 2 goto abort
echo After this operation, %sizeOnDisk% kB disk space will be freed.
echo Removing sudo (.cmd, .ps1, .txt) ...
if exist "%usrbin%\sudo.txt" del "%usrbin%\sudo.txt"
if exist "%usrbin%\sudo.ps1" del "%usrbin%\sudo.ps1"
if exist "%usrbin%\sudo.cmd" del "%usrbin%\sudo.cmd"
echo|set /p=Processing directories for system PATH environment (%sysEnvVer%%Caption%)
call :ReportFolderState "%usrbin%"
set foldersize=%ERRORLEVEL%
if %foldersize% equ 0 rmdir /Q "%usrbin%"
if not exist "%usrbin%" powershell "$path = [System.Environment]::GetEnvironmentVariable('path', 'Machine');$path = ($path.Split(';') | Where-Object { $_ -ne '%removePath%' }) -join ';';[System.Environment]::SetEnvironmentVariable('path', $path, 'Machine')"
call :ReportFolderState "%usr%"
set foldersize=%ERRORLEVEL%
if %foldersize% equ 0 rmdir "%usr%"
goto :eof

:abort
echo|set /p=Abort.
goto :eof

:ReportFolderState <directory>
@call :CheckFolder "%~f1"
@set RESULT=%ERRORLEVEL%
@if %RESULT% equ 999 @exit /b 999 &:: Folder doesn't exist
@if %RESULT% equ 1   @exit /b 1 &::   Not empty!
@if %RESULT% equ 0   @exit /b 0 &::   Empty!
@exit /b 
 
:CheckFolder <directory>
@if not exist "%~f1" @exit /b 999
@for %%I in ("%~f1\*.*") do @exit /b 1
@exit /b 0

:eof
if exist "%tempStore%" rmdir /Q/S "%tempStore%"
exit