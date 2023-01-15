#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1
# Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
# If a program you use isn't in any of the lists here, either fork/edit/push, or create an issue at: https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20%28or%20more%20preferably%2C%20the%20installer%20location%20on%20the%20PC%2C%20and%20where%20the%20shortcut%20normally%20resides%20--%3E%0A%0A
# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

# Application objects are setup like so:
<# @{
       Name="[name of shortcut here]";
       TargetPath="[path to exe/url/folder here]";
       Arguments="[any arguments that an app starts with here]";
       SystemLnk="[path to lnk or name of app here]";
       StartIn="[start in path, if needed, here]";
       Description="[comment, that shows up in tooltip, here]"
       RunAsAdmin="[true or false, if needed]"
   } #>



# Constants

Set-Variable NotInstalled -Option Constant -Value "NOT-INSTALLED"



# Variables

$isWindows11 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 11")
$isWindows10 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 10")
$isWin10orNewer = [System.Environment]::OSVersion.Version.Major -ge 10



# Functions

function Recreate-Shortcut {
    param(
    [Parameter(Mandatory=$true)]
    [Alias("name","n")]
    [string]$sName,

    [Parameter(Mandatory=$true)]
    [Alias("targetpath","tp")]
    [string]$sTargetPath,

    [Alias("arguments","a")]
    [string]$sArguments, # Optional (for special shortcuts)

    [Alias("systemlnk", "sl")]
    [string]$sSystemLnk, # Optional (for if name / path is different from normal)

    [Alias("startin","si")]
    [string]$sStartIn, # Optional (for special shortcuts)

    [Alias("description", "d")]
    [string]$sDescription, # Optional (some shortcuts have comments for tooltips)
    
    [Alias("runasadmin", "r")]
    [bool]$sRunAsAdmin, # Optional (if the shortcut should be ran as admin)

    [Alias("user", "u")]
    [string]$sUser # Optional (username of the user to install shortcut to)
  )

  $result = $true
  $resultMsg = @()
  $warnMsg = @()
  $errorMsg = @()

  Set-Variable ProgramShortcutsPath -Option Constant -Value "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
  Set-Variable UserProgramShortcutsPath -Option Constant -Value "C:\Users\${sUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"

  # only create shortcut if name and target given, and target exists
  if ($sName -And $sTargetPath -And (Test-Path $sTargetPath -PathType leaf)) {
    $WScriptObj = New-Object -ComObject WScript.Shell

    # if shortcut path not given, create one at default location with $sName
    if (-Not ($sSystemLnk)) {$sSystemLnk = $sName}
    # if doesn't have $ProgramShortcutsPath or $UserProgramShortcutsPath (and not start with drive letter), it'll assume a path for it
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^'+[Regex]::Escape($ProgramShortcutsPath)+'.*') -Or $sSystemLnk -match ('^'+[Regex]::Escape($UserProgramShortcutsPath)+'.*'))) {
      $sSystemLnk = $(if ($sUser) {$UserProgramShortcutsPath} else {$ProgramShortcutsPath})+'\'+$sSystemLnk
    }
    # if it ends with '\', then we append the name to the end
    if ($sSystemLnk.EndsWith('\')) {$sSystemLnk = $sSystemLnk+$sName}
    # if doesn't end with .lnk, add it
    if (-Not ($sSystemLnk -match '.*\.lnk$')) {$sSystemLnk = $sSystemLnk+'.lnk'}
    $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)

    $newLNK.TargetPath = $sTargetPath

    if ($sArguments) {
      $newLNK.Arguments =  $sArguments
    }

    if ($sStartIn) {
      $newLNK.WorkingDirectory = $sStartIn
    }

    if ($sDescription) {
      $newLNK.Description = $sDescription
    }

    $newLNK.Save()
    $result = $?
    [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null

    if ($result) {
      $resultMsg += "Created shortcut at:`n${sSystemLnk}"

      # set to run as admin if needed
      if ($sRunAsAdmin) {
        $bytes = [System.IO.File]::ReadAllBytes($sSystemLnk)
        $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
        [System.IO.File]::WriteAllBytes($sSystemLnk, $bytes)
        $result = $?
        if ($result) {$resultMsg += "Shortcut set to Run as Admin, at: ${sSystemLnk}"}
        else {$errorMsg += "Failed to set shortcut to Run as Admin, at: ${sSystemLnk}"}
      }
    } else {$errorMsg += "Failed to create shortcut, with target at: ${sTargetPath}"}
  } elseif (-Not ($sName -Or $sTargetPath)) {
    if (-Not $sName) {
      $errorMsg += "Error! Name is missing!"
    }
    if (-Not $sTargetPath) {
      $errorMsg += "Error! Target is missing!"
    }

    $result = $false
  } else {
    $warnMsg += "Target invalid! Doesn't exist or is spelled wrong:`n${sTargetPath}"

    $result = $false
  }

  if ($result) {Write-Host -ForegroundColor Green $sName}
  else {Write-Host -ForegroundColor Red $sName}

  if ($resultMsg.length -gt 0) {
    for ($msgNum = 0; $msgNum -lt $resultMsg.length; $msgNum++) {
      Write-Host $resultMsg[$msgNum]
    }
  } elseif ($errortMsg.length -gt 0) {
    for ($msgNum = 0; $msgNum -lt $errorMsg.length; $msgNum++) {
      Write-Error $errorMsg[$msgNum]
    }
  }
  if ($warnMsg.length -gt 0) {
    for ($msgNum = 0; $msgNum -lt $warnMsg.length; $msgNum++) {
      Write-Warning $warnMsg[$msgNum]
    }
  }
  Write-Host ""

  return $result
}



# MAIN

if (-Not $isWin10orNewer) {
  Write-Error "This script is only meant to be ran on Windows 10 and newer!"
  exit 1
}



# System Applications

# App paths dependant on app version

# Powershell (7 or newer)
$PowerShell_32bit_TargetPath = "C:\Program Files (x86)\PowerShell\"
$PowerShell_32bit_Version = (Get-ChildItem -Directory -Path $PowerShell_TargetPath | Where-Object {$_.Name -match '^[0-9]+$'} | Sort-Object -Descending)[0].name
$PowerShell_32bit_TargetPath += if ($PowerShell_32bit_Version) {"${PowerShell32bit_Version}\pwsh.exe"} else {"${NotInstalled}\${NotInstalled}.exe"}
$PowerShell_TargetPath = "C:\Program Files\PowerShell\"
$PowerShell_Version = (Get-ChildItem -Directory -Path $PowerShell_TargetPath | Where-Object {$_.Name -match '^[0-9]+$'} | Sort-Object -Descending)[0].name
$PowerShell_TargetPath += if ($PowerShell_Version) {"${PowerShell_Version}\pwsh.exe"} else {"${NotInstalled}\${NotInstalled}.exe"}

# App names dependant on OS or app version

# PowerShell (7 or newer)
$PowerShell_32bit_Name = "PowerShell "+$(if ($PowerShell_Version) {$PowerShell_Version} else {$NotInstalled})+" (x86)"
$PowerShell_Name = "PowerShell "+$(if ($PowerShell_Version) {$PowerShell_Version} else {$NotInstalled})+" (x64)"
# PowerToys
$PowerToys_Name = "PowerToys"+$(if (winget list -q "Microsoft.PowerToys" -e | Select-String "^PowerToys \(Preview\)") {" (Preview)"})

$sysAppList = @(
  # Edge
  @{Name="Microsoft Edge"; TargetPath="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"; StartIn="C:\Program Files (x86)\Microsoft\Edge\Application"; Description="Browse the web"}, # it's the only install on 64-bit
  @{Name="Microsoft Edge"; TargetPath="C:\Program Files\Microsoft\Edge\Application\msedge.exe"; StartIn="C:\Program Files\Microsoft\Edge\Application"; Description="Browse the web"}, # it's the only install on 32-bit
  # PowerShell (7 or newer)
  @{Name=$PowerShell_32bit_Name; TargetPath=$PowerShell_32bit_TargetPath; Arguments="-WorkingDirectory ~"; SystemLnk="PowerShell\"; Description=$PowerShell_32bit_Name},
  @{Name=$PowerShell_Name; TargetPath=$PowerShell_TargetPath; Arguments="-WorkingDirectory ~"; SystemLnk="PowerShell\"; Description=$PowerShell_Name},
  # Intune Management Extension
  @{Name="Microsoft Intune Management Extension"; TargetPath="C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk="Microsoft Intune Management Extension\"; Description="Microsoft Intune Management Extension"},
  # PowerToys
  @{Name=$PowerToys_Name; TargetPath="C:\Program Files\PowerToys\PowerToys.exe"; SystemLnk=$PowerToys_Name+'\'; StartIn="C:\Program Files\PowerToys\"; Description="PowerToys - Windows system utilities to maximize productivity"},
  # OneDrive
  @{Name="OneDrive"; TargetPath="C:\Program Files\Microsoft OneDrive\OneDrive.exe"; Description="Keep your most important files with you wherever you go, on any device."},
  # Office
  @{Name="Access"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE"; Description="Build a professional app quickly to manage data."},
  @{Name="Excel"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"; Description="Easily discover, visualize, and share insights from your data."},
  @{Name="OneNote"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"; Description="Take notes and have them when you need them."},
  @{Name="Outlook"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description="Manage your email, schedules, contacts, and to-dos."},
  @{Name="PowerPoint"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"; Description="Design and deliver beautiful presentations with ease and confidence."},
  @{Name="Publisher"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE"; Description="Create professional-grade publications that make an impact."},
  @{Name="Word"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"; Description="Create beautiful documents, easily work with others, and enjoy the read."},
  @{Name="Database Compare"; TargetPath="C:\Program Files\Microsoft Office\root\Client\AppVLP.exe"; Arguments="`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""; SystemLnk="Microsoft Office Tools\"; Description="Compare versions of an Access database."},
  @{Name="Office Language Preferences"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk="Microsoft Office Tools\"; Description="Change the language preferences for Office applications."},
  @{Name="Spreadsheet Compare"; TargetPath="C:\Program Files\Microsoft Office\root\Client\AppVLP.exe"; Arguments="`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""; SystemLnk="Microsoft Office Tools\"; Description="Compare versions of an Excel workbook."},
  @{Name="Telemetry Log for Office"; TargetPath="C:\Program Files\Microsoft Office\root\Office16\msoev.exe"; SystemLnk="Microsoft Office Tools\"; Description="View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log."},
  # Visual Studio
  @{Name="Visual Studio Installer"; TargetPath="C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe"; StartIn="C:\Program Files (x86)\Microsoft Visual Studio\Installer"},
  @{Name="Visual Studio Code"; TargetPath="C:\Program Files\Microsoft VS Code\Code.exe"; SystemLnk="Visual Studio Code\"; StartIn="C:\Program Files\Microsoft VS Code"}
#  @{Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; RunAsAdmin=($true|$false)}
)

for ($i = 0; $i -lt $sysAppList.length; $i++) {
  $app = $sysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}
  $aRunAsAdmin = if ($app.RunAsAdmin) {$app.RunAsAdmin} else {$false}

  $Results = Recreate-Shortcut -n $aName -tp $aTargetPath -a $sArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -r $aRunAsAdmin
}



# OEM System Applications (e.g. Dell)

# App paths dependant on app version

## App Name
#$App_TargetPath = ...
#$App_StartIn = ...

# App names dependant on OS or app version

## App Name
#$App_Name = ...

$oemSysAppList = @(
  # Dell
  @{Name="Dell OS Recovery Tool"; TargetPath="C:\Program Files (x86)\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk="Dell\"; StartIn="C:\Program Files (x86)\Dell\OS Recovery Tool\"},
  @{Name="SupportAssist Recovery Assistant"; TargetPath="C:\Program Files\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk="Dell\SupportAssist\"},
  # NVIDIA Corporation
  @{Name="GeForce Experience"; TargetPath="C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"; SystemLnk="NVIDIA Corporation\"; StartIn="C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience"}
#  @{Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; RunAsAdmin=($true|$false)}
)

for ($i = 0; $i -lt $oemSysAppList.length; $i++) {
  $app = $oemSysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}
  $aRunAsAdmin = if ($app.RunAsAdmin) {$app.RunAsAdmin} else {$false}

  $Results = Recreate-Shortcut -n $aName -tp $aTargetPath -a $sArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -r $aRunAsAdmin
}



# Third-Party System Applications (not made by Microsoft)

# App paths dependant on app version

# Google Drive
$GoogleDrive_TargetPath = "C:\Program Files\Google\Drive File Stream\"
$GoogleDrive_Version = (Get-ChildItem -Directory -Path $GoogleDrive_TargetPath | Where-Object {$_.Name -match '^[.0-9]+$'} | Sort-Object -Descending)[0].name
$GoogleDrive_TargetPath += if ($GoogleDrive_Version) {"${GoogleDrive_Version}\GoogleDriveFS.exe"} else {"${NotInstalled}\${NotInstalled}.exe"}
# VPN By Google One
$GoogleOneVPN_TargetPath = "C:\Program Files\Google\VPN by Google One\"
$GoogleOneVPN_Version = (Get-ChildItem -Directory -Path $GoogleOneVPN_TargetPath | Where-Object {$_.Name -match '^[.0-9]+$'} | Sort-Object -Descending)[0].name
$GoogleOneVPN_TargetPath += if ($GoogleOneVPN_Version) {"${GoogleOneVPN_Version}\googleone.exe"} else {"${NotInstalled}\${NotInstalled}.exe"}
# GIMP
$GIMP_TargetPath = "C:\Program Files\"
$GIMP_FindFolder = (Get-ChildItem -Directory -Path $GIMP_TargetPath | Where-Object {$_.Name -match '^GIMP'} | Sort-Object -Descending)[0].name
$GIMP_TargetPath += if ($GIMP_FindFolder) {"${GIMP_FindFolder}\bin\"} else {"${NotInstalled}\${NotInstalled}\"}
$GIMP_FindExe = (Get-ChildItem -File -Path $GIMP_TargetPath | Where-Object {$_.Name -match '^gimp\-[.0-9]+exe$'} | Sort-Object -Descending)[0].name
$GIMP_TargetPath += if ($GIMP_FindExe) {$GIMP_FindExe} else {"${NotInstalled}.exe"}

# App names dependant on OS or app version

# GIMP
$GIMP_Version = ([string](winget list -q "GIMP.GIMP" -e | Select-String "^GIMP")).split(' ')[3]
$GIMP_Name = "GIMP "+$(if ($GIMP_Version) {$GIMP_Version} else {$NotInstalled})

$sys3rdPartyAppList = @(
  # Google
  @{Name="Google Chrome (32-bit)"; TargetPath="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"; StartIn="C:\Program Files (x86)\Google\Chrome\Application"; Description="Access the Internet"},
  @{Name="Google Chrome"; TargetPath="C:\Program Files\Google\Chrome\Application\chrome.exe"; StartIn="C:\Program Files\Google\Chrome\Application"; Description="Access the Internet"},
  @{Name="Google Drive"; TargetPath=$GoogleDrive_TargetPath; Description="Google Drive"},
  @{Name="VPN by Google One"; TargetPath=$GoogleOneVPN_TargetPath; Description="VPN by Google One"},
  # Mozilla
  @{Name="Firefox (32-bit)"; TargetPath="C:\Program Files (x86)\Mozilla Firefox\firefox.exe"; StartIn="C:\Program Files (x86)\Mozilla Firefox"},
  @{Name="Firefox Private Browsing (32-bit)"; TargetPath="C:\Program Files (x86)\Mozilla Firefox\private_browsing.exe"; StartIn="C:\Program Files (x86)\Mozilla Firefox"; Description="Firefox Private Browsing"},
  @{Name="Firefox"; TargetPath="C:\Program Files\Mozilla Firefox\firefox.exe"; StartIn="C:\Program Files\Mozilla Firefox"},
  @{Name="Firefox Private Browsing"; TargetPath="C:\Program Files\Mozilla Firefox\private_browsing.exe"; StartIn="C:\Program Files\Mozilla Firefox"; Description="Firefox Private Browsing"},
  @{Name="Thunderbird"; TargetPath="C:\Program Files\Mozilla Thunderbird\thunderbird.exe"; StartIn="C:\Program Files\Mozilla Thunderbird"},
  # 7-Zip
  @{Name="7-Zip File Manager (32-bit)"; TargetPath="C:\Program Files (x86)\7-Zip\7zFM.exe"; SystemLnk="7-Zip\"},
  @{Name="7-Zip File Manager"; TargetPath="C:\Program Files\7-Zip\7zFM.exe"; SystemLnk="7-Zip\"},
  @{Name="7-Zip Help"; TargetPath="C:\Program Files (x86)\7-Zip\7-zip.chm"; SystemLnk="7-Zip\"},
  @{Name="7-Zip Help"; TargetPath="C:\Program Files\7-Zip\7-zip.chm"; SystemLnk="7-Zip\"},
  # GIMP
  @{Name=$GIMP_Name; TargetPath=$GIMP_TargetPath; StartIn="%USERPROFILE%"; Description=$GIMP_Name},
  # Audacity
  @{Name="Audacity"; TargetPath="C:\Program Files\Audacity\Audacity.exe"; StartIn="C:\Program Files\Audacity"},
  # Kdenlive
  @{Name="Kdenlive"; TargetPath="C:\Program Files\kdenlive\bin\kdenlive.exe"; StartIn="{workingDirectory}"; Description="Libre Video Editor, by KDE community"},
  # VideoLAN
  @{Name="Documentation"; TargetPath="C:\Program Files\VideoLAN\VLC\Documentation.url"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  @{Name="Release Notes"; TargetPath="C:\Program Files\VideoLAN\VLC\NEWS.txt"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  @{Name="VideoLAN Website"; TargetPath="C:\Program Files\VideoLAN\VLC\VideoLAN Website.url"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  @{Name="VLC media player - reset preferences and cache files"; TargetPath="C:\Program Files\VideoLAN\VLC\vlc.exe"; Arguments="--reset-config --reset-plugins-cache vlc://quit"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  @{Name="VLC media player skinned"; TargetPath="C:\Program Files\VideoLAN\VLC\vlc.exe"; Arguments="-Iskins"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  @{Name="VLC media player"; TargetPath="C:\Program Files\VideoLAN\VLC\vlc.exe"; SystemLnk="VideoLAN\"; StartIn="C:\Program Files\VideoLAN\VLC"},
  # Notepad++
  @{Name="Notepad++"; TargetPath="C:\Program Files\Notepad++\notepad++.exe"; StartIn="C:\Program Files\Notepad++"},
  # AutoHotkey
  @{Name="AutoHotkey Help File"; TargetPath="C:\Program Files\AutoHotkey\AutoHotkey.chm"; SystemLnk="AutoHotkey\"},
  @{Name="AutoHotkey Setup"; TargetPath="C:\Program Files\AutoHotkey\Installer.ahk"; SystemLnk="AutoHotkey\"},
  @{Name="AutoHotkey"; TargetPath="C:\Program Files\AutoHotkey\AutoHotkey.exe"; SystemLnk="AutoHotkey\"},
  @{Name="Convert .ahk to .exe"; TargetPath="C:\Program Files\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk="AutoHotkey\"},
  @{Name="Website"; TargetPath="C:\Program Files\AutoHotkey\AutoHotkey Website.url"; SystemLnk="AutoHotkey\"},
  @{Name="Window Spy"; TargetPath="C:\Program Files\AutoHotkey\WindowSpy.ahk"; SystemLnk="AutoHotkey\"},
  # Bulk Crap Uninstaller
  @{Name="BCUninstaller"; TargetPath="C:\Program Files\BCUninstaller\BCUninstaller.exe"; SystemLnk="BCUninstaller\"; StartIn="C:\Program Files\BCUninstaller"},
  @{Name="Uninstall BCUninstaller"; TargetPath="C:\Program Files\BCUninstaller\unins000.exe"; SystemLnk="BCUninstaller\"; StartIn="C:\Program Files\BCUninstaller"},
  # CodeTwo Active Directory Photos
  @{Name="CodeTwo Active Directory Photos"; TargetPath="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="CodeTwo Active Directory Photos"},
  @{Name="Go to program home page"; TargetPath="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="CodeTwo Active Directory Photos home page"},
  @{Name="User's manual"; TargetPath="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="Go to User Guide"},
  # Local Administrator Password Solution
  @{Name="LAPS UI"; TargetPath="C:\Program Files\LAPS\AdmPwd.UI.exe"; SystemLnk="LAPS\"; StartIn="C:\Program Files\LAPS\"},
  # VMware
  @{Name="Command Prompt for vctl"; TargetPath="C:\Windows\System32\cmd.exe"; Arguments="/k set PATH=C:\Program Files (x86)\VMware\VMware Player\;%PATH% && vctl.exe -h"; SystemLnk="VMware\"; StartIn="C:\Program Files (x86)\VMware\VMware Player\bin\"},
  @{Name="VMware Workstation 16 Player"; TargetPath="C:\Program Files (x86)\VMware\VMware Player\vmplayer.exe"; SystemLnk="VMware\"; StartIn="C:\Program Files (x86)\VMware\VMware Player\"},
  # Oracle
  @{Name="License (English)"; TargetPath="C:\Program Files\Oracle\VirtualBox\License_en_US.rtf"; SystemLnk="Oracle VM VirtualBox\"; StartIn="C:\Program Files\Oracle\VirtualBox\"; Description="License"},
  @{Name="Oracle VM VirtualBox"; TargetPath="C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"; SystemLnk="Oracle VM VirtualBox\"; StartIn="C:\Program Files\Oracle\VirtualBox\"; Description="Oracle VM VirtualBox"},
  @{Name="User manual (CHM, English)"; TargetPath="C:\Program Files\Oracle\VirtualBox\VirtualBox.chm"; SystemLnk="Oracle VM VirtualBox\"; Description="User manual"},
  @{Name="User manual (PDF, English)"; TargetPath="C:\Program Files\Oracle\VirtualBox\doc\UserManual.pdf"; SystemLnk="Oracle VM VirtualBox\"; Description="User manual"},
  # OSFMount
  @{Name="OSFMount Documentation"; TargetPath="C:\Program Files\OSFMount\osfmount_Help.exe"; SystemLnk="OSFMount\"; StartIn="C:\Program Files\OSFMount"},
  @{Name="OSFMount on the Web"; TargetPath="C:\Program Files\OSFMount\OSFMount.url"; SystemLnk="OSFMount\"; StartIn="C:\Program Files\OSFMount"},
  @{Name="OSFMount"; TargetPath="C:\Program Files\OSFMount\OSFMount.exe"; SystemLnk="OSFMount\"; StartIn="C:\Program Files\OSFMount"},
  @{Name="Uninstall OSFMount"; TargetPath="C:\Program Files\OSFMount\unins000.exe"; SystemLnk="OSFMount\"; StartIn="C:\Program Files\OSFMount"},
  # Win32DiskImager
  @{Name="Uninstall Win32DiskImager"; TargetPath="C:\Program Files (x86)\ImageWriter\unins000.exe"; SystemLnk="Image Writer\"; StartIn="C:\Program Files (x86)\ImageWriter"},
  @{Name="Win32DiskImager"; TargetPath="C:\Program Files (x86)\ImageWriter\Win32DiskImager.exe"; SystemLnk="Image Writer\"; StartIn="C:\Program Files (x86)\ImageWriter"},
  # RealVNC
  @{Name="VNC Server"; TargetPath="C:\Program Files\RealVNC\VNC Server\vncguihelper.exe"; Arguments="vncserver.exe -_fromGui -start -showstatus"; SystemLnk="RealVNC\"; StartIn="C:\Program Files\RealVNC\VNC Server\"},
  @{Name="VNC Viewer"; TargetPath="C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe"; SystemLnk="RealVNC\"; StartIn="C:\Program Files\RealVNC\VNC Viewer\"},
  # WinSCP
  @{Name="WinSCP"; TargetPath="C:\Program Files (x86)\WinSCP\WinSCP.exe"; StartIn="C:\Program Files (x86)\WinSCP"; Description="WinSCP: SFTP, FTP, WebDAV and SCP client"},
  # Winaero
  @{Name="EULA"; TargetPath="C:\Program Files\Winaero Tweaker\Winaero EULA.txt"; SystemLnk="Winaero Tweaker\"; StartIn="C:\Program Files\Winaero Tweaker"; Description="Read the license agreement"},
  @{Name="Winaero Tweaker"; TargetPath="C:\Program Files\Winaero Tweaker\WinaeroTweaker.exe"; SystemLnk="Winaero Tweaker\"; StartIn="C:\Program Files\Winaero Tweaker"},
  @{Name="Winaero Website"; TargetPath="C:\Program Files\Winaero Tweaker\Winaero.url"; SystemLnk="Winaero Tweaker\"; StartIn="C:\Program Files\Winaero Tweaker"; Description="Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user."},
  # SoundSwitch
  @{Name="SoundSwitch"; TargetPath="C:\Program Files\SoundSwitch\SoundSwitch.exe"; SystemLnk="SoundSwitch\"; StartIn="C:\Program Files\SoundSwitch"},
  @{Name="Uninstall SoundSwitch"; TargetPath="C:\Program Files\SoundSwitch\unins000.exe"; SystemLnk="SoundSwitch\"; StartIn="C:\Program Files\SoundSwitch"},
  # OpenVPN
  @{Name="OpenVPN"; TargetPath="C:\Program Files\OpenVPN\bin\openvpn-gui.exe"; SystemLnk="OpenVPN\OpenVPN GUI"; StartIn="C:\Program Files\OpenVPN\bin\"},
  @{Name="OpenVPN Manual Page"; TargetPath="C:\Program Files\OpenVPN\doc\openvpn.8.html"; SystemLnk="OpenVPN\Documentation\"; StartIn="C:\Program Files\OpenVPN\doc\"},
  @{Name="OpenVPN Windows Notes"; TargetPath="C:\Program Files\OpenVPN\doc\INSTALL-win32.txt"; SystemLnk="OpenVPN\Documentation\"; StartIn="C:\Program Files\OpenVPN\doc\"},
  @{Name="OpenVPN Configuration File Directory"; TargetPath="C:\Program Files\OpenVPN\config"; SystemLnk="OpenVPN\Shortcuts\"; StartIn="C:\Program Files\OpenVPN\config\"},
  @{Name="OpenVPN Log File Directory"; TargetPath="C:\Program Files\OpenVPN\log"; SystemLnk="OpenVPN\Shortcuts\"; StartIn="C:\Program Files\OpenVPN\log\"},
  @{Name="OpenVPN Sample Configuration Files"; TargetPath="C:\Program Files\OpenVPN\sample-config"; SystemLnk="OpenVPN\Shortcuts\"; StartIn="C:\Program Files\OpenVPN\sample-config\"},
  @{Name="Add a new TAP-Windows6 virtual network adapter"; TargetPath="C:\Program Files\OpenVPN\bin\tapctl.exe"; Arguments="create --hwid root\tap0901"; SystemLnk="OpenVPN\Utilities\"; StartIn="C:\Program Files\OpenVPN\bin\"},
  @{Name="Add a new Wintun virtual network adapter"; TargetPath="C:\Program Files\OpenVPN\bin\tapctl.exe"; Arguments="create --hwid wintun"; SystemLnk="OpenVPN\Utilities\"; StartIn="C:\Program Files\OpenVPN\bin\"},
  # SonicWall Global VPN Client
  @{Name="Global VPN Client"; TargetPath="C:\Program Files\SonicWALL\Global VPN Client\SWGVC.exe"; StartIn="C:\Program Files\SonicWall\Global VPN Client\"; Description="Launch the Global VPN Client"},
  # GoTo
  @{Name="GoTo Resolve Desktop Console (32-bit)"; TargetPath="C:\Program Files (x86)\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn="C:\Program Files (x86)\GoTo\GoTo Resolve Desktop Console\"},
  @{Name="GoTo Resolve Desktop Console (64-bit)"; TargetPath="C:\Program Files\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn="C:\Program Files\GoTo\GoTo Resolve Desktop Console\"},
  # Adobe Acrobat
  @{Name="Adobe Acrobat (32-bit)"; TargetPath="C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe"},
  @{Name="Adobe Acrobat"; TargetPath="C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"},
  # Samsung
  @{Name="Samsung DeX"; TargetPath="C:\Program Files (x86)\Samsung\Samsung DeX\SamsungDeX.exe"; StartIn="C:\Program Files (x86)\Samsung\Samsung DeX\"},
  # Epson
  @{Name="Epson Scan 2"; TargetPath="C:\Program Files (x86)\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk="EPSON\Epson Scan 2\"},
  @{Name="FAX Utility"; TargetPath="C:\Program Files (x86)\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk="EPSON Software\"},
  # Altair Monarch
  @{Name="Altair Monarch 2020"; TargetPath="C:\Program Files\Altair Monarch 2020\DWMonarch.exe"; SystemLnk="Altair Monarch 2020\"},
  # USB Redirector TS Edition
  @{Name="USB Redirector TS Edition - Workstation"; TargetPath="C:\Program Files\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk="USB Redirector TS Edition - Workstation\"}
#  @{Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; RunAsAdmin=($true|$false)}
)

for ($i = 0; $i -lt $sys3rdPartyAppList.length; $i++) {
  $app = $sys3rdPartyAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}
  $aRunAsAdmin = if ($app.RunAsAdmin) {$app.RunAsAdmin} else {$false}

  $Results = Recreate-Shortcut -n $aName -tp $aTargetPath -a $sArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -r $aRunAsAdmin
}



# User Applications (per user installed apps)

# get all users 
$Users = (Get-ChildItem "C:\Users\" | % { $_.name })
if ($Users[0].length -eq 1) {$Users = @("$Users")} # if only one user, array needs to be recreated

# System app paths dependant on app version

# Blender
$Blender_TargetPath = "C:\Program Files\Blender Foundation\"
$Blender_FindFolder = (Get-ChildItem -Directory -Path $Blender_TargetPath | Where-Object {$_.Name -match '^Blender'} | Sort-Object -Descending)[0].name
$Blender_StartIn = $Blender_TargetPath+$(if ($Blender_FindFolder) {"${Blender_FindFolder}\"} else {"${NotInstalled}\"})
$Blender_TargetPath = $Blender_StartIn+$(if ($Blender_FindFolder) {"blender-launcher.exe"} else {"${NotInstalled}.exe"})

# App names dependant on OS or app version

# Microsoft Teams
$MicrosoftTeams_Name = "Microsoft Teams"+$(if ($isWindows11) {" (work or school)"})

for ($i = 0; $i -lt $Users.length; $i++) {
  # get user
  $aUser = $Users[$i]

  # User app paths dependant on app version

  # 1Password
  $OnePassword_TargetPath = "C:\Users\${aUser}\AppData\Local\1Password\app\"
  $OnePassword_Version = (Get-ChildItem -Directory -Path $OnePassword_TargetPath | Where-Object {$_.Name -match '^[.0-9]+$'} | Sort-Object -Descending)[0].name
  $OnePassword_TargetPath += if ($OnePassword_Version) {"${OnePassword_Version}\1Password.exe"} else {"${NotInstalled}\${NotInstalled}.exe"}
  # GitHub Desktop
  $GitHubDesktop_StartIn = "C:\Users\${aUser}\AppData\Local\GitHubDesktop\"
  $GitHubDesktop_TargetPath = $GitHubDesktop_StartIn+"GitHubDesktop.exe"
  $GitHubDesktop_Version = (Get-ChildItem -Directory -Path $GitHubDesktop_StartIn | Where-Object {$_.Name -match '^app\-[.0-9]+$'} | Sort-Object -Descending)[0].name
  $GitHubDesktop_StartIn += if ($GitHubDesktop_Version) {"${GitHubDesktop_Version}"} else {$NotInstalled}
  # Python
  $Python_StartIn = "C:\Users\${aUser}\AppData\Local\Programs\Python\"
  $Python_FindFolder = (Get-ChildItem -Directory -Path $Python_StartIn | Where-Object {$_.Name -match '^Python[.0-9]+$'} | Sort-Object -Descending)[0].name
  $Python_StartIn += if ($Python_FindFolder) {"${Python_FindFolder}\"} else {"${NotInstalled}\"}
  $PythonIDLE_TargetPath = $Python_StartIn+$(if ($Python_FindFolder) {"Lib\idlelib\idle.pyw"} else {"${NotInstalled}\${NotInstalled}\${NotInstalled}.pyw"})
  $Python_TargetPath = $Python_StartIn+$(if ($Python_FindFolder) {"python.exe"} else {"${NotInstalled}.exe"})
  $Python_FileVersionRaw = if (Test-Path -Path $Python_TargetPath -PathType Leaf) {(Get-Item $Python_TargetPath).VersionInfo.FileVersionRaw}
  $Python_Version = if ($Python_Item) {[string]($Python_FileVersionRaw.Major)+'.'+[string]($Python_FileVersionRaw.Minor)} else {$NotInstalled}
  $PythonIDLE_Description = "Launches IDLE, the interactive environment for Python ${Python_Version}."
  $Python_Description = "Launches the Python ${Python_Version} interpreter."
  $PythonModuleDocs_Description = "Start the Python ${Python_Version} documentation server."
  $Python_SystemLnk = "Python ${Python_Version}\"
  $Python_Info = if (Test-Path -Path $Python_TargetPath -PathType Leaf) {(& "${Python_TargetPath}" -VV)}
  $Python_Arch = if ($Python_Info) {if ($Python_Info | Select-String "\[[^\[\]]+32 bit[^\[\]]+\]") {32} elseif ($Python_Info | Select-String "\[[^\[\]]+64 bit[^\[\]]+\]") {64} else {"unknown"}} else {$NotInstalled}
  $PythonIDLE_Name = "IDLE (Python ${Python_Version} ${Python_Arch}-bit)"
  $Python_Name = "Python ${Python_Version} (${Python_Arch}-bit)"
  $PythonModuleDocs_Name = "Python ${Python_Version} Module Docs (${Python_Arch}-bit)"
  # Discord
  $Discord_StartIn = "C:\Users\${aUser}\AppData\Local\Discord\"
  $Discord_TargetPath = $Discord_StartIn+"Update.exe"
  $Discord_Version = (Get-ChildItem -Directory -Path $Discord_StartIn | Where-Object {$_.Name -match '^app\-[.0-9]+$'} | Sort-Object -Descending)[0].name
  $Discord_StartIn += if ($Discord_Version) {"${Discord_Version}"} else {$NotInstalled}

  $userAppList = @( # all instances of "${aUser}" get's replaced with the username
    # Microsoft
    @{Name="Visual Studio Code"; TargetPath="C:\Users\${aUser}\AppData\Local\Programs\Microsoft VS Code\Code.exe"; SystemLnk="Visual Studio Code\"; StartIn="C:\Users\${aUser}\AppData\Local\Programs\Microsoft VS Code"},
    @{Name="OneDrive"; TargetPath="C:\Users\${aUser}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"; Description="Keep your most important files with you wherever you go, on any device."},
    @{Name=$MicrosoftTeams_Name; TargetPath="C:\Users\${aUser}\AppData\Local\Microsoft\Teams\Update.exe"; Arguments="--processStart `"Teams.exe`""; StartIn="C:\Users\${aUser}\AppData\Local\Microsoft\Teams"},
    # Google
    @{Name="Google Chrome"; TargetPath="C:\Users\${aUser}\AppData\Local\Google\Chrome\Application\chrome.exe"; StartIn="C:\Users\${aUser}\AppData\Local\Google\Chrome\Application"; Description="Access the Internet"},
    # Mozilla
    @{Name="Firefox"; TargetPath="C:\Users\${aUser}\AppData\Local\Mozilla Firefox\firefox.exe"; StartIn="C:\Users\${aUser}\AppData\Local\Mozilla Firefox"},
    # NVIDIA Corporation
    @{Name="NVIDIA GeForce NOW"; TargetPath="C:\Users\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF\GeForceNOW.exe"; StartIn="C:\Users\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF"},
    # 1Password
    @{Name="1Password"; TargetPath=$OnePassword_TargetPath; Description="1Password"},
    # Blender
    @{Name="Blender"; TargetPath=$Blender_TargetPath; SystemLnk="blender\"; StartIn=$Blender_StartIn},
    # Inkscape
    @{Name="Inkscape"; TargetPath="C:\Program Files\Inkscape\bin\inkscape.exe"; SystemLnk="Inkscape\"; StartIn="C:\Program Files\Inkscape\bin\"},
    @{Name="Inkview"; TargetPath="C:\Program Files\Inkscape\bin\inkview.exe"; SystemLnk="Inkscape\"; StartIn="C:\Program Files\Inkscape\bin\"},
    # GitHub Desktop
    @{Name="GitHub Desktop"; TargetPath=$GitHubDesktop_TargetPath; SystemLnk="GitHub, Inc\"; StartIn=$GitHubDesktop_StartIn; Description="Simple collaboration from your desktop"},
    # Python
    @{Name=$PythonIDLE_Name; TargetPath=$PythonIDLE_TargetPath; SystemLnk=$Python_SystemLnk; StartIn=$Python_StartIn; Description=$PythonIDLE_Description},
    @{Name=$Python_Name; TargetPath=$Python_TargetPath; SystemLnk=$Python_SystemLnk; StartIn=$Python_StartIn; Description=$Python_Description},
    @{Name=$PythonModuleDocs_Name; TargetPath=$Python_TargetPath; Arguments="-m pydoc -b"; SystemLnk=$Python_SystemLnk; StartIn=$Python_StartIn; Description=$PythonModuleDocs_Description},
    # WinDirStat
    @{Name="Help (ENG)"; TargetPath="C:\Program Files (x86)\WinDirStat\windirstat.chm"; SystemLnk="WinDirStat\"; StartIn="C:\Program Files (x86)\WinDirStat"},
    @{Name="Uninstall WinDirStat"; TargetPath="C:\Program Files (x86)\WinDirStat\Uninstall.exe"; SystemLnk="WinDirStat\"; StartIn="C:\Program Files (x86)\WinDirStat"},
    @{Name="WinDirStat"; TargetPath="C:\Program Files (x86)\WinDirStat\windirstat.exe"; SystemLnk="WinDirStat\"; StartIn="C:\Program Files (x86)\WinDirStat"},
    # balenaEtcher
    @{Name="balenaEtcher"; TargetPath="C:\Users\${aUser}\AppData\Local\Programs\balena-etcher\balenaEtcher.exe"; StartIn="C:\Users\${aUser}\AppData\Local\Programs\balena-etcher"; Description="Flash OS images to SD cards and USB drives, safely and easily."},
    # Raspberry Pi Imager
    @{Name="Raspberry Pi Imager"; TargetPath="C:\Program Files (x86)\Raspberry Pi Imager\rpi-imager.exe"; StartIn="C:\Program Files (x86)\Raspberry Pi Imager"},
    # Discord
    @{Name="Discord"; TargetPath=$Discord_TargetPath; Arguments="--processStart Discord.exe"; SystemLnk="Discord Inc\"; StartIn=$Discord_StartIn; Description="Discord - https://discord.com"},
    # RingCentral
    @{Name="RingCentral"; TargetPath="C:\Users\${aUser}\AppData\Local\Programs\RingCentral\RingCentral.exe"; StartIn="C:\Users\${aUser}\AppData\Local\Programs\RingCentral"; Description="RingCentral"},
    @{Name="RingCentral Meetings"; TargetPath="C:\Users\${aUser}\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe"; SystemLnk="RingCentral Meetings\"; Description="RingCentral Meetings"},
    @{Name="Uninstall RingCentral Meetings"; TargetPath="C:\Users\${aUser}\AppData\Roaming\RingCentralMeetings\uninstall\Installer.exe"; Arguments="/uninstall"; SystemLnk="RingCentral Meetings\"; Description="Uninstall RingCentral Meetings"}
  #  @{Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; RunAsAdmin=($true|$false)}
  )

  for ($j = 0; $j -lt $userAppList.length; $j++) {
    $app = $userAppList[$j]
    $aName = $app.Name
    $aTargetPath = $app.TargetPath
    $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
    $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
    $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
    $aDescription = if ($app.Description) {$app.Description} else {""}
    $aRunAsAdmin = if ($app.RunAsAdmin) {$app.RunAsAdmin} else {$false}

    $Results = Recreate-Shortcut -n $aName -tp $aTargetPath -a $sArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -r $aRunAsAdmin -u $aUser
  }
}