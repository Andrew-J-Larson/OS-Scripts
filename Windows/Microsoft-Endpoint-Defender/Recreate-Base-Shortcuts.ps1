#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1
# Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
# If a program you use isn't in any of the lists here, either fork/edit/push, or create an issue at:
# https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20--%3E%0A%0A

# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

# Application objects are setup like so:
<# @{
       Name="[name of shortcut here]";
       TargetPath="[path to exe/url/folder here]";
       Arguments="[any arguments that an app starts with here]";
       SystemLnk="[path to lnk or name of app here]";
       StartIn="[start in path, if needed, here]";
       Description="[comment, that shows up in tooltip, here]";
       IconLocation="[path to ico|exe|ico w/ index]";
       RunAsAdmin="[true or false, if needed]"
   } #>



Start-Transcript -Path "C:\Recreate-Base-Shortcuts.log"
Write-Host "" # Makes log look better

# Constants

Set-Variable NotInstalled -Option Constant -Value "NOT-INSTALLED"



# Variables

$isWindows11 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 11")
$isWindows10 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 10")
$isWin10orNewer = [System.Environment]::OSVersion.Version.Major -ge 10
$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$UninstallList = foreach ($UninstallKey in $UninstallKeys) {
  Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$' } | Select-Object @{n = 'GUID'; e = { $_.PSChildName } }, @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
}



# Functions

function New-Shortcut {
  param(
    [Parameter(Mandatory = $true)]
    [Alias("name", "n")]
    [string]$sName,

    [Parameter(Mandatory = $true)]
    [Alias("targetpath", "tp")]
    [string]$sTargetPath,

    [Alias("arguments", "a")]
    [string]$sArguments, # Optional (for special shortcuts)

    [Alias("systemlnk", "sl")]
    [string]$sSystemLnk, # Optional (for if name / path is different from normal)

    [Alias("startin", "si")]
    [string]$sStartIn, # Optional (for special shortcuts)

    [Alias("description", "d")]
    [string]$sDescription, # Optional (some shortcuts have comments for tooltips)

    [Alias("iconlocation", "il")]
    [string]$sIconLocation, # Optional (some shortcuts have a custom icon)
    
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

  # validate name and target path
  if ($sName -And $sTargetPath -And (Test-Path $sTargetPath -PathType leaf)) {
    # if shortcut path not given, create one at default location with $sName
    if (-Not ($sSystemLnk)) { $sSystemLnk = $sName }
    # if doesn't have $ProgramShortcutsPath or $UserProgramShortcutsPath (and not start with drive letter), it'll assume a path for it
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^' + [Regex]::Escape($ProgramShortcutsPath) + '.*') -Or $sSystemLnk -match ('^' + [Regex]::Escape($UserProgramShortcutsPath) + '.*'))) {
      $sSystemLnk = $(if ($sUser) { $UserProgramShortcutsPath } else { $ProgramShortcutsPath }) + '\' + $sSystemLnk
    }
    # if it ends with '\', then we append the name to the end
    if ($sSystemLnk.EndsWith('\')) { $sSystemLnk = $sSystemLnk + $sName }
    # if doesn't end with .lnk, add it
    if (-Not ($sSystemLnk -match '.*\.lnk$')) { $sSystemLnk = $sSystemLnk + '.lnk' }

    # only create shortcut if it doesn't already exist
    if (Test-Path $sSystemLnk -PathType leaf) {
      $resultMsg += "A shortcut already exists at:`n${sSystemLnk}"
      $result = $false
    }
    else {
      $WScriptObj = New-Object -ComObject WScript.Shell
      $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)

      $newLNK.TargetPath = $sTargetPath
      if ($sArguments) { $newLNK.Arguments = $sArguments }
      if ($sStartIn) { $newLNK.WorkingDirectory = $sStartIn }
      if ($sDescription) { $newLNK.Description = $sDescription }
      if ($sIconLocation) { $newLNK.IconLocation = $sIconLocation }

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
          if ($result) { $resultMsg += "Shortcut set to Run as Admin, at: ${sSystemLnk}" }
          else { $errorMsg += "Failed to set shortcut to Run as Admin, at: ${sSystemLnk}" }
        }
      }
      else { $errorMsg += "Failed to create shortcut, with target at: ${sTargetPath}" }
    }
  }
  elseif (-Not ($sName -Or $sTargetPath)) {
    if (-Not $sName) {
      $errorMsg += "Error! Name is missing!"
    }
    if (-Not $sTargetPath) {
      $errorMsg += "Error! Target is missing!"
    }

    $result = $false
  }
  else {
    $warnMsg += "Target invalid! Doesn't exist or is spelled wrong:`n${sTargetPath}"

    $result = $false
  }

  if ($result) { Write-Host -ForegroundColor Green $sName }
  else { Write-Host -ForegroundColor Red $sName }

  if ($resultMsg.length -gt 0) {
    for ($msgNum = 0; $msgNum -lt $resultMsg.length; $msgNum++) {
      Write-Host $resultMsg[$msgNum]
    }
  }
  elseif ($errorMsg.length -gt 0) {
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

$ScriptResults = $true

if (-Not $isWin10orNewer) {
  Write-Error "This script is only meant to be ran on Windows 10 and newer!"
  exit 1
}



# System Applications

# App arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# App paths dependant on app version

# Powershell (7 or newer)
$PowerShell_TargetPath = "C:\Program Files\PowerShell\"
$PowerShell_Version = if (Test-Path -Path $PowerShell_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Descending }
$PowerShell_Version = if ($PowerShell_Version.length -ge 1) { $PowerShell_Version[0].name } else { $NotInstalled }
$PowerShell_TargetPath += "${PowerShell_Version}\pwsh.exe"
$PowerShell_32bit_TargetPath = "C:\Program Files (x86)\PowerShell\"
$PowerShell_32bit_Version = if (Test-Path -Path $PowerShell_32bit_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_32bit_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Descending }
$PowerShell_32bit_Version = if ($PowerShell_32bit_Version.length -ge 1) { $PowerShell_32bit_Version[0].name } else { $NotInstalled }
$PowerShell_32bit_TargetPath += "${PowerShell32bit_Version}\pwsh.exe"
# PowerToys
$PowerToys_TargetPath = "C:\Program Files\PowerToys\PowerToys.exe"

# App names dependant on OS or app version

# PowerShell (7 or newer)
$PowerShell_Name = "PowerShell " + $(if ($PowerShell_Version) { $PowerShell_Version } else { $NotInstalled }) + " (x64)"
$PowerShell_32bit_Name = "PowerShell " + $(if ($PowerShell_32bit_Version) { $PowerShell_32bit_Version } else { $NotInstalled }) + " (x86)"
# PowerToys
$PowerToys_isPreview = if (Test-Path -Path $PowerToys_TargetPath -PathType Leaf) { (Get-Item $PowerToys_TargetPath).VersionInfo.FileVersionRaw.Major -eq 0 }
$PowerToys_Name = "PowerToys" + $(if ($PowerToys_isPreview) { " (Preview)" })
# Windows Accessories
$WindowsMediaPlayerOld_Name = "Windows Media Player" + $(if ($isWindows11) { " Legacy" })

$sysAppList = @(
  # Azure
  @{Name = "Azure Data Studio"; TargetPath = "C:\Program Files\Azure Data Studio\azuredatastudio.exe"; SystemLnk = "Azure Data Studio\"; StartIn = "C:\Program Files\Azure Data Studio" },
  # Edge
  @{Name = "Microsoft Edge"; TargetPath = "C:\Program Files\Microsoft\Edge\Application\msedge.exe"; StartIn = "C:\Program Files\Microsoft\Edge\Application"; Description = "Browse the web" }, # it's the only install on 32-bit
  @{Name = "Microsoft Edge"; TargetPath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"; StartIn = "C:\Program Files (x86)\Microsoft\Edge\Application"; Description = "Browse the web" }, # it's the only install on 64-bit
  # Intune Management Extension
  @{Name = "Microsoft Intune Management Extension"; TargetPath = "C:\Program Files\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk = "Microsoft Intune Management Extension\"; Description = "Microsoft Intune Management Extension" }, # it's the only install on 32-bit
  @{Name = "Microsoft Intune Management Extension"; TargetPath = "C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk = "Microsoft Intune Management Extension\"; Description = "Microsoft Intune Management Extension" }, # it's the only install on 64-bit
  # Office
  @{Name = "Access"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE"; Description = "Build a professional app quickly to manage data." },
  @{Name = "Excel"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"; Description = "Easily discover, visualize, and share insights from your data." },
  @{Name = "OneNote"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"; Description = "Take notes and have them when you need them." },
  @{Name = "Outlook"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description = "Manage your email, schedules, contacts, and to-dos." },
  @{Name = "PowerPoint"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"; Description = "Design and deliver beautiful presentations with ease and confidence." },
  @{Name = "Project"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\WINPROJ.EXE"; Description = "Easily collaborate with others to quickly start and deliver winning projects." },
  @{Name = "Publisher"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE"; Description = "Create professional-grade publications that make an impact." },
  @{Name = "Visio"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\VISIO.EXE"; Description = "Create professional and versatile diagrams that simplify complex information." },
  @{Name = "Word"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"; Description = "Create beautiful documents, easily work with others, and enjoy the read." },
  @{Name = "Database Compare"; TargetPath = "C:\Program Files\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Access database." },
  @{Name = "Office Language Preferences"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk = "Microsoft Office Tools\"; Description = "Change the language preferences for Office applications." },
  @{Name = "Spreadsheet Compare"; TargetPath = "C:\Program Files\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Excel workbook." },
  @{Name = "Telemetry Log for Office"; TargetPath = "C:\Program Files\Microsoft Office\root\Office16\msoev.exe"; SystemLnk = "Microsoft Office Tools\"; Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." },
  @{Name = "Access (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\MSACCESS.EXE"; Description = "Build a professional app quickly to manage data." },
  @{Name = "Excel (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\EXCEL.EXE"; Description = "Easily discover, visualize, and share insights from your data." },
  @{Name = "OneNote (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\ONENOTE.EXE"; Description = "Take notes and have them when you need them." },
  @{Name = "Outlook (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description = "Manage your email, schedules, contacts, and to-dos." },
  @{Name = "PowerPoint (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\POWERPNT.EXE"; Description = "Design and deliver beautiful presentations with ease and confidence." },
  @{Name = "Project (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\WINPROJ.EXE"; Description = "Easily collaborate with others to quickly start and deliver winning projects." },
  @{Name = "Publisher (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\MSPUB.EXE"; Description = "Create professional-grade publications that make an impact." },
  @{Name = "Visio (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\VISIO.EXE"; Description = "Create professional and versatile diagrams that simplify complex information." },
  @{Name = "Word (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\WINWORD.EXE"; Description = "Create beautiful documents, easily work with others, and enjoy the read." },
  @{Name = "Database Compare (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Access database." },
  @{Name = "Office Language Preferences (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk = "Microsoft Office Tools\"; Description = "Change the language preferences for Office applications." },
  @{Name = "Spreadsheet Compare (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Excel workbook." },
  @{Name = "Telemetry Log for Office (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft Office\root\Office16\msoev.exe"; SystemLnk = "Microsoft Office Tools\"; Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." },
  # OneDrive
  @{Name = "OneDrive"; TargetPath = "C:\Program Files\Microsoft OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
  @{Name = "OneDrive (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
  # PowerShell (7 or newer)
  @{Name = $PowerShell_Name; TargetPath = $PowerShell_TargetPath; Arguments = "-WorkingDirectory ~"; SystemLnk = "PowerShell\"; Description = $PowerShell_Name },
  @{Name = $PowerShell_32bit_Name; TargetPath = $PowerShell_32bit_TargetPath; Arguments = "-WorkingDirectory ~"; SystemLnk = "PowerShell\"; Description = $PowerShell_32bit_Name },
  # PowerToys
  @{Name = $PowerToys_Name; TargetPath = $PowerToys_TargetPath; SystemLnk = $PowerToys_Name + '\'; StartIn = "C:\Program Files\PowerToys\"; Description = "PowerToys - Windows system utilities to maximize productivity" },
  # Visual Studio
  @{Name = "Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Professional\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\devenv.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Community\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Professional\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "C:\Program Files\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\Blend.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Visual Studio Code"; TargetPath = "C:\Program Files\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "C:\Program Files\Microsoft VS Code" },
  @{Name = "Visual Studio Code (32-bit)"; TargetPath = "C:\Program Files (x86)\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "C:\Program Files\Microsoft VS Code" },
  @{Name = "Visual Studio Installer"; TargetPath = "C:\Program Files\Microsoft Visual Studio\Installer\setup.exe"; StartIn = "C:\Program Files\Microsoft Visual Studio\Installer" }, # it's the only install on 32-bit
  @{Name = "Visual Studio Installer"; TargetPath = "C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe"; StartIn = "C:\Program Files (x86)\Microsoft Visual Studio\Installer" }, # it's the only install on 64-bit
  # Windows Accessories
  @{Name = "Remote Desktop Connection"; TargetPath = "%windir%\system32\mstsc.exe"; SystemLnk = "Accessories\"; StartIn = "%windir%\system32\"; Description = "Use your computer to connect to a computer that is located elsewhere and run programs or access files." },
  @{Name = "Steps Recorder"; TargetPath = "%windir%\system32\psr.exe"; SystemLnk = "Accessories\"; Description = "Capture steps with screenshots to save or share." },
  @{Name = "Windows Fax and Scan"; TargetPath = "%windir%\system32\WFS.exe"; SystemLnk = "Accessories\"; Description = "Send and receive faxes or scan pictures and documents." },
  @{Name = $WindowsMediaPlayerOld_Name; TargetPath = "%ProgramFiles%\Windows Media Player\wmplayer.exe"; Arguments = "/prefetch:1"; SystemLnk = "Accessories\"; StartIn = "%ProgramFiles(x86)%\Windows Media Player" }, # it's the only install on 32-bit
  @{Name = $WindowsMediaPlayerOld_Name; TargetPath = "%ProgramFiles(x86)%\Windows Media Player\wmplayer.exe"; Arguments = "/prefetch:1"; SystemLnk = "Accessories\"; StartIn = "%ProgramFiles(x86)%\Windows Media Player" }, # it's the only install on 64-bit
  @{Name = "WordPad"; TargetPath = "%ProgramFiles%\Windows NT\Accessories\wordpad.exe"; SystemLnk = "Accessories\"; Description = "Creates and edits text documents with complex formatting." },
  @{Name = "Character Map"; TargetPath = "%windir%\system32\charmap.exe"; SystemLnk = "Accessories\System Tools\"; Description = "Selects special characters and copies them to your document." }
  #@{ Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; IconLocation=""; RunAsAdmin=($true -Or $false) },
)

for ($i = 0; $i -lt $sysAppList.length; $i++) {
  $app = $sysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aStartIn = if ($app.StartIn) { $app.StartIn } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $ScriptResults = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -il $aIconLocation -r $aRunAsAdmin
}



# OEM System Applications (e.g. Dell)

# App arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# App paths dependant on app version

## App Name
#$App_TargetPath = ...
#$App_StartIn = ...

# App names dependant on OS or app version

## App Name
#$App_Name = ...

$oemSysAppList = @(
  # Dell
  @{Name = "Dell OS Recovery Tool"; TargetPath = "C:\Program Files\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk = "Dell\"; StartIn = "C:\Program Files\Dell\OS Recovery Tool\" }, # it's the only install on 32-bit
  @{Name = "Dell OS Recovery Tool"; TargetPath = "C:\Program Files (x86)\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk = "Dell\"; StartIn = "C:\Program Files (x86)\Dell\OS Recovery Tool\" }, # it's the only install on 64-bit
  @{Name = "SupportAssist Recovery Assistant"; TargetPath = "C:\Program Files\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk = "Dell\SupportAssist\" },
  @{Name = "SupportAssist Recovery Assistant (32-bit)"; TargetPath = "C:\Program Files (x86)\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk = "Dell\SupportAssist\" },
  # NVIDIA Corporation
  @{Name = "GeForce Experience"; TargetPath = "C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"; SystemLnk = "NVIDIA Corporation\"; StartIn = "C:\Program Files\NVIDIA Corporation\NVIDIA GeForce Experience" }
  #@{ Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; IconLocation=""; RunAsAdmin=($true -Or $false) },
)

for ($i = 0; $i -lt $oemSysAppList.length; $i++) {
  $app = $oemSysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aStartIn = if ($app.StartIn) { $app.StartIn } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $ScriptResults = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -il $aIconLocation -r $aRunAsAdmin
}



# Third-Party System Applications (not made by Microsoft)

# App arguments dependant on uninstall strings

# Egnyte Desktop App
$EgnyteDesktopAppUninstallGUID = $UninstallList | Where-Object { $_.Name -match "Egnyte Desktop App" }
$EgnyteDesktopAppUninstallGUID = if ($EgnyteDesktopAppUninstallGUID.length -ge 1) { $EgnyteDesktopAppUninstallGUID[0].GUID } else { $null }
$EgnyteDesktopAppUninstall_Arguments = if ($EgnyteDesktopAppUninstallGUID) { "/x ${EgnyteDesktopAppUninstallGUID}" } else { "" }
$EgnyteDesktopAppUninstall_TargetPath = if ($EgnyteDesktopAppUninstallGUID) { "C:\Windows\System32\msiexec.exe" } else { "C:\${NotInstalled}\${NotInstalled}\${NotInstalled}.exe" }

# App paths dependant on app version

# Adobe Aero
$Aero_TargetPath = "C:\Program Files\Adobe\"
$Aero_Name = if (Test-Path -Path $Aero_TargetPath) { Get-ChildItem -Directory -Path $Aero_TargetPath | Where-Object { $_.Name -match '^.*Aero(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Aero_Name = if ($Aero_Name.length -ge 1) { $Aero_Name[0].name } else { "Adobe Aero" }
$Aero_StartIn = $Aero_TargetPath + $Aero_Name
$Aero_StartInAlt = $Aero_StartIn + "\Support Files"
$Aero_StartInAlt2 = $Aero_StartInAlt + "\Contents\Windows"
$Aero_TargetPath = $Aero_StartIn + "\Aero.exe"
$Aero_TargetPathAlt = $Aero_StartInAlt + "\Aero.exe"
$Aero_TargetPathAlt2 = $Aero_StartInAlt2 + "\Aero.exe"
$Aero_TargetPath = if (Test-Path -Path $Aero_TargetPath -PathType leaf) { $Aero_TargetPath } elseif (Test-Path -Path $Aero_TargetPathAlt -PathType leaf) { $Aero_TargetPathAlt } else { $Aero_TargetPathAlt2 }
$Aero_Beta_TargetPath = "C:\Program Files\Adobe\"
$Aero_Beta_Name = if (Test-Path -Path $Aero_Beta_TargetPath) { Get-ChildItem -Directory -Path $Aero_Beta_TargetPath | Where-Object { $_.Name -match '^.*Aero.*\(Beta\)$' } | Sort-Object -Descending }
$Aero_Beta_Name = if ($Aero_Beta_Name.length -ge 1) { $Aero_Beta_Name[0].name } else { "Adobe Aero (Beta)" }
$Aero_Beta_StartIn = $Aero_Beta_TargetPath + $Aero_Beta_Name
$Aero_Beta_StartInAlt = $Aero_Beta_StartIn + "\Support Files"
$Aero_Beta_StartInAlt2 = $Aero_Beta_StartInAlt + "\Contents\Windows"
$Aero_Beta_TargetPathExeAlt = $Aero_Beta_StartIn + "\Aero.exe"
$Aero_Beta_TargetPathAltExeAlt = $Aero_Beta_StartInAlt + "\Aero.exe"
$Aero_Beta_TargetPathAlt2ExeAlt = $Aero_Beta_StartInAlt2 + "\Aero.exe"
$Aero_Beta_TargetPath = $Aero_Beta_StartIn + "\Aero (Beta).exe"
$Aero_Beta_TargetPathAlt = $Aero_Beta_StartInAlt + "\Aero (Beta).exe"
$Aero_Beta_TargetPathAlt2 = $Aero_Beta_StartInAlt2 + "\Aero (Beta).exe"
$Aero_Beta_TargetPath = if (Test-Path -Path $Aero_Beta_TargetPathExeAlt -PathType leaf) { $Aero_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Aero_Beta_TargetPathAltExeAlt -PathType leaf) { $Aero_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Aero_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Aero_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Aero_Beta_TargetPath -PathType leaf) { $Aero_Beta_TargetPath } elseif (Test-Path -Path $Aero_Beta_TargetPathAlt -PathType leaf) { $Aero_Beta_TargetPathAlt } else { $Aero_Beta_TargetPathAlt2 }
# Adobe After Effects
$AfterEffects_TargetPath = "C:\Program Files\Adobe\"
$AfterEffects_Name = if (Test-Path -Path $AfterEffects_TargetPath) { Get-ChildItem -Directory -Path $AfterEffects_TargetPath | Where-Object { $_.Name -match '^.*After Effects(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$AfterEffects_Name = if ($AfterEffects_Name.length -ge 1) { $AfterEffects_Name[0].name } else { "Adobe After Effects" }
$AfterEffects_StartIn = $AfterEffects_TargetPath + $AfterEffects_Name
$AfterEffects_StartInAlt = $AfterEffects_StartIn + "\Support Files"
$AfterEffects_StartInAlt2 = $AfterEffects_StartInAlt + "\Contents\Windows"
$AfterEffects_TargetPath = $AfterEffects_StartIn + "\AfterFX.exe"
$AfterEffects_TargetPathAlt = $AfterEffects_StartInAlt + "\AfterFX.exe"
$AfterEffects_TargetPathAlt2 = $AfterEffects_StartInAlt2 + "\AfterFX.exe"
$AfterEffects_TargetPath = if (Test-Path -Path $AfterEffects_TargetPath -PathType leaf) { $AfterEffects_TargetPath } elseif (Test-Path -Path $AfterEffects_TargetPathAlt -PathType leaf) { $AfterEffects_TargetPathAlt } else { $AfterEffects_TargetPathAlt2 }
$AfterEffects_Beta_TargetPath = "C:\Program Files\Adobe\"
$AfterEffects_Beta_Name = if (Test-Path -Path $AfterEffects_Beta_TargetPath) { Get-ChildItem -Directory -Path $AfterEffects_Beta_TargetPath | Where-Object { $_.Name -match '^.*After Effects.*\(Beta\)$' } | Sort-Object -Descending }
$AfterEffects_Beta_Name = if ($AfterEffects_Beta_Name.length -ge 1) { $AfterEffects_Beta_Name[0].name } else { "Adobe After Effects (Beta)" }
$AfterEffects_Beta_StartIn = $AfterEffects_Beta_TargetPath + $AfterEffects_Beta_Name
$AfterEffects_Beta_StartInAlt = $AfterEffects_Beta_StartIn + "\Support Files"
$AfterEffects_Beta_StartInAlt2 = $AfterEffects_Beta_StartInAlt + "\Contents\Windows"
$AfterEffects_Beta_TargetPathExeAlt = $AfterEffects_Beta_StartIn + "\AfterFX.exe"
$AfterEffects_Beta_TargetPathAltExeAlt = $AfterEffects_Beta_StartInAlt + "\AfterFX.exe"
$AfterEffects_Beta_TargetPathAlt2ExeAlt = $AfterEffects_Beta_StartInAlt2 + "\AfterFX.exe"
$AfterEffects_Beta_TargetPath = $AfterEffects_Beta_StartIn + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPathAlt = $AfterEffects_Beta_StartInAlt + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPathAlt2 = $AfterEffects_Beta_StartInAlt2 + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPath = if (Test-Path -Path $AfterEffects_Beta_TargetPathExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathExeAlt } elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAltExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $AfterEffects_Beta_TargetPath -PathType leaf) { $AfterEffects_Beta_TargetPath } elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAlt } else { $AfterEffects_Beta_TargetPathAlt2 }
# Adobe Animate
$Animate_TargetPath = "C:\Program Files\Adobe\"
$Animate_Name = if (Test-Path -Path $Animate_TargetPath) { Get-ChildItem -Directory -Path $Animate_TargetPath | Where-Object { $_.Name -match '^.*Animate(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Animate_Name = if ($Animate_Name.length -ge 1) { $Animate_Name[0].name } else { "Adobe Animate" }
$Animate_StartIn = $Animate_TargetPath + $Animate_Name
$Animate_StartInAlt = $Animate_StartIn + "\Support Files"
$Animate_StartInAlt2 = $Animate_StartInAlt + "\Contents\Windows"
$Animate_TargetPath = $Animate_StartIn + "\Animate.exe"
$Animate_TargetPathAlt = $Animate_StartInAlt + "\Animate.exe"
$Animate_TargetPathAlt2 = $Animate_StartInAlt2 + "\Animate.exe"
$Animate_TargetPath = if (Test-Path -Path $Animate_TargetPath -PathType leaf) { $Animate_TargetPath } elseif (Test-Path -Path $Animate_TargetPathAlt -PathType leaf) { $Animate_TargetPathAlt } else { $Animate_TargetPathAlt2 }
$Animate_Beta_TargetPath = "C:\Program Files\Adobe\"
$Animate_Beta_Name = if (Test-Path -Path $Animate_Beta_TargetPath) { Get-ChildItem -Directory -Path $Animate_Beta_TargetPath | Where-Object { $_.Name -match '^.*Animate.*\(Beta\)$' } | Sort-Object -Descending }
$Animate_Beta_Name = if ($Animate_Beta_Name.length -ge 1) { $Animate_Beta_Name[0].name } else { "Adobe Animate (Beta)" }
$Animate_Beta_StartIn = $Animate_Beta_TargetPath + $Animate_Beta_Name
$Animate_Beta_StartInAlt = $Animate_Beta_StartIn + "\Support Files"
$Animate_Beta_StartInAlt2 = $Animate_Beta_StartInAlt + "\Contents\Windows"
$Animate_Beta_TargetPathExeAlt = $Animate_Beta_StartIn + "\Animate.exe"
$Animate_Beta_TargetPathAltExeAlt = $Animate_Beta_StartInAlt + "\Animate.exe"
$Animate_Beta_TargetPathAlt2ExeAlt = $Animate_Beta_StartInAlt2 + "\Animate.exe"
$Animate_Beta_TargetPath = $Animate_Beta_StartIn + "\Animate (Beta).exe"
$Animate_Beta_TargetPathAlt = $Animate_Beta_StartInAlt + "\Animate (Beta).exe"
$Animate_Beta_TargetPathAlt2 = $Animate_Beta_StartInAlt2 + "\Animate (Beta).exe"
$Animate_Beta_TargetPath = if (Test-Path -Path $Animate_Beta_TargetPathExeAlt -PathType leaf) { $Animate_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Animate_Beta_TargetPathAltExeAlt -PathType leaf) { $Animate_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Animate_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Animate_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Animate_Beta_TargetPath -PathType leaf) { $Animate_Beta_TargetPath } elseif (Test-Path -Path $Animate_Beta_TargetPathAlt -PathType leaf) { $Animate_Beta_TargetPathAlt } else { $Animate_Beta_TargetPathAlt2 }
# Adobe Audition
$Audition_TargetPath = "C:\Program Files\Adobe\"
$Audition_Name = if (Test-Path -Path $Audition_TargetPath) { Get-ChildItem -Directory -Path $Audition_TargetPath | Where-Object { $_.Name -match '^.*Audition(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Audition_Name = if ($Audition_Name.length -ge 1) { $Audition_Name[0].name } else { "Adobe Audition" }
$Audition_StartIn = $Audition_TargetPath + $Audition_Name
$Audition_StartInAlt = $Audition_StartIn + "\Support Files"
$Audition_StartInAlt2 = $Audition_StartInAlt + "\Contents\Windows"
$Audition_TargetPath = $Audition_StartIn + "\Adobe Audition.exe"
$Audition_TargetPathAlt = $Audition_StartInAlt + "\Adobe Audition.exe"
$Audition_TargetPathAlt2 = $Audition_StartInAlt2 + "\Adobe Audition.exe"
$Audition_TargetPath = if (Test-Path -Path $Audition_TargetPath -PathType leaf) { $Audition_TargetPath } elseif (Test-Path -Path $Audition_TargetPathAlt -PathType leaf) { $Audition_TargetPathAlt } else { $Audition_TargetPathAlt2 }
$Audition_Beta_TargetPath = "C:\Program Files\Adobe\"
$Audition_Beta_Name = if (Test-Path -Path $Audition_Beta_TargetPath) { Get-ChildItem -Directory -Path $Audition_Beta_TargetPath | Where-Object { $_.Name -match '^.*Audition.*\(Beta\)$' } | Sort-Object -Descending }
$Audition_Beta_Name = if ($Audition_Beta_Name.length -ge 1) { $Audition_Beta_Name[0].name } else { "Adobe Audition (Beta)" }
$Audition_Beta_StartIn = $Audition_Beta_TargetPath + $Audition_Beta_Name
$Audition_Beta_StartInAlt = $Audition_Beta_StartIn + "\Support Files"
$Audition_Beta_StartInAlt2 = $Audition_Beta_StartInAlt + "\Contents\Windows"
$Audition_Beta_TargetPathExeAlt = $Audition_Beta_StartIn + "\Adobe Audition.exe"
$Audition_Beta_TargetPathAltExeAlt = $Audition_Beta_StartInAlt + "\Adobe Audition.exe"
$Audition_Beta_TargetPathAlt2ExeAlt = $Audition_Beta_StartInAlt2 + "\Adobe Audition.exe"
$Audition_Beta_TargetPath = $Audition_Beta_StartIn + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPathAlt = $Audition_Beta_StartInAlt + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPathAlt2 = $Audition_Beta_StartInAlt2 + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPath = if (Test-Path -Path $Audition_Beta_TargetPathExeAlt -PathType leaf) { $Audition_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Audition_Beta_TargetPathAltExeAlt -PathType leaf) { $Audition_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Audition_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Audition_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Audition_Beta_TargetPath -PathType leaf) { $Audition_Beta_TargetPath } elseif (Test-Path -Path $Audition_Beta_TargetPathAlt -PathType leaf) { $Audition_Beta_TargetPathAlt } else { $Audition_Beta_TargetPathAlt2 }
# Adobe Bridge
$Bridge_TargetPath = "C:\Program Files\Adobe\"
$Bridge_Name = if (Test-Path -Path $Bridge_TargetPath) { Get-ChildItem -Directory -Path $Bridge_TargetPath | Where-Object { $_.Name -match '^.*Bridge(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Bridge_Name = if ($Bridge_Name.length -ge 1) { $Bridge_Name[0].name } else { "Adobe Bridge" }
$Bridge_StartIn = $Bridge_TargetPath + $Bridge_Name
$Bridge_StartInAlt = $Bridge_StartIn + "\Support Files"
$Bridge_StartInAlt2 = $Bridge_StartInAlt + "\Contents\Windows"
$Bridge_TargetPath = $Bridge_StartIn + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt = $Bridge_StartInAlt + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt2 = $Bridge_StartInAlt2 + "\Adobe Bridge.exe"
$Bridge_TargetPath = if (Test-Path -Path $Bridge_TargetPath -PathType leaf) { $Bridge_TargetPath } elseif (Test-Path -Path $Bridge_TargetPathAlt -PathType leaf) { $Bridge_TargetPathAlt } else { $Bridge_TargetPathAlt2 }
$Bridge_Beta_TargetPath = "C:\Program Files\Adobe\"
$Bridge_Beta_Name = if (Test-Path -Path $Bridge_Beta_TargetPath) { Get-ChildItem -Directory -Path $Bridge_Beta_TargetPath | Where-Object { $_.Name -match '^.*Bridge.*\(Beta\)$' } | Sort-Object -Descending }
$Bridge_Beta_Name = if ($Bridge_Beta_Name.length -ge 1) { $Bridge_Beta_Name[0].name } else { "Adobe Bridge (Beta)" }
$Bridge_Beta_StartIn = $Bridge_Beta_TargetPath + $Bridge_Beta_Name
$Bridge_Beta_StartInAlt = $Bridge_Beta_StartIn + "\Support Files"
$Bridge_Beta_StartInAlt2 = $Bridge_Beta_StartInAlt + "\Contents\Windows"
$Bridge_Beta_TargetPathExeAlt = $Bridge_Beta_StartIn + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPathAltExeAlt = $Bridge_Beta_StartInAlt + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPathAlt2ExeAlt = $Bridge_Beta_StartInAlt2 + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPath = $Bridge_Beta_StartIn + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPathAlt = $Bridge_Beta_StartInAlt + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPathAlt2 = $Bridge_Beta_StartInAlt2 + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPath = if (Test-Path -Path $Bridge_Beta_TargetPathExeAlt -PathType leaf) { $Bridge_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Bridge_Beta_TargetPathAltExeAlt -PathType leaf) { $Bridge_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Bridge_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Bridge_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Bridge_Beta_TargetPath -PathType leaf) { $Bridge_Beta_TargetPath } elseif (Test-Path -Path $Bridge_Beta_TargetPathAlt -PathType leaf) { $Bridge_Beta_TargetPathAlt } else { $Bridge_Beta_TargetPathAlt2 }
# Adobe Character Animator
$CharacterAnimator_TargetPath = "C:\Program Files\Adobe\"
$CharacterAnimator_Name = if (Test-Path -Path $CharacterAnimator_TargetPath) { Get-ChildItem -Directory -Path $CharacterAnimator_TargetPath | Where-Object { $_.Name -match '^.*Character Animator(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$CharacterAnimator_Name = if ($CharacterAnimator_Name.length -ge 1) { $CharacterAnimator_Name[0].name } else { "Adobe Character Animator" }
$CharacterAnimator_StartIn = $CharacterAnimator_TargetPath + $CharacterAnimator_Name
$CharacterAnimator_StartInAlt = $CharacterAnimator_StartIn + "\Support Files"
$CharacterAnimator_StartInAlt2 = $CharacterAnimator_StartInAlt + "\Contents\Windows"
$CharacterAnimator_TargetPath = $CharacterAnimator_StartIn + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt = $CharacterAnimator_StartInAlt + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt2 = $CharacterAnimator_StartInAlt2 + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPath = if (Test-Path -Path $CharacterAnimator_TargetPath -PathType leaf) { $CharacterAnimator_TargetPath } elseif (Test-Path -Path $CharacterAnimator_TargetPathAlt -PathType leaf) { $CharacterAnimator_TargetPathAlt } else { $CharacterAnimator_TargetPathAlt2 }
$CharacterAnimator_Beta_TargetPath = "C:\Program Files\Adobe\"
$CharacterAnimator_Beta_Name = if (Test-Path -Path $CharacterAnimator_Beta_TargetPath) { Get-ChildItem -Directory -Path $CharacterAnimator_Beta_TargetPath | Where-Object { $_.Name -match '^.*Character Animator.*\(Beta\)$' } | Sort-Object -Descending }
$CharacterAnimator_Beta_Name = if ($CharacterAnimator_Beta_Name.length -ge 1) { $CharacterAnimator_Beta_Name[0].name } else { "Adobe Character Animator (Beta)" }
$CharacterAnimator_Beta_StartIn = $CharacterAnimator_Beta_TargetPath + $CharacterAnimator_Beta_Name
$CharacterAnimator_Beta_StartInAlt = $CharacterAnimator_Beta_StartIn + "\Support Files"
$CharacterAnimator_Beta_StartInAlt2 = $CharacterAnimator_Beta_StartInAlt + "\Contents\Windows"
$CharacterAnimator_Beta_TargetPathExeAlt = $CharacterAnimator_Beta_StartIn + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPathAltExeAlt = $CharacterAnimator_Beta_StartInAlt + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPathAlt2ExeAlt = $CharacterAnimator_Beta_StartInAlt2 + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPath = $CharacterAnimator_Beta_StartIn + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPathAlt = $CharacterAnimator_Beta_StartInAlt + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPathAlt2 = $CharacterAnimator_Beta_StartInAlt2 + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPath = if (Test-Path -Path $CharacterAnimator_Beta_TargetPathExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathExeAlt } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAltExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPath -PathType leaf) { $CharacterAnimator_Beta_TargetPath } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAlt } else { $CharacterAnimator_Beta_TargetPathAlt2 }
# Adobe Dimension
$Dimension_TargetPath = "C:\Program Files\Adobe\"
$Dimension_Name = if (Test-Path -Path $Dimension_TargetPath) { Get-ChildItem -Directory -Path $Dimension_TargetPath | Where-Object { $_.Name -match '^.*Dimension(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Dimension_Name = if ($Dimension_Name.length -ge 1) { $Dimension_Name[0].name } else { "Dimension" }
$Dimension_StartIn = $Dimension_TargetPath + $Dimension_Name
$Dimension_StartInAlt = $Dimension_StartIn + "\Support Files"
$Dimension_StartInAlt2 = $Dimension_StartInAlt + "\Contents\Windows"
$Dimension_TargetPath = $Dimension_StartIn + "\Dimension.exe"
$Dimension_TargetPathAlt = $Dimension_StartInAlt + "\Dimension.exe"
$Dimension_TargetPathAlt2 = $Dimension_StartInAlt2 + "\Dimension.exe"
$Dimension_TargetPath = if (Test-Path -Path $Dimension_TargetPath -PathType leaf) { $Dimension_TargetPath } elseif (Test-Path -Path $Dimension_TargetPathAlt -PathType leaf) { $Dimension_TargetPathAlt } else { $Dimension_TargetPathAlt2 }
$Dimension_Beta_TargetPath = "C:\Program Files\Adobe\"
$Dimension_Beta_Name = if (Test-Path -Path $Dimension_Beta_TargetPath) { Get-ChildItem -Directory -Path $Dimension_Beta_TargetPath | Where-Object { $_.Name -match '^.*Dimension.*\(Beta\)$' } | Sort-Object -Descending }
$Dimension_Beta_Name = if ($Dimension_Beta_Name.length -ge 1) { $Dimension_Beta_Name[0].name } else { "Dimension (Beta)" }
$Dimension_Beta_StartIn = $Dimension_Beta_TargetPath + $Dimension_Beta_Name
$Dimension_Beta_StartInAlt = $Dimension_Beta_StartIn + "\Support Files"
$Dimension_Beta_StartInAlt2 = $Dimension_Beta_StartInAlt + "\Contents\Windows"
$Dimension_Beta_TargetPathExeAlt = $Dimension_Beta_StartIn + "\Dimension.exe"
$Dimension_Beta_TargetPathAltExeAlt = $Dimension_Beta_StartInAlt + "\Dimension.exe"
$Dimension_Beta_TargetPathAlt2ExeAlt = $Dimension_Beta_StartInAlt2 + "\Dimension.exe"
$Dimension_Beta_TargetPath = $Dimension_Beta_StartIn + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPathAlt = $Dimension_Beta_StartInAlt + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPathAlt2 = $Dimension_Beta_StartInAlt2 + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPath = if (Test-Path -Path $Dimension_Beta_TargetPathExeAlt -PathType leaf) { $Dimension_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Dimension_Beta_TargetPathAltExeAlt -PathType leaf) { $Dimension_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Dimension_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Dimension_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Dimension_Beta_TargetPath -PathType leaf) { $Dimension_Beta_TargetPath } elseif (Test-Path -Path $Dimension_Beta_TargetPathAlt -PathType leaf) { $Dimension_Beta_TargetPathAlt } else { $Dimension_Beta_TargetPathAlt2 }
# Adobe Dreamweaver
$Dreamweaver_TargetPath = "C:\Program Files\Adobe\"
$Dreamweaver_Name = if (Test-Path -Path $Dreamweaver_TargetPath) { Get-ChildItem -Directory -Path $Dreamweaver_TargetPath | Where-Object { $_.Name -match '^.*Dreamweaver(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Dreamweaver_Name = if ($Dreamweaver_Name.length -ge 1) { $Dreamweaver_Name[0].name } else { "Adobe Dreamweaver" }
$Dreamweaver_StartIn = $Dreamweaver_TargetPath + $Dreamweaver_Name
$Dreamweaver_StartInAlt = $Dreamweaver_StartIn + "\Support Files"
$Dreamweaver_StartInAlt2 = $Dreamweaver_StartInAlt + "\Contents\Windows"
$Dreamweaver_TargetPath = $Dreamweaver_StartIn + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt = $Dreamweaver_StartInAlt + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt2 = $Dreamweaver_StartInAlt2 + "\Dreamweaver.exe"
$Dreamweaver_TargetPath = if (Test-Path -Path $Dreamweaver_TargetPath -PathType leaf) { $Dreamweaver_TargetPath } elseif (Test-Path -Path $Dreamweaver_TargetPathAlt -PathType leaf) { $Dreamweaver_TargetPathAlt } else { $Dreamweaver_TargetPathAlt2 }
$Dreamweaver_Beta_TargetPath = "C:\Program Files\Adobe\"
$Dreamweaver_Beta_Name = if (Test-Path -Path $Dreamweaver_Beta_TargetPath) { Get-ChildItem -Directory -Path $Dreamweaver_Beta_TargetPath | Where-Object { $_.Name -match '^.*Dreamweaver.*\(Beta\)$' } | Sort-Object -Descending }
$Dreamweaver_Beta_Name = if ($Dreamweaver_Beta_Name.length -ge 1) { $Dreamweaver_Beta_Name[0].name } else { "Adobe Dreamweaver (Beta)" }
$Dreamweaver_Beta_StartIn = $Dreamweaver_Beta_TargetPath + $Dreamweaver_Beta_Name
$Dreamweaver_Beta_StartInAlt = $Dreamweaver_Beta_StartIn + "\Support Files"
$Dreamweaver_Beta_StartInAlt2 = $Dreamweaver_Beta_StartInAlt + "\Contents\Windows"
$Dreamweaver_Beta_TargetPathExeAlt = $Dreamweaver_Beta_StartIn + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPathAltExeAlt = $Dreamweaver_Beta_StartInAlt + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPathAlt2ExeAlt = $Dreamweaver_Beta_StartInAlt2 + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPath = $Dreamweaver_Beta_StartIn + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPathAlt = $Dreamweaver_Beta_StartInAlt + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPathAlt2 = $Dreamweaver_Beta_StartInAlt2 + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPath = if (Test-Path -Path $Dreamweaver_Beta_TargetPathExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAltExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPath -PathType leaf) { $Dreamweaver_Beta_TargetPath } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAlt } else { $Dreamweaver_Beta_TargetPathAlt2 }
# Adobe Illustrator
$Illustrator_TargetPath = "C:\Program Files\Adobe\"
$Illustrator_Name = if (Test-Path -Path $Illustrator_TargetPath) { Get-ChildItem -Directory -Path $Illustrator_TargetPath | Where-Object { $_.Name -match '^.*Illustrator(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Illustrator_Name = if ($Illustrator_Name.length -ge 1) { $Illustrator_Name[0].name } else { "Adobe Illustrator" }
$Illustrator_StartIn = $Illustrator_TargetPath + $Illustrator_Name
$Illustrator_StartInAlt = $Illustrator_StartIn + "\Support Files"
$Illustrator_StartInAlt2 = $Illustrator_StartInAlt + "\Contents\Windows"
$Illustrator_TargetPath = $Illustrator_StartIn + "\Illustrator.exe"
$Illustrator_TargetPathAlt = $Illustrator_StartInAlt + "\Illustrator.exe"
$Illustrator_TargetPathAlt2 = $Illustrator_StartInAlt2 + "\Illustrator.exe"
$Illustrator_TargetPath = if (Test-Path -Path $Illustrator_TargetPath -PathType leaf) { $Illustrator_TargetPath } elseif (Test-Path -Path $Illustrator_TargetPathAlt -PathType leaf) { $Illustrator_TargetPathAlt } else { $Illustrator_TargetPathAlt2 }
$Illustrator_Beta_TargetPath = "C:\Program Files\Adobe\"
$Illustrator_Beta_Name = if (Test-Path -Path $Illustrator_Beta_TargetPath) { Get-ChildItem -Directory -Path $Illustrator_Beta_TargetPath | Where-Object { $_.Name -match '^.*Illustrator.*\(Beta\)$' } | Sort-Object -Descending }
$Illustrator_Beta_Name = if ($Illustrator_Beta_Name.length -ge 1) { $Illustrator_Beta_Name[0].name } else { "Adobe Illustrator (Beta)" }
$Illustrator_Beta_StartIn = $Illustrator_Beta_TargetPath + $Illustrator_Beta_Name
$Illustrator_Beta_StartInAlt = $Illustrator_Beta_StartIn + "\Support Files"
$Illustrator_Beta_StartInAlt2 = $Illustrator_Beta_StartInAlt + "\Contents\Windows"
$Illustrator_Beta_TargetPathExeAlt = $Illustrator_Beta_StartIn + "\Illustrator.exe"
$Illustrator_Beta_TargetPathAltExeAlt = $Illustrator_Beta_StartInAlt + "\Illustrator.exe"
$Illustrator_Beta_TargetPathAlt2ExeAlt = $Illustrator_Beta_StartInAlt2 + "\Illustrator.exe"
$Illustrator_Beta_TargetPath = $Illustrator_Beta_StartIn + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPathAlt = $Illustrator_Beta_StartInAlt + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPathAlt2 = $Illustrator_Beta_StartInAlt2 + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPath = if (Test-Path -Path $Illustrator_Beta_TargetPathExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Illustrator_Beta_TargetPathAltExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Illustrator_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Illustrator_Beta_TargetPath -PathType leaf) { $Illustrator_Beta_TargetPath } elseif (Test-Path -Path $Illustrator_Beta_TargetPathAlt -PathType leaf) { $Illustrator_Beta_TargetPathAlt } else { $Illustrator_Beta_TargetPathAlt2 }
# Adobe InCopy
$InCopy_TargetPath = "C:\Program Files\Adobe\"
$InCopy_Name = if (Test-Path -Path $InCopy_TargetPath) { Get-ChildItem -Directory -Path $InCopy_TargetPath | Where-Object { $_.Name -match '^.*InCopy(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$InCopy_Name = if ($InCopy_Name.length -ge 1) { $InCopy_Name[0].name } else { "Adobe InCopy" }
$InCopy_StartIn = $InCopy_TargetPath + $InCopy_Name
$InCopy_StartInAlt = $InCopy_StartIn + "\Support Files"
$InCopy_StartInAlt2 = $InCopy_StartInAlt + "\Contents\Windows"
$InCopy_TargetPath = $InCopy_StartIn + "\InCopy.exe"
$InCopy_TargetPathAlt = $InCopy_StartInAlt + "\InCopy.exe"
$InCopy_TargetPathAlt2 = $InCopy_StartInAlt2 + "\InCopy.exe"
$InCopy_TargetPath = if (Test-Path -Path $InCopy_TargetPath -PathType leaf) { $InCopy_TargetPath } elseif (Test-Path -Path $InCopy_TargetPathAlt -PathType leaf) { $InCopy_TargetPathAlt } else { $InCopy_TargetPathAlt2 }
$InCopy_Beta_TargetPath = "C:\Program Files\Adobe\"
$InCopy_Beta_Name = if (Test-Path -Path $InCopy_Beta_TargetPath) { Get-ChildItem -Directory -Path $InCopy_Beta_TargetPath | Where-Object { $_.Name -match '^.*InCopy.*\(Beta\)$' } | Sort-Object -Descending }
$InCopy_Beta_Name = if ($InCopy_Beta_Name.length -ge 1) { $InCopy_Beta_Name[0].name } else { "Adobe InCopy (Beta)" }
$InCopy_Beta_StartIn = $InCopy_Beta_TargetPath + $InCopy_Beta_Name
$InCopy_Beta_StartInAlt = $InCopy_Beta_StartIn + "\Support Files"
$InCopy_Beta_StartInAlt2 = $InCopy_Beta_StartInAlt + "\Contents\Windows"
$InCopy_Beta_TargetPathExeAlt = $InCopy_Beta_StartIn + "\InCopy.exe"
$InCopy_Beta_TargetPathAltExeAlt = $InCopy_Beta_StartInAlt + "\InCopy.exe"
$InCopy_Beta_TargetPathAlt2ExeAlt = $InCopy_Beta_StartInAlt2 + "\InCopy.exe"
$InCopy_Beta_TargetPath = $InCopy_Beta_StartIn + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPathAlt = $InCopy_Beta_StartInAlt + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPathAlt2 = $InCopy_Beta_StartInAlt2 + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPath = if (Test-Path -Path $InCopy_Beta_TargetPathExeAlt -PathType leaf) { $InCopy_Beta_TargetPathExeAlt } elseif (Test-Path -Path $InCopy_Beta_TargetPathAltExeAlt -PathType leaf) { $InCopy_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $InCopy_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $InCopy_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $InCopy_Beta_TargetPath -PathType leaf) { $InCopy_Beta_TargetPath } elseif (Test-Path -Path $InCopy_Beta_TargetPathAlt -PathType leaf) { $InCopy_Beta_TargetPathAlt } else { $InCopy_Beta_TargetPathAlt2 }
# Adobe InDesign
$InDesign_TargetPath = "C:\Program Files\Adobe\"
$InDesign_Name = if (Test-Path -Path $InDesign_TargetPath) { Get-ChildItem -Directory -Path $InDesign_TargetPath | Where-Object { $_.Name -match '^.*InDesign(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$InDesign_Name = if ($InDesign_Name.length -ge 1) { $InDesign_Name[0].name } else { "Adobe InDesign" }
$InDesign_StartIn = $InDesign_TargetPath + $InDesign_Name
$InDesign_StartInAlt = $InDesign_StartIn + "\Support Files"
$InDesign_StartInAlt2 = $InDesign_StartInAlt + "\Contents\Windows"
$InDesign_TargetPath = $InDesign_StartIn + "\InDesign.exe"
$InDesign_TargetPathAlt = $InDesign_StartInAlt + "\InDesign.exe"
$InDesign_TargetPathAlt2 = $InDesign_StartInAlt2 + "\InDesign.exe"
$InDesign_TargetPath = if (Test-Path -Path $InDesign_TargetPath -PathType leaf) { $InDesign_TargetPath } elseif (Test-Path -Path $InDesign_TargetPathAlt -PathType leaf) { $InDesign_TargetPathAlt } else { $InDesign_TargetPathAlt2 }
$InDesign_Beta_TargetPath = "C:\Program Files\Adobe\"
$InDesign_Beta_Name = if (Test-Path -Path $InDesign_Beta_TargetPath) { Get-ChildItem -Directory -Path $InDesign_Beta_TargetPath | Where-Object { $_.Name -match '^.*InDesign.*\(Beta\)$' } | Sort-Object -Descending }
$InDesign_Beta_Name = if ($InDesign_Beta_Name.length -ge 1) { $InDesign_Beta_Name[0].name } else { "Adobe InDesign (Beta)" }
$InDesign_Beta_StartIn = $InDesign_Beta_TargetPath + $InDesign_Beta_Name
$InDesign_Beta_StartInAlt = $InDesign_Beta_StartIn + "\Support Files"
$InDesign_Beta_StartInAlt2 = $InDesign_Beta_StartInAlt + "\Contents\Windows"
$InDesign_Beta_TargetPathExeAlt = $InDesign_Beta_StartIn + "\InDesign.exe"
$InDesign_Beta_TargetPathAltExeAlt = $InDesign_Beta_StartInAlt + "\InDesign.exe"
$InDesign_Beta_TargetPathAlt2ExeAlt = $InDesign_Beta_StartInAlt2 + "\InDesign.exe"
$InDesign_Beta_TargetPath = $InDesign_Beta_StartIn + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPathAlt = $InDesign_Beta_StartInAlt + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPathAlt2 = $InDesign_Beta_StartInAlt2 + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPath = if (Test-Path -Path $InDesign_Beta_TargetPathExeAlt -PathType leaf) { $InDesign_Beta_TargetPathExeAlt } elseif (Test-Path -Path $InDesign_Beta_TargetPathAltExeAlt -PathType leaf) { $InDesign_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $InDesign_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $InDesign_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $InDesign_Beta_TargetPath -PathType leaf) { $InDesign_Beta_TargetPath } elseif (Test-Path -Path $InDesign_Beta_TargetPathAlt -PathType leaf) { $InDesign_Beta_TargetPathAlt } else { $InDesign_Beta_TargetPathAlt2 }
# Adobe Lightroom
$Lightroom_TargetPath = "C:\Program Files\Adobe\"
$Lightroom_Name = if (Test-Path -Path $Lightroom_TargetPath) { Get-ChildItem -Directory -Path $Lightroom_TargetPath | Where-Object { $_.Name -match '^.*Lightroom(?!.*Classic)(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Lightroom_Name = if ($Lightroom_Name.length -ge 1) { $Lightroom_Name[0].name } else { "Adobe Lightroom" }
$Lightroom_StartIn = $Lightroom_TargetPath + $Lightroom_Name
$Lightroom_StartInAlt = $Lightroom_StartIn + "\Support Files"
$Lightroom_StartInAlt2 = $Lightroom_StartInAlt + "\Contents\Windows"
$Lightroom_TargetPath = $Lightroom_StartIn + "\lightroom.exe"
$Lightroom_TargetPathAlt = $Lightroom_StartInAlt + "\lightroom.exe"
$Lightroom_TargetPathAlt2 = $Lightroom_StartInAlt2 + "\lightroom.exe"
$Lightroom_TargetPath = if (Test-Path -Path $Lightroom_TargetPath -PathType leaf) { $Lightroom_TargetPath } elseif (Test-Path -Path $Lightroom_TargetPathAlt -PathType leaf) { $Lightroom_TargetPathAlt } else { $Lightroom_TargetPathAlt2 }
$Lightroom_Beta_TargetPath = "C:\Program Files\Adobe\"
$Lightroom_Beta_Name = if (Test-Path -Path $Lightroom_Beta_TargetPath) { Get-ChildItem -Directory -Path $Lightroom_Beta_TargetPath | Where-Object { $_.Name -match '^.*Lightroom(?!.*Classic).*\(Beta\)$' } | Sort-Object -Descending }
$Lightroom_Beta_Name = if ($Lightroom_Beta_Name.length -ge 1) { $Lightroom_Beta_Name[0].name } else { "Adobe Lightroom (Beta)" }
$Lightroom_Beta_StartIn = $Lightroom_Beta_TargetPath + $Lightroom_Beta_Name
$Lightroom_Beta_StartInAlt = $Lightroom_Beta_StartIn + "\Support Files"
$Lightroom_Beta_StartInAlt2 = $Lightroom_Beta_StartInAlt + "\Contents\Windows"
$Lightroom_Beta_TargetPathExeAlt = $Lightroom_Beta_StartIn + "\lightroom.exe"
$Lightroom_Beta_TargetPathAltExeAlt = $Lightroom_Beta_StartInAlt + "\lightroom.exe"
$Lightroom_Beta_TargetPathAlt2ExeAlt = $Lightroom_Beta_StartInAlt2 + "\lightroom.exe"
$Lightroom_Beta_TargetPath = $Lightroom_Beta_StartIn + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPathAlt = $Lightroom_Beta_StartInAlt + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPathAlt2 = $Lightroom_Beta_StartInAlt2 + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPath = if (Test-Path -Path $Lightroom_Beta_TargetPathExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Lightroom_Beta_TargetPathAltExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Lightroom_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Lightroom_Beta_TargetPath -PathType leaf) { $Lightroom_Beta_TargetPath } elseif (Test-Path -Path $Lightroom_Beta_TargetPathAlt -PathType leaf) { $Lightroom_Beta_TargetPathAlt } else { $Lightroom_Beta_TargetPathAlt2 }
# Adobe Lightroom Classic
$LightroomClassic_TargetPath = "C:\Program Files\Adobe\"
$LightroomClassic_Name = if (Test-Path -Path $LightroomClassic_TargetPath) { Get-ChildItem -Directory -Path $LightroomClassic_TargetPath | Where-Object { $_.Name -match '^.*Lightroom Classic(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$LightroomClassic_Name = if ($LightroomClassic_Name.length -ge 1) { $LightroomClassic_Name[0].name } else { "Adobe Lightroom Classic" }
$LightroomClassic_StartIn = $LightroomClassic_TargetPath + $LightroomClassic_Name
$LightroomClassic_StartInAlt = $LightroomClassic_StartIn + "\Support Files"
$LightroomClassic_StartInAlt2 = $LightroomClassic_StartInAlt + "\Contents\Windows"
$LightroomClassic_TargetPath = $LightroomClassic_StartIn + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt = $LightroomClassic_StartInAlt + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt2 = $LightroomClassic_StartInAlt2 + "\Lightroom.exe"
$LightroomClassic_TargetPath = if (Test-Path -Path $LightroomClassic_TargetPath -PathType leaf) { $LightroomClassic_TargetPath } elseif (Test-Path -Path $LightroomClassic_TargetPathAlt -PathType leaf) { $LightroomClassic_TargetPathAlt } else { $LightroomClassic_TargetPathAlt2 }
$LightroomClassic_Beta_TargetPath = "C:\Program Files\Adobe\"
$LightroomClassic_Beta_Name = if (Test-Path -Path $LightroomClassic_Beta_TargetPath) { Get-ChildItem -Directory -Path $LightroomClassic_Beta_TargetPath | Where-Object { $_.Name -match '^.*Lightroom Classic.*\(Beta\)$' } | Sort-Object -Descending }
$LightroomClassic_Beta_Name = if ($LightroomClassic_Beta_Name.length -ge 1) { $LightroomClassic_Beta_Name[0].name } else { "Adobe Lightroom Classic (Beta)" }
$LightroomClassic_Beta_StartIn = $LightroomClassic_Beta_TargetPath + $LightroomClassic_Beta_Name
$LightroomClassic_Beta_StartInAlt = $LightroomClassic_Beta_StartIn + "\Support Files"
$LightroomClassic_Beta_StartInAlt2 = $LightroomClassic_Beta_StartInAlt + "\Contents\Windows"
$LightroomClassic_Beta_TargetPathExeAlt = $LightroomClassic_Beta_StartIn + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPathAltExeAlt = $LightroomClassic_Beta_StartInAlt + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPathAlt2ExeAlt = $LightroomClassic_Beta_StartInAlt2 + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPath = $LightroomClassic_Beta_StartIn + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPathAlt = $LightroomClassic_Beta_StartInAlt + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPathAlt2 = $LightroomClassic_Beta_StartInAlt2 + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPath = if (Test-Path -Path $LightroomClassic_Beta_TargetPathExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathExeAlt } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAltExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPath -PathType leaf) { $LightroomClassic_Beta_TargetPath } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAlt } else { $LightroomClassic_Beta_TargetPathAlt2 }
# Adobe Media Encoder
$MediaEncoder_TargetPath = "C:\Program Files\Adobe\"
$MediaEncoder_Name = if (Test-Path -Path $MediaEncoder_TargetPath) { Get-ChildItem -Directory -Path $MediaEncoder_TargetPath | Where-Object { $_.Name -match '^.*Media Encoder(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$MediaEncoder_Name = if ($MediaEncoder_Name.length -ge 1) { $MediaEncoder_Name[0].name } else { "Adobe Media Encoder" }
$MediaEncoder_StartIn = $MediaEncoder_TargetPath + $MediaEncoder_Name
$MediaEncoder_StartInAlt = $MediaEncoder_StartIn + "\Support Files"
$MediaEncoder_StartInAlt2 = $MediaEncoder_StartInAlt + "\Contents\Windows"
$MediaEncoder_TargetPath = $MediaEncoder_StartIn + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt = $MediaEncoder_StartInAlt + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt2 = $MediaEncoder_StartInAlt2 + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPath = if (Test-Path -Path $MediaEncoder_TargetPath -PathType leaf) { $MediaEncoder_TargetPath } elseif (Test-Path -Path $MediaEncoder_TargetPathAlt -PathType leaf) { $MediaEncoder_TargetPathAlt } else { $MediaEncoder_TargetPathAlt2 }
$MediaEncoder_Beta_TargetPath = "C:\Program Files\Adobe\"
$MediaEncoder_Beta_Name = if (Test-Path -Path $MediaEncoder_Beta_TargetPath) { Get-ChildItem -Directory -Path $MediaEncoder_Beta_TargetPath | Where-Object { $_.Name -match '^.*Media Encoder.*\(Beta\)$' } | Sort-Object -Descending }
$MediaEncoder_Beta_Name = if ($MediaEncoder_Beta_Name.length -ge 1) { $MediaEncoder_Beta_Name[0].name } else { "Adobe Media Encoder (Beta)" }
$MediaEncoder_Beta_StartIn = $MediaEncoder_Beta_TargetPath + $MediaEncoder_Beta_Name
$MediaEncoder_Beta_StartInAlt = $MediaEncoder_Beta_StartIn + "\Support Files"
$MediaEncoder_Beta_StartInAlt2 = $MediaEncoder_Beta_StartInAlt + "\Contents\Windows"
$MediaEncoder_Beta_TargetPathExeAlt = $MediaEncoder_Beta_StartIn + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPathAltExeAlt = $MediaEncoder_Beta_StartInAlt + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPathAlt2ExeAlt = $MediaEncoder_Beta_StartInAlt2 + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPath = $MediaEncoder_Beta_StartIn + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPathAlt = $MediaEncoder_Beta_StartInAlt + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPathAlt2 = $MediaEncoder_Beta_StartInAlt2 + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPath = if (Test-Path -Path $MediaEncoder_Beta_TargetPathExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathExeAlt } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAltExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPath -PathType leaf) { $MediaEncoder_Beta_TargetPath } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAlt } else { $MediaEncoder_Beta_TargetPathAlt2 }
# Adobe Photoshop
$Photoshop_TargetPath = "C:\Program Files\Adobe\"
$Photoshop_Name = if (Test-Path -Path $Photoshop_TargetPath) { Get-ChildItem -Directory -Path $Photoshop_TargetPath | Where-Object { $_.Name -match '^.*Photoshop(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Photoshop_Name = if ($Photoshop_Name.length -ge 1) { $Photoshop_Name[0].name } else { "Adobe Photoshop" }
$Photoshop_StartIn = $Photoshop_TargetPath + $Photoshop_Name
$Photoshop_StartInAlt = $Photoshop_StartIn + "\Support Files"
$Photoshop_StartInAlt2 = $Photoshop_StartInAlt + "\Contents\Windows"
$Photoshop_TargetPath = $Photoshop_StartIn + "\Photoshop.exe"
$Photoshop_TargetPathAlt = $Photoshop_StartInAlt + "\Photoshop.exe"
$Photoshop_TargetPathAlt2 = $Photoshop_StartInAlt2 + "\Photoshop.exe"
$Photoshop_TargetPath = if (Test-Path -Path $Photoshop_TargetPath -PathType leaf) { $Photoshop_TargetPath } elseif (Test-Path -Path $Photoshop_TargetPathAlt -PathType leaf) { $Photoshop_TargetPathAlt } else { $Photoshop_TargetPathAlt2 }
$Photoshop_Beta_TargetPath = "C:\Program Files\Adobe\"
$Photoshop_Beta_Name = if (Test-Path -Path $Photoshop_Beta_TargetPath) { Get-ChildItem -Directory -Path $Photoshop_Beta_TargetPath | Where-Object { $_.Name -match '^.*Photoshop.*\(Beta\)$' } | Sort-Object -Descending }
$Photoshop_Beta_Name = if ($Photoshop_Beta_Name.length -ge 1) { $Photoshop_Beta_Name[0].name } else { "Adobe Photoshop (Beta)" }
$Photoshop_Beta_StartIn = $Photoshop_Beta_TargetPath + $Photoshop_Beta_Name
$Photoshop_Beta_StartInAlt = $Photoshop_Beta_StartIn + "\Support Files"
$Photoshop_Beta_StartInAlt2 = $Photoshop_Beta_StartInAlt + "\Contents\Windows"
$Photoshop_Beta_TargetPathExeAlt = $Photoshop_Beta_StartIn + "\Photoshop.exe"
$Photoshop_Beta_TargetPathAltExeAlt = $Photoshop_Beta_StartInAlt + "\Photoshop.exe"
$Photoshop_Beta_TargetPathAlt2ExeAlt = $Photoshop_Beta_StartInAlt2 + "\Photoshop.exe"
$Photoshop_Beta_TargetPath = $Photoshop_Beta_StartIn + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPathAlt = $Photoshop_Beta_StartInAlt + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPathAlt2 = $Photoshop_Beta_StartInAlt2 + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPath = if (Test-Path -Path $Photoshop_Beta_TargetPathExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Photoshop_Beta_TargetPathAltExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Photoshop_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Photoshop_Beta_TargetPath -PathType leaf) { $Photoshop_Beta_TargetPath } elseif (Test-Path -Path $Photoshop_Beta_TargetPathAlt -PathType leaf) { $Photoshop_Beta_TargetPathAlt } else { $Photoshop_Beta_TargetPathAlt2 }
# Adobe Premiere Pro
$PremierePro_TargetPath = "C:\Program Files\Adobe\"
$PremierePro_Name = if (Test-Path -Path $PremierePro_TargetPath) { Get-ChildItem -Directory -Path $PremierePro_TargetPath | Where-Object { $_.Name -match '^.*Premiere Pro(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$PremierePro_Name = if ($PremierePro_Name.length -ge 1) { $PremierePro_Name[0].name } else { "Adobe Premiere Pro" }
$PremierePro_StartIn = $PremierePro_TargetPath + $PremierePro_Name
$PremierePro_StartInAlt = $PremierePro_StartIn + "\Support Files"
$PremierePro_StartInAlt2 = $PremierePro_StartInAlt + "\Contents\Windows"
$PremierePro_TargetPath = $PremierePro_StartIn + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt = $PremierePro_StartInAlt + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt2 = $PremierePro_StartInAlt2 + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPath = if (Test-Path -Path $PremierePro_TargetPath -PathType leaf) { $PremierePro_TargetPath } elseif (Test-Path -Path $PremierePro_TargetPathAlt -PathType leaf) { $PremierePro_TargetPathAlt } else { $PremierePro_TargetPathAlt2 }
$PremierePro_Beta_TargetPath = "C:\Program Files\Adobe\"
$PremierePro_Beta_Name = if (Test-Path -Path $PremierePro_Beta_TargetPath) { Get-ChildItem -Directory -Path $PremierePro_Beta_TargetPath | Where-Object { $_.Name -match '^.*Premiere Pro.*\(Beta\)$' } | Sort-Object -Descending }
$PremierePro_Beta_Name = if ($PremierePro_Beta_Name.length -ge 1) { $PremierePro_Beta_Name[0].name } else { "Adobe Premiere Pro (Beta)" }
$PremierePro_Beta_StartIn = $PremierePro_Beta_TargetPath + $PremierePro_Beta_Name
$PremierePro_Beta_StartInAlt = $PremierePro_Beta_StartIn + "\Support Files"
$PremierePro_Beta_StartInAlt2 = $PremierePro_Beta_StartInAlt + "\Contents\Windows"
$PremierePro_Beta_TargetPathExeAlt = $PremierePro_Beta_StartIn + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPathAltExeAlt = $PremierePro_Beta_StartInAlt + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPathAlt2ExeAlt = $PremierePro_Beta_StartInAlt2 + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPath = $PremierePro_Beta_StartIn + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPathAlt = $PremierePro_Beta_StartInAlt + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPathAlt2 = $PremierePro_Beta_StartInAlt2 + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPath = if (Test-Path -Path $PremierePro_Beta_TargetPathExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathExeAlt } elseif (Test-Path -Path $PremierePro_Beta_TargetPathAltExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $PremierePro_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $PremierePro_Beta_TargetPath -PathType leaf) { $PremierePro_Beta_TargetPath } elseif (Test-Path -Path $PremierePro_Beta_TargetPathAlt -PathType leaf) { $PremierePro_Beta_TargetPathAlt } else { $PremierePro_Beta_TargetPathAlt2 }
# Adobe Premiere Rush
$PremiereRush_TargetPath = "C:\Program Files\Adobe\"
$PremiereRush_Name = if (Test-Path -Path $PremiereRush_TargetPath) { Get-ChildItem -Directory -Path $PremiereRush_TargetPath | Where-Object { $_.Name -match '^.*Premiere Rush(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$PremiereRush_Name = if ($PremiereRush_Name.length -ge 1) { $PremiereRush_Name[0].name } else { "Adobe Premiere Rush" }
$PremiereRush_StartIn = $PremiereRush_TargetPath + $PremiereRush_Name
$PremiereRush_StartInAlt = $PremiereRush_StartIn + "\Support Files"
$PremiereRush_StartInAlt2 = $PremiereRush_StartInAlt + "\Contents\Windows"
$PremiereRush_TargetPath = $PremiereRush_StartIn + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt = $PremiereRush_StartInAlt + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt2 = $PremiereRush_StartInAlt2 + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPath = if (Test-Path -Path $PremiereRush_TargetPath -PathType leaf) { $PremiereRush_TargetPath } elseif (Test-Path -Path $PremiereRush_TargetPathAlt -PathType leaf) { $PremiereRush_TargetPathAlt } else { $PremiereRush_TargetPathAlt2 }
$PremiereRush_Beta_TargetPath = "C:\Program Files\Adobe\"
$PremiereRush_Beta_Name = if (Test-Path -Path $PremiereRush_Beta_TargetPath) { Get-ChildItem -Directory -Path $PremiereRush_Beta_TargetPath | Where-Object { $_.Name -match '^.*Premiere Rush.*\(Beta\)$' } | Sort-Object -Descending }
$PremiereRush_Beta_Name = if ($PremiereRush_Beta_Name.length -ge 1) { $PremiereRush_Beta_Name[0].name } else { "Adobe Premiere Rush (Beta)" }
$PremiereRush_Beta_StartIn = $PremiereRush_Beta_TargetPath + $PremiereRush_Beta_Name
$PremiereRush_Beta_StartInAlt = $PremiereRush_Beta_StartIn + "\Support Files"
$PremiereRush_Beta_StartInAlt2 = $PremiereRush_Beta_StartInAlt + "\Contents\Windows"
$PremiereRush_Beta_TargetPathExeAlt = $PremiereRush_Beta_StartIn + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPathAltExeAlt = $PremiereRush_Beta_StartInAlt + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPathAlt2ExeAlt = $PremiereRush_Beta_StartInAlt2 + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPath = $PremiereRush_Beta_StartIn + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPathAlt = $PremiereRush_Beta_StartInAlt + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPathAlt2 = $PremiereRush_Beta_StartInAlt2 + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPath = if (Test-Path -Path $PremiereRush_Beta_TargetPathExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathExeAlt } elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAltExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $PremiereRush_Beta_TargetPath -PathType leaf) { $PremiereRush_Beta_TargetPath } elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAlt } else { $PremiereRush_Beta_TargetPathAlt2 }
# Adobe Substance 3D Designer
$Substance3dDesigner_TargetPath = "C:\Program Files\Adobe\"
$Substance3dDesigner_Name = if (Test-Path -Path $Substance3dDesigner_TargetPath) { Get-ChildItem -Directory -Path $Substance3dDesigner_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Designer(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dDesigner_Name = if ($Substance3dDesigner_Name.length -ge 1) { $Substance3dDesigner_Name[0].name } else { "Adobe Substance 3D Designer" }
$Substance3dDesigner_StartIn = $Substance3dDesigner_TargetPath + $Substance3dDesigner_Name
$Substance3dDesigner_StartInAlt = $Substance3dDesigner_StartIn + "\Support Files"
$Substance3dDesigner_StartInAlt2 = $Substance3dDesigner_StartInAlt + "\Contents\Windows"
$Substance3dDesigner_TargetPath = $Substance3dDesigner_StartIn + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt = $Substance3dDesigner_StartInAlt + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt2 = $Substance3dDesigner_StartInAlt2 + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPath = if (Test-Path -Path $Substance3dDesigner_TargetPath -PathType leaf) { $Substance3dDesigner_TargetPath } elseif (Test-Path -Path $Substance3dDesigner_TargetPathAlt -PathType leaf) { $Substance3dDesigner_TargetPathAlt } else { $Substance3dDesigner_TargetPathAlt2 }
$Substance3dDesigner_Beta_TargetPath = "C:\Program Files\Adobe\"
$Substance3dDesigner_Beta_Name = if (Test-Path -Path $Substance3dDesigner_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dDesigner_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Designer.*\(Beta\)$' } | Sort-Object -Descending }
$Substance3dDesigner_Beta_Name = if ($Substance3dDesigner_Beta_Name.length -ge 1) { $Substance3dDesigner_Beta_Name[0].name } else { "Adobe Substance 3D Designer (Beta)" }
$Substance3dDesigner_Beta_StartIn = $Substance3dDesigner_Beta_TargetPath + $Substance3dDesigner_Beta_Name
$Substance3dDesigner_Beta_StartInAlt = $Substance3dDesigner_Beta_StartIn + "\Support Files"
$Substance3dDesigner_Beta_StartInAlt2 = $Substance3dDesigner_Beta_StartInAlt + "\Contents\Windows"
$Substance3dDesigner_Beta_TargetPathExeAlt = $Substance3dDesigner_Beta_StartIn + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPathAltExeAlt = $Substance3dDesigner_Beta_StartInAlt + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPathAlt2ExeAlt = $Substance3dDesigner_Beta_StartInAlt2 + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPath = $Substance3dDesigner_Beta_StartIn + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPathAlt = $Substance3dDesigner_Beta_StartInAlt + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPathAlt2 = $Substance3dDesigner_Beta_StartInAlt2 + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPath = if (Test-Path -Path $Substance3dDesigner_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPath -PathType leaf) { $Substance3dDesigner_Beta_TargetPath } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAlt } else { $Substance3dDesigner_Beta_TargetPathAlt2 }
# Adobe Substance 3D Modeler
$Substance3dModeler_TargetPath = "C:\Program Files\Adobe\"
$Substance3dModeler_Name = if (Test-Path -Path $Substance3dModeler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dModeler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Modeler(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dModeler_Name = if ($Substance3dModeler_Name.length -ge 1) { $Substance3dModeler_Name[0].name } else { "Adobe Substance 3D Modeler" }
$Substance3dModeler_StartIn = $Substance3dModeler_TargetPath + $Substance3dModeler_Name
$Substance3dModeler_StartInAlt = $Substance3dModeler_StartIn + "\Support Files"
$Substance3dModeler_StartInAlt2 = $Substance3dModeler_StartInAlt + "\Contents\Windows"
$Substance3dModeler_TargetPath = $Substance3dModeler_StartIn + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt = $Substance3dModeler_StartInAlt + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt2 = $Substance3dModeler_StartInAlt2 + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPath = if (Test-Path -Path $Substance3dModeler_TargetPath -PathType leaf) { $Substance3dModeler_TargetPath } elseif (Test-Path -Path $Substance3dModeler_TargetPathAlt -PathType leaf) { $Substance3dModeler_TargetPathAlt } else { $Substance3dModeler_TargetPathAlt2 }
$Substance3dModeler_Beta_TargetPath = "C:\Program Files\Adobe\"
$Substance3dModeler_Beta_Name = if (Test-Path -Path $Substance3dModeler_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dModeler_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Modeler.*\(Beta\)$' } | Sort-Object -Descending }
$Substance3dModeler_Beta_Name = if ($Substance3dModeler_Beta_Name.length -ge 1) { $Substance3dModeler_Beta_Name[0].name } else { "Adobe Substance 3D Modeler (Beta)" }
$Substance3dModeler_Beta_StartIn = $Substance3dModeler_Beta_TargetPath + $Substance3dModeler_Beta_Name
$Substance3dModeler_Beta_StartInAlt = $Substance3dModeler_Beta_StartIn + "\Support Files"
$Substance3dModeler_Beta_StartInAlt2 = $Substance3dModeler_Beta_StartInAlt + "\Contents\Windows"
$Substance3dModeler_Beta_TargetPathExeAlt = $Substance3dModeler_Beta_StartIn + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPathAltExeAlt = $Substance3dModeler_Beta_StartInAlt + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPathAlt2ExeAlt = $Substance3dModeler_Beta_StartInAlt2 + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPath = $Substance3dModeler_Beta_StartIn + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPathAlt = $Substance3dModeler_Beta_StartInAlt + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPathAlt2 = $Substance3dModeler_Beta_StartInAlt2 + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPath = if (Test-Path -Path $Substance3dModeler_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPath -PathType leaf) { $Substance3dModeler_Beta_TargetPath } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAlt } else { $Substance3dModeler_Beta_TargetPathAlt2 }
# Adobe Substance 3D Painter
$Substance3dPainter_TargetPath = "C:\Program Files\Adobe\"
$Substance3dPainter_Name = if (Test-Path -Path $Substance3dPainter_TargetPath) { Get-ChildItem -Directory -Path $Substance3dPainter_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Painter(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dPainter_Name = if ($Substance3dPainter_Name.length -ge 1) { $Substance3dPainter_Name[0].name } else { "Adobe Substance 3D Painter" }
$Substance3dPainter_StartIn = $Substance3dPainter_TargetPath + $Substance3dPainter_Name
$Substance3dPainter_StartInAlt = $Substance3dPainter_StartIn + "\Support Files"
$Substance3dPainter_StartInAlt2 = $Substance3dPainter_StartInAlt + "\Contents\Windows"
$Substance3dPainter_TargetPath = $Substance3dPainter_StartIn + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt = $Substance3dPainter_StartInAlt + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt2 = $Substance3dPainter_StartInAlt2 + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPath = if (Test-Path -Path $Substance3dPainter_TargetPath -PathType leaf) { $Substance3dPainter_TargetPath } elseif (Test-Path -Path $Substance3dPainter_TargetPathAlt -PathType leaf) { $Substance3dPainter_TargetPathAlt } else { $Substance3dPainter_TargetPathAlt2 }
$Substance3dPainter_Beta_TargetPath = "C:\Program Files\Adobe\"
$Substance3dPainter_Beta_Name = if (Test-Path -Path $Substance3dPainter_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dPainter_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Painter.*\(Beta\)$' } | Sort-Object -Descending }
$Substance3dPainter_Beta_Name = if ($Substance3dPainter_Beta_Name.length -ge 1) { $Substance3dPainter_Beta_Name[0].name } else { "Adobe Substance 3D Painter (Beta)" }
$Substance3dPainter_Beta_StartIn = $Substance3dPainter_Beta_TargetPath + $Substance3dPainter_Beta_Name
$Substance3dPainter_Beta_StartInAlt = $Substance3dPainter_Beta_StartIn + "\Support Files"
$Substance3dPainter_Beta_StartInAlt2 = $Substance3dPainter_Beta_StartInAlt + "\Contents\Windows"
$Substance3dPainter_Beta_TargetPathExeAlt = $Substance3dPainter_Beta_StartIn + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPathAltExeAlt = $Substance3dPainter_Beta_StartInAlt + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPathAlt2ExeAlt = $Substance3dPainter_Beta_StartInAlt2 + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPath = $Substance3dPainter_Beta_StartIn + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPathAlt = $Substance3dPainter_Beta_StartInAlt + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPathAlt2 = $Substance3dPainter_Beta_StartInAlt2 + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPath = if (Test-Path -Path $Substance3dPainter_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPath -PathType leaf) { $Substance3dPainter_Beta_TargetPath } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAlt } else { $Substance3dPainter_Beta_TargetPathAlt2 }
# Adobe Substance 3D Sampler
$Substance3dSampler_TargetPath = "C:\Program Files\Adobe\"
$Substance3dSampler_Name = if (Test-Path -Path $Substance3dSampler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dSampler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Sampler(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dSampler_Name = if ($Substance3dSampler_Name.length -ge 1) { $Substance3dSampler_Name[0].name } else { "Adobe Substance 3D Sampler" }
$Substance3dSampler_StartIn = $Substance3dSampler_TargetPath + $Substance3dSampler_Name
$Substance3dSampler_StartInAlt = $Substance3dSampler_StartIn + "\Support Files"
$Substance3dSampler_StartInAlt2 = $Substance3dSampler_StartInAlt + "\Contents\Windows"
$Substance3dSampler_TargetPath = $Substance3dSampler_StartIn + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt = $Substance3dSampler_StartInAlt + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt2 = $Substance3dSampler_StartInAlt2 + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPath = if (Test-Path -Path $Substance3dSampler_TargetPath -PathType leaf) { $Substance3dSampler_TargetPath } elseif (Test-Path -Path $Substance3dSampler_TargetPathAlt -PathType leaf) { $Substance3dSampler_TargetPathAlt } else { $Substance3dSampler_TargetPathAlt2 }
$Substance3dSampler_Beta_TargetPath = "C:\Program Files\Adobe\"
$Substance3dSampler_Beta_Name = if (Test-Path -Path $Substance3dSampler_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dSampler_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Sampler.*\(Beta\)$' } | Sort-Object -Descending }
$Substance3dSampler_Beta_Name = if ($Substance3dSampler_Beta_Name.length -ge 1) { $Substance3dSampler_Beta_Name[0].name } else { "Adobe Substance 3D Sampler (Beta)" }
$Substance3dSampler_Beta_StartIn = $Substance3dSampler_Beta_TargetPath + $Substance3dSampler_Beta_Name
$Substance3dSampler_Beta_StartInAlt = $Substance3dSampler_Beta_StartIn + "\Support Files"
$Substance3dSampler_Beta_StartInAlt2 = $Substance3dSampler_Beta_StartInAlt + "\Contents\Windows"
$Substance3dSampler_Beta_TargetPathExeAlt = $Substance3dSampler_Beta_StartIn + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPathAltExeAlt = $Substance3dSampler_Beta_StartInAlt + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPathAlt2ExeAlt = $Substance3dSampler_Beta_StartInAlt2 + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPath = $Substance3dSampler_Beta_StartIn + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPathAlt = $Substance3dSampler_Beta_StartInAlt + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPathAlt2 = $Substance3dSampler_Beta_StartInAlt2 + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPath = if (Test-Path -Path $Substance3dSampler_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPath -PathType leaf) { $Substance3dSampler_Beta_TargetPath } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAlt } else { $Substance3dSampler_Beta_TargetPathAlt2 }
# Adobe Substance 3D Stager
$Substance3dStager_TargetPath = "C:\Program Files\Adobe\"
$Substance3dStager_Name = if (Test-Path -Path $Substance3dStager_TargetPath) { Get-ChildItem -Directory -Path $Substance3dStager_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Stager(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dStager_Name = if ($Substance3dStager_Name.length -ge 1) { $Substance3dStager_Name[0].name } else { "Adobe Substance 3D Stager" }
$Substance3dStager_StartIn = $Substance3dStager_TargetPath + $Substance3dStager_Name
$Substance3dStager_StartInAlt = $Substance3dStager_StartIn + "\Support Files"
$Substance3dStager_StartInAlt2 = $Substance3dStager_StartInAlt + "\Contents\Windows"
$Substance3dStager_TargetPath = $Substance3dStager_StartIn + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt = $Substance3dStager_StartInAlt + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt2 = $Substance3dStager_StartInAlt2 + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPath = if (Test-Path -Path $Substance3dStager_TargetPath -PathType leaf) { $Substance3dStager_TargetPath } elseif (Test-Path -Path $Substance3dStager_TargetPathAlt -PathType leaf) { $Substance3dStager_TargetPathAlt } else { $Substance3dStager_TargetPathAlt2 }
$Substance3dStager_Beta_TargetPath = "C:\Program Files\Adobe\"
$Substance3dStager_Beta_Name = if (Test-Path -Path $Substance3dStager_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dStager_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Stager.*\(Beta\)$' } | Sort-Object -Descending }
$Substance3dStager_Beta_Name = if ($Substance3dStager_Beta_Name.length -ge 1) { $Substance3dStager_Beta_Name[0].name } else { "Adobe Substance 3D Stager (Beta)" }
$Substance3dStager_Beta_StartIn = $Substance3dStager_Beta_TargetPath + $Substance3dStager_Beta_Name
$Substance3dStager_Beta_StartInAlt = $Substance3dStager_Beta_StartIn + "\Support Files"
$Substance3dStager_Beta_StartInAlt2 = $Substance3dStager_Beta_StartInAlt + "\Contents\Windows"
$Substance3dStager_Beta_TargetPathExeAlt = $Substance3dStager_Beta_StartIn + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPathAltExeAlt = $Substance3dStager_Beta_StartInAlt + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPathAlt2ExeAlt = $Substance3dStager_Beta_StartInAlt2 + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPath = $Substance3dStager_Beta_StartIn + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPathAlt = $Substance3dStager_Beta_StartInAlt + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPathAlt2 = $Substance3dStager_Beta_StartInAlt2 + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPath = if (Test-Path -Path $Substance3dStager_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPath -PathType leaf) { $Substance3dStager_Beta_TargetPath } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAlt } else { $Substance3dStager_Beta_TargetPathAlt2 }
# GIMP
$GIMP_TargetPath = "C:\Program Files\"
$GIMP_FindFolder = Get-ChildItem -Directory -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Descending
$GIMP_FindFolder = if ($GIMP_FindFolder.length -ge 1) { $GIMP_FindFolder[0].name } else { $NotInstalled }
$GIMP_TargetPath += "${GIMP_FindFolder}\bin\"
$GIMP_FindExe = if (Test-Path -Path $GIMP_TargetPath) { Get-ChildItem -File -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Descending }
$GIMP_FindExe = if ($GIMP_FindExe.length -ge 1) { $GIMP_FindExe[0].name } else { "${NotInstalled}.exe" }
$GIMP_TargetPath += $GIMP_FindExe
$GIMP_32bit_TargetPath = "C:\Program Files (x86)\"
$GIMP_32bit_FindFolder = Get-ChildItem -Directory -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Descending
$GIMP_32bit_FindFolder = if ($GIMP_32bit_FindFolder.length -ge 1) { $GIMP_32bit_FindFolder[0].name } else { $NotInstalled }
$GIMP_32bit_TargetPath += "${GIMP_32bit_FindFolder}\bin\"
$GIMP_32bit_FindExe = if (Test-Path -Path $GIMP_32bit_TargetPath) { Get-ChildItem -File -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Descending }
$GIMP_32bit_FindExe = if ($GIMP_32bit_FindExe.length -ge 1) { $GIMP_32bit_FindExe[0].name } else { "${NotInstalled}.exe" }
$GIMP_32bit_TargetPath += $GIMP_32bit_FindExe
# Google
$GoogleDrive_TargetPath = "C:\Program Files\Google\Drive File Stream\"
$GoogleDrive_Version = if (Test-Path -Path $GoogleDrive_TargetPath) { Get-ChildItem -Directory -Path $GoogleDrive_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleDrive_Version = if ($GoogleDrive_Version.length -ge 1) { $GoogleDrive_Version[0].name } else { $NotInstalled }
$GoogleDrive_TargetPath += "${GoogleDrive_Version}\GoogleDriveFS.exe"
$GoogleOneVPN_TargetPath = "C:\Program Files\Google\VPN by Google One\"
$GoogleOneVPN_Version = if (Test-Path -Path $GoogleOneVPN_TargetPath) { Get-ChildItem -Directory -Path $GoogleOneVPN_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleOneVPN_Version = if ($GoogleOneVPN_Version.length -ge 1) { $GoogleOneVPN_Version[0].name } else { $NotInstalled }
$GoogleOneVPN_TargetPath += "${GoogleOneVPN_Version}\googleone.exe"
# KeePass
$KeePass_StartIn = "C:\Program Files\"
$KeePass_FindFolder = Get-ChildItem -Directory -Path $KeePass_StartIn | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Descending
$KeePass_FindFolder = if ($KeePass_FindFolder.length -ge 1) { $KeePass_FindFolder[0].name } else { $NotInstalled }
$KeePass_TargetPath = "${KeePass_FindFolder}\KeePass.exe"
$KeePass_32bit_StartIn = "C:\Program Files (x86)\"
$KeePass_32bit_FindFolder = Get-ChildItem -Directory -Path $KeePass_32bit_StartIn | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Descending
$KeePass_32bit_FindFolder = if ($KeePass_32bit_FindFolder.length -ge 1) { $KeePass_32bit_FindFolder[0].name } else { $NotInstalled }
$KeePass_32bit_TargetPath = "${KeePass_32bit_FindFolder}\KeePass.exe"
# Maxon
$MaxonCinema4D_StartIn = "C:\Program Files\"
$MaxonCinema4D_FindFolder = Get-ChildItem -Directory -Path $MaxonCinema4D_StartIn | Where-Object { $_.Name -match '^Maxon Cinema 4D' } | Sort-Object -Descending
$MaxonCinema4D_FindFolder = if ($MaxonCinema4D_FindFolder.length -ge 1) { $MaxonCinema4D_FindFolder[0].name } else { $NotInstalled }
$MaxonCinema4D_Version = $MaxonCinema4D_FindFolder | Select-String -pattern "\d\d\d\d$" -All
$MaxonCinema4D_Version = if ($MaxonCinema4D_Version.length -ge 1) { $MaxonCinema4D_Version.Matches[-1].value } else { $NotInstalled }
$MaxonCinema4D_StartIn += $MaxonCinema4D_FindFolder
$MaxonCinema4D_Commandline_TargetPath = $MaxonCinema4D_StartIn + "\Commandline.exe"
$MaxonCinema4D_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D.exe"
$MaxonCinema4D_TeamRenderClient_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D Team Render Client.exe"
$MaxonCinema4D_TeamRenderServer_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D Team Render Server.exe"
# VMware
$VMwareWorkstationPlayer_TargetPath = "C:\Program Files\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_Path = if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType Leaf) { "C:\Windows\System32\cmd.exe" } else { "C:\Program Files\${NotInstalled}\${NotInstalled}\${NotInstalled}.exe" }
$VMwareWorkstationPlayer_32bit_TargetPath = "C:\Program Files (x86)\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_32bit_Path = if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType Leaf) { "C:\Windows\System32\cmd.exe" } else { "C:\Program Files (x86)\${NotInstalled}\${NotInstalled}\${NotInstalled}.exe" }

# App names dependant on OS or app version

# GIMP
$GIMP_ProductVersion = if (Test-Path -Path $GIMP_TargetPath -PathType Leaf) { (Get-Item $GIMP_TargetPath).VersionInfo.ProductVersion }
$GIMP_Version = if ($GIMP_ProductVersion) { $GIMP_ProductVersion } else { $NotInstalled }
$GIMP_Name = "GIMP ${GIMP_Version}"
$GIMP_32bit_ProductVersion = if (Test-Path -Path $GIMP_32bit_TargetPath -PathType Leaf) { (Get-Item $GIMP_32bit_TargetPath).VersionInfo.ProductVersion }
$GIMP_32bit_Version = if ($GIMP_32bit_ProductVersion) { $GIMP_32bit_ProductVersion } else { $NotInstalled }
$GIMP_32bit_Name = "GIMP ${GIMP_32bit_Version}"
# KeePass
$KeePass_FileVersionRaw = if (Test-Path -Path $KeePass_TargetPath -PathType Leaf) { (Get-Item $KeePass_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_Version = if ($KeePass_FileVersionRaw) { $KeePass_FileVersionRaw.Major } else { $NotInstalled }
$KeePass_Name = "KeePass ${KeePass_Version}"
$KeePass_32bit_FileVersionRaw = if (Test-Path -Path $KeePass_32bit_TargetPath -PathType Leaf) { (Get-Item $KeePass_32bit_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_32bit_Version = if ($KeePass_32bit_FileVersionRaw) { $KeePass_32bit_FileVersionRaw.Major } else { $NotInstalled }
$KeePass_32bit_Name = "KeePass ${KeePass_32bit_Version}"
# Maxon
$MaxonCinema4D_Commandline_Name = "Commandline" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_Name = "Maxon Cinema 4D" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderClient_Name = "Team Render Client" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderServer_Name = "Team Render Server" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
# VMware
$VMwareWorkstationPlayer_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType Leaf) { (Get-Item $VMwareWorkstationPlayer_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_Version = if ($VMwareWorkstationPlayer_FileVersionRaw) { $VMwareWorkstationPlayer_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NotInstalled }
$VMwareWorkstationPlayer_Name = "VMware Workstation ${VMwareWorkstationPlayer_Version} Player"
$VMwareWorkstationPlayer_32bit_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType Leaf) { (Get-Item $VMwareWorkstationPlayer_32bit_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_32bit_Version = if ($VMwareWorkstationPlayer_32bit_FileVersionRaw) { $VMwareWorkstationPlayer_32bit_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NotInstalled }
$VMwareWorkstationPlayer_32bit_Name = "VMware Workstation ${VMwareWorkstationPlayer_32bit_Version} Player"

$sys3rdPartyAppList = @(
  # 7-Zip
  @{Name = "7-Zip File Manager"; TargetPath = "C:\Program Files\7-Zip\7zFM.exe"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip Help"; TargetPath = "C:\Program Files\7-Zip\7-zip.chm"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip File Manager (32-bit)"; TargetPath = "C:\Program Files (x86)\7-Zip\7zFM.exe"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip Help"; TargetPath = "C:\Program Files (x86)\7-Zip\7-zip.chm"; SystemLnk = "7-Zip\" },
  # Adobe
  @{Name = "Adobe Acrobat"; TargetPath = "C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "C:\Program Files\Adobe\Acrobat DC\Acrobat\acrodist.exe" },
  @{Name = "Adobe Creative Cloud"; TargetPath = "C:\Program Files\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe" },
  @{Name = $Aero_Name; TargetPath = $Aero_TargetPath; StartIn = $Aero_StartIn },
  @{Name = $Aero_Beta_Name; TargetPath = $Aero_Beta_TargetPath; StartIn = $Aero_Beta_StartIn },
  @{Name = $AfterEffects_Name; TargetPath = $AfterEffects_TargetPath; StartIn = $AfterEffects_StartIn },
  @{Name = $AfterEffects_Beta_Name; TargetPath = $AfterEffects_Beta_TargetPath; StartIn = $AfterEffects_Beta_StartIn },
  @{Name = $Animate_Name; TargetPath = $Animate_TargetPath; StartIn = $Animate_StartIn },
  @{Name = $Animate_Beta_Name; TargetPath = $Animate_Beta_TargetPath; StartIn = $Animate_Beta_StartIn },
  @{Name = $Audition_Name; TargetPath = $Audition_TargetPath; StartIn = $Audition_StartIn },
  @{Name = $Audition_Beta_Name; TargetPath = $Audition_Beta_TargetPath; StartIn = $Audition_Beta_StartIn },
  @{Name = $Bridge_Name; TargetPath = $Bridge_TargetPath; StartIn = $Bridge_StartIn },
  @{Name = $Bridge_Beta_Name; TargetPath = $Bridge_Beta_TargetPath; StartIn = $Bridge_Beta_StartIn },
  @{Name = $CharacterAnimator_Name; TargetPath = $CharacterAnimator_TargetPath; StartIn = $CharacterAnimator_StartIn },
  @{Name = $CharacterAnimator_Beta_Name; TargetPath = $CharacterAnimator_Beta_TargetPath; StartIn = $CharacterAnimator_Beta_StartIn },
  @{Name = $Dimension_Name; TargetPath = $Dimension_TargetPath; StartIn = $Dimension_StartIn },
  @{Name = $Dimension_Beta_Name; TargetPath = $Dimension_Beta_TargetPath; StartIn = $Dimension_Beta_StartIn },
  @{Name = $Dreamweaver_Name; TargetPath = $Dreamweaver_TargetPath; StartIn = $Dreamweaver_StartIn },
  @{Name = $Dreamweaver_Beta_Name; TargetPath = $Dreamweaver_Beta_TargetPath; StartIn = $Dreamweaver_Beta_StartIn },
  @{Name = $Illustrator_Name; TargetPath = $Illustrator_TargetPath; StartIn = $Illustrator_StartIn },
  @{Name = $Illustrator_Beta_Name; TargetPath = $Illustrator_Beta_TargetPath; StartIn = $Illustrator_Beta_StartIn },
  @{Name = $InCopy_Name; TargetPath = $InCopy_TargetPath; StartIn = $InCopy_StartIn },
  @{Name = $InCopy_Beta_Name; TargetPath = $InCopy_Beta_TargetPath; StartIn = $InCopy_Beta_StartIn },
  @{Name = $InDesign_Name; TargetPath = $InDesign_TargetPath; StartIn = $InDesign_StartIn },
  @{Name = $InDesign_Beta_Name; TargetPath = $InDesign_Beta_TargetPath; StartIn = $InDesign_Beta_StartIn },
  @{Name = $Lightroom_Name; TargetPath = $Lightroom_TargetPath; StartIn = $Lightroom_StartIn },
  @{Name = $Lightroom_Beta_Name; TargetPath = $Lightroom_Beta_TargetPath; StartIn = $Lightroom_Beta_StartIn },
  @{Name = $LightroomClassic_Name; TargetPath = $LightroomClassic_TargetPath; StartIn = $LightroomClassic_StartIn },
  @{Name = $LightroomClassic_Beta_Name; TargetPath = $LightroomClassic_Beta_TargetPath; StartIn = $LightroomClassic_Beta_StartIn },
  @{Name = $MediaEncoder_Name; TargetPath = $MediaEncoder_TargetPath; StartIn = $MediaEncoder_StartIn },
  @{Name = $MediaEncoder_Beta_Name; TargetPath = $MediaEncoder_Beta_TargetPath; StartIn = $MediaEncoder_Beta_StartIn },
  @{Name = $Photoshop_Name; TargetPath = $Photoshop_TargetPath; StartIn = $Photoshop_StartIn },
  @{Name = $Photoshop_Beta_Name; TargetPath = $Photoshop_Beta_TargetPath; StartIn = $Photoshop_Beta_StartIn },
  @{Name = $PremierePro_Name; TargetPath = $PremierePro_TargetPath; StartIn = $PremierePro_StartIn },
  @{Name = $PremierePro_Beta_Name; TargetPath = $PremierePro_Beta_TargetPath; StartIn = $PremierePro_Beta_StartIn },
  @{Name = $PremiereRush_Name; TargetPath = $PremiereRush_TargetPath; StartIn = $PremiereRush_StartIn },
  @{Name = $PremiereRush_Beta_Name; TargetPath = $PremiereRush_Beta_TargetPath; StartIn = $PremiereRush_Beta_StartIn },
  @{Name = $Substance3dDesigner_Name; TargetPath = $Substance3dDesigner_TargetPath; StartIn = $Substance3dDesigner_StartIn },
  @{Name = $Substance3dDesigner_Beta_Name; TargetPath = $Substance3dDesigner_Beta_TargetPath; StartIn = $Substance3dDesigner_Beta_StartIn },
  @{Name = $Substance3dModeler_Name; TargetPath = $Substance3dModeler_TargetPath; StartIn = $Substance3dModeler_StartIn },
  @{Name = $Substance3dModeler_Beta_Name; TargetPath = $Substance3dModeler_Beta_TargetPath; StartIn = $Substance3dModeler_Beta_StartIn },
  @{Name = $Substance3dPainter_Name; TargetPath = $Substance3dPainter_TargetPath; StartIn = $Substance3dPainter_StartIn },
  @{Name = $Substance3dPainter_Beta_Name; TargetPath = $Substance3dPainter_Beta_TargetPath; StartIn = $Substance3dPainter_Beta_StartIn },
  @{Name = $Substance3dSampler_Name; TargetPath = $Substance3dSampler_TargetPath; StartIn = $Substance3dSampler_StartIn },
  @{Name = $Substance3dSampler_Beta_Name; TargetPath = $Substance3dSampler_Beta_TargetPath; StartIn = $Substance3dSampler_Beta_StartIn },
  @{Name = $Substance3dStager_Name; TargetPath = $Substance3dStager_TargetPath; StartIn = $Substance3dStager_StartIn },
  @{Name = $Substance3dStager_Beta_Name; TargetPath = $Substance3dStager_Beta_TargetPath; StartIn = $Substance3dStager_Beta_StartIn },
  @{Name = "Adobe UXP Developer Tool"; TargetPath = "C:\Program Files\Adobe\Adobe UXP Developer Tool\Adobe UXP Developer Tool.exe"; StartIn = "C:\Program Files\Adobe\Adobe UXP Developer Tool" },
  @{Name = "Adobe Acrobat (32-bit)"; TargetPath = "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{Name = "Adobe Acrobat Distiller (32-bit)"; TargetPath = "C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\acrodist.exe" },
  @{Name = "Adobe Acrobat Reader"; TargetPath = "C:\Program Files\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" }, # old version; it's the only install on 32-bit
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "C:\Program Files\Adobe\Acrobat Reader DC\Reader\acrodist.exe" }, # old version; it's the only install on 32-bit
  @{Name = "Adobe Acrobat Reader"; TargetPath = "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" }, # old version; it's the only install on 64-bit
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\acrodist.exe" }, # old version; it's the only install on 64-bit
  # Altair Monarch
  @{Name = "Altair Monarch 2021"; TargetPath = "C:\Program Files\Altair Monarch 2021\DWMonarch.exe"; SystemLnk = "Altair Monarch 2021\" },
  @{Name = "Altair Monarch 2021 (32-bit)"; TargetPath = "C:\Program Files (x86)\Altair Monarch 2021\DWMonarch.exe"; SystemLnk = "Altair Monarch 2021\" },
  @{Name = "Altair Monarch 2020"; TargetPath = "C:\Program Files\Altair Monarch 2020\DWMonarch.exe"; SystemLnk = "Altair Monarch 2020\" },
  @{Name = "Altair Monarch 2020 (32-bit)"; TargetPath = "C:\Program Files (x86)\Altair Monarch 2020\DWMonarch.exe"; SystemLnk = "Altair Monarch 2020\" },
  # AmbiBox
  @{Name = "AmbiBox Web Site"; TargetPath = "C:\Program Files\AmbiBox\www.ambibox.ru.url"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "AmbiBox"; TargetPath = "C:\Program Files\AmbiBox\AmbiBox.exe"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "Android AmbiBox Remote App"; TargetPath = "C:\Program Files\AmbiBox\Android AmbiBox Remote App"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "MediaPortal Extension"; TargetPath = "C:\Program Files\AmbiBox\MediaPortal Extension"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "Uninstall AmbiBox"; TargetPath = "C:\Program Files\AmbiBox\unins000.exe"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "AmbiBox Web Site"; TargetPath = "C:\Program Files (x86)\AmbiBox\www.ambibox.ru.url"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files (x86)\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "AmbiBox"; TargetPath = "C:\Program Files (x86)\AmbiBox\AmbiBox.exe"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files (x86)\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "Android AmbiBox Remote App"; TargetPath = "C:\Program Files (x86)\AmbiBox\Android AmbiBox Remote App"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files (x86)\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "MediaPortal Extension"; TargetPath = "C:\Program Files (x86)\AmbiBox\MediaPortal Extension"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files (x86)\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "Uninstall AmbiBox"; TargetPath = "C:\Program Files (x86)\AmbiBox\unins000.exe"; SystemLnk = "AmbiBox\"; StartIn = "C:\Program Files (x86)\AmbiBox" }, # it's the only install on 64-bit
  # Audacity
  @{Name = "Audacity"; TargetPath = "C:\Program Files\Audacity\Audacity.exe"; StartIn = "C:\Program Files\Audacity" },
  @{Name = "Audacity (32-bit)"; TargetPath = "C:\Program Files (x86)\Audacity\Audacity.exe"; StartIn = "C:\Program Files (x86)\Audacity" },
  # AutoHotkey
  @{Name = "AutoHotkey Help File"; TargetPath = "C:\Program Files\AutoHotkey\AutoHotkey.chm"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Setup"; TargetPath = "C:\Program Files\AutoHotkey\Installer.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey"; TargetPath = "C:\Program Files\AutoHotkey\AutoHotkey.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Convert .ahk to .exe"; TargetPath = "C:\Program Files\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Website"; TargetPath = "C:\Program Files\AutoHotkey\AutoHotkey Website.url"; SystemLnk = "AutoHotkey\" },
  @{Name = "Window Spy"; TargetPath = "C:\Program Files\AutoHotkey\WindowSpy.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Help File"; TargetPath = "C:\Program Files (x86)\AutoHotkey\AutoHotkey.chm"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Setup"; TargetPath = "C:\Program Files (x86)\AutoHotkey\Installer.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey (32-bit)"; TargetPath = "C:\Program Files (x86)\AutoHotkey\AutoHotkey.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Convert .ahk to .exe (32-bit)"; TargetPath = "C:\Program Files (x86)\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Website"; TargetPath = "C:\Program Files (x86)\AutoHotkey\AutoHotkey Website.url"; SystemLnk = "AutoHotkey\" },
  @{Name = "Window Spy"; TargetPath = "C:\Program Files (x86)\AutoHotkey\WindowSpy.ahk"; SystemLnk = "AutoHotkey\" },
  # Bulk Crap Uninstaller
  @{Name = "BCUninstaller"; TargetPath = "C:\Program Files\BCUninstaller\BCUninstaller.exe"; SystemLnk = "BCUninstaller\"; StartIn = "C:\Program Files\BCUninstaller" },
  @{Name = "Uninstall BCUninstaller"; TargetPath = "C:\Program Files\BCUninstaller\unins000.exe"; SystemLnk = "BCUninstaller\"; StartIn = "C:\Program Files\BCUninstaller" },
  @{Name = "BCUninstaller (32-bit)"; TargetPath = "C:\Program Files (x86)\BCUninstaller\BCUninstaller.exe"; SystemLnk = "BCUninstaller\"; StartIn = "C:\Program Files (x86)\BCUninstaller" },
  @{Name = "Uninstall BCUninstaller (32-bit)"; TargetPath = "C:\Program Files (x86)\BCUninstaller\unins000.exe"; SystemLnk = "BCUninstaller\"; StartIn = "C:\Program Files (x86)\BCUninstaller" },
  # Bytello
  @{Name = "Bytello Share"; TargetPath = "C:\Program Files\Bytello Share\Bytello Share.exe"; SystemLnk = "Bytello Share\"; StartIn = "C:\Program Files\Bytello Share" }, # it's the only install on 32-bit
  @{Name = "Bytello Share"; TargetPath = "C:\Program Files (x86)\Bytello Share\Bytello Share.exe"; SystemLnk = "Bytello Share\"; StartIn = "C:\Program Files (x86)\Bytello Share" }, # it's the only install on 64-bit
  # Cisco
  @{Name = "Cisco AnyConnect Secure Mobility Client"; TargetPath = "C:\Program Files\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"; SystemLnk = "C:\Program Files\Cisco\Cisco AnyConnect Secure Mobility Client\"; Description = "Cisco AnyConnect Secure Mobility Client" }, # it's the only install on 32-bit
  @{Name = "Cisco AnyConnect Secure Mobility Client"; TargetPath = "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"; SystemLnk = "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\"; Description = "Cisco AnyConnect Secure Mobility Client" }, # it's the only install on 64-bit
  # Citrix Workspace
  @{Name = "Citrix Workspace"; TargetPath = "C:\Program Files\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"; Arguments = "-showAppPicker"; StartIn = "C:\Program Files\Citrix\ICA Client\SelfServicePlugin\"; Description = "Select applications you want to use on your computer" }, # it's the only install on 32-bit
  @{Name = "Citrix Workspace"; TargetPath = "C:\Program Files (x86)\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"; Arguments = "-showAppPicker"; StartIn = "C:\Program Files (x86)\Citrix\ICA Client\SelfServicePlugin\"; Description = "Select applications you want to use on your computer" }, # it's the only install on 64-bit
  # CodeTwo Active Directory Photos
  @{Name = "CodeTwo Active Directory Photos"; TargetPath = "C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos" },
  @{Name = "Go to program home page"; TargetPath = "C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos home page" },
  @{Name = "User's manual"; TargetPath = "C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "Go to User Guide" },
  @{Name = "CodeTwo Active Directory Photos (32-bit)"; TargetPath = "C:\Program Files (x86)\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos" },
  @{Name = "Go to program home page"; TargetPath = "C:\Program Files (x86)\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos home page" },
  @{Name = "User's manual"; TargetPath = "C:\Program Files (x86)\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "Go to User Guide" },
  # Docker
  @{Name = "Docker Desktop"; TargetPath = "C:\Program Files\Docker\Docker\Docker Desktop.exe"; SystemLnk = "C:\ProgramData\Microsoft\Windows\Start Menu\"; Description = "Docker Desktop" },
  # draw.io
  @{Name = "draw.io"; TargetPath = "C:\Program Files\draw.io\draw.io.exe"; StartIn = "C:\Program Files\draw.io"; Description = "draw.io desktop" },
  @{Name = "draw.io (32-bit)"; TargetPath = "C:\Program Files (x86)\draw.io\draw.io.exe"; StartIn = "C:\Program Files (x86)\draw.io"; Description = "draw.io desktop" },
  # Egnyte
  @{Name = "Egnyte Desktop App"; TargetPath = "C:\Program Files\Egnyte Connect\EgnyteClient.exe"; Arguments = "--short-menu"; SystemLnk = "Egnyte Connect\"; StartIn = "C:\Program Files\Egnyte Connect\" }, # it's the only install on 32-bit
  @{Name = "Egnyte Desktop App"; TargetPath = "C:\Program Files (x86)\Egnyte Connect\EgnyteClient.exe"; Arguments = "--short-menu"; SystemLnk = "Egnyte Connect\"; StartIn = "C:\Program Files (x86)\Egnyte Connect\" }, # it's the only install on 64-bit
  @{Name = "Uninstall Egnyte Desktop App"; TargetPath = $EgnyteDesktopAppUninstall_TargetPath; Arguments = $EgnyteDesktopAppUninstall_Arguments; SystemLnk = "Egnyte Connect\"; Description = "Uninstalls Egnyte Desktop App" },
  # Epson
  @{Name = "Epson Scan 2"; TargetPath = "C:\Program Files\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk = "EPSON\Epson Scan 2\" }, # it's the only install on 32-bit
  @{Name = "FAX Utility"; TargetPath = "C:\Program Files\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk = "EPSON Software\" }, # it's the only install on 32-bit
  @{Name = "Epson Scan 2"; TargetPath = "C:\Program Files (x86)\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk = "EPSON\Epson Scan 2\" }, # it's the only install on 64-bit
  @{Name = "FAX Utility"; TargetPath = "C:\Program Files (x86)\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk = "EPSON Software\" }, # it's the only install on 64-bit
  # GIMP
  @{Name = $GIMP_Name; TargetPath = $GIMP_TargetPath; StartIn = "%USERPROFILE%"; Description = $GIMP_Name },
  @{Name = $GIMP_32bit_Name; TargetPath = $GIMP_32bit_TargetPath; StartIn = "%USERPROFILE%"; Description = $GIMP_32bit_Name },
  # Google
  @{Name = "Google Chrome"; TargetPath = "C:\Program Files\Google\Chrome\Application\chrome.exe"; StartIn = "C:\Program Files\Google\Chrome\Application"; Description = "Access the Internet" },
  @{Name = "Google Chrome (32-bit)"; TargetPath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"; StartIn = "C:\Program Files (x86)\Google\Chrome\Application"; Description = "Access the Internet" },
  @{Name = "Google Drive"; TargetPath = $GoogleDrive_TargetPath; Description = "Google Drive" },
  @{Name = "VPN by Google One"; TargetPath = $GoogleOneVPN_TargetPath; Description = "VPN by Google One" },
  # GoTo
  @{Name = "GoTo Resolve Desktop Console (64-bit)"; TargetPath = "C:\Program Files\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn = "C:\Program Files\GoTo\GoTo Resolve Desktop Console\" },
  @{Name = "GoTo Resolve Desktop Console (32-bit)"; TargetPath = "C:\Program Files (x86)\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn = "C:\Program Files (x86)\GoTo\GoTo Resolve Desktop Console\" },
  # KC Softwares
  @{Name = "SUMo"; TargetPath = "C:\Program Files\KC Softwares\SUMo\SUMo.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "C:\Program Files\KC Softwares\SUMo" }, # it's the only install on 32-bit
  @{Name = "Uninstall SUMo"; TargetPath = "C:\Program Files\KC Softwares\SUMo\unins000.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "C:\Program Files\KC Softwares\SUMo" }, # it's the only install on 32-bit
  @{Name = "SUMo"; TargetPath = "C:\Program Files (x86)\KC Softwares\SUMo\SUMo.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "C:\Program Files (x86)\KC Softwares\SUMo" }, # it's the only install on 64-bit
  @{Name = "Uninstall SUMo"; TargetPath = "C:\Program Files (x86)\KC Softwares\SUMo\unins000.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "C:\Program Files (x86)\KC Softwares\SUMo" }, # it's the only install on 64-bit
  # Kdenlive
  @{Name = "Kdenlive"; TargetPath = "C:\Program Files\kdenlive\bin\kdenlive.exe"; StartIn = "{workingDirectory}"; Description = "Libre Video Editor, by KDE community" },
  @{Name = "Kdenlive (32-bit)"; TargetPath = "C:\Program Files (x86)\kdenlive\bin\kdenlive.exe"; StartIn = "{workingDirectory}"; Description = "Libre Video Editor, by KDE community" },
  # KeePass
  @{Name = $KeePass_Name; TargetPath = $KeePass_TargetPath; StartIn = $KeePass_StartIn }, # new version 2+
  @{Name = $KeePass_32bit_Name; TargetPath = $KeePass_32bit_TargetPath; StartIn = $KeePass_32bit_StartIn }, # new version 2+
  @{Name = "KeePass"; TargetPath = "C:\Program Files\KeePass Password Safe\KeePass.exe"; StartIn = "C:\Program Files\KeePass Password Safe" }, # old version 1.x; it's the only install on 32-bit
  @{Name = "KeePass"; TargetPath = "C:\Program Files (x86)\KeePass Password Safe\KeePass.exe"; StartIn = "C:\Program Files (x86)\KeePass Password Safe" }, # old version 1.x; it's the only install on 64-bit
  # Ledger Live
  @{Name = "Ledger Live"; TargetPath = "C:\Program Files\Ledger Live\Ledger Live.exe"; StartIn = "C:\Program Files\Ledger Live"; Description = "Ledger Live - Desktop" },
  @{Name = "Ledger Live (32-bit)"; TargetPath = "C:\Program Files (x86)\Ledger Live\Ledger Live.exe"; StartIn = "C:\Program Files (x86)\Ledger Live"; Description = "Ledger Live - Desktop" },
  # Local Administrator Password Solution
  @{Name = "LAPS UI"; TargetPath = "C:\Program Files\LAPS\AdmPwd.UI.exe"; SystemLnk = "LAPS\"; StartIn = "C:\Program Files\LAPS\" },
  @{Name = "LAPS UI (32-bit)"; TargetPath = "C:\Program Files (x86)\LAPS\AdmPwd.UI.exe"; SystemLnk = "LAPS\"; StartIn = "C:\Program Files (x86)\LAPS\" },
  # Maxon
  @{Name = $MaxonCinema4D_Commandline_Name; TargetPath = $MaxonCinema4D_Commandline_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Commandline" },
  @{Name = $MaxonCinema4D_Name; TargetPath = $MaxonCinema4D_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Maxon Cinema 4D" },
  @{Name = $MaxonCinema4D_TeamRenderClient_Name; TargetPath = $MaxonCinema4D_TeamRenderClient_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Team Render Client" },
  @{Name = $MaxonCinema4D_TeamRenderServer_Name; TargetPath = $MaxonCinema4D_TeamRenderServer_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Team Render Server" },
  # Mozilla
  @{Name = "Firefox"; TargetPath = "C:\Program Files\Mozilla Firefox\firefox.exe"; StartIn = "C:\Program Files\Mozilla Firefox" },
  @{Name = "Firefox Private Browsing"; TargetPath = "C:\Program Files\Mozilla Firefox\private_browsing.exe"; StartIn = "C:\Program Files\Mozilla Firefox"; Description = "Firefox Private Browsing" },
  @{Name = "Firefox (32-bit)"; TargetPath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"; StartIn = "C:\Program Files (x86)\Mozilla Firefox" },
  @{Name = "Firefox Private Browsing (32-bit)"; TargetPath = "C:\Program Files (x86)\Mozilla Firefox\private_browsing.exe"; StartIn = "C:\Program Files (x86)\Mozilla Firefox"; Description = "Firefox Private Browsing" },
  @{Name = "Thunderbird"; TargetPath = "C:\Program Files\Mozilla Thunderbird\thunderbird.exe"; StartIn = "C:\Program Files\Mozilla Thunderbird" },
  @{Name = "Thunderbird (32-bit)"; TargetPath = "C:\Program Files (x86)\Mozilla Thunderbird\thunderbird.exe"; StartIn = "C:\Program Files (x86)\Mozilla Thunderbird" },
  # Notepad++
  @{Name = "Notepad++"; TargetPath = "C:\Program Files\Notepad++\notepad++.exe"; StartIn = "C:\Program Files\Notepad++" },
  @{Name = "Notepad++ (32-bit)"; TargetPath = "C:\Program Files (x86)\Notepad++\notepad++.exe"; StartIn = "C:\Program Files (x86)\Notepad++" },
  # OpenVPN
  @{Name = "OpenVPN"; TargetPath = "C:\Program Files\OpenVPN\bin\openvpn-gui.exe"; SystemLnk = "OpenVPN\OpenVPN GUI"; StartIn = "C:\Program Files\OpenVPN\bin\" },
  @{Name = "OpenVPN Manual Page"; TargetPath = "C:\Program Files\OpenVPN\doc\openvpn.8.html"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "C:\Program Files\OpenVPN\doc\" },
  @{Name = "OpenVPN Windows Notes"; TargetPath = "C:\Program Files\OpenVPN\doc\INSTALL-win32.txt"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "C:\Program Files\OpenVPN\doc\" },
  @{Name = "OpenVPN Configuration File Directory"; TargetPath = "C:\Program Files\OpenVPN\config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files\OpenVPN\config\" },
  @{Name = "OpenVPN Log File Directory"; TargetPath = "C:\Program Files\OpenVPN\log"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files\OpenVPN\log\" },
  @{Name = "OpenVPN Sample Configuration Files"; TargetPath = "C:\Program Files\OpenVPN\sample-config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files\OpenVPN\sample-config\" },
  @{Name = "Add a new TAP-Windows6 virtual network adapter"; TargetPath = "C:\Program Files\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid root\tap0901"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "C:\Program Files\OpenVPN\bin\" },
  @{Name = "Add a new Wintun virtual network adapter"; TargetPath = "C:\Program Files\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid wintun"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "C:\Program Files\OpenVPN\bin\" },
  @{Name = "OpenVPN (32-bit)"; TargetPath = "C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe"; SystemLnk = "OpenVPN\OpenVPN GUI"; StartIn = "C:\Program Files (x86)\OpenVPN\bin\" },
  @{Name = "OpenVPN Manual Page"; TargetPath = "C:\Program Files (x86)\OpenVPN\doc\openvpn.8.html"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "C:\Program Files (x86)\OpenVPN\doc\" },
  @{Name = "OpenVPN Windows Notes"; TargetPath = "C:\Program Files (x86)\OpenVPN\doc\INSTALL-win32.txt"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "C:\Program Files (x86)\OpenVPN\doc\" },
  @{Name = "OpenVPN Configuration File Directory"; TargetPath = "C:\Program Files (x86)\OpenVPN\config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files (x86)\OpenVPN\config\" },
  @{Name = "OpenVPN Log File Directory"; TargetPath = "C:\Program Files (x86)\OpenVPN\log"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files (x86)\OpenVPN\log\" },
  @{Name = "OpenVPN Sample Configuration Files"; TargetPath = "C:\Program Files (x86)\OpenVPN\sample-config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "C:\Program Files (x86)\OpenVPN\sample-config\" },
  @{Name = "Add a new TAP-Windows6 virtual network adapter (32-bit)"; TargetPath = "C:\Program Files (x86)\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid root\tap0901"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "C:\Program Files (x86)\OpenVPN\bin\" },
  @{Name = "Add a new Wintun virtual network adapter (32-bit)"; TargetPath = "C:\Program Files (x86)\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid wintun"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "C:\Program Files (x86)\OpenVPN\bin\" },
  # Oracle
  @{Name = "License (English)"; TargetPath = "C:\Program Files\Oracle\VirtualBox\License_en_US.rtf"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "C:\Program Files\Oracle\VirtualBox\"; Description = "License" },
  @{Name = "Oracle VM VirtualBox"; TargetPath = "C:\Program Files\Oracle\VirtualBox\VirtualBox.exe"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "C:\Program Files\Oracle\VirtualBox\"; Description = "Oracle VM VirtualBox" },
  @{Name = "User manual (CHM, English)"; TargetPath = "C:\Program Files\Oracle\VirtualBox\VirtualBox.chm"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "User manual (PDF, English)"; TargetPath = "C:\Program Files\Oracle\VirtualBox\doc\UserManual.pdf"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "License (English)"; TargetPath = "C:\Program Files (x86)\Oracle\VirtualBox\License_en_US.rtf"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "C:\Program Files (x86)\Oracle\VirtualBox\"; Description = "License" },
  @{Name = "Oracle VM VirtualBox (32-bit)"; TargetPath = "C:\Program Files (x86)\Oracle\VirtualBox\VirtualBox.exe"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "C:\Program Files (x86)\Oracle\VirtualBox\"; Description = "Oracle VM VirtualBox" },
  @{Name = "User manual (CHM, English)"; TargetPath = "C:\Program Files (x86)\Oracle\VirtualBox\VirtualBox.chm"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "User manual (PDF, English)"; TargetPath = "C:\Program Files (x86)\Oracle\VirtualBox\doc\UserManual.pdf"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  # OSFMount
  @{Name = "OSFMount Documentation"; TargetPath = "C:\Program Files\OSFMount\osfmount_Help.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files\OSFMount" },
  @{Name = "OSFMount on the Web"; TargetPath = "C:\Program Files\OSFMount\OSFMount.url"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files\OSFMount" },
  @{Name = "OSFMount"; TargetPath = "C:\Program Files\OSFMount\OSFMount.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files\OSFMount" },
  @{Name = "Uninstall OSFMount"; TargetPath = "C:\Program Files\OSFMount\unins000.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files\OSFMount" },
  @{Name = "OSFMount Documentation (32-bit)"; TargetPath = "C:\Program Files (x86)\OSFMount\osfmount_Help.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files (x86)\OSFMount" },
  @{Name = "OSFMount on the Web"; TargetPath = "C:\Program Files (x86)\OSFMount\OSFMount.url"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files (x86)\OSFMount" },
  @{Name = "OSFMount (32-bit)"; TargetPath = "C:\Program Files (x86)\OSFMount\OSFMount.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files (x86)\OSFMount" },
  @{Name = "Uninstall OSFMount (32-bit)"; TargetPath = "C:\Program Files (x86)\OSFMount\unins000.exe"; SystemLnk = "OSFMount\"; StartIn = "C:\Program Files (x86)\OSFMount" },
  # paint.net
  @{Name = "paint.net"; TargetPath = "C:\Program Files\paint.net\paintdotnet.exe"; StartIn = "C:\Program Files\paint.net"; Description = "Create, edit, scan, and print images and photographs." },
  @{Name = "paint.net (32-bit)"; TargetPath = "C:\Program Files (x86)\paint.net\paintdotnet.exe"; StartIn = "C:\Program Files (x86)\paint.net"; Description = "Create, edit, scan, and print images and photographs." },
  # RealVNC
  @{Name = "VNC Server"; TargetPath = "C:\Program Files\RealVNC\VNC Server\vncguihelper.exe"; Arguments = "vncserver.exe -_fromGui -start -showstatus"; SystemLnk = "RealVNC\"; StartIn = "C:\Program Files\RealVNC\VNC Server\" },
  @{Name = "VNC Server (32-bit)"; TargetPath = "C:\Program Files (x86)\RealVNC\VNC Server\vncguihelper.exe"; Arguments = "vncserver.exe -_fromGui -start -showstatus"; SystemLnk = "RealVNC\"; StartIn = "C:\Program Files (x86)\RealVNC\VNC Server\" },
  @{Name = "VNC Viewer"; TargetPath = "C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe"; SystemLnk = "RealVNC\"; StartIn = "C:\Program Files\RealVNC\VNC Viewer\" },
  @{Name = "VNC Viewer (32-bit)"; TargetPath = "C:\Program Files (x86)\RealVNC\VNC Viewer\vncviewer.exe"; SystemLnk = "RealVNC\"; StartIn = "C:\Program Files (x86)\RealVNC\VNC Viewer\" },
  # Samsung
  @{Name = "Samsung DeX"; TargetPath = "C:\Program Files\Samsung\Samsung DeX\SamsungDeX.exe"; StartIn = "C:\Program Files\Samsung\Samsung DeX\" }, # it's the only install on 32-bit
  @{Name = "Samsung DeX"; TargetPath = "C:\Program Files (x86)\Samsung\Samsung DeX\SamsungDeX.exe"; StartIn = "C:\Program Files (x86)\Samsung\Samsung DeX\" }, # it's the only install on 64-bit
  # SonicWall Global VPN Client
  @{Name = "Global VPN Client"; TargetPath = "C:\Program Files\SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "C:\Program Files\SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  @{Name = "Global VPN Client (32-bit)"; TargetPath = "C:\Program Files (x86)\SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "C:\Program Files (x86)\SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  # SoundSwitch
  @{Name = "SoundSwitch"; TargetPath = "C:\Program Files\SoundSwitch\SoundSwitch.exe"; SystemLnk = "SoundSwitch\"; StartIn = "C:\Program Files\SoundSwitch" },
  @{Name = "SoundSwitch (32-bit)"; TargetPath = "C:\Program Files (x86)\SoundSwitch\SoundSwitch.exe"; SystemLnk = "SoundSwitch\"; StartIn = "C:\Program Files (x86)\SoundSwitch" },
  @{Name = "Uninstall SoundSwitch"; TargetPath = "C:\Program Files\SoundSwitch\unins000.exe"; SystemLnk = "SoundSwitch\"; StartIn = "C:\Program Files\SoundSwitch" },
  @{Name = "Uninstall SoundSwitch (32-bit)"; TargetPath = "C:\Program Files (x86)\SoundSwitch\unins000.exe"; SystemLnk = "SoundSwitch\"; StartIn = "C:\Program Files (x86)\SoundSwitch" },
  # USB Redirector TS Edition
  @{Name = "USB Redirector TS Edition - Workstation"; TargetPath = "C:\Program Files\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk = "USB Redirector TS Edition - Workstation\" },
  @{Name = "USB Redirector TS Edition - Workstation (32-bit)"; TargetPath = "C:\Program Files (x86)\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk = "USB Redirector TS Edition - Workstation\" },
  # VideoLAN
  @{Name = "Documentation"; TargetPath = "C:\Program Files\VideoLAN\VLC\Documentation.url"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "Release Notes"; TargetPath = "C:\Program Files\VideoLAN\VLC\NEWS.txt"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "VideoLAN Website"; TargetPath = "C:\Program Files\VideoLAN\VLC\VideoLAN Website.url"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "VLC media player - reset preferences and cache files"; TargetPath = "C:\Program Files\VideoLAN\VLC\vlc.exe"; Arguments = "--reset-config --reset-plugins-cache vlc://quit"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "VLC media player skinned"; TargetPath = "C:\Program Files\VideoLAN\VLC\vlc.exe"; Arguments = "-Iskins"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "VLC media player"; TargetPath = "C:\Program Files\VideoLAN\VLC\vlc.exe"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files\VideoLAN\VLC" },
  @{Name = "Documentation"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\Documentation.url"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  @{Name = "Release Notes"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\NEWS.txt"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  @{Name = "VideoLAN Website"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\VideoLAN Website.url"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  @{Name = "VLC media player - reset preferences and cache files (32-bit)"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\vlc.exe"; Arguments = "--reset-config --reset-plugins-cache vlc://quit"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  @{Name = "VLC media player skinned (32-bit)"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\vlc.exe"; Arguments = "-Iskins"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  @{Name = "VLC media player (32-bit)"; TargetPath = "C:\Program Files x86\VideoLAN\VLC\vlc.exe"; SystemLnk = "VideoLAN\"; StartIn = "C:\Program Files x86\VideoLAN\VLC" },
  # VMware
  @{Name = "Command Prompt for vctl"; TargetPath = $CommandPromptforvctl_Path; Arguments = "/k set PATH=C:\Program Files\VMware\VMware Player\;%PATH% && vctl.exe -h"; SystemLnk = "VMware\"; StartIn = "C:\Program Files\VMware\VMware Player\bin\" }, # it's the only install on 32-bit
  @{Name = $VMwareWorkstationPlayer_Name; TargetPath = $VMwareWorkstationPlayer_TargetPath; SystemLnk = "VMware\"; StartIn = "C:\Program Files\VMware\VMware Player\" }, # it's the only install on 32-bit
  @{Name = "Command Prompt for vctl"; TargetPath = $CommandPromptforvctl_32bit_Path; Arguments = "/k set PATH=C:\Program Files (x86)\VMware\VMware Player\;%PATH% && vctl.exe -h"; SystemLnk = "VMware\"; StartIn = "C:\Program Files (x86)\VMware\VMware Player\bin\" }, # it's the only install on 64-bit
  @{Name = $VMwareWorkstationPlayer_32bit_Name; TargetPath = $VMwareWorkstationPlayer_32bit_TargetPath; SystemLnk = "VMware\"; StartIn = "C:\Program Files (x86)\VMware\VMware Player\" }, # it's the only install on 64-bit
  # Win32DiskImager
  @{Name = "Uninstall Win32DiskImager"; TargetPath = "C:\Program Files\ImageWriter\unins000.exe"; SystemLnk = "Image Writer\"; StartIn = "C:\Program Files\ImageWriter" }, # it's the only install on 32-bit
  @{Name = "Win32DiskImager"; TargetPath = "C:\Program Files\ImageWriter\Win32DiskImager.exe"; SystemLnk = "Image Writer\"; StartIn = "C:\Program Files\ImageWriter" }, # it's the only install on 32-bit
  @{Name = "Uninstall Win32DiskImager"; TargetPath = "C:\Program Files (x86)\ImageWriter\unins000.exe"; SystemLnk = "Image Writer\"; StartIn = "C:\Program Files (x86)\ImageWriter" }, # it's the only install on 64-bit
  @{Name = "Win32DiskImager"; TargetPath = "C:\Program Files (x86)\ImageWriter\Win32DiskImager.exe"; SystemLnk = "Image Writer\"; StartIn = "C:\Program Files (x86)\ImageWriter" }, # it's the only install on 64-bit
  # Winaero
  @{Name = "EULA"; TargetPath = "C:\Program Files\Winaero Tweaker\Winaero EULA.txt"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files\Winaero Tweaker"; Description = "Read the license agreement" },
  @{Name = "Winaero Tweaker"; TargetPath = "C:\Program Files\Winaero Tweaker\WinaeroTweaker.exe"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files\Winaero Tweaker" },
  @{Name = "Winaero Website"; TargetPath = "C:\Program Files\Winaero Tweaker\Winaero.url"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files\Winaero Tweaker"; Description = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user." },
  @{Name = "EULA"; TargetPath = "C:\Program Files (x86)\Winaero Tweaker\Winaero EULA.txt"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files (x86)\Winaero Tweaker"; Description = "Read the license agreement" },
  @{Name = "Winaero Tweaker (32-bit)"; TargetPath = "C:\Program Files (x86)\Winaero Tweaker\WinaeroTweaker.exe"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files (x86)\Winaero Tweaker" },
  @{Name = "Winaero Website"; TargetPath = "C:\Program Files (x86)\Winaero Tweaker\Winaero.url"; SystemLnk = "Winaero Tweaker\"; StartIn = "C:\Program Files (x86)\Winaero Tweaker"; Description = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user." },
  # WinSCP
  @{Name = "WinSCP"; TargetPath = "C:\Program Files\WinSCP\WinSCP.exe"; StartIn = "C:\Program Files\WinSCP"; Description = "WinSCP: SFTP, FTP, WebDAV and SCP client" }, # it's the only install on 32-bit
  @{Name = "WinSCP"; TargetPath = "C:\Program Files (x86)\WinSCP\WinSCP.exe"; StartIn = "C:\Program Files (x86)\WinSCP"; Description = "WinSCP: SFTP, FTP, WebDAV and SCP client" } # it's the only install on 64-bit
  #@{ Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; IconLocation=""; RunAsAdmin=($true -Or $false) },
)

for ($i = 0; $i -lt $sys3rdPartyAppList.length; $i++) {
  $app = $sys3rdPartyAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aStartIn = if ($app.StartIn) { $app.StartIn } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $ScriptResults = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -il $aIconLocation -r $aRunAsAdmin
}



# User Applications (per user installed apps)

# get all users 
$Users = (Get-ChildItem -Directory -Path "C:\Users\" | ForEach-Object { if (($_.name -ne "Default") -And ($_.name -ne "Public")) { $_.name } })
if ($Users -And ($Users[0].length -eq 1)) { $Users = @("$Users") } # if only one user, array needs to be recreated

# System app arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# System app paths dependant on app version

# Adobe
$AdobeDigitalEditions_TargetPath = "C:\Program Files\Adobe\"
$AdobeDigitalEditions_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Descending) }
$AdobeDigitalEditions_FindFolder = if ($AdobeDigitalEditions_FindFolders.length -ge 1) { $AdobeDigitalEditions_FindFolders[0].name } else { $NotInstalled }
$AdobeDigitalEditions_TargetPath += "${AdobeDigitalEditions_FindFolder}\DigitalEditions.exe"
$AdobeDigitalEditions_32bit_TargetPath = "C:\Program Files (x86)\Adobe\"
$AdobeDigitalEditions_32bit_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_32bit_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Descending) }
$AdobeDigitalEditions_32bit_FindFolder = if ($AdobeDigitalEditions_32bit_FindFolders.length -ge 1) { $AdobeDigitalEditions_32bit_FindFolders[0].name } else { $NotInstalled }
$AdobeDigitalEditions_32bit_TargetPath += "${AdobeDigitalEditions_32bit_FindFolder}\DigitalEditions.exe"
# Blender
$Blender_TargetPath = "C:\Program Files\Blender Foundation\"
$Blender_FindFolder = if (Test-Path -Path $Blender_TargetPath) { Get-ChildItem -Directory -Path $Blender_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Descending }
$Blender_FindFolder = if ($Blender_FindFolder.length -ge 1) { $Blender_FindFolder[0].name } else { $NotInstalled }
$Blender_StartIn = $Blender_TargetPath + "${Blender_FindFolder}\"
$Blender_TargetPath = $Blender_StartIn + "blender-launcher.exe"
$Blender_32bit_TargetPath = "C:\Program Files (x86)\Blender Foundation\"
$Blender_32bit_FindFolder = if (Test-Path -Path $Blender_32bit_TargetPath) { Get-ChildItem -Directory -Path $Blender_32bit_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Descending }
$Blender_32bit_FindFolder = if ($Blender_32bit_FindFolder.length -ge 1) { $Blender_32bit_FindFolder[0].name } else { $NotInstalled }
$Blender_32bit_StartIn = $Blender_32bit_TargetPath + "${Blender_32bit_FindFolder}\"
$Blender_32bit_TargetPath = $Blender_32bit_StartIn + "blender-launcher.exe"

# System app names dependant on OS or app version

# Adobe
$AdobeDigitalEditions_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_TargetPath -PathType Leaf) { (Get-Item $AdobeDigitalEditions_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_Version = if ($AdobeDigitalEditions_FileVersionRaw) { [string]($AdobeDigitalEditions_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_FileVersionRaw.Minor) } else { $NotInstalled }
$AdobeDigitalEditions_Name = "Adobe Digital Editions ${AdobeDigitalEditions_Version}"
$AdobeDigitalEditions_32bit_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath -PathType Leaf) { (Get-Item $AdobeDigitalEditions_32bit_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_32bit_Version = if ($AdobeDigitalEditions_32bit_FileVersionRaw) { [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Minor) } else { $NotInstalled }
$AdobeDigitalEditions_32bit_Name = "Adobe Digital Editions ${AdobeDigitalEditions_32bit_Version}"

# App names dependant on OS or app version

# Microsoft Teams
$MicrosoftTeams_Name = "Microsoft Teams" + $(if ($isWindows11) { " (work or school)" })

for ($i = 0; $i -lt $Users.length; $i++) {
  # get user
  $aUser = $Users[$i]

  # User app paths dependant on app version

  # 1Password
  $OnePassword_TargetPath = "C:\Users\${aUser}\AppData\Local\1Password\app\"
  $OnePassword_FindFolder = if (Test-Path -Path $OnePassword_TargetPath) { Get-ChildItem -Directory -Path $OnePassword_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
  $OnePassword_FindFolder = if ($OnePassword_FindFolder.length -ge 1) { $OnePassword_FindFolder[0].name } else { $NotInstalled }
  $OnePassword_TargetPath += "${OnePassword_FindFolder}\1Password.exe"
  # Adobe
  $AdobeDigitalEditions_StartIn = "C:\Users\${aUser}\AppData\Local\Temp"
  # Discord
  $Discord_StartIn = "C:\Users\${aUser}\AppData\Local\Discord\"
  $Discord_TargetPath = $Discord_StartIn + "Update.exe"
  $Discord_FindFolder = if (Test-Path -Path $Discord_StartIn) { Get-ChildItem -Directory -Path $Discord_StartIn | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Descending }
  $Discord_FindFolder = if ($Discord_FindFolder.length -ge 1) { $Discord_FindFolder[0].name } else { $NotInstalled }
  $Discord_StartIn += $Discord_FindFolder
  # GitHub
  $GitHubDesktop_StartIn = "C:\Users\${aUser}\AppData\Local\GitHubDesktop\"
  $GitHubDesktop_TargetPath = $GitHubDesktop_StartIn + "GitHubDesktop.exe"
  $GitHubDesktop_FindFolder = if (Test-Path -Path $GitHubDesktop_StartIn) { Get-ChildItem -Directory -Path $GitHubDesktop_StartIn | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Descending }
  $GitHubDesktop_FindFolder = if ($GitHubDesktop_FindFolder.length -ge 1) { $GitHubDesktop_FindFolder[0].name } else { $NotInstalled }
  $GitHubDesktop_StartIn += $GitHubDesktop_FindFolder
  # Microsoft
  $AzureIoTExplorerPreview_TargetPath = "C:\Users\${aUser}\AppData\Local\Programs\azure-iot-explorer\Azure IoT Explorer Preview.exe"
  $AzureIoTExplorer_TargetPath = if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType Leaf) { $AzureIoTExplorerPreview_TargetPath } else { "C:\Users\${aUser}\AppData\Local\Programs\azure-iot-explorer\Azure IoT Explorer.exe" }
  $AzureIoTExplorer_Name = "Azure IoT Explorer" + $(if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType Leaf) { " Preview" })
  # Python
  $Python_StartIn = "C:\Users\${aUser}\AppData\Local\Programs\Python\"
  $Python_FindFolder = if (Test-Path -Path $Python_StartIn) { Get-ChildItem -Directory -Path $Python_StartIn | Where-Object { $_.Name -match '^Python[.0-9]+$' } | Sort-Object -Descending }
  $Python_FindFolder = if ($Python_FindFolder.length -ge 1) { $Python_FindFolder[0].name } else { $NotInstalled }
  $Python_StartIn += "${Python_FindFolder}\"
  $PythonIDLE_TargetPath = $Python_StartIn + "Lib\idlelib\idle.pyw"
  $Python_TargetPath = $Python_StartIn + "python.exe"
  $Python_FileVersionRaw = if (Test-Path -Path $Python_TargetPath -PathType Leaf) { (Get-Item $Python_TargetPath).VersionInfo.FileVersionRaw }
  $Python_Version = if ($Python_FileVersionRaw) { [string]($Python_FileVersionRaw.Major) + '.' + [string]($Python_FileVersionRaw.Minor) } else { $NotInstalled }
  $PythonIDLE_Description = "Launches IDLE, the interactive environment for Python ${Python_Version}."
  $Python_Description = "Launches the Python ${Python_Version} interpreter."
  $PythonModuleDocs_Description = "Start the Python ${Python_Version} documentation server."
  $Python_SystemLnk = "Python ${Python_Version}\"
  $Python_Info = if (Test-Path -Path $Python_TargetPath -PathType Leaf) { (& "${Python_TargetPath}" -VV) }
  $Python_Arch = if ($Python_Info) { if ($Python_Info | Select-String "\[[^\[\]]+32 bit[^\[\]]+\]") { 32 } elseif ($Python_Info | Select-String "\[[^\[\]]+64 bit[^\[\]]+\]") { 64 } else { "unknown" } } else { $NotInstalled }
  $PythonIDLE_Name = "IDLE (Python ${Python_Version} ${Python_Arch}-bit)"
  $Python_Name = "Python ${Python_Version} (${Python_Arch}-bit)"
  $PythonModuleDocs_Name = "Python ${Python_Version} Module Docs (${Python_Arch}-bit)"
  
  # User app names dependant on OS or app version

  $userAppList = @( # all instances of "${aUser}" get's replaced with the username
    # 1Password
    @{Name = "1Password"; TargetPath = $OnePassword_TargetPath; Description = "1Password" },
    # Adobe
    @{Name = $AdobeDigitalEditions_Name; TargetPath = $AdobeDigitalEditions_TargetPath; StartIn = $AdobeDigitalEditions_StartIn },
    @{Name = $AdobeDigitalEditions_32bit_Name; TargetPath = $AdobeDigitalEditions_32bit_TargetPath; StartIn = $AdobeDigitalEditions_StartIn },
    # balenaEtcher
    @{Name = "balenaEtcher"; TargetPath = "C:\Users\${aUser}\AppData\Local\Programs\balena-etcher\balenaEtcher.exe"; StartIn = "C:\Users\${aUser}\AppData\Local\Programs\balena-etcher"; Description = "Flash OS images to SD cards and USB drives, safely and easily." },
    # Blender
    @{Name = "Blender"; TargetPath = $Blender_TargetPath; SystemLnk = "blender\"; StartIn = $Blender_StartIn },
    @{Name = "Blender"; TargetPath = $Blender_32bit_TargetPath; SystemLnk = "blender\"; StartIn = $Blender_32bit_StartIn },
    # Discord
    @{Name = "Discord"; TargetPath = $Discord_TargetPath; Arguments = "--processStart Discord.exe"; SystemLnk = "Discord Inc\"; StartIn = $Discord_StartIn; Description = "Discord - https://discord.com" },
    # GitHub
    @{Name = "GitHub Desktop"; TargetPath = $GitHubDesktop_TargetPath; SystemLnk = "GitHub, Inc\"; StartIn = $GitHubDesktop_StartIn; Description = "Simple collaboration from your desktop" },
    # Google
    @{Name = "Google Chrome"; TargetPath = "C:\Users\${aUser}\AppData\Local\Google\Chrome\Application\chrome.exe"; StartIn = "C:\Users\${aUser}\AppData\Local\Google\Chrome\Application"; Description = "Access the Internet" },
    # Inkscape
    @{Name = "Inkscape"; TargetPath = "C:\Program Files\Inkscape\bin\inkscape.exe"; SystemLnk = "Inkscape\"; StartIn = "C:\Program Files\Inkscape\bin\" },
    @{Name = "Inkscape (32-bit)"; TargetPath = "C:\Program Files (x86)\Inkscape\bin\inkscape.exe"; SystemLnk = "Inkscape\"; StartIn = "C:\Program Files (x86)\Inkscape\bin\" },
    @{Name = "Inkview"; TargetPath = "C:\Program Files\Inkscape\bin\inkview.exe"; SystemLnk = "Inkscape\"; StartIn = "C:\Program Files\Inkscape\bin\" },
    @{Name = "Inkview (32-bit)"; TargetPath = "C:\Program Files (x86)\Inkscape\bin\inkview.exe"; SystemLnk = "Inkscape\"; StartIn = "C:\Program Files (x86)\Inkscape\bin\" },
    # Microsoft
    @{Name = "Azure Data Studio"; TargetPath = "C:\Users\${aUser}\AppData\Local\Programs\Azure Data Studio\azuredatastudio.exe"; SystemLnk = "Azure Data Studio\"; StartIn = "C:\Users\${aUser}\AppData\Local\Programs\Azure Data Studio" },
    @{Name = $AzureIoTExplorer_Name; TargetPath = $AzureIoTExplorer_TargetPath; StartIn = "C:\Users\${aUser}\AppData\Local\Programs\azure-iot-explorer\" },
    @{Name = "Visual Studio Code"; TargetPath = "C:\Users\${aUser}\AppData\Local\Programs\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "C:\Users\${aUser}\AppData\Local\Programs\Microsoft VS Code" },
    @{Name = "OneDrive"; TargetPath = "C:\Users\${aUser}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
    @{Name = $MicrosoftTeams_Name; TargetPath = "C:\Users\${aUser}\AppData\Local\Microsoft\Teams\Update.exe"; Arguments = "--processStart `"Teams.exe`""; StartIn = "C:\Users\${aUser}\AppData\Local\Microsoft\Teams" },
    # Mozilla
    @{Name = "Firefox"; TargetPath = "C:\Users\${aUser}\AppData\Local\Mozilla Firefox\firefox.exe"; StartIn = "C:\Users\${aUser}\AppData\Local\Mozilla Firefox" },
    # NVIDIA Corporation
    @{Name = "NVIDIA GeForce NOW"; TargetPath = "C:\Users\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF\GeForceNOW.exe"; StartIn = "C:\Users\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF" },
    # Python
    @{Name = $PythonIDLE_Name; TargetPath = $PythonIDLE_TargetPath; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $PythonIDLE_Description },
    @{Name = $Python_Name; TargetPath = $Python_TargetPath; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $Python_Description },
    @{Name = $PythonModuleDocs_Name; TargetPath = $Python_TargetPath; Arguments = "-m pydoc -b"; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $PythonModuleDocs_Description },
    # Raspberry Pi Imager
    @{Name = "Raspberry Pi Imager"; TargetPath = "C:\Program Files\Raspberry Pi Imager\rpi-imager.exe"; StartIn = "C:\Program Files\Raspberry Pi Imager" }, # it's the only install on 32-bit
    @{Name = "Raspberry Pi Imager"; TargetPath = "C:\Program Files (x86)\Raspberry Pi Imager\rpi-imager.exe"; StartIn = "C:\Program Files (x86)\Raspberry Pi Imager" }, # it's the only install on 64-bit
    # RingCentral
    @{Name = "RingCentral"; TargetPath = "C:\Users\${aUser}\AppData\Local\Programs\RingCentral\RingCentral.exe"; StartIn = "C:\Users\${aUser}\AppData\Local\Programs\RingCentral"; Description = "RingCentral" },
    @{Name = "RingCentral Meetings"; TargetPath = "C:\Users\${aUser}\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe"; SystemLnk = "RingCentral Meetings\"; Description = "RingCentral Meetings" },
    @{Name = "Uninstall RingCentral Meetings"; TargetPath = "C:\Users\${aUser}\AppData\Roaming\RingCentralMeetings\uninstall\Installer.exe"; Arguments = "/uninstall"; SystemLnk = "RingCentral Meetings\"; Description = "Uninstall RingCentral Meetings" },
    # WinDirStat
    @{Name = "Help (ENG)"; TargetPath = "C:\Program Files\WinDirStat\windirstat.chm"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "Uninstall WinDirStat"; TargetPath = "C:\Program Files\WinDirStat\Uninstall.exe"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "WinDirStat"; TargetPath = "C:\Program Files\WinDirStat\windirstat.exe"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "Help (ENG)"; TargetPath = "C:\Program Files (x86)\WinDirStat\windirstat.chm"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files (x86)\WinDirStat" }, # it's the only install on 64-bit
    @{Name = "Uninstall WinDirStat"; TargetPath = "C:\Program Files (x86)\WinDirStat\Uninstall.exe"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files (x86)\WinDirStat" }, # it's the only install on 64-bit
    @{Name = "WinDirStat"; TargetPath = "C:\Program Files (x86)\WinDirStat\windirstat.exe"; SystemLnk = "WinDirStat\"; StartIn = "C:\Program Files (x86)\WinDirStat" } # it's the only install on 64-bit
    #@{ Name=""; TargetPath=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""; IconLocation=""; RunAsAdmin=($true -Or $false) },
  )

  for ($j = 0; $j -lt $userAppList.length; $j++) {
    $app = $userAppList[$j]
    $aName = $app.Name
    $aTargetPath = $app.TargetPath
    $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
    $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
    $aStartIn = if ($app.StartIn) { $app.StartIn } else { "" }
    $aDescription = if ($app.Description) { $app.Description } else { "" }
    $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
    $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

    $ScriptResults = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -si $aStartIn -d $aDescription -il $aIconLocation -r $aRunAsAdmin -u $aUser
  }
}

Stop-Transcript

if ($ScriptResults) { Write-Host "Script completed successfully." }
else { Write-Warning "Script completed with warnings and/or errors." }
