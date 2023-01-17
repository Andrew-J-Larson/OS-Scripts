#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1
# Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
# If a program you use isn't in any of the lists here, either fork/edit/push, or create an issue at:
# https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20--%3E%0A%0A

# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

# Application objects are setup like so:
<# @{
     Name = "[name of shortcut here]";
     TargetPath = "[path to exe/url/folder here]";
     Arguments = "[any arguments that an app starts with here]";
     SystemLnk = "[path to lnk or name of app here]";
     StartIn = "[start in path, if needed, here]";
     Description = "[comment, that shows up in tooltip, here]";
     IconLocation = "[path to ico|exe|ico w/ index]";
     RunAsAdmin = "[true or false, if needed]"
   } #>



Start-Transcript -Path "${env:HOMEDRIVE}\Recreate-Base-Shortcuts.log"
Write-Host "" # Makes log look better

# Constants

# TODO: FOR LATER ... this will aid in repairing the taskbar (duplicate pinned apps issue)
#Set-Variable PROGRAM_SHORTCUTS_PIN_PATH -Option Constant -Value "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs"
#Set-Variable PROGRAM_SHORTCUTS_USER_PIN_PATH -Option Constant -Value "%APPDATA%\Microsoft\Windows\Start Menu\Programs"
Set-Variable USERS_FOLDER -Option Constant -Value "${env:HOMEDRIVE}\Users"
Set-Variable NOT_INSTALLED -Option Constant -Value "NOT-INSTALLED"



# Variables

$isWindows11 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 11")
$isWindows10 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 10")
$isWin10orNewer = [System.Environment]::OSVersion.Version.Major -ge 10
$UninstallKeys = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$UninstallList = foreach ($UninstallKey in $UninstallKeys) {
  Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$' } | Select-Object @{n = 'GUID'; e = { $_.PSChildName } }, @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
}
$UninstallKeys_32bit = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
$UninstallList_32bit = foreach ($UninstallKey in $UninstallKeys_32bit) {
  Get-ChildItem -Path $UninstallKey -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$' } | Select-Object @{n = 'GUID'; e = { $_.PSChildName } }, @{n = 'Name'; e = { $_.GetValue('DisplayName') } }
}



# Functions

# code via https://gist.github.com/MattUebel/2292484
function Get-BinaryType {
  <#
    .SYNOPSIS
      Gets the binary executable type for a given set of files
    .DESCRIPTION
      PowerShell wrapper around the GetBinaryType Windows API that inspects file headers
      and reports the binary file type (e.g., 32-bit Windows app, 64-bit Windows app, 16-bit DOS/Windows app, etc.)
    .PARAMETER Path
      File path(s) to inspect
    .EXAMPLE
      #Reports the file type of C:\Windows\Explorer.exe:
      Get-BinaryType C:\Windows\Explorer.exe
    .EXAMPLE
      #Attempts to get the binary type of all files in the current directory
      Get-ChildItem | where { !$_.PsIsContainer } | Get-BinaryType
    .EXAMPLE
      #Attempts to get the binary type of all exe files in the windows directory,
      #ignoring any non-terminating errors
      Get-ChildItem $env:windir -filter *.exe | Get-BinaryType -ErrorAction SilentlyContinue
    .EXAMPLE
      #From a 32bit process on a 64 bit Windows install, attempts to get the binary type of all exe files 
      #in the windows system32 directory by bypassing filesystem redirection using "sysnative",
      #ignoring any non-terminating errors, and finally showing the file name and binary type
      Get-ChildItem $env:windir\sysnative -filter *.exe | Get-BinaryType -ErrorAction SilentlyContinue -passthrough | select Name,BinaryType
    .NOTES
      Author:      Battleship, Aaron Margosis
      Inspiration: http://pinvoke.net/default.aspx/kernel32/GetBinaryType.html
    .LINK
      http://wonkysoftware.appspot.com
  #> 

  [CmdletBinding(  
    SupportsShouldProcess = $false,
    ConfirmImpact = "none",
    DefaultParameterSetName = ""
  )]

  param
  (
    [Parameter(
      HelpMessage = "Enter binary file(s) to examine",
      Position = 0,
      Mandatory = $true,
      ValueFromPipeline = $true,
      ValueFromPipelineByPropertyName = $true
    )]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({ Test-Path $_.FullName })]
    [IO.FileInfo[]]
    $Path,

    [Alias("PassThru")]
    [switch]
    $PassThrough
  )

  begin {
    try {
      #add the enum for the binary types
      #Using more user friendly names since they won't likely be used outside this context
      Add-Type "
        public enum BinaryType 
        {
          BIT32 = 0, // A 32-bit Windows-based application,           SCS_32BIT_BINARY
          DOS   = 1, // An MS-DOS - based application,            SCS_DOS_BINARY
          WOW   = 2, // A 16-bit Windows-based application,           SCS_WOW_BINARY
          PIF   = 3, // A PIF file that executes an MS-DOS based application, SCS_PIF_BINARY
          POSIX = 4, // A POSIX based application,                SCS_POSIX_BINARY
          OS216 = 5, // A 16-bit OS/2-based application,              SCS_OS216_BINARY
          BIT64 = 6  // A 64-bit Windows-based application,           SCS_64BIT_BINARY
        }"
    }
    catch {} #type already been loaded, do nothing

    try {
      # create the win32 signature
      $Signature = '
        [DllImport("kernel32.dll")]
        public static extern bool GetBinaryType(
          string lpApplicationName,
          ref int lpBinaryType
        );
      '

      # Create a new type that lets us access the Windows API function
      Add-Type -MemberDefinition $Signature `
        -Name                 BinaryType `
        -Namespace             Win32Utils
    }
    catch {} #type already been loaded, do nothing
  }

  process {
    foreach ($Item in $Path) {
      $ReturnedType = -1
      Write-Verbose "Attempting to get type for file: $($Item.FullName)"
      $Result = [Win32Utils.BinaryType]::GetBinaryType($Item.FullName, [ref] $ReturnedType)

      #if the function returned $false, indicating an error, or the binary type wasn't returned
      if (!$Result -or ($ReturnedType -eq -1)) {
        Write-Error "Failed to get binary type for file $($Item.FullName)"
      }
      else {
        $ToReturn = [BinaryType]$ReturnedType
        if ($PassThrough) {
          #get the file object, attach a property indicating the type, and passthru to pipeline
          Get-Item $Item.FullName -Force |
          Add-Member -MemberType noteproperty -Name BinaryType -Value $ToReturn -Force -PassThru 
        }
        else { 
          #Put enum object directly into pipeline
          $ToReturn 
        }
      }
    }
  }
}

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

  Set-Variable PROGRAM_SHORTCUTS_PATH -Option Constant -Value "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs"
  Set-Variable PROGRAM_SHORTCUTS_USER_PATH -Option Constant -Value "${USERS_FOLDER}\${sUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"

  # validate name and target path
  if ($sName -And $sTargetPath -And (Test-Path $sTargetPath -PathType leaf)) {
    # if shortcut path not given, create one at default location with $sName
    if (-Not ($sSystemLnk)) { $sSystemLnk = $sName }
    # if doesn't have $PROGRAM_SHORTCUTS_PATH or $PROGRAM_SHORTCUTS_USER_PATH (and not start with drive letter), it'll assume a path for it
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^' + [Regex]::Escape($PROGRAM_SHORTCUTS_PATH) + '.*') -Or $sSystemLnk -match ('^' + [Regex]::Escape($PROGRAM_SHORTCUTS_USER_PATH) + '.*'))) {
      $sSystemLnk = $(if ($sUser) { $PROGRAM_SHORTCUTS_USER_PATH } else { $PROGRAM_SHORTCUTS_PATH }) + '\' + $sSystemLnk
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
      [Runtime.InteropServices.Marshal]::ReleaseComObject($WScriptObj) | Out-Null

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
$PowerShell_TargetPath = "${env:ProgramFiles}\PowerShell\"
$PowerShell_Version = if (Test-Path -Path $PowerShell_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Descending }
$PowerShell_Version = if ($PowerShell_Version.length -ge 1) { $PowerShell_Version[0].name } else { $NOT_INSTALLED }
$PowerShell_TargetPath += "${PowerShell_Version}\pwsh.exe"
$PowerShell_32bit_TargetPath = "${env:ProgramFiles(x86)}\PowerShell\"
$PowerShell_32bit_Version = if (Test-Path -Path $PowerShell_32bit_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_32bit_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Descending }
$PowerShell_32bit_Version = if ($PowerShell_32bit_Version.length -ge 1) { $PowerShell_32bit_Version[0].name } else { $NOT_INSTALLED }
$PowerShell_32bit_TargetPath += "${PowerShell32bit_Version}\pwsh.exe"
# PowerToys
$PowerToys_TargetPath = "${env:ProgramFiles}\PowerToys\PowerToys.exe"

# App names dependant on OS or app version

# Office
$O365_DatabaseCompare_Exe = "${env:ProgramFiles}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE"
$O365_DatabaseCompare_Arguments = "`"${O365_DatabaseCompare_Exe}`""
$O365_DatabaseCompare_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_DatabaseCompare_TargetPath += if (Test-Path -Path $O365_DatabaseCompare_Exe -PathType Leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" } 
$O365_SpreadsheetCompare_Exe = "${env:ProgramFiles}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE"
$O365_SpreadsheetCompare_Arguments = "`"${O365_SpreadsheetCompare_Exe}`""
$O365_SpreadsheetCompare_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_SpreadsheetCompare_TargetPath += if (Test-Path -Path $O365_SpreadsheetCompare_Exe -PathType Leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
$O365_DatabaseCompare_32bit_Exe = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE"
$O365_DatabaseCompare_32bit_Arguments = "`"${O365_DatabaseCompare_32bit_Exe}`""
$O365_DatabaseCompare_32bit_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_DatabaseCompare_32bit_TargetPath += if (Test-Path -Path $O365_DatabaseCompare_32bit_Exe -PathType Leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
$O365_SpreadsheetCompare_32bit_Exe = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE"
$O365_SpreadsheetCompare_32bit_Arguments = "`"${O365_SpreadsheetCompare_32bit_Exe}`""
$O365_SpreadsheetCompare_32bit_TargetPath += "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_SpreadsheetCompare_32bit_TargetPath = if (Test-Path -Path $O365_SpreadsheetCompare_32bit_Exe -PathType Leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
# PowerShell (7 or newer)
$PowerShell_Name = "PowerShell " + $(if ($PowerShell_Version) { $PowerShell_Version } else { $NOT_INSTALLED }) + " (x64)"
$PowerShell_32bit_Name = "PowerShell " + $(if ($PowerShell_32bit_Version) { $PowerShell_32bit_Version } else { $NOT_INSTALLED }) + " (x86)"
# PowerToys
$PowerToys_isPreview = if (Test-Path -Path $PowerToys_TargetPath -PathType Leaf) { (Get-Item $PowerToys_TargetPath).VersionInfo.FileVersionRaw.Major -eq 0 }
$PowerToys_Name = "PowerToys" + $(if ($PowerToys_isPreview) { " (Preview)" })
# Windows Accessories
$WindowsMediaPlayerOld_Name = "Windows Media Player" + $(if ($isWindows11) { " Legacy" })

$sysAppList = @(
  # Azure
  @{Name = "Azure Data Studio"; TargetPath = "${env:ProgramFiles}\Azure Data Studio\azuredatastudio.exe"; SystemLnk = "Azure Data Studio\"; StartIn = "${env:ProgramFiles}\Azure Data Studio" },
  @{Name = "Azure Data Studio"; TargetPath = "${env:ProgramFiles(x86)}\Azure Data Studio\azuredatastudio.exe"; SystemLnk = "Azure Data Studio\"; StartIn = "${env:ProgramFiles(x86)}\Azure Data Studio" },
  # Edge
  @{Name = "Microsoft Edge"; TargetPath = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"; StartIn = "${env:ProgramFiles}\Microsoft\Edge\Application"; Description = "Browse the web" }, # it's the only install on 32-bit
  @{Name = "Microsoft Edge"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"; Description = "Browse the web" }, # it's the only install on 64-bit
  # Intune 
  @{Name = "Microsoft Intune Management Extension"; TargetPath = "${env:ProgramFiles}\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk = "Microsoft Intune Management Extension\"; Description = "Microsoft Intune Management Extension" }, # it's the only install on 32-bit
  @{Name = "Remote help"; TargetPath = "${env:ProgramFiles}\Remote help\RemoteHelp.exe"; SystemLnk = "Remote help\"; StartIn = "${env:ProgramFiles}\Remote help\"; Description = "Remote help" },
  @{Name = "Microsoft Intune Management Extension"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk = "Microsoft Intune Management Extension\"; Description = "Microsoft Intune Management Extension" }, # it's the only install on 64-bit
  @{Name = "Remote help"; TargetPath = "${env:ProgramFiles(x86)}\Remote help\RemoteHelp.exe"; SystemLnk = "Remote help\"; StartIn = "${env:ProgramFiles(x86)}\Remote help\"; Description = "Remote help" },
  # Office (note: "Database Compare" and "Spreadsheet Compare" have specialized paths that need to be accounted for)
  @{Name = "Access"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\MSACCESS.EXE"; Description = "Build a professional app quickly to manage data." },
  @{Name = "Excel"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\EXCEL.EXE"; Description = "Easily discover, visualize, and share insights from your data." },
  @{Name = "OneNote"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\ONENOTE.EXE"; Description = "Take notes and have them when you need them." },
  @{Name = "Outlook"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description = "Manage your email, schedules, contacts, and to-dos." },
  @{Name = "PowerPoint"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\POWERPNT.EXE"; Description = "Design and deliver beautiful presentations with ease and confidence." },
  @{Name = "Project"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINPROJ.EXE"; Description = "Easily collaborate with others to quickly start and deliver winning projects." },
  @{Name = "Publisher"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\MSPUB.EXE"; Description = "Create professional-grade publications that make an impact." },
  @{Name = "Skype for Business"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\LYNC.EXE"; Description = "Connect with people everywhere through voice and video calls, Skype Meetings, and IM." },
  @{Name = "Visio"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\VISIO.EXE"; Description = "Create professional and versatile diagrams that simplify complex information." },
  @{Name = "Word"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINWORD.EXE"; Description = "Create beautiful documents, easily work with others, and enjoy the read." },
  @{Name = "Database Compare"; TargetPath = $O365_DatabaseCompare_TargetPath; Arguments = $O365_DatabaseCompare_Arguments; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Access database." }, # it's the only install on 32-bit
  @{Name = "Database Compare"; TargetPath = $O365_DatabaseCompare_32bit_TargetPath; Arguments = $O365_DatabaseCompare_32bit_Arguments; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Access database." }, # it's the only install on 64-bit
  @{Name = "Office Language Preferences"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk = "Microsoft Office Tools\"; Description = "Change the language preferences for Office applications." },
  @{Name = "Spreadsheet Compare"; TargetPath = $O365_SpreadsheetCompare_TargetPath; Arguments = $O365_SpreadsheetCompare_Arguments; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Excel workbook." }, # it's the only install on 32-bit
  @{Name = "Spreadsheet Compare"; TargetPath = $O365_SpreadsheetCompare_32bit_TargetPath; Arguments = $O365_SpreadsheetCompare_32bit_Arguments; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Excel workbook." }, # it's the only install on 64-bit
  @{Name = "Telemetry Log for Office"; TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Office16\msoev.exe"; SystemLnk = "Microsoft Office Tools\"; Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." },
  @{Name = "Access"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\MSACCESS.EXE"; Description = "Build a professional app quickly to manage data." },
  @{Name = "Excel"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\EXCEL.EXE"; Description = "Easily discover, visualize, and share insights from your data." },
  @{Name = "OneNote"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\ONENOTE.EXE"; Description = "Take notes and have them when you need them." },
  @{Name = "Outlook"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description = "Manage your email, schedules, contacts, and to-dos." },
  @{Name = "PowerPoint"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\POWERPNT.EXE"; Description = "Design and deliver beautiful presentations with ease and confidence." },
  @{Name = "Project"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINPROJ.EXE"; Description = "Easily collaborate with others to quickly start and deliver winning projects." },
  @{Name = "Publisher"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\MSPUB.EXE"; Description = "Create professional-grade publications that make an impact." },
  @{Name = "Skype for Business"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\LYNC.EXE"; Description = "Connect with people everywhere through voice and video calls, Skype Meetings, and IM." },
  @{Name = "Visio"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\VISIO.EXE"; Description = "Create professional and versatile diagrams that simplify complex information." },
  @{Name = "Word"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINWORD.EXE"; Description = "Create beautiful documents, easily work with others, and enjoy the read." },
  @{Name = "Database Compare"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Access database." },
  @{Name = "Office Language Preferences"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk = "Microsoft Office Tools\"; Description = "Change the language preferences for Office applications." },
  @{Name = "Spreadsheet Compare"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Client\AppVLP.exe"; Arguments = "`"${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""; SystemLnk = "Microsoft Office Tools\"; Description = "Compare versions of an Excel workbook." },
  @{Name = "Telemetry Log for Office"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\msoev.exe"; SystemLnk = "Microsoft Office Tools\"; Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." },
  # OneDrive
  @{Name = "OneDrive"; TargetPath = "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
  @{Name = "OneDrive"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
  # Power BI Desktop
  @{Name = "Power BI Desktop"; TargetPath = "${env:ProgramFiles}\Microsoft Power BI Desktop\bin\PBIDesktop.exe"; SystemLnk = "Microsoft Power BI Desktop\"; StartIn = "${env:ProgramFiles}\Microsoft Power BI Desktop\bin\"; Description = "Power BI Desktop" },
  @{Name = "Power BI Desktop"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Power BI Desktop\bin\PBIDesktop.exe"; SystemLnk = "Microsoft Power BI Desktop\"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Power BI Desktop\bin\"; Description = "Power BI Desktop" },
  # PowerShell (7 or newer)
  @{Name = $PowerShell_Name; TargetPath = $PowerShell_TargetPath; Arguments = "-WorkingDirectory ~"; SystemLnk = "PowerShell\"; Description = $PowerShell_Name },
  @{Name = $PowerShell_32bit_Name; TargetPath = $PowerShell_32bit_TargetPath; Arguments = "-WorkingDirectory ~"; SystemLnk = "PowerShell\"; Description = $PowerShell_32bit_Name },
  # PowerToys (note: there will never be a 32-bit version)
  @{Name = $PowerToys_Name; TargetPath = $PowerToys_TargetPath; SystemLnk = $PowerToys_Name + '\'; StartIn = "${env:ProgramFiles}\PowerToys\"; Description = "PowerToys - Windows system utilities to maximize productivity" },
  # Visual Studio
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Visual Studio Code"; TargetPath = "${env:ProgramFiles}\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "${env:ProgramFiles}\Microsoft VS Code" },
  @{Name = "Visual Studio Installer"; TargetPath = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\setup.exe"; StartIn = "${env:ProgramFiles}\Microsoft Visual Studio\Installer" }, # it's the only install on 32-bit
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Blend for Visual Studio 2022"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2022" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Blend for Visual Studio 2019"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2019" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\devenv.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Blend for Visual Studio 2017"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\Blend.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"; Description = "Microsoft Blend for Visual Studio 2017" },
  @{Name = "Visual Studio Code"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "${env:ProgramFiles(x86)}\Microsoft VS Code" },
  @{Name = "Visual Studio Installer"; TargetPath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe"; StartIn = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer" }, # it's the only install on 64-bit
  # Windows Accessories (note: these CMD variables are not a mistake)
  @{Name = "Remote Desktop Connection"; TargetPath = "%windir%\system32\mstsc.exe"; SystemLnk = "Accessories\"; StartIn = "%windir%\system32\"; Description = "Use your computer to connect to a computer that is located elsewhere and run programs or access files." },
  @{Name = "Steps Recorder"; TargetPath = "%windir%\system32\psr.exe"; SystemLnk = "Accessories\"; Description = "Capture steps with screenshots to save or share." },
  @{Name = "Windows Fax and Scan"; TargetPath = "%windir%\system32\WFS.exe"; SystemLnk = "Accessories\"; Description = "Send and receive faxes or scan pictures and documents." },
  @{Name = $WindowsMediaPlayerOld_Name; TargetPath = "%ProgramFiles%\Windows Media Player\wmplayer.exe"; Arguments = "/prefetch:1"; SystemLnk = "Accessories\"; StartIn = "%ProgramFiles%\Windows Media Player" }, # it's the only install on 32-bit
  @{Name = $WindowsMediaPlayerOld_Name; TargetPath = "%ProgramFiles(x86)%\Windows Media Player\wmplayer.exe"; Arguments = "/prefetch:1"; SystemLnk = "Accessories\"; StartIn = "%ProgramFiles(x86)%\Windows Media Player" }, # it's the only install on 64-bit
  @{Name = "WordPad"; TargetPath = "%ProgramFiles%\Windows NT\Accessories\wordpad.exe"; SystemLnk = "Accessories\"; Description = "Creates and edits text documents with complex formatting." },
  @{Name = "Character Map"; TargetPath = "%windir%\system32\charmap.exe"; SystemLnk = "Accessories\System Tools\"; Description = "Selects special characters and copies them to your document." }
  #@{Name = ""; TargetPath = ""; Arguments = ""; SystemLnk = ""; StartIn = ""; Description = ""; IconLocation = ""; RunAsAdmin = ($true -Or $false) },
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
  @{Name = "Dell OS Recovery Tool"; TargetPath = "${env:ProgramFiles}\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk = "Dell\"; StartIn = "${env:ProgramFiles}\Dell\OS Recovery Tool\" }, # it's the only install on 32-bit
  @{Name = "SupportAssist Recovery Assistant"; TargetPath = "${env:ProgramFiles}\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk = "Dell\SupportAssist\" },
  @{Name = "Dell OS Recovery Tool"; TargetPath = "${env:ProgramFiles(x86)}\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk = "Dell\"; StartIn = "${env:ProgramFiles(x86)}\Dell\OS Recovery Tool\" }, # it's the only install on 64-bit
  @{Name = "SupportAssist Recovery Assistant"; TargetPath = "${env:ProgramFiles(x86)}\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk = "Dell\SupportAssist\" },
  # NVIDIA Corporation
  @{Name = "GeForce Experience"; TargetPath = "${env:ProgramFiles}\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"; SystemLnk = "NVIDIA Corporation\"; StartIn = "${env:ProgramFiles}\NVIDIA Corporation\NVIDIA GeForce Experience" }
  #@{Name = ""; TargetPath = ""; Arguments = ""; SystemLnk = ""; StartIn = ""; Description = ""; IconLocation = ""; RunAsAdmin = ($true -Or $false) },
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
$EgnyteDesktopApp_Uninstall_GUID = $UninstallList | Where-Object { $_.Name -match "Egnyte Desktop App" }
$EgnyteDesktopApp_Uninstall_GUID = if ($EgnyteDesktopApp_Uninstall_GUID.length -ge 1) { $EgnyteDesktopApp_Uninstall_GUID[0].GUID } else { $null }
$EgnyteDesktopApp_Uninstall_Arguments = if ($EgnyteDesktopApp_Uninstall_GUID) { "/x ${EgnyteDesktopApp_Uninstall_GUID}" } else { "" }
$EgnyteDesktopApp_Uninstall_TargetPath = if ($EgnyteDesktopApp_Uninstall_GUID) { "${env:HOMEDRIVE}\Windows\System32\msiexec.exe" } else { "${env:HOMEDRIVE}\${NOT_INSTALLED}\${NOT_INSTALLED}\${NOT_INSTALLED}.exe" }
$EgnyteDesktopApp_Uninstall_32bit_GUID = $UninstallList_32bit | Where-Object { $_.Name -match "Egnyte Desktop App" }
$EgnyteDesktopApp_Uninstall_32bit_GUID = if ($EgnyteDesktopApp_Uninstall_32bit_GUID.length -ge 1) { $EgnyteDesktopApp_Uninstall_32bit_GUID[0].GUID } else { $null }
$EgnyteDesktopApp_Uninstall_32bit_Arguments = if ($EgnyteDesktopApp_Uninstall_32bit_GUID) { "/x ${EgnyteDesktopApp_Uninstall_32bit_GUID}" } else { "" }
$EgnyteDesktopApp_Uninstall_32bit_TargetPath = if ($EgnyteDesktopApp_Uninstall_32bit_GUID) { "${env:HOMEDRIVE}\Windows\System32\msiexec.exe" } else { "${env:HOMEDRIVE}\${NOT_INSTALLED}\${NOT_INSTALLED}\${NOT_INSTALLED}.exe" }

# App paths dependant on app version

# Adobe Aero
$Aero_TargetPath = "${env:ProgramFiles}\Adobe\"
$Aero_Name = if (Test-Path -Path $Aero_TargetPath) { Get-ChildItem -Directory -Path $Aero_TargetPath | Where-Object { $_.Name -match '^.*Aero(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Aero_Name = if ($Aero_Name.length -ge 1) { $Aero_Name[0].name } else { "Adobe Aero" }
$Aero_StartIn = $Aero_TargetPath + $Aero_Name
$Aero_StartInAlt = $Aero_StartIn + "\Support Files"
$Aero_StartInAlt2 = $Aero_StartInAlt + "\Contents\Windows"
$Aero_TargetPath = $Aero_StartIn + "\Aero.exe"
$Aero_TargetPathAlt = $Aero_StartInAlt + "\Aero.exe"
$Aero_TargetPathAlt2 = $Aero_StartInAlt2 + "\Aero.exe"
$Aero_TargetPath = if (Test-Path -Path $Aero_TargetPath -PathType leaf) { $Aero_TargetPath } elseif (Test-Path -Path $Aero_TargetPathAlt -PathType leaf) { $Aero_TargetPathAlt } else { $Aero_TargetPathAlt2 }
$Aero_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$AfterEffects_TargetPath = "${env:ProgramFiles}\Adobe\"
$AfterEffects_Name = if (Test-Path -Path $AfterEffects_TargetPath) { Get-ChildItem -Directory -Path $AfterEffects_TargetPath | Where-Object { $_.Name -match '^.*After Effects(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$AfterEffects_Name = if ($AfterEffects_Name.length -ge 1) { $AfterEffects_Name[0].name } else { "Adobe After Effects" }
$AfterEffects_StartIn = $AfterEffects_TargetPath + $AfterEffects_Name
$AfterEffects_StartInAlt = $AfterEffects_StartIn + "\Support Files"
$AfterEffects_StartInAlt2 = $AfterEffects_StartInAlt + "\Contents\Windows"
$AfterEffects_TargetPath = $AfterEffects_StartIn + "\AfterFX.exe"
$AfterEffects_TargetPathAlt = $AfterEffects_StartInAlt + "\AfterFX.exe"
$AfterEffects_TargetPathAlt2 = $AfterEffects_StartInAlt2 + "\AfterFX.exe"
$AfterEffects_TargetPath = if (Test-Path -Path $AfterEffects_TargetPath -PathType leaf) { $AfterEffects_TargetPath } elseif (Test-Path -Path $AfterEffects_TargetPathAlt -PathType leaf) { $AfterEffects_TargetPathAlt } else { $AfterEffects_TargetPathAlt2 }
$AfterEffects_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Animate_TargetPath = "${env:ProgramFiles}\Adobe\"
$Animate_Name = if (Test-Path -Path $Animate_TargetPath) { Get-ChildItem -Directory -Path $Animate_TargetPath | Where-Object { $_.Name -match '^.*Animate(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Animate_Name = if ($Animate_Name.length -ge 1) { $Animate_Name[0].name } else { "Adobe Animate" }
$Animate_StartIn = $Animate_TargetPath + $Animate_Name
$Animate_StartInAlt = $Animate_StartIn + "\Support Files"
$Animate_StartInAlt2 = $Animate_StartInAlt + "\Contents\Windows"
$Animate_TargetPath = $Animate_StartIn + "\Animate.exe"
$Animate_TargetPathAlt = $Animate_StartInAlt + "\Animate.exe"
$Animate_TargetPathAlt2 = $Animate_StartInAlt2 + "\Animate.exe"
$Animate_TargetPath = if (Test-Path -Path $Animate_TargetPath -PathType leaf) { $Animate_TargetPath } elseif (Test-Path -Path $Animate_TargetPathAlt -PathType leaf) { $Animate_TargetPathAlt } else { $Animate_TargetPathAlt2 }
$Animate_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Audition_TargetPath = "${env:ProgramFiles}\Adobe\"
$Audition_Name = if (Test-Path -Path $Audition_TargetPath) { Get-ChildItem -Directory -Path $Audition_TargetPath | Where-Object { $_.Name -match '^.*Audition(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Audition_Name = if ($Audition_Name.length -ge 1) { $Audition_Name[0].name } else { "Adobe Audition" }
$Audition_StartIn = $Audition_TargetPath + $Audition_Name
$Audition_StartInAlt = $Audition_StartIn + "\Support Files"
$Audition_StartInAlt2 = $Audition_StartInAlt + "\Contents\Windows"
$Audition_TargetPath = $Audition_StartIn + "\Adobe Audition.exe"
$Audition_TargetPathAlt = $Audition_StartInAlt + "\Adobe Audition.exe"
$Audition_TargetPathAlt2 = $Audition_StartInAlt2 + "\Adobe Audition.exe"
$Audition_TargetPath = if (Test-Path -Path $Audition_TargetPath -PathType leaf) { $Audition_TargetPath } elseif (Test-Path -Path $Audition_TargetPathAlt -PathType leaf) { $Audition_TargetPathAlt } else { $Audition_TargetPathAlt2 }
$Audition_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Bridge_TargetPath = "${env:ProgramFiles}\Adobe\"
$Bridge_Name = if (Test-Path -Path $Bridge_TargetPath) { Get-ChildItem -Directory -Path $Bridge_TargetPath | Where-Object { $_.Name -match '^.*Bridge(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Bridge_Name = if ($Bridge_Name.length -ge 1) { $Bridge_Name[0].name } else { "Adobe Bridge" }
$Bridge_StartIn = $Bridge_TargetPath + $Bridge_Name
$Bridge_StartInAlt = $Bridge_StartIn + "\Support Files"
$Bridge_StartInAlt2 = $Bridge_StartInAlt + "\Contents\Windows"
$Bridge_TargetPath = $Bridge_StartIn + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt = $Bridge_StartInAlt + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt2 = $Bridge_StartInAlt2 + "\Adobe Bridge.exe"
$Bridge_TargetPath = if (Test-Path -Path $Bridge_TargetPath -PathType leaf) { $Bridge_TargetPath } elseif (Test-Path -Path $Bridge_TargetPathAlt -PathType leaf) { $Bridge_TargetPathAlt } else { $Bridge_TargetPathAlt2 }
$Bridge_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$CharacterAnimator_TargetPath = "${env:ProgramFiles}\Adobe\"
$CharacterAnimator_Name = if (Test-Path -Path $CharacterAnimator_TargetPath) { Get-ChildItem -Directory -Path $CharacterAnimator_TargetPath | Where-Object { $_.Name -match '^.*Character Animator(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$CharacterAnimator_Name = if ($CharacterAnimator_Name.length -ge 1) { $CharacterAnimator_Name[0].name } else { "Adobe Character Animator" }
$CharacterAnimator_StartIn = $CharacterAnimator_TargetPath + $CharacterAnimator_Name
$CharacterAnimator_StartInAlt = $CharacterAnimator_StartIn + "\Support Files"
$CharacterAnimator_StartInAlt2 = $CharacterAnimator_StartInAlt + "\Contents\Windows"
$CharacterAnimator_TargetPath = $CharacterAnimator_StartIn + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt = $CharacterAnimator_StartInAlt + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt2 = $CharacterAnimator_StartInAlt2 + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPath = if (Test-Path -Path $CharacterAnimator_TargetPath -PathType leaf) { $CharacterAnimator_TargetPath } elseif (Test-Path -Path $CharacterAnimator_TargetPathAlt -PathType leaf) { $CharacterAnimator_TargetPathAlt } else { $CharacterAnimator_TargetPathAlt2 }
$CharacterAnimator_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Dimension_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dimension_Name = if (Test-Path -Path $Dimension_TargetPath) { Get-ChildItem -Directory -Path $Dimension_TargetPath | Where-Object { $_.Name -match '^.*Dimension(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Dimension_Name = if ($Dimension_Name.length -ge 1) { $Dimension_Name[0].name } else { "Dimension" }
$Dimension_StartIn = $Dimension_TargetPath + $Dimension_Name
$Dimension_StartInAlt = $Dimension_StartIn + "\Support Files"
$Dimension_StartInAlt2 = $Dimension_StartInAlt + "\Contents\Windows"
$Dimension_TargetPath = $Dimension_StartIn + "\Dimension.exe"
$Dimension_TargetPathAlt = $Dimension_StartInAlt + "\Dimension.exe"
$Dimension_TargetPathAlt2 = $Dimension_StartInAlt2 + "\Dimension.exe"
$Dimension_TargetPath = if (Test-Path -Path $Dimension_TargetPath -PathType leaf) { $Dimension_TargetPath } elseif (Test-Path -Path $Dimension_TargetPathAlt -PathType leaf) { $Dimension_TargetPathAlt } else { $Dimension_TargetPathAlt2 }
$Dimension_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Dreamweaver_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dreamweaver_Name = if (Test-Path -Path $Dreamweaver_TargetPath) { Get-ChildItem -Directory -Path $Dreamweaver_TargetPath | Where-Object { $_.Name -match '^.*Dreamweaver(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Dreamweaver_Name = if ($Dreamweaver_Name.length -ge 1) { $Dreamweaver_Name[0].name } else { "Adobe Dreamweaver" }
$Dreamweaver_StartIn = $Dreamweaver_TargetPath + $Dreamweaver_Name
$Dreamweaver_StartInAlt = $Dreamweaver_StartIn + "\Support Files"
$Dreamweaver_StartInAlt2 = $Dreamweaver_StartInAlt + "\Contents\Windows"
$Dreamweaver_TargetPath = $Dreamweaver_StartIn + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt = $Dreamweaver_StartInAlt + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt2 = $Dreamweaver_StartInAlt2 + "\Dreamweaver.exe"
$Dreamweaver_TargetPath = if (Test-Path -Path $Dreamweaver_TargetPath -PathType leaf) { $Dreamweaver_TargetPath } elseif (Test-Path -Path $Dreamweaver_TargetPathAlt -PathType leaf) { $Dreamweaver_TargetPathAlt } else { $Dreamweaver_TargetPathAlt2 }
$Dreamweaver_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Illustrator_TargetPath = "${env:ProgramFiles}\Adobe\"
$Illustrator_Name = if (Test-Path -Path $Illustrator_TargetPath) { Get-ChildItem -Directory -Path $Illustrator_TargetPath | Where-Object { $_.Name -match '^.*Illustrator(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Illustrator_Name = if ($Illustrator_Name.length -ge 1) { $Illustrator_Name[0].name } else { "Adobe Illustrator" }
$Illustrator_StartIn = $Illustrator_TargetPath + $Illustrator_Name
$Illustrator_StartInAlt = $Illustrator_StartIn + "\Support Files"
$Illustrator_StartInAlt2 = $Illustrator_StartInAlt + "\Contents\Windows"
$Illustrator_TargetPath = $Illustrator_StartIn + "\Illustrator.exe"
$Illustrator_TargetPathAlt = $Illustrator_StartInAlt + "\Illustrator.exe"
$Illustrator_TargetPathAlt2 = $Illustrator_StartInAlt2 + "\Illustrator.exe"
$Illustrator_TargetPath = if (Test-Path -Path $Illustrator_TargetPath -PathType leaf) { $Illustrator_TargetPath } elseif (Test-Path -Path $Illustrator_TargetPathAlt -PathType leaf) { $Illustrator_TargetPathAlt } else { $Illustrator_TargetPathAlt2 }
$Illustrator_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$InCopy_TargetPath = "${env:ProgramFiles}\Adobe\"
$InCopy_Name = if (Test-Path -Path $InCopy_TargetPath) { Get-ChildItem -Directory -Path $InCopy_TargetPath | Where-Object { $_.Name -match '^.*InCopy(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$InCopy_Name = if ($InCopy_Name.length -ge 1) { $InCopy_Name[0].name } else { "Adobe InCopy" }
$InCopy_StartIn = $InCopy_TargetPath + $InCopy_Name
$InCopy_StartInAlt = $InCopy_StartIn + "\Support Files"
$InCopy_StartInAlt2 = $InCopy_StartInAlt + "\Contents\Windows"
$InCopy_TargetPath = $InCopy_StartIn + "\InCopy.exe"
$InCopy_TargetPathAlt = $InCopy_StartInAlt + "\InCopy.exe"
$InCopy_TargetPathAlt2 = $InCopy_StartInAlt2 + "\InCopy.exe"
$InCopy_TargetPath = if (Test-Path -Path $InCopy_TargetPath -PathType leaf) { $InCopy_TargetPath } elseif (Test-Path -Path $InCopy_TargetPathAlt -PathType leaf) { $InCopy_TargetPathAlt } else { $InCopy_TargetPathAlt2 }
$InCopy_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$InDesign_TargetPath = "${env:ProgramFiles}\Adobe\"
$InDesign_Name = if (Test-Path -Path $InDesign_TargetPath) { Get-ChildItem -Directory -Path $InDesign_TargetPath | Where-Object { $_.Name -match '^.*InDesign(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$InDesign_Name = if ($InDesign_Name.length -ge 1) { $InDesign_Name[0].name } else { "Adobe InDesign" }
$InDesign_StartIn = $InDesign_TargetPath + $InDesign_Name
$InDesign_StartInAlt = $InDesign_StartIn + "\Support Files"
$InDesign_StartInAlt2 = $InDesign_StartInAlt + "\Contents\Windows"
$InDesign_TargetPath = $InDesign_StartIn + "\InDesign.exe"
$InDesign_TargetPathAlt = $InDesign_StartInAlt + "\InDesign.exe"
$InDesign_TargetPathAlt2 = $InDesign_StartInAlt2 + "\InDesign.exe"
$InDesign_TargetPath = if (Test-Path -Path $InDesign_TargetPath -PathType leaf) { $InDesign_TargetPath } elseif (Test-Path -Path $InDesign_TargetPathAlt -PathType leaf) { $InDesign_TargetPathAlt } else { $InDesign_TargetPathAlt2 }
$InDesign_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Lightroom_TargetPath = "${env:ProgramFiles}\Adobe\"
$Lightroom_Name = if (Test-Path -Path $Lightroom_TargetPath) { Get-ChildItem -Directory -Path $Lightroom_TargetPath | Where-Object { $_.Name -match '^.*Lightroom(?!.*Classic)(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Lightroom_Name = if ($Lightroom_Name.length -ge 1) { $Lightroom_Name[0].name } else { "Adobe Lightroom" }
$Lightroom_StartIn = $Lightroom_TargetPath + $Lightroom_Name
$Lightroom_StartInAlt = $Lightroom_StartIn + "\Support Files"
$Lightroom_StartInAlt2 = $Lightroom_StartInAlt + "\Contents\Windows"
$Lightroom_TargetPath = $Lightroom_StartIn + "\lightroom.exe"
$Lightroom_TargetPathAlt = $Lightroom_StartInAlt + "\lightroom.exe"
$Lightroom_TargetPathAlt2 = $Lightroom_StartInAlt2 + "\lightroom.exe"
$Lightroom_TargetPath = if (Test-Path -Path $Lightroom_TargetPath -PathType leaf) { $Lightroom_TargetPath } elseif (Test-Path -Path $Lightroom_TargetPathAlt -PathType leaf) { $Lightroom_TargetPathAlt } else { $Lightroom_TargetPathAlt2 }
$Lightroom_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$LightroomClassic_TargetPath = "${env:ProgramFiles}\Adobe\"
$LightroomClassic_Name = if (Test-Path -Path $LightroomClassic_TargetPath) { Get-ChildItem -Directory -Path $LightroomClassic_TargetPath | Where-Object { $_.Name -match '^.*Lightroom Classic(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$LightroomClassic_Name = if ($LightroomClassic_Name.length -ge 1) { $LightroomClassic_Name[0].name } else { "Adobe Lightroom Classic" }
$LightroomClassic_StartIn = $LightroomClassic_TargetPath + $LightroomClassic_Name
$LightroomClassic_StartInAlt = $LightroomClassic_StartIn + "\Support Files"
$LightroomClassic_StartInAlt2 = $LightroomClassic_StartInAlt + "\Contents\Windows"
$LightroomClassic_TargetPath = $LightroomClassic_StartIn + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt = $LightroomClassic_StartInAlt + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt2 = $LightroomClassic_StartInAlt2 + "\Lightroom.exe"
$LightroomClassic_TargetPath = if (Test-Path -Path $LightroomClassic_TargetPath -PathType leaf) { $LightroomClassic_TargetPath } elseif (Test-Path -Path $LightroomClassic_TargetPathAlt -PathType leaf) { $LightroomClassic_TargetPathAlt } else { $LightroomClassic_TargetPathAlt2 }
$LightroomClassic_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$MediaEncoder_TargetPath = "${env:ProgramFiles}\Adobe\"
$MediaEncoder_Name = if (Test-Path -Path $MediaEncoder_TargetPath) { Get-ChildItem -Directory -Path $MediaEncoder_TargetPath | Where-Object { $_.Name -match '^.*Media Encoder(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$MediaEncoder_Name = if ($MediaEncoder_Name.length -ge 1) { $MediaEncoder_Name[0].name } else { "Adobe Media Encoder" }
$MediaEncoder_StartIn = $MediaEncoder_TargetPath + $MediaEncoder_Name
$MediaEncoder_StartInAlt = $MediaEncoder_StartIn + "\Support Files"
$MediaEncoder_StartInAlt2 = $MediaEncoder_StartInAlt + "\Contents\Windows"
$MediaEncoder_TargetPath = $MediaEncoder_StartIn + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt = $MediaEncoder_StartInAlt + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt2 = $MediaEncoder_StartInAlt2 + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPath = if (Test-Path -Path $MediaEncoder_TargetPath -PathType leaf) { $MediaEncoder_TargetPath } elseif (Test-Path -Path $MediaEncoder_TargetPathAlt -PathType leaf) { $MediaEncoder_TargetPathAlt } else { $MediaEncoder_TargetPathAlt2 }
$MediaEncoder_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Photoshop_TargetPath = "${env:ProgramFiles}\Adobe\"
$Photoshop_Name = if (Test-Path -Path $Photoshop_TargetPath) { Get-ChildItem -Directory -Path $Photoshop_TargetPath | Where-Object { $_.Name -match '^.*Photoshop(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Photoshop_Name = if ($Photoshop_Name.length -ge 1) { $Photoshop_Name[0].name } else { "Adobe Photoshop" }
$Photoshop_StartIn = $Photoshop_TargetPath + $Photoshop_Name
$Photoshop_StartInAlt = $Photoshop_StartIn + "\Support Files"
$Photoshop_StartInAlt2 = $Photoshop_StartInAlt + "\Contents\Windows"
$Photoshop_TargetPath = $Photoshop_StartIn + "\Photoshop.exe"
$Photoshop_TargetPathAlt = $Photoshop_StartInAlt + "\Photoshop.exe"
$Photoshop_TargetPathAlt2 = $Photoshop_StartInAlt2 + "\Photoshop.exe"
$Photoshop_TargetPath = if (Test-Path -Path $Photoshop_TargetPath -PathType leaf) { $Photoshop_TargetPath } elseif (Test-Path -Path $Photoshop_TargetPathAlt -PathType leaf) { $Photoshop_TargetPathAlt } else { $Photoshop_TargetPathAlt2 }
$Photoshop_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$PremierePro_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremierePro_Name = if (Test-Path -Path $PremierePro_TargetPath) { Get-ChildItem -Directory -Path $PremierePro_TargetPath | Where-Object { $_.Name -match '^.*Premiere Pro(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$PremierePro_Name = if ($PremierePro_Name.length -ge 1) { $PremierePro_Name[0].name } else { "Adobe Premiere Pro" }
$PremierePro_StartIn = $PremierePro_TargetPath + $PremierePro_Name
$PremierePro_StartInAlt = $PremierePro_StartIn + "\Support Files"
$PremierePro_StartInAlt2 = $PremierePro_StartInAlt + "\Contents\Windows"
$PremierePro_TargetPath = $PremierePro_StartIn + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt = $PremierePro_StartInAlt + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt2 = $PremierePro_StartInAlt2 + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPath = if (Test-Path -Path $PremierePro_TargetPath -PathType leaf) { $PremierePro_TargetPath } elseif (Test-Path -Path $PremierePro_TargetPathAlt -PathType leaf) { $PremierePro_TargetPathAlt } else { $PremierePro_TargetPathAlt2 }
$PremierePro_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$PremiereRush_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremiereRush_Name = if (Test-Path -Path $PremiereRush_TargetPath) { Get-ChildItem -Directory -Path $PremiereRush_TargetPath | Where-Object { $_.Name -match '^.*Premiere Rush(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$PremiereRush_Name = if ($PremiereRush_Name.length -ge 1) { $PremiereRush_Name[0].name } else { "Adobe Premiere Rush" }
$PremiereRush_StartIn = $PremiereRush_TargetPath + $PremiereRush_Name
$PremiereRush_StartInAlt = $PremiereRush_StartIn + "\Support Files"
$PremiereRush_StartInAlt2 = $PremiereRush_StartInAlt + "\Contents\Windows"
$PremiereRush_TargetPath = $PremiereRush_StartIn + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt = $PremiereRush_StartInAlt + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt2 = $PremiereRush_StartInAlt2 + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPath = if (Test-Path -Path $PremiereRush_TargetPath -PathType leaf) { $PremiereRush_TargetPath } elseif (Test-Path -Path $PremiereRush_TargetPathAlt -PathType leaf) { $PremiereRush_TargetPathAlt } else { $PremiereRush_TargetPathAlt2 }
$PremiereRush_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Substance3dDesigner_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dDesigner_Name = if (Test-Path -Path $Substance3dDesigner_TargetPath) { Get-ChildItem -Directory -Path $Substance3dDesigner_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Designer(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dDesigner_Name = if ($Substance3dDesigner_Name.length -ge 1) { $Substance3dDesigner_Name[0].name } else { "Adobe Substance 3D Designer" }
$Substance3dDesigner_StartIn = $Substance3dDesigner_TargetPath + $Substance3dDesigner_Name
$Substance3dDesigner_StartInAlt = $Substance3dDesigner_StartIn + "\Support Files"
$Substance3dDesigner_StartInAlt2 = $Substance3dDesigner_StartInAlt + "\Contents\Windows"
$Substance3dDesigner_TargetPath = $Substance3dDesigner_StartIn + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt = $Substance3dDesigner_StartInAlt + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt2 = $Substance3dDesigner_StartInAlt2 + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPath = if (Test-Path -Path $Substance3dDesigner_TargetPath -PathType leaf) { $Substance3dDesigner_TargetPath } elseif (Test-Path -Path $Substance3dDesigner_TargetPathAlt -PathType leaf) { $Substance3dDesigner_TargetPathAlt } else { $Substance3dDesigner_TargetPathAlt2 }
$Substance3dDesigner_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Substance3dModeler_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dModeler_Name = if (Test-Path -Path $Substance3dModeler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dModeler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Modeler(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dModeler_Name = if ($Substance3dModeler_Name.length -ge 1) { $Substance3dModeler_Name[0].name } else { "Adobe Substance 3D Modeler" }
$Substance3dModeler_StartIn = $Substance3dModeler_TargetPath + $Substance3dModeler_Name
$Substance3dModeler_StartInAlt = $Substance3dModeler_StartIn + "\Support Files"
$Substance3dModeler_StartInAlt2 = $Substance3dModeler_StartInAlt + "\Contents\Windows"
$Substance3dModeler_TargetPath = $Substance3dModeler_StartIn + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt = $Substance3dModeler_StartInAlt + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt2 = $Substance3dModeler_StartInAlt2 + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPath = if (Test-Path -Path $Substance3dModeler_TargetPath -PathType leaf) { $Substance3dModeler_TargetPath } elseif (Test-Path -Path $Substance3dModeler_TargetPathAlt -PathType leaf) { $Substance3dModeler_TargetPathAlt } else { $Substance3dModeler_TargetPathAlt2 }
$Substance3dModeler_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Substance3dPainter_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dPainter_Name = if (Test-Path -Path $Substance3dPainter_TargetPath) { Get-ChildItem -Directory -Path $Substance3dPainter_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Painter(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dPainter_Name = if ($Substance3dPainter_Name.length -ge 1) { $Substance3dPainter_Name[0].name } else { "Adobe Substance 3D Painter" }
$Substance3dPainter_StartIn = $Substance3dPainter_TargetPath + $Substance3dPainter_Name
$Substance3dPainter_StartInAlt = $Substance3dPainter_StartIn + "\Support Files"
$Substance3dPainter_StartInAlt2 = $Substance3dPainter_StartInAlt + "\Contents\Windows"
$Substance3dPainter_TargetPath = $Substance3dPainter_StartIn + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt = $Substance3dPainter_StartInAlt + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt2 = $Substance3dPainter_StartInAlt2 + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPath = if (Test-Path -Path $Substance3dPainter_TargetPath -PathType leaf) { $Substance3dPainter_TargetPath } elseif (Test-Path -Path $Substance3dPainter_TargetPathAlt -PathType leaf) { $Substance3dPainter_TargetPathAlt } else { $Substance3dPainter_TargetPathAlt2 }
$Substance3dPainter_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Substance3dSampler_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dSampler_Name = if (Test-Path -Path $Substance3dSampler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dSampler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Sampler(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dSampler_Name = if ($Substance3dSampler_Name.length -ge 1) { $Substance3dSampler_Name[0].name } else { "Adobe Substance 3D Sampler" }
$Substance3dSampler_StartIn = $Substance3dSampler_TargetPath + $Substance3dSampler_Name
$Substance3dSampler_StartInAlt = $Substance3dSampler_StartIn + "\Support Files"
$Substance3dSampler_StartInAlt2 = $Substance3dSampler_StartInAlt + "\Contents\Windows"
$Substance3dSampler_TargetPath = $Substance3dSampler_StartIn + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt = $Substance3dSampler_StartInAlt + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt2 = $Substance3dSampler_StartInAlt2 + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPath = if (Test-Path -Path $Substance3dSampler_TargetPath -PathType leaf) { $Substance3dSampler_TargetPath } elseif (Test-Path -Path $Substance3dSampler_TargetPathAlt -PathType leaf) { $Substance3dSampler_TargetPathAlt } else { $Substance3dSampler_TargetPathAlt2 }
$Substance3dSampler_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$Substance3dStager_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dStager_Name = if (Test-Path -Path $Substance3dStager_TargetPath) { Get-ChildItem -Directory -Path $Substance3dStager_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Stager(?!.*\(Beta\)$)' } | Sort-Object -Descending }
$Substance3dStager_Name = if ($Substance3dStager_Name.length -ge 1) { $Substance3dStager_Name[0].name } else { "Adobe Substance 3D Stager" }
$Substance3dStager_StartIn = $Substance3dStager_TargetPath + $Substance3dStager_Name
$Substance3dStager_StartInAlt = $Substance3dStager_StartIn + "\Support Files"
$Substance3dStager_StartInAlt2 = $Substance3dStager_StartInAlt + "\Contents\Windows"
$Substance3dStager_TargetPath = $Substance3dStager_StartIn + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt = $Substance3dStager_StartInAlt + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt2 = $Substance3dStager_StartInAlt2 + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPath = if (Test-Path -Path $Substance3dStager_TargetPath -PathType leaf) { $Substance3dStager_TargetPath } elseif (Test-Path -Path $Substance3dStager_TargetPathAlt -PathType leaf) { $Substance3dStager_TargetPathAlt } else { $Substance3dStager_TargetPathAlt2 }
$Substance3dStager_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
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
$GIMP_TargetPath = "${env:ProgramFiles}\"
$GIMP_FindFolder = Get-ChildItem -Directory -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Descending
$GIMP_FindFolder = if ($GIMP_FindFolder.length -ge 1) { $GIMP_FindFolder[0].name } else { $NOT_INSTALLED }
$GIMP_TargetPath += "${GIMP_FindFolder}\bin\"
$GIMP_FindExe = if (Test-Path -Path $GIMP_TargetPath) { Get-ChildItem -File -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Descending }
$GIMP_FindExe = if ($GIMP_FindExe.length -ge 1) { $GIMP_FindExe[0].name } else { "${NOT_INSTALLED}.exe" }
$GIMP_TargetPath += $GIMP_FindExe
$GIMP_32bit_TargetPath = "${env:ProgramFiles(x86)}\"
$GIMP_32bit_FindFolder = Get-ChildItem -Directory -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Descending
$GIMP_32bit_FindFolder = if ($GIMP_32bit_FindFolder.length -ge 1) { $GIMP_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$GIMP_32bit_TargetPath += "${GIMP_32bit_FindFolder}\bin\"
$GIMP_32bit_FindExe = if (Test-Path -Path $GIMP_32bit_TargetPath) { Get-ChildItem -File -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Descending }
$GIMP_32bit_FindExe = if ($GIMP_32bit_FindExe.length -ge 1) { $GIMP_32bit_FindExe[0].name } else { "${NOT_INSTALLED}.exe" }
$GIMP_32bit_TargetPath += $GIMP_32bit_FindExe
# Google
$GoogleDrive_TargetPath = "${env:ProgramFiles}\Google\Drive File Stream\"
$GoogleDrive_Version = if (Test-Path -Path $GoogleDrive_TargetPath) { Get-ChildItem -Directory -Path $GoogleDrive_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleDrive_Version = if ($GoogleDrive_Version.length -ge 1) { $GoogleDrive_Version[0].name } else { $NOT_INSTALLED }
$GoogleDrive_TargetPath += "${GoogleDrive_Version}\GoogleDriveFS.exe"
$GoogleDrive_32bit_TargetPath = "${env:ProgramFiles(x86)}\Google\Drive File Stream\"
$GoogleDrive_32bit_Version = if (Test-Path -Path $GoogleDrive_32bit_TargetPath) { Get-ChildItem -Directory -Path $GoogleDrive_32bit_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleDrive_32bit_Version = if ($GoogleDrive_32bit_Version.length -ge 1) { $GoogleDrive_32bit_Version[0].name } else { $NOT_INSTALLED }
$GoogleDrive_32bit_TargetPath += "${GoogleDrive_32bit_Version}\GoogleDriveFS.exe"
$GoogleOneVPN_TargetPath = "${env:ProgramFiles}\Google\VPN by Google One\"
$GoogleOneVPN_Version = if (Test-Path -Path $GoogleOneVPN_TargetPath) { Get-ChildItem -Directory -Path $GoogleOneVPN_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleOneVPN_Version = if ($GoogleOneVPN_Version.length -ge 1) { $GoogleOneVPN_Version[0].name } else { $NOT_INSTALLED }
$GoogleOneVPN_TargetPath += "${GoogleOneVPN_Version}\googleone.exe"
$GoogleOneVPN_32bit_TargetPath = "${env:ProgramFiles}\Google\VPN by Google One\"
$GoogleOneVPN_32bit_Version = if (Test-Path -Path $GoogleOneVPN_32bit_TargetPath) { Get-ChildItem -Directory -Path $GoogleOneVPN_32bit_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
$GoogleOneVPN_32bit_Version = if ($GoogleOneVPN_32bit_Version.length -ge 1) { $GoogleOneVPN_32bit_Version[0].name } else { $NOT_INSTALLED }
$GoogleOneVPN_32bit_TargetPath += "${GoogleOneVPN_32bit_Version}\googleone.exe"
# KeePass
$KeePass_StartIn = "${env:ProgramFiles}\"
$KeePass_FindFolder = Get-ChildItem -Directory -Path $KeePass_StartIn | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Descending
$KeePass_FindFolder = if ($KeePass_FindFolder.length -ge 1) { $KeePass_FindFolder[0].name } else { $NOT_INSTALLED }
$KeePass_TargetPath = "${KeePass_FindFolder}\KeePass.exe"
$KeePass_32bit_StartIn = "${env:ProgramFiles(x86)}\"
$KeePass_32bit_FindFolder = Get-ChildItem -Directory -Path $KeePass_32bit_StartIn | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Descending
$KeePass_32bit_FindFolder = if ($KeePass_32bit_FindFolder.length -ge 1) { $KeePass_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$KeePass_32bit_TargetPath = "${KeePass_32bit_FindFolder}\KeePass.exe"
# Maxon
$MaxonCinema4D_StartIn = "${env:ProgramFiles}\"
$MaxonCinema4D_FindFolder = Get-ChildItem -Directory -Path $MaxonCinema4D_StartIn | Where-Object { $_.Name -match '^Maxon Cinema 4D' } | Sort-Object -Descending
$MaxonCinema4D_FindFolder = if ($MaxonCinema4D_FindFolder.length -ge 1) { $MaxonCinema4D_FindFolder[0].name } else { $NOT_INSTALLED }
$MaxonCinema4D_Version = $MaxonCinema4D_FindFolder | Select-String -pattern "\d\d\d\d$" -All
$MaxonCinema4D_Version = if ($MaxonCinema4D_Version.length -ge 1) { $MaxonCinema4D_Version.Matches[-1].value } else { $NOT_INSTALLED }
$MaxonCinema4D_StartIn += $MaxonCinema4D_FindFolder
$MaxonCinema4D_Commandline_TargetPath = $MaxonCinema4D_StartIn + "\Commandline.exe"
$MaxonCinema4D_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D.exe"
$MaxonCinema4D_TeamRenderClient_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D Team Render Client.exe"
$MaxonCinema4D_TeamRenderServer_TargetPath = $MaxonCinema4D_StartIn + "\Cinema 4D Team Render Server.exe"
# VMware
$VMwareWorkstationPlayer_TargetPath = "${env:ProgramFiles}\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_Path = if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType Leaf) { "${env:HOMEDRIVE}\Windows\System32\cmd.exe" } else { "${env:ProgramFiles}\${NOT_INSTALLED}\${NOT_INSTALLED}\${NOT_INSTALLED}.exe" }
$VMwareWorkstationPlayer_32bit_TargetPath = "${env:ProgramFiles(x86)}\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_32bit_Path = if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType Leaf) { "${env:HOMEDRIVE}\Windows\System32\cmd.exe" } else { "${env:ProgramFiles(x86)}\${NOT_INSTALLED}\${NOT_INSTALLED}\${NOT_INSTALLED}.exe" }

# App names dependant on OS or app version

# GIMP
$GIMP_ProductVersion = if (Test-Path -Path $GIMP_TargetPath -PathType Leaf) { (Get-Item $GIMP_TargetPath).VersionInfo.ProductVersion }
$GIMP_Version = if ($GIMP_ProductVersion) { $GIMP_ProductVersion } else { $NOT_INSTALLED }
$GIMP_Name = "GIMP ${GIMP_Version}"
$GIMP_32bit_ProductVersion = if (Test-Path -Path $GIMP_32bit_TargetPath -PathType Leaf) { (Get-Item $GIMP_32bit_TargetPath).VersionInfo.ProductVersion }
$GIMP_32bit_Version = if ($GIMP_32bit_ProductVersion) { $GIMP_32bit_ProductVersion } else { $NOT_INSTALLED }
$GIMP_32bit_Name = "GIMP ${GIMP_32bit_Version}"
# KeePass
$KeePass_FileVersionRaw = if (Test-Path -Path $KeePass_TargetPath -PathType Leaf) { (Get-Item $KeePass_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_Version = if ($KeePass_FileVersionRaw) { $KeePass_FileVersionRaw.Major } else { $NOT_INSTALLED }
$KeePass_Name = "KeePass ${KeePass_Version}"
$KeePass_32bit_FileVersionRaw = if (Test-Path -Path $KeePass_32bit_TargetPath -PathType Leaf) { (Get-Item $KeePass_32bit_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_32bit_Version = if ($KeePass_32bit_FileVersionRaw) { $KeePass_32bit_FileVersionRaw.Major } else { $NOT_INSTALLED }
$KeePass_32bit_Name = "KeePass ${KeePass_32bit_Version}"
# Maxon
$MaxonCinema4D_Commandline_Name = "Commandline" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_Name = "Maxon Cinema 4D" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderClient_Name = "Team Render Client" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderServer_Name = "Team Render Server" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
# VMware
$VMwareWorkstationPlayer_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType Leaf) { (Get-Item $VMwareWorkstationPlayer_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_Version = if ($VMwareWorkstationPlayer_FileVersionRaw) { $VMwareWorkstationPlayer_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NOT_INSTALLED }
$VMwareWorkstationPlayer_Name = "VMware Workstation ${VMwareWorkstationPlayer_Version} Player"
$VMwareWorkstationPlayer_32bit_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType Leaf) { (Get-Item $VMwareWorkstationPlayer_32bit_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_32bit_Version = if ($VMwareWorkstationPlayer_32bit_FileVersionRaw) { $VMwareWorkstationPlayer_32bit_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NOT_INSTALLED }
$VMwareWorkstationPlayer_32bit_Name = "VMware Workstation ${VMwareWorkstationPlayer_32bit_Version} Player"

$sys3rdPartyAppList = @(
  # 7-Zip
  @{Name = "7-Zip File Manager"; TargetPath = "${env:ProgramFiles}\7-Zip\7zFM.exe"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip Help"; TargetPath = "${env:ProgramFiles}\7-Zip\7-zip.chm"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip File Manager"; TargetPath = "${env:ProgramFiles(x86)}\7-Zip\7zFM.exe"; SystemLnk = "7-Zip\" },
  @{Name = "7-Zip Help"; TargetPath = "${env:ProgramFiles(x86)}\7-Zip\7-zip.chm"; SystemLnk = "7-Zip\" },
  # Adobe
  @{Name = "Adobe Creative Cloud"; TargetPath = "${env:ProgramFiles}\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe" },
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
  @{Name = "Adobe UXP Developer Tool"; TargetPath = "${env:ProgramFiles}\Adobe\Adobe UXP Developer Tool\Adobe UXP Developer Tool.exe"; StartIn = "${env:ProgramFiles}\Adobe\Adobe UXP Developer Tool" },
  @{Name = "Adobe Acrobat"; TargetPath = "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\acrodist.exe" },
  @{Name = "Adobe Acrobat"; TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe" },
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\acrodist.exe" },
  @{Name = "Adobe Acrobat Reader"; TargetPath = "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" }, # old version; it's the only install on 32-bit
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\acrodist.exe" }, # old version; it's the only install on 32-bit
  @{Name = "Adobe Acrobat Reader"; TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" }, # old version; it's the only install on 64-bit
  @{Name = "Adobe Acrobat Distiller"; TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\acrodist.exe" }, # old version; it's the only install on 64-bit
  # Altair Monarch
  @{Name = "Altair Monarch 2021"; TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\DWMonarch.exe"; SystemLnk = "Altair Monarch 2021\" },
  @{Name = "Altair Monarch 2020"; TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\DWMonarch.exe"; SystemLnk = "Altair Monarch 2020\" },
  @{Name = "Altair Monarch 2021"; TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\DWMonarch.exe"; SystemLnk = "Altair Monarch 2021\" },
  @{Name = "Altair Monarch 2020"; TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\DWMonarch.exe"; SystemLnk = "Altair Monarch 2020\" },
  # Amazon
  @{Name = "AWS VPN Client"; TargetPath = "${env:ProgramFiles}\Amazon\AWS VPN Client\AWSVPNClient.exe"; SystemLnk = "AWS VPN Client\"; StartIn = "${env:ProgramFiles}\Amazon\AWS VPN Client\"; Description = "Client application for AWS Client VPN service" },
  @{Name = "AWS VPN Client"; TargetPath = "${env:ProgramFiles(x86)}\Amazon\AWS VPN Client\AWSVPNClient.exe"; SystemLnk = "AWS VPN Client\"; StartIn = "${env:ProgramFiles(x86)}\Amazon\AWS VPN Client\"; Description = "Client application for AWS Client VPN service" },
  # AmbiBox
  @{Name = "AmbiBox Web Site"; TargetPath = "${env:ProgramFiles}\AmbiBox\www.ambibox.ru.url"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles}\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "AmbiBox"; TargetPath = "${env:ProgramFiles}\AmbiBox\AmbiBox.exe"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles}\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "Android AmbiBox Remote App"; TargetPath = "${env:ProgramFiles}\AmbiBox\Android AmbiBox Remote App"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles}\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "MediaPortal Extension"; TargetPath = "${env:ProgramFiles}\AmbiBox\MediaPortal Extension"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles}\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "Uninstall AmbiBox"; TargetPath = "${env:ProgramFiles}\AmbiBox\unins000.exe"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles}\AmbiBox" }, # it's the only install on 32-bit
  @{Name = "AmbiBox Web Site"; TargetPath = "${env:ProgramFiles(x86)}\AmbiBox\www.ambibox.ru.url"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles(x86)}\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "AmbiBox"; TargetPath = "${env:ProgramFiles(x86)}\AmbiBox\AmbiBox.exe"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles(x86)}\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "Android AmbiBox Remote App"; TargetPath = "${env:ProgramFiles(x86)}\AmbiBox\Android AmbiBox Remote App"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles(x86)}\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "MediaPortal Extension"; TargetPath = "${env:ProgramFiles(x86)}\AmbiBox\MediaPortal Extension"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles(x86)}\AmbiBox" }, # it's the only install on 64-bit
  @{Name = "Uninstall AmbiBox"; TargetPath = "${env:ProgramFiles(x86)}\AmbiBox\unins000.exe"; SystemLnk = "AmbiBox\"; StartIn = "${env:ProgramFiles(x86)}\AmbiBox" }, # it's the only install on 64-bit
  # Audacity
  @{Name = "Audacity"; TargetPath = "${env:ProgramFiles}\Audacity\Audacity.exe"; StartIn = "${env:ProgramFiles}\Audacity" },
  @{Name = "Audacity"; TargetPath = "${env:ProgramFiles(x86)}\Audacity\Audacity.exe"; StartIn = "${env:ProgramFiles(x86)}\Audacity" },
  # AutoHotkey V2
  @{Name = "AutoHotkey Window Spy"; TargetPath = "${env:ProgramFiles}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${env:ProgramFiles}\AutoHotkey\UX\WindowSpy.ahk`""; Description = "AutoHotkey Window Spy" },
  @{Name = "AutoHotkey"; TargetPath = "${env:ProgramFiles}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${env:ProgramFiles}\AutoHotkey\UX\ui-dash.ahk`""; Description = "AutoHotkey Dash" },
  @{Name = "AutoHotkey Window Spy"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${env:ProgramFiles(x86)}\AutoHotkey\UX\WindowSpy.ahk`""; Description = "AutoHotkey Window Spy" },
  @{Name = "AutoHotkey"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${env:ProgramFiles(x86)}\AutoHotkey\UX\ui-dash.ahk`""; Description = "AutoHotkey Dash" },
  # AutoHotkey
  @{Name = "AutoHotkey Help File"; TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey.chm"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Setup"; TargetPath = "${env:ProgramFiles}\AutoHotkey\Installer.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey"; TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Convert .ahk to .exe"; TargetPath = "${env:ProgramFiles}\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Website"; TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey Website.url"; SystemLnk = "AutoHotkey\" },
  @{Name = "Window Spy"; TargetPath = "${env:ProgramFiles}\AutoHotkey\WindowSpy.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Help File"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey.chm"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey Setup"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\Installer.ahk"; SystemLnk = "AutoHotkey\" },
  @{Name = "AutoHotkey"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Convert .ahk to .exe"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk = "AutoHotkey\" },
  @{Name = "Website"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey Website.url"; SystemLnk = "AutoHotkey\" },
  @{Name = "Window Spy"; TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\WindowSpy.ahk"; SystemLnk = "AutoHotkey\" },
  # Bulk Crap Uninstaller
  @{Name = "BCUninstaller"; TargetPath = "${env:ProgramFiles}\BCUninstaller\BCUninstaller.exe"; SystemLnk = "BCUninstaller\"; StartIn = "${env:ProgramFiles}\BCUninstaller" },
  @{Name = "Uninstall BCUninstaller"; TargetPath = "${env:ProgramFiles}\BCUninstaller\unins000.exe"; SystemLnk = "BCUninstaller\"; StartIn = "${env:ProgramFiles}\BCUninstaller" },
  @{Name = "BCUninstaller"; TargetPath = "${env:ProgramFiles(x86)}\BCUninstaller\BCUninstaller.exe"; SystemLnk = "BCUninstaller\"; StartIn = "${env:ProgramFiles(x86)}\BCUninstaller" },
  @{Name = "Uninstall BCUninstaller"; TargetPath = "${env:ProgramFiles(x86)}\BCUninstaller\unins000.exe"; SystemLnk = "BCUninstaller\"; StartIn = "${env:ProgramFiles(x86)}\BCUninstaller" },
  # Bytello
  @{Name = "Bytello Share"; TargetPath = "${env:ProgramFiles}\Bytello Share\Bytello Share.exe"; SystemLnk = "Bytello Share\"; StartIn = "${env:ProgramFiles}\Bytello Share" }, # it's the only install on 32-bit
  @{Name = "Bytello Share"; TargetPath = "${env:ProgramFiles(x86)}\Bytello Share\Bytello Share.exe"; SystemLnk = "Bytello Share\"; StartIn = "${env:ProgramFiles(x86)}\Bytello Share" }, # it's the only install on 64-bit
  # Cisco
  @{Name = "Cisco AnyConnect Secure Mobility Client"; TargetPath = "${env:ProgramFiles}\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"; SystemLnk = "Cisco\Cisco AnyConnect Secure Mobility Client"; StartIn = "${env:ProgramFiles}\Cisco\Cisco AnyConnect Secure Mobility Client\"; Description = "Cisco AnyConnect Secure Mobility Client" }, # it's the only install on 32-bit
  @{Name = "Cisco Jabber Problem Report"; TargetPath = "${env:ProgramFiles}\Cisco Systems\Cisco Jabber\CiscoJabberPrt.exe"; SystemLnk = "Cisco Jabber\"; Description = "Cisco Jabber Problem Report" }, # it's the only install on 32-bit
  @{Name = "Cisco Jabber"; TargetPath = "${env:ProgramFiles}\Cisco Systems\Cisco Jabber\CiscoJabber.exe"; SystemLnk = "Cisco Jabber\"; Description = "Cisco Jabber" }, # it's the only install on 32-bit
  @{Name = "Cisco AnyConnect Secure Mobility Client"; TargetPath = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"; SystemLnk = "Cisco\Cisco AnyConnect Secure Mobility Client"; StartIn = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\"; Description = "Cisco AnyConnect Secure Mobility Client" }, # it's the only install on 64-bit
  @{Name = "Cisco Jabber Problem Report"; TargetPath = "${env:ProgramFiles(x86)}\Cisco Systems\Cisco Jabber\CiscoJabberPrt.exe"; SystemLnk = "Cisco Jabber\"; Description = "Cisco Jabber Problem Report" }, # it's the only install on 64-bit
  @{Name = "Cisco Jabber"; TargetPath = "${env:ProgramFiles(x86)}\Cisco Systems\Cisco Jabber\CiscoJabber.exe"; SystemLnk = "Cisco Jabber\"; Description = "Cisco Jabber" }, # it's the only install on 64-bit
  # Citrix Workspace
  @{Name = "Citrix Workspace"; TargetPath = "${env:ProgramFiles}\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"; Arguments = "-showAppPicker"; StartIn = "${env:ProgramFiles}\Citrix\ICA Client\SelfServicePlugin\"; Description = "Select applications you want to use on your computer" }, # it's the only install on 32-bit
  @{Name = "Citrix Workspace"; TargetPath = "${env:ProgramFiles(x86)}\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"; Arguments = "-showAppPicker"; StartIn = "${env:ProgramFiles(x86)}\Citrix\ICA Client\SelfServicePlugin\"; Description = "Select applications you want to use on your computer" }, # it's the only install on 64-bit
  # CodeTwo Active Directory Photos
  @{Name = "CodeTwo Active Directory Photos"; TargetPath = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos" },
  @{Name = "Go to program home page"; TargetPath = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos home page" },
  @{Name = "User's manual"; TargetPath = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "Go to User Guide" },
  @{Name = "CodeTwo Active Directory Photos"; TargetPath = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos" },
  @{Name = "Go to program home page"; TargetPath = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "CodeTwo Active Directory Photos home page" },
  @{Name = "User's manual"; TargetPath = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk = "CodeTwo\CodeTwo Active Directory Photos\"; Description = "Go to User Guide" },
  # Docker
  @{Name = "Docker Desktop"; TargetPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"; SystemLnk = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\"; Description = "Docker Desktop" },
  @{Name = "Docker Desktop"; TargetPath = "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe"; SystemLnk = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\"; Description = "Docker Desktop" },
  # draw.io
  @{Name = "draw.io"; TargetPath = "${env:ProgramFiles}\draw.io\draw.io.exe"; StartIn = "${env:ProgramFiles}\draw.io"; Description = "draw.io desktop" },
  @{Name = "draw.io"; TargetPath = "${env:ProgramFiles(x86)}\draw.io\draw.io.exe"; StartIn = "${env:ProgramFiles(x86)}\draw.io"; Description = "draw.io desktop" },
  # Egnyte (note: uninstaller is architecture independent)
  @{Name = "Egnyte Desktop App"; TargetPath = "${env:ProgramFiles}\Egnyte Connect\EgnyteClient.exe"; Arguments = "--short-menu"; SystemLnk = "Egnyte Connect\"; StartIn = "${env:ProgramFiles}\Egnyte Connect\" }, # it's the only install on 32-bit
  @{Name = "Uninstall Egnyte Desktop App"; TargetPath = $EgnyteDesktopApp_Uninstall_TargetPath; Arguments = $EgnyteDesktopApp_Uninstall_Arguments; SystemLnk = "Egnyte Connect\"; Description = "Uninstalls Egnyte Desktop App" },
  @{Name = "Egnyte Desktop App"; TargetPath = "${env:ProgramFiles(x86)}\Egnyte Connect\EgnyteClient.exe"; Arguments = "--short-menu"; SystemLnk = "Egnyte Connect\"; StartIn = "${env:ProgramFiles(x86)}\Egnyte Connect\" }, # it's the only install on 64-bit
  @{Name = "Uninstall Egnyte Desktop App"; TargetPath = $EgnyteDesktopApp_Uninstall_32bit_TargetPath; Arguments = $EgnyteDesktopApp_Uninstall_32bit_Arguments; SystemLnk = "Egnyte Connect\"; Description = "Uninstalls Egnyte Desktop App" },
  # Epson
  @{Name = "Epson Scan 2"; TargetPath = "${env:ProgramFiles}\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk = "EPSON\Epson Scan 2\" }, # it's the only install on 32-bit
  @{Name = "FAX Utility"; TargetPath = "${env:ProgramFiles}\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk = "EPSON Software\" }, # it's the only install on 32-bit
  @{Name = "Epson Scan 2"; TargetPath = "${env:ProgramFiles(x86)}\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk = "EPSON\Epson Scan 2\" }, # it's the only install on 64-bit
  @{Name = "FAX Utility"; TargetPath = "${env:ProgramFiles(x86)}\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk = "EPSON Software\" }, # it's the only install on 64-bit
  # GIMP
  @{Name = $GIMP_Name; TargetPath = $GIMP_TargetPath; StartIn = "%USERPROFILE%"; Description = $GIMP_Name },
  @{Name = $GIMP_32bit_Name; TargetPath = $GIMP_32bit_TargetPath; StartIn = "%USERPROFILE%"; Description = $GIMP_32bit_Name },
  # Google
  @{Name = "Google Chrome"; TargetPath = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"; StartIn = "${env:ProgramFiles}\Google\Chrome\Application"; Description = "Access the Internet" },
  @{Name = "Google Drive"; TargetPath = $GoogleDrive_TargetPath; Description = "Google Drive" },
  @{Name = "VPN by Google One"; TargetPath = $GoogleOneVPN_TargetPath; Description = "VPN by Google One" },
  @{Name = "Google Chrome"; TargetPath = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"; StartIn = "${env:ProgramFiles(x86)}\Google\Chrome\Application"; Description = "Access the Internet" },
  @{Name = "Google Drive"; TargetPath = $GoogleDrive_32bit_TargetPath; Description = "Google Drive" },
  @{Name = "VPN by Google One"; TargetPath = $GoogleOneVPN_32bit_TargetPath; Description = "VPN by Google One" },
  # GoTo
  @{Name = "GoTo Resolve Desktop Console (64-bit)"; TargetPath = "${env:ProgramFiles}\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn = "${env:ProgramFiles}\GoTo\GoTo Resolve Desktop Console\" },
  @{Name = "GoTo Resolve Desktop Console"; TargetPath = "${env:ProgramFiles(x86)}\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"; StartIn = "${env:ProgramFiles(x86)}\GoTo\GoTo Resolve Desktop Console\" },
  # KC Softwares
  @{Name = "SUMo"; TargetPath = "${env:ProgramFiles}\KC Softwares\SUMo\SUMo.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "${env:ProgramFiles}\KC Softwares\SUMo" }, # it's the only install on 32-bit
  @{Name = "Uninstall SUMo"; TargetPath = "${env:ProgramFiles}\KC Softwares\SUMo\unins000.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "${env:ProgramFiles}\KC Softwares\SUMo" }, # it's the only install on 32-bit
  @{Name = "SUMo"; TargetPath = "${env:ProgramFiles(x86)}\KC Softwares\SUMo\SUMo.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "${env:ProgramFiles(x86)}\KC Softwares\SUMo" }, # it's the only install on 64-bit
  @{Name = "Uninstall SUMo"; TargetPath = "${env:ProgramFiles(x86)}\KC Softwares\SUMo\unins000.exe"; SystemLnk = "KC Softwares\SUMo\"; StartIn = "${env:ProgramFiles(x86)}\KC Softwares\SUMo" }, # it's the only install on 64-bit
  # Kdenlive
  @{Name = "Kdenlive"; TargetPath = "${env:ProgramFiles}\kdenlive\bin\kdenlive.exe"; StartIn = "{workingDirectory}"; Description = "Libre Video Editor, by KDE community" },
  @{Name = "Kdenlive"; TargetPath = "${env:ProgramFiles(x86)}\kdenlive\bin\kdenlive.exe"; StartIn = "{workingDirectory}"; Description = "Libre Video Editor, by KDE community" },
  # KeePass
  @{Name = $KeePass_Name; TargetPath = $KeePass_TargetPath; StartIn = $KeePass_StartIn }, # new version 2+
  @{Name = "KeePass"; TargetPath = "${env:ProgramFiles}\KeePass Password Safe\KeePass.exe"; StartIn = "${env:ProgramFiles}\KeePass Password Safe" }, # old version 1.x; it's the only install on 32-bit
  @{Name = $KeePass_32bit_Name; TargetPath = $KeePass_32bit_TargetPath; StartIn = $KeePass_32bit_StartIn }, # new version 2+
  @{Name = "KeePass"; TargetPath = "${env:ProgramFiles(x86)}\KeePass Password Safe\KeePass.exe"; StartIn = "${env:ProgramFiles(x86)}\KeePass Password Safe" }, # old version 1.x; it's the only install on 64-bit
  # Ledger Live
  @{Name = "Ledger Live"; TargetPath = "${env:ProgramFiles}\Ledger Live\Ledger Live.exe"; StartIn = "${env:ProgramFiles}\Ledger Live"; Description = "Ledger Live - Desktop" },
  @{Name = "Ledger Live"; TargetPath = "${env:ProgramFiles(x86)}\Ledger Live\Ledger Live.exe"; StartIn = "${env:ProgramFiles(x86)}\Ledger Live"; Description = "Ledger Live - Desktop" },
  # Local Administrator Password Solution
  @{Name = "LAPS UI"; TargetPath = "${env:ProgramFiles}\LAPS\AdmPwd.UI.exe"; SystemLnk = "LAPS\"; StartIn = "${env:ProgramFiles}\LAPS\" },
  @{Name = "LAPS UI"; TargetPath = "${env:ProgramFiles(x86)}\LAPS\AdmPwd.UI.exe"; SystemLnk = "LAPS\"; StartIn = "${env:ProgramFiles(x86)}\LAPS\" },
  # Maxon
  @{Name = $MaxonCinema4D_Commandline_Name; TargetPath = $MaxonCinema4D_Commandline_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Commandline" },
  @{Name = $MaxonCinema4D_Name; TargetPath = $MaxonCinema4D_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Maxon Cinema 4D" },
  @{Name = $MaxonCinema4D_TeamRenderClient_Name; TargetPath = $MaxonCinema4D_TeamRenderClient_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Team Render Client" },
  @{Name = $MaxonCinema4D_TeamRenderServer_Name; TargetPath = $MaxonCinema4D_TeamRenderServer_TargetPath; SystemLnk = "Maxon\${MaxonCinema4D_Name}\"; StartIn = $MaxonCinema4D_StartIn; Description = "Team Render Server" },
  # Mozilla
  @{Name = "Firefox"; TargetPath = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"; StartIn = "${env:ProgramFiles}\Mozilla Firefox" },
  @{Name = "Firefox Private Browsing"; TargetPath = "${env:ProgramFiles}\Mozilla Firefox\private_browsing.exe"; StartIn = "${env:ProgramFiles}\Mozilla Firefox"; Description = "Firefox Private Browsing" },
  @{Name = "Thunderbird"; TargetPath = "${env:ProgramFiles}\Mozilla Thunderbird\thunderbird.exe"; StartIn = "${env:ProgramFiles}\Mozilla Thunderbird" },
  @{Name = "Firefox"; TargetPath = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"; StartIn = "${env:ProgramFiles(x86)}\Mozilla Firefox" },
  @{Name = "Firefox Private Browsing"; TargetPath = "${env:ProgramFiles(x86)}\Mozilla Firefox\private_browsing.exe"; StartIn = "${env:ProgramFiles(x86)}\Mozilla Firefox"; Description = "Firefox Private Browsing" },
  @{Name = "Thunderbird"; TargetPath = "${env:ProgramFiles(x86)}\Mozilla Thunderbird\thunderbird.exe"; StartIn = "${env:ProgramFiles(x86)}\Mozilla Thunderbird" },
  # Notepad++
  @{Name = "Notepad++"; TargetPath = "${env:ProgramFiles}\Notepad++\notepad++.exe"; StartIn = "${env:ProgramFiles}\Notepad++" },
  @{Name = "Notepad++"; TargetPath = "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"; StartIn = "${env:ProgramFiles(x86)}\Notepad++" },
  # OpenVPN
  @{Name = "OpenVPN"; TargetPath = "${env:ProgramFiles}\OpenVPN\bin\openvpn-gui.exe"; SystemLnk = "OpenVPN\OpenVPN GUI"; StartIn = "${env:ProgramFiles}\OpenVPN\bin\" },
  @{Name = "OpenVPN Manual Page"; TargetPath = "${env:ProgramFiles}\OpenVPN\doc\openvpn.8.html"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "${env:ProgramFiles}\OpenVPN\doc\" },
  @{Name = "OpenVPN Windows Notes"; TargetPath = "${env:ProgramFiles}\OpenVPN\doc\INSTALL-win32.txt"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "${env:ProgramFiles}\OpenVPN\doc\" },
  @{Name = "OpenVPN Configuration File Directory"; TargetPath = "${env:ProgramFiles}\OpenVPN\config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles}\OpenVPN\config\" },
  @{Name = "OpenVPN Log File Directory"; TargetPath = "${env:ProgramFiles}\OpenVPN\log"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles}\OpenVPN\log\" },
  @{Name = "OpenVPN Sample Configuration Files"; TargetPath = "${env:ProgramFiles}\OpenVPN\sample-config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles}\OpenVPN\sample-config\" },
  @{Name = "Add a new TAP-Windows6 virtual network adapter"; TargetPath = "${env:ProgramFiles}\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid root\tap0901"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "${env:ProgramFiles}\OpenVPN\bin\" },
  @{Name = "Add a new Wintun virtual network adapter"; TargetPath = "${env:ProgramFiles}\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid wintun"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "${env:ProgramFiles}\OpenVPN\bin\" },
  @{Name = "OpenVPN"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn-gui.exe"; SystemLnk = "OpenVPN\OpenVPN GUI"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\bin\" },
  @{Name = "OpenVPN Manual Page"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\doc\openvpn.8.html"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\doc\" },
  @{Name = "OpenVPN Windows Notes"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\doc\INSTALL-win32.txt"; SystemLnk = "OpenVPN\Documentation\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\doc\" },
  @{Name = "OpenVPN Configuration File Directory"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\config\" },
  @{Name = "OpenVPN Log File Directory"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\log"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\log\" },
  @{Name = "OpenVPN Sample Configuration Files"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\sample-config"; SystemLnk = "OpenVPN\Shortcuts\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\sample-config\" },
  @{Name = "Add a new TAP-Windows6 virtual network adapter"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid root\tap0901"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\bin\" },
  @{Name = "Add a new Wintun virtual network adapter"; TargetPath = "${env:ProgramFiles(x86)}\OpenVPN\bin\tapctl.exe"; Arguments = "create --hwid wintun"; SystemLnk = "OpenVPN\Utilities\"; StartIn = "${env:ProgramFiles(x86)}\OpenVPN\bin\" },
  # Oracle
  @{Name = "License (English)"; TargetPath = "${env:ProgramFiles}\Oracle\VirtualBox\License_en_US.rtf"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "${env:ProgramFiles}\Oracle\VirtualBox\"; Description = "License" },
  @{Name = "Oracle VM VirtualBox"; TargetPath = "${env:ProgramFiles}\Oracle\VirtualBox\VirtualBox.exe"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "${env:ProgramFiles}\Oracle\VirtualBox\"; Description = "Oracle VM VirtualBox" },
  @{Name = "User manual (CHM, English)"; TargetPath = "${env:ProgramFiles}\Oracle\VirtualBox\VirtualBox.chm"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "User manual (PDF, English)"; TargetPath = "${env:ProgramFiles}\Oracle\VirtualBox\doc\UserManual.pdf"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "License (English)"; TargetPath = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\License_en_US.rtf"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\"; Description = "License" },
  @{Name = "Oracle VM VirtualBox"; TargetPath = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VirtualBox.exe"; SystemLnk = "Oracle VM VirtualBox\"; StartIn = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\"; Description = "Oracle VM VirtualBox" },
  @{Name = "User manual (CHM, English)"; TargetPath = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VirtualBox.chm"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  @{Name = "User manual (PDF, English)"; TargetPath = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\doc\UserManual.pdf"; SystemLnk = "Oracle VM VirtualBox\"; Description = "User manual" },
  # OSFMount
  @{Name = "OSFMount Documentation"; TargetPath = "${env:ProgramFiles}\OSFMount\osfmount_Help.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles}\OSFMount" },
  @{Name = "OSFMount on the Web"; TargetPath = "${env:ProgramFiles}\OSFMount\OSFMount.url"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles}\OSFMount" },
  @{Name = "OSFMount"; TargetPath = "${env:ProgramFiles}\OSFMount\OSFMount.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles}\OSFMount" },
  @{Name = "Uninstall OSFMount"; TargetPath = "${env:ProgramFiles}\OSFMount\unins000.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles}\OSFMount" },
  @{Name = "OSFMount Documentation"; TargetPath = "${env:ProgramFiles(x86)}\OSFMount\osfmount_Help.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles(x86)}\OSFMount" },
  @{Name = "OSFMount on the Web"; TargetPath = "${env:ProgramFiles(x86)}\OSFMount\OSFMount.url"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles(x86)}\OSFMount" },
  @{Name = "OSFMount"; TargetPath = "${env:ProgramFiles(x86)}\OSFMount\OSFMount.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles(x86)}\OSFMount" },
  @{Name = "Uninstall OSFMount"; TargetPath = "${env:ProgramFiles(x86)}\OSFMount\unins000.exe"; SystemLnk = "OSFMount\"; StartIn = "${env:ProgramFiles(x86)}\OSFMount" },
  # paint.net
  @{Name = "paint.net"; TargetPath = "${env:ProgramFiles}\paint.net\paintdotnet.exe"; StartIn = "${env:ProgramFiles}\paint.net"; Description = "Create, edit, scan, and print images and photographs." },
  @{Name = "paint.net"; TargetPath = "${env:ProgramFiles(x86)}\paint.net\paintdotnet.exe"; StartIn = "${env:ProgramFiles(x86)}\paint.net"; Description = "Create, edit, scan, and print images and photographs." },
  # Pulse Secure
  @{Name = "Pulse Secure"; TargetPath = "${env:ProgramFiles}\Common Files\Pulse Secure\JamUI\Pulse.exe"; Arguments = "-show"; SystemLnk = "Pulse Secure\"; Description = "Pulse Secure Desktop Client" }, # it's the only install on 32-bit
  @{Name = "Pulse Secure"; TargetPath = "${env:ProgramFiles(x86)}\Common Files\Pulse Secure\JamUI\Pulse.exe"; Arguments = "-show"; SystemLnk = "Pulse Secure\"; Description = "Pulse Secure Desktop Client" }, # it's the only install on 64-bit
  # PuTTY
  @{Name = "Pageant"; TargetPath = "${env:ProgramFiles}\PuTTY\pageant.exe"; SystemLnk = "PuTTY (64-bit)\"; StartIn = "${env:ProgramFiles}\PuTTY\" },
  @{Name = "PSFTP"; TargetPath = "${env:ProgramFiles}\PuTTY\psftp.exe"; SystemLnk = "PuTTY (64-bit)\"; StartIn = "${env:ProgramFiles}\PuTTY\" },
  @{Name = "PuTTY Manual"; TargetPath = "${env:ProgramFiles}\PuTTY\putty.chm"; SystemLnk = "PuTTY (64-bit)\" },
  @{Name = "PuTTY Web Site"; TargetPath = "${env:ProgramFiles}\PuTTY\website.url"; SystemLnk = "PuTTY (64-bit)\" },
  @{Name = "PuTTY"; TargetPath = "${env:ProgramFiles}\PuTTY\putty.exe"; SystemLnk = "PuTTY (64-bit)\"; StartIn = "${env:ProgramFiles}\PuTTY\" },
  @{Name = "PuTTYgen"; TargetPath = "${env:ProgramFiles}\PuTTY\puttygen.exe"; SystemLnk = "PuTTY (64-bit)\"; StartIn = "${env:ProgramFiles}\PuTTY\" },
  @{Name = "Pageant"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\pageant.exe"; SystemLnk = "PuTTY\"; StartIn = "${env:ProgramFiles(x86)}\PuTTY\" },
  @{Name = "PSFTP"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\psftp.exe"; SystemLnk = "PuTTY\"; StartIn = "${env:ProgramFiles(x86)}\PuTTY\" },
  @{Name = "PuTTY Manual"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\putty.chm"; SystemLnk = "PuTTY\" },
  @{Name = "PuTTY Web Site"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\website.url"; SystemLnk = "PuTTY\" },
  @{Name = "PuTTY"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\putty.exe"; SystemLnk = "PuTTY\"; StartIn = "${env:ProgramFiles(x86)}\PuTTY\" },
  @{Name = "PuTTYgen"; TargetPath = "${env:ProgramFiles(x86)}\PuTTY\puttygen.exe"; SystemLnk = "PuTTY\"; StartIn = "${env:ProgramFiles(x86)}\PuTTY\" },
  # RealVNC
  @{Name = "VNC Server"; TargetPath = "${env:ProgramFiles}\RealVNC\VNC Server\vncguihelper.exe"; Arguments = "vncserver.exe -_fromGui -start -showstatus"; SystemLnk = "RealVNC\"; StartIn = "${env:ProgramFiles}\RealVNC\VNC Server\" },
  @{Name = "VNC Viewer"; TargetPath = "${env:ProgramFiles}\RealVNC\VNC Viewer\vncviewer.exe"; SystemLnk = "RealVNC\"; StartIn = "${env:ProgramFiles}\RealVNC\VNC Viewer\" },
  @{Name = "VNC Server"; TargetPath = "${env:ProgramFiles(x86)}\RealVNC\VNC Server\vncguihelper.exe"; Arguments = "vncserver.exe -_fromGui -start -showstatus"; SystemLnk = "RealVNC\"; StartIn = "${env:ProgramFiles(x86)}\RealVNC\VNC Server\" },
  @{Name = "VNC Viewer"; TargetPath = "${env:ProgramFiles(x86)}\RealVNC\VNC Viewer\vncviewer.exe"; SystemLnk = "RealVNC\"; StartIn = "${env:ProgramFiles(x86)}\RealVNC\VNC Viewer\" },
  # Samsung
  @{Name = "Samsung DeX"; TargetPath = "${env:ProgramFiles}\Samsung\Samsung DeX\SamsungDeX.exe"; StartIn = "${env:ProgramFiles}\Samsung\Samsung DeX\" }, # it's the only install on 32-bit
  @{Name = "Samsung DeX"; TargetPath = "${env:ProgramFiles(x86)}\Samsung\Samsung DeX\SamsungDeX.exe"; StartIn = "${env:ProgramFiles(x86)}\Samsung\Samsung DeX\" }, # it's the only install on 64-bit
  # SonicWall Global VPN Client
  @{Name = "Global VPN Client"; TargetPath = "${env:ProgramFiles}\SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "${env:ProgramFiles}\SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  @{Name = "Global VPN Client"; TargetPath = "${env:ProgramFiles}\Dell SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "${env:ProgramFiles}\Dell SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  @{Name = "Global VPN Client"; TargetPath = "${env:ProgramFiles(x86)}\SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "${env:ProgramFiles(x86)}\SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  @{Name = "Global VPN Client"; TargetPath = "${env:ProgramFiles(x86)}\Dell SonicWALL\Global VPN Client\SWGVC.exe"; StartIn = "${env:ProgramFiles(x86)}\Dell SonicWall\Global VPN Client\"; Description = "Launch the Global VPN Client" },
  # SoundSwitch
  @{Name = "SoundSwitch"; TargetPath = "${env:ProgramFiles}\SoundSwitch\SoundSwitch.exe"; SystemLnk = "SoundSwitch\"; StartIn = "${env:ProgramFiles}\SoundSwitch" },
  @{Name = "Uninstall SoundSwitch"; TargetPath = "${env:ProgramFiles}\SoundSwitch\unins000.exe"; SystemLnk = "SoundSwitch\"; StartIn = "${env:ProgramFiles}\SoundSwitch" },
  @{Name = "SoundSwitch"; TargetPath = "${env:ProgramFiles(x86)}\SoundSwitch\SoundSwitch.exe"; SystemLnk = "SoundSwitch\"; StartIn = "${env:ProgramFiles(x86)}\SoundSwitch" },
  @{Name = "Uninstall SoundSwitch"; TargetPath = "${env:ProgramFiles(x86)}\SoundSwitch\unins000.exe"; SystemLnk = "SoundSwitch\"; StartIn = "${env:ProgramFiles(x86)}\SoundSwitch" },
  # USB Redirector TS Edition
  @{Name = "USB Redirector TS Edition - Workstation"; TargetPath = "${env:ProgramFiles}\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk = "USB Redirector TS Edition - Workstation\" },
  @{Name = "USB Redirector TS Edition - Workstation"; TargetPath = "${env:ProgramFiles(x86)}\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk = "USB Redirector TS Edition - Workstation\" },
  # VideoLAN
  @{Name = "Documentation"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\Documentation.url"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "Release Notes"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\NEWS.txt"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "VideoLAN Website"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\VideoLAN Website.url"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "VLC media player - reset preferences and cache files"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"; Arguments = "--reset-config --reset-plugins-cache vlc://quit"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "VLC media player skinned"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"; Arguments = "-Iskins"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "VLC media player"; TargetPath = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles}\VideoLAN\VLC" },
  @{Name = "Documentation"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\Documentation.url"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  @{Name = "Release Notes"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\NEWS.txt"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  @{Name = "VideoLAN Website"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\VideoLAN Website.url"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  @{Name = "VLC media player - reset preferences and cache files"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"; Arguments = "--reset-config --reset-plugins-cache vlc://quit"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  @{Name = "VLC media player skinned"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"; Arguments = "-Iskins"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  @{Name = "VLC media player"; TargetPath = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"; SystemLnk = "VideoLAN\"; StartIn = "${env:ProgramFiles(x86)}\VideoLAN\VLC" },
  # VMware
  @{Name = "Command Prompt for vctl"; TargetPath = $CommandPromptforvctl_Path; Arguments = "/k set PATH=${env:ProgramFiles}\VMware\VMware Player\;%PATH% && vctl.exe -h"; SystemLnk = "VMware\"; StartIn = "${env:ProgramFiles}\VMware\VMware Player\bin\" }, # it's the only install on 32-bit
  @{Name = $VMwareWorkstationPlayer_Name; TargetPath = $VMwareWorkstationPlayer_TargetPath; SystemLnk = "VMware\"; StartIn = "${env:ProgramFiles}\VMware\VMware Player\" }, # it's the only install on 32-bit
  @{Name = "Command Prompt for vctl"; TargetPath = $CommandPromptforvctl_32bit_Path; Arguments = "/k set PATH=${env:ProgramFiles(x86)}\VMware\VMware Player\;%PATH% && vctl.exe -h"; SystemLnk = "VMware\"; StartIn = "${env:ProgramFiles(x86)}\VMware\VMware Player\bin\" }, # it's the only install on 64-bit
  @{Name = $VMwareWorkstationPlayer_32bit_Name; TargetPath = $VMwareWorkstationPlayer_32bit_TargetPath; SystemLnk = "VMware\"; StartIn = "${env:ProgramFiles(x86)}\VMware\VMware Player\" }, # it's the only install on 64-bit
  # Win32DiskImager
  @{Name = "Uninstall Win32DiskImager"; TargetPath = "${env:ProgramFiles}\ImageWriter\unins000.exe"; SystemLnk = "Image Writer\"; StartIn = "${env:ProgramFiles}\ImageWriter" }, # it's the only install on 32-bit
  @{Name = "Win32DiskImager"; TargetPath = "${env:ProgramFiles}\ImageWriter\Win32DiskImager.exe"; SystemLnk = "Image Writer\"; StartIn = "${env:ProgramFiles}\ImageWriter" }, # it's the only install on 32-bit
  @{Name = "Uninstall Win32DiskImager"; TargetPath = "${env:ProgramFiles(x86)}\ImageWriter\unins000.exe"; SystemLnk = "Image Writer\"; StartIn = "${env:ProgramFiles(x86)}\ImageWriter" }, # it's the only install on 64-bit
  @{Name = "Win32DiskImager"; TargetPath = "${env:ProgramFiles(x86)}\ImageWriter\Win32DiskImager.exe"; SystemLnk = "Image Writer\"; StartIn = "${env:ProgramFiles(x86)}\ImageWriter" }, # it's the only install on 64-bit
  # Winaero
  @{Name = "EULA"; TargetPath = "${env:ProgramFiles}\Winaero Tweaker\Winaero EULA.txt"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles}\Winaero Tweaker"; Description = "Read the license agreement" },
  @{Name = "Winaero Tweaker"; TargetPath = "${env:ProgramFiles}\Winaero Tweaker\WinaeroTweaker.exe"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles}\Winaero Tweaker" },
  @{Name = "Winaero Website"; TargetPath = "${env:ProgramFiles}\Winaero Tweaker\Winaero.url"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles}\Winaero Tweaker"; Description = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user." },
  @{Name = "EULA"; TargetPath = "${env:ProgramFiles(x86)}\Winaero Tweaker\Winaero EULA.txt"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles(x86)}\Winaero Tweaker"; Description = "Read the license agreement" },
  @{Name = "Winaero Tweaker"; TargetPath = "${env:ProgramFiles(x86)}\Winaero Tweaker\WinaeroTweaker.exe"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles(x86)}\Winaero Tweaker" },
  @{Name = "Winaero Website"; TargetPath = "${env:ProgramFiles(x86)}\Winaero Tweaker\Winaero.url"; SystemLnk = "Winaero Tweaker\"; StartIn = "${env:ProgramFiles(x86)}\Winaero Tweaker"; Description = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user." },
  # WinSCP
  @{Name = "WinSCP"; TargetPath = "${env:ProgramFiles}\WinSCP\WinSCP.exe"; StartIn = "${env:ProgramFiles}\WinSCP"; Description = "WinSCP: SFTP, FTP, WebDAV and SCP client" }, # it's the only install on 32-bit
  @{Name = "WinSCP"; TargetPath = "${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe"; StartIn = "${env:ProgramFiles(x86)}\WinSCP"; Description = "WinSCP: SFTP, FTP, WebDAV and SCP client" } # it's the only install on 64-bit
  #@{Name = ""; TargetPath = ""; Arguments = ""; SystemLnk = ""; StartIn = ""; Description = ""; IconLocation = ""; RunAsAdmin = ($true -Or $false) },
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
$Users = (Get-ChildItem -Directory -Path "${USERS_FOLDER}\" | ForEach-Object { if (($_.name -ne "Default") -And ($_.name -ne "Public")) { $_.name } })
if ($Users -And ($Users[0].length -eq 1)) { $Users = @("$Users") } # if only one user, array needs to be recreated

# System app arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# System app paths dependant on app version

# Adobe
$AdobeDigitalEditions_TargetPath = "${env:ProgramFiles}\Adobe\"
$AdobeDigitalEditions_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Descending) }
$AdobeDigitalEditions_FindFolder = if ($AdobeDigitalEditions_FindFolders.length -ge 1) { $AdobeDigitalEditions_FindFolders[0].name } else { $NOT_INSTALLED }
$AdobeDigitalEditions_TargetPath += "${AdobeDigitalEditions_FindFolder}\DigitalEditions.exe"
$AdobeDigitalEditions_32bit_TargetPath = "${env:ProgramFiles(x86)}\Adobe\"
$AdobeDigitalEditions_32bit_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_32bit_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Descending) }
$AdobeDigitalEditions_32bit_FindFolder = if ($AdobeDigitalEditions_32bit_FindFolders.length -ge 1) { $AdobeDigitalEditions_32bit_FindFolders[0].name } else { $NOT_INSTALLED }
$AdobeDigitalEditions_32bit_TargetPath += "${AdobeDigitalEditions_32bit_FindFolder}\DigitalEditions.exe"
# Blender
$Blender_TargetPath = "${env:ProgramFiles}\Blender Foundation\"
$Blender_FindFolder = if (Test-Path -Path $Blender_TargetPath) { Get-ChildItem -Directory -Path $Blender_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Descending }
$Blender_FindFolder = if ($Blender_FindFolder.length -ge 1) { $Blender_FindFolder[0].name } else { $NOT_INSTALLED }
$Blender_StartIn = $Blender_TargetPath + "${Blender_FindFolder}\"
$Blender_TargetPath = $Blender_StartIn + "blender-launcher.exe"
$Blender_32bit_TargetPath = "${env:ProgramFiles(x86)}\Blender Foundation\"
$Blender_32bit_FindFolder = if (Test-Path -Path $Blender_32bit_TargetPath) { Get-ChildItem -Directory -Path $Blender_32bit_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Descending }
$Blender_32bit_FindFolder = if ($Blender_32bit_FindFolder.length -ge 1) { $Blender_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$Blender_32bit_StartIn = $Blender_32bit_TargetPath + "${Blender_32bit_FindFolder}\"
$Blender_32bit_TargetPath = $Blender_32bit_StartIn + "blender-launcher.exe"

# System app names dependant on OS or app version

# Adobe
$AdobeDigitalEditions_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_TargetPath -PathType Leaf) { (Get-Item $AdobeDigitalEditions_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_Version = if ($AdobeDigitalEditions_FileVersionRaw) { [string]($AdobeDigitalEditions_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
$AdobeDigitalEditions_Name = "Adobe Digital Editions ${AdobeDigitalEditions_Version}"
$AdobeDigitalEditions_32bit_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath -PathType Leaf) { (Get-Item $AdobeDigitalEditions_32bit_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_32bit_Version = if ($AdobeDigitalEditions_32bit_FileVersionRaw) { [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
$AdobeDigitalEditions_32bit_Name = "Adobe Digital Editions ${AdobeDigitalEditions_32bit_Version}"

# App names dependant on OS or app version

# Microsoft Teams
$MicrosoftTeams_Name = "Microsoft Teams" + $(if ($isWindows11) { " (work or school)" })

for ($i = 0; $i -lt $Users.length; $i++) {
  # get user
  $aUser = $Users[$i]

  # User app paths dependant on app version

  # 1Password
  $OnePassword_TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\1Password\app\"
  $OnePassword_FindFolder = if (Test-Path -Path $OnePassword_TargetPath) { Get-ChildItem -Directory -Path $OnePassword_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Descending }
  $OnePassword_FindFolder = if ($OnePassword_FindFolder.length -ge 1) { $OnePassword_FindFolder[0].name } else { $NOT_INSTALLED }
  $OnePassword_TargetPath += "${OnePassword_FindFolder}\1Password.exe"
  # Adobe
  $AdobeDigitalEditions_StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Temp"
  # Discord
  $Discord_StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Discord\"
  $Discord_TargetPath = $Discord_StartIn + "Update.exe"
  $Discord_FindFolder = if (Test-Path -Path $Discord_StartIn) { Get-ChildItem -Directory -Path $Discord_StartIn | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Descending }
  $Discord_FindFolder = if ($Discord_FindFolder.length -ge 1) { $Discord_FindFolder[0].name } else { $NOT_INSTALLED }
  $Discord_StartIn += $Discord_FindFolder
  # GitHub
  $GitHubDesktop_StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\GitHubDesktop\"
  $GitHubDesktop_TargetPath = $GitHubDesktop_StartIn + "GitHubDesktop.exe"
  $GitHubDesktop_FindFolder = if (Test-Path -Path $GitHubDesktop_StartIn) { Get-ChildItem -Directory -Path $GitHubDesktop_StartIn | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Descending }
  $GitHubDesktop_FindFolder = if ($GitHubDesktop_FindFolder.length -ge 1) { $GitHubDesktop_FindFolder[0].name } else { $NOT_INSTALLED }
  $GitHubDesktop_StartIn += $GitHubDesktop_FindFolder
  # GoTo
  $GoToResolveDesktopConsole_StartIn = "${USERS_FOLDER}\${aUser}\GoTo\GoTo Resolve Desktop Console\"
  $GoToResolveDesktopConsole_Exe = $GoToResolveDesktopConsole_StartIn + "ra-technician-console.exe"
  $GoToResolveDesktopConsole_Arch = if (Test-Path -Path $GoToResolveDesktopConsole_TargetPath) { Get-BinaryType $GoToResolveDesktopConsole_TargetPath }
  $GoToResolveDesktopConsole_TargetPath = if ($GoToResolveDesktopConsole_Arch -And ($GoToResolveDesktopConsole_Arch -eq "BIT64")) { $GoToResolveDesktopConsole_Exe } else { $GoToResolveDesktopConsole_StartIn + $NOT_INSTALLED }
  $GoToResolveDesktopConsole_32bit_TargetPath = if ($GoToResolveDesktopConsole_Arch -And ($GoToResolveDesktopConsole_Arch -eq "BIT32")) { $GoToResolveDesktopConsole_Exe } else { $GoToResolveDesktopConsole_StartIn + $NOT_INSTALLED }
  # Microsoft
  $AzureIoTExplorerPreview_TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\azure-iot-explorer\Azure IoT Explorer Preview.exe"
  $AzureIoTExplorer_TargetPath = if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType Leaf) { $AzureIoTExplorerPreview_TargetPath } else { "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\azure-iot-explorer\Azure IoT Explorer.exe" }
  # Python
  $Python_StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\Python\"
  $Python_FindFolder = if (Test-Path -Path $Python_StartIn) { Get-ChildItem -Directory -Path $Python_StartIn | Where-Object { $_.Name -match '^Python[.0-9]+$' } | Sort-Object -Descending }
  $Python_FindFolder = if ($Python_FindFolder.length -ge 1) { $Python_FindFolder[0].name } else { $NOT_INSTALLED }
  $Python_StartIn += "${Python_FindFolder}\"
  $PythonIDLE_TargetPath = $Python_StartIn + "Lib\idlelib\idle.pyw"
  $PythonManuals_TargetPath = $Python_StartIn + "Doc\html\index.html"
  $Python_TargetPath = $Python_StartIn + "python.exe"
  $Python_FileVersionRaw = if (Test-Path -Path $Python_TargetPath -PathType Leaf) { (Get-Item $Python_TargetPath).VersionInfo.FileVersionRaw }
  $Python_Version = if ($Python_FileVersionRaw) { [string]($Python_FileVersionRaw.Major) + '.' + [string]($Python_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
  $Python_SystemLnk = "Python ${Python_Version}\"
  # Slack
  $Slack_StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\slack\"
  $Slack_TargetPath = $Slack_StartIn + "slack.exe"
  $Slack_FindFolder = if (Test-Path -Path $Slack_StartIn) { Get-ChildItem -Directory -Path $Slack_StartIn | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Descending }
  $Slack_FindFolder = if ($Slack_FindFolder.length -ge 1) { $Slack_FindFolder[0].name } else { $NOT_INSTALLED }
  $Slack_StartIn += $Slack_FindFolder
  
  # User app names dependant on OS or app version

  # Microsoft
  $AzureIoTExplorer_Name = "Azure IoT Explorer" + $(if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType Leaf) { " Preview" })
  # Python
  $PythonIDLE_Description = "Launches IDLE, the interactive environment for Python ${Python_Version}."
  $Python_Description = "Launches the Python ${Python_Version} interpreter."
  $PythonManuals_Description = "View the Python ${Python_Version} documentation."
  $PythonModuleDocs_Description = "Start the Python ${Python_Version} documentation server."
  $Python_Arch = if (Test-Path -Path $Python_TargetPath) { Get-BinaryType $Python_TargetPath }
  $Python_Arch = if ($Python_Arch -And ($Python_Arch -eq "BIT64")) { 64 } else { 32 }
  $PythonIDLE_Name = "IDLE (Python ${Python_Version} ${Python_Arch}-bit)"
  $Python_Name = "Python ${Python_Version} (${Python_Arch}-bit)"
  $PythonManuals_Name = "Python ${Python_Version} Manuals (${Python_Arch}-bit)"
  $PythonModuleDocs_Name = "Python ${Python_Version} Module Docs (${Python_Arch}-bit)"

  $userAppList = @( # all instances of "${aUser}" get's replaced with the username
    # 1Password
    @{Name = "1Password"; TargetPath = $OnePassword_TargetPath; Description = "1Password" },
    # Adobe
    @{Name = $AdobeDigitalEditions_Name; TargetPath = $AdobeDigitalEditions_TargetPath; StartIn = $AdobeDigitalEditions_StartIn },
    @{Name = $AdobeDigitalEditions_32bit_Name; TargetPath = $AdobeDigitalEditions_32bit_TargetPath; StartIn = $AdobeDigitalEditions_StartIn },
    # AutoHotkey V2
    @{Name = "AutoHotkey Window Spy"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${USERS_FOLDER}\${aUser}\AutoHotkey\UX\WindowSpy.ahk`""; Description = "AutoHotkey Window Spy" },
    @{Name = "AutoHotkey"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\UX\AutoHotkeyUX.exe"; Arguments = "`"${USERS_FOLDER}\${aUser}\AutoHotkey\UX\ui-dash.ahk`""; Description = "AutoHotkey Dash" },
    # AutoHotkey
    @{Name = "AutoHotkey Help File"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\AutoHotkey.chm"; SystemLnk = "AutoHotkey\" },
    @{Name = "AutoHotkey Setup"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\Installer.ahk"; SystemLnk = "AutoHotkey\" },
    @{Name = "AutoHotkey"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\AutoHotkey.exe"; SystemLnk = "AutoHotkey\" },
    @{Name = "Convert .ahk to .exe"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\Compiler\Ahk2Exe.exe"; SystemLnk = "AutoHotkey\" },
    @{Name = "Website"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\AutoHotkey Website.url"; SystemLnk = "AutoHotkey\" },
    @{Name = "Window Spy"; TargetPath = "${USERS_FOLDER}\${aUser}\AutoHotkey\WindowSpy.ahk"; SystemLnk = "AutoHotkey\" },
    # balenaEtcher
    @{Name = "balenaEtcher"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\balena-etcher\balenaEtcher.exe"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\balena-etcher"; Description = "Flash OS images to SD cards and USB drives, safely and easily." },
    # Blender
    @{Name = "Blender"; TargetPath = $Blender_TargetPath; SystemLnk = "blender\"; StartIn = $Blender_StartIn },
    @{Name = "Blender"; TargetPath = $Blender_32bit_TargetPath; SystemLnk = "blender\"; StartIn = $Blender_32bit_StartIn },
    # Discord
    @{Name = "Discord"; TargetPath = $Discord_TargetPath; Arguments = "--processStart Discord.exe"; SystemLnk = "Discord Inc\"; StartIn = $Discord_StartIn; Description = "Discord - https://discord.com" },
    # GitHub
    @{Name = "GitHub Desktop"; TargetPath = $GitHubDesktop_TargetPath; SystemLnk = "GitHub, Inc\"; StartIn = $GitHubDesktop_StartIn; Description = "Simple collaboration from your desktop" },
    # Google
    @{Name = "Google Chrome"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Google\Chrome\Application\chrome.exe"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Google\Chrome\Application"; Description = "Access the Internet" },
    # GoTo
    @{Name = "GoTo Resolve Desktop Console (64-bit)"; TargetPath = $GoToResolveDesktopConsole_TargetPath; StartIn = $GoToResolveDesktopConsole_StartIn },
    @{Name = "GoTo Resolve Desktop Console"; TargetPath = $GoToResolveDesktopConsole_32bit_TargetPath; StartIn = $GoToResolveDesktopConsole_StartIn },
    # Inkscape
    @{Name = "Inkscape"; TargetPath = "${env:ProgramFiles}\Inkscape\bin\inkscape.exe"; SystemLnk = "Inkscape\"; StartIn = "${env:ProgramFiles}\Inkscape\bin\" },
    @{Name = "Inkview"; TargetPath = "${env:ProgramFiles}\Inkscape\bin\inkview.exe"; SystemLnk = "Inkscape\"; StartIn = "${env:ProgramFiles}\Inkscape\bin\" },
    @{Name = "Inkscape"; TargetPath = "${env:ProgramFiles(x86)}\Inkscape\bin\inkscape.exe"; SystemLnk = "Inkscape\"; StartIn = "${env:ProgramFiles(x86)}\Inkscape\bin\" },
    @{Name = "Inkview"; TargetPath = "${env:ProgramFiles(x86)}\Inkscape\bin\inkview.exe"; SystemLnk = "Inkscape\"; StartIn = "${env:ProgramFiles(x86)}\Inkscape\bin\" },
    # Microsoft
    @{Name = "Azure Data Studio"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\Azure Data Studio\azuredatastudio.exe"; SystemLnk = "Azure Data Studio\"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\Azure Data Studio" },
    @{Name = $AzureIoTExplorer_Name; TargetPath = $AzureIoTExplorer_TargetPath; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\azure-iot-explorer\" },
    @{Name = "Visual Studio Code"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\Microsoft VS Code\Code.exe"; SystemLnk = "Visual Studio Code\"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\Microsoft VS Code" },
    @{Name = $MicrosoftTeams_Name; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Microsoft\Teams\Update.exe"; Arguments = "--processStart `"Teams.exe`""; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Microsoft\Teams" },
    @{Name = "OneDrive"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Microsoft\OneDrive\OneDrive.exe"; Description = "Keep your most important files with you wherever you go, on any device." },
    # Mozilla
    @{Name = "Firefox"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Mozilla Firefox\firefox.exe"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Mozilla Firefox" },
    # NVIDIA Corporation
    @{Name = "NVIDIA GeForce NOW"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF\GeForceNOW.exe"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\NVIDIA Corporation\GeForceNOW\CEF" },
    # Python
    @{Name = $PythonIDLE_Name; TargetPath = $PythonIDLE_TargetPath; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $PythonIDLE_Description },
    @{Name = $Python_Name; TargetPath = $Python_TargetPath; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $Python_Description },
    @{Name = $PythonManuals_Name; TargetPath = $PythonManuals_TargetPath; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $PythonManuals_Description },
    @{Name = $PythonModuleDocs_Name; TargetPath = $Python_TargetPath; Arguments = "-m pydoc -b"; SystemLnk = $Python_SystemLnk; StartIn = $Python_StartIn; Description = $PythonModuleDocs_Description },
    # Slack
    @{Name = "Slack"; TargetPath = $Slack_TargetPath; SystemLnk = "Slack Technologies Inc\"; StartIn = $Slack_StartIn; Description = "Slack Desktop" },
    # Raspberry Pi Imager
    @{Name = "Raspberry Pi Imager"; TargetPath = "${env:ProgramFiles}\Raspberry Pi Imager\rpi-imager.exe"; StartIn = "${env:ProgramFiles}\Raspberry Pi Imager" }, # it's the only install on 32-bit
    @{Name = "Raspberry Pi Imager"; TargetPath = "${env:ProgramFiles(x86)}\Raspberry Pi Imager\rpi-imager.exe"; StartIn = "${env:ProgramFiles(x86)}\Raspberry Pi Imager" }, # it's the only install on 64-bit
    # RingCentral
    @{Name = "RingCentral"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\RingCentral\RingCentral.exe"; StartIn = "${USERS_FOLDER}\${aUser}\AppData\Local\Programs\RingCentral"; Description = "RingCentral" },
    @{Name = "RingCentral Meetings"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe"; SystemLnk = "RingCentral Meetings\"; Description = "RingCentral Meetings" },
    @{Name = "Uninstall RingCentral Meetings"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Roaming\RingCentralMeetings\uninstall\Installer.exe"; Arguments = "/uninstall"; SystemLnk = "RingCentral Meetings\"; Description = "Uninstall RingCentral Meetings" },
    # WinDirStat
    @{Name = "Help (ENG)"; TargetPath = "${env:ProgramFiles}\WinDirStat\windirstat.chm"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles}\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "Uninstall WinDirStat"; TargetPath = "${env:ProgramFiles}\WinDirStat\Uninstall.exe"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles}\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "WinDirStat"; TargetPath = "${env:ProgramFiles}\WinDirStat\windirstat.exe"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles}\WinDirStat" }, # it's the only install on 32-bit
    @{Name = "Help (ENG)"; TargetPath = "${env:ProgramFiles(x86)}\WinDirStat\windirstat.chm"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles(x86)}\WinDirStat" }, # it's the only install on 64-bit
    @{Name = "Uninstall WinDirStat"; TargetPath = "${env:ProgramFiles(x86)}\WinDirStat\Uninstall.exe"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles(x86)}\WinDirStat" }, # it's the only install on 64-bit
    @{Name = "WinDirStat"; TargetPath = "${env:ProgramFiles(x86)}\WinDirStat\windirstat.exe"; SystemLnk = "WinDirStat\"; StartIn = "${env:ProgramFiles(x86)}\WinDirStat" }, # it's the only install on 64-bit
    # Zoom
    @{Name = "Uninstall Zoom"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Roaming\Zoom\uninstall\Installer.exe"; Arguments = "/uninstall"; SystemLnk = "Zoom\"; Description = "Uninstall Zoom" },
    @{Name = "Zoom"; TargetPath = "${USERS_FOLDER}\${aUser}\AppData\Roaming\Zoom\bin\Zoom.exe"; SystemLnk = "Zoom\"; Description = "Zoom UMX" }
    #@{Name = ""; TargetPath = ""; Arguments = ""; SystemLnk = ""; StartIn = ""; Description = ""; IconLocation = ""; RunAsAdmin = ($true -Or $false) },
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
