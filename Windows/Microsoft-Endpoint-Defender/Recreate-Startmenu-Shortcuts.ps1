<#
  .SYNOPSIS
  Recreate Startmenu Shortcuts v0.9.020

  .DESCRIPTION
  Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
  
  If a program you use isn't in any of the lists here, either fork/edit/push, or create with the "Need an app added?" link below.
  
  If you are looking to use this in Intune, there is a secondary script for the to avoid the "script is too big" issue.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Creates shortcuts (if they don't already exist).
  Successes, warnings, and errors log to the console (this also logs to the file at `${env:SystemDrive}\Recreate-Startmenu-Shortcuts.log`).
  
  Returns $true or $false if script ran successfully.

  .EXAMPLE
  .\Recreate-Startmenu-Shortcuts.ps1

  .NOTES
  Requires admin! Because VBscript (used to create shortcuts) requires admin to create shortcuts in system folders.
  
  If you're going to edit the script to manually include more apps, then here's how the application objects are setup:
  
  @{
    Name = "[name of shortcut here]"
    TargetPath = "[path to exe/url/folder here]"
    Arguments = "[any arguments that an app starts with here]"
    SystemLnk = "[path to lnk or name of app here]"
    WorkingDirectory = "[start in path, if needed, here]"
    Description = "[comment, that shows up in tooltip, here]"
    IconLocation = "[path to ico|exe|ico w/ index]"
    RunAsAdmin = "[true or false, if needed]"
  }

  .LINK
  About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

  .LINK
  Intune version of script: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Startmenu-Shortcuts-INTUNE.ps1

  .LINK
  Need an app added?: https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Startmenu-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20--%3E%0A%0A

  .LINK
  Script from: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Startmenu-Shortcuts.ps1
#>
#Requires -RunAsAdministrator

# Copyright (C) 2023  Andrew Larson (thealiendrew@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

param(
  [Alias("h")]
  [switch]$Help
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}


# Logging

Start-Transcript -Path "${env:SystemDrive}\Recreate-Startmenu-Shortcuts.log"
Write-Host "" # Makes log look better



# Constants

# TODO: FOR LATER ... this will aid in repairing the taskbar (duplicate pinned apps issue)
#Set-Variable -Name PROGRAM_SHORTCUTS_PIN_PATH -Option Constant -Value "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs"
#Set-Variable -Name PROGRAM_SHORTCUTS_USER_PIN_PATH -Option Constant -Value "%APPDATA%\Microsoft\Windows\Start Menu\Programs"
Set-Variable -Name USERS_FOLDER -Option Constant -Value "${env:SystemDrive}\Users"
Set-Variable -Name NOT_INSTALLED -Option Constant -Value "NOT-INSTALLED"



# Variables

$isWindows11 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 11")
#$isWindows10 = ((Get-WMIObject win32_operatingsystem).Caption).StartsWith("Microsoft Windows 10")
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
    [ValidateScript({ Test-Path -Path $_.FullName })]
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
    } catch {} #type already been loaded, do nothing

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
    } catch {} #type already been loaded, do nothing
  }

  process {
    foreach ($Item in $Path) {
      $ReturnedType = -1
      Write-Verbose "Attempting to get type for file: `"$($Item.FullName)`""
      $Result = [Win32Utils.BinaryType]::GetBinaryType($Item.FullName, [ref] $ReturnedType)

      #if the function returned $false, indicating an error, or the binary type wasn't returned
      if (!$Result -or ($ReturnedType -eq -1)) {
        Write-Error "Failed to get binary type for file: `"$($Item.FullName)`""
      } else {
        $ToReturn = [BinaryType]$ReturnedType
        if ($PassThrough) {
          #get the file object, attach a property indicating the type, and passthru to pipeline
          Get-Item $Item.FullName -Force |
          Add-Member -MemberType noteproperty -Name BinaryType -Value $ToReturn -Force -PassThru 
        } else { 
          #Put enum object directly into pipeline
          $ToReturn 
        }
      }
    }
  }
}

function New-Shortcut {
  <#
    .SYNOPSIS
      Creates shortcut files that show up in users start menus.
    .DESCRIPTION
      Heavily uses vbscript to create the shortcuts and a little bit of byte manipulation (for "Run as admin" option).
    .PARAMETER sName
      Required: name that the shortcut .LNK will use
    .PARAMETER sTargetPath
      Required: path to the program/script file that shortcut will point to
    .PARAMETER sArguments
      Optional: arguments that are used to run the target (for special shortcuts)
    .PARAMETER sSystemLnk
      Optional: path to where the shortcut .LNK will be made (for if name/path of the .LNK is different from normal)
        - If not used, the default path is the system's start menu programs folder
    .PARAMETER sWorkingDirectory
      Optional: path where the program/script file will start in
                (e.g. like setting the directory that CMD opens in when opening the short cut)
    .PARAMETER sDescription
      Optional: sets the comment text for the shortcut (this shows up in the tooltip when hovering over shortcut)
    .PARAMETER sIconLocation
      Optional: path and index of exe/dll to use a custom icon (e.g. "example.dll, 0" uses the 1st icon)
    .PARAMETER sRunAsAdmin
      Optional: turns on the shortcut option "Run as Admin"
    .PARAMETER sUser
      Optional: username of the user
        - If sSystemLnk is not used, then the default path is the user's start menu programs folder
    .EXAMPLE
      # Create shortcut to CMD that is set to run as admin, start in the path of Jerry's profile,
      # place shortcut on Jerry's desktop, and use the default CMD icon
      New-Shortcut -n "CMD (Admin)" -tp "%windir%\system32\cmd.exe" -a "/k `"echo This is an example.`"" -sl "${env:SystemDrive}\Users\Jerry\Desktop\" -wd "${env:SystemDrive}\Users\Jerry" -d "Performs text-based (command-line) functions." -il "%windir%\system32\cmd.exe, 0" -r $true -u "Jerry"
    .NOTES
      Author: TheAlienDrew
    .LINK
      https://github.com/TheAlienDrew/OS-Scripts/tree/master/Windows
  #>
  #Requires -RunAsAdministrator

  param(
    [Parameter(Mandatory = $true)]
    [Alias("name", "n")]
    [string]$sName,

    [Parameter(Mandatory = $true)]
    [Alias("targetpath", "tp")]
    [string]$sTargetPath,

    [Alias("arguments", "a")]
    [string]$sArguments,

    [Alias("systemlnk", "sl")]
    [string]$sSystemLnk,

    [Alias("workingdirectory", "wd")]
    [string]$sWorkingDirectory,

    [Alias("description", "d")]
    [string]$sDescription,

    [Alias("iconlocation", "il")]
    [string]$sIconLocation,

    [Alias("runasadmin", "r")]
    [bool]$sRunAsAdmin,

    [Alias("user", "u")]
    [string]$sUser
  )

  $result = $true
  $resultMsg = @()
  $warnMsg = @()
  $errorMsg = @()

  Set-Variable -Name RESULT_SUCCESS -Option Constant -Value 1
  Set-Variable -Name RESULT_WARNING -Option Constant -Value 2
  Set-Variable -Name RESULT_FAILURE -Option Constant -Value 0
  Set-Variable -Name PROGRAM_SHORTCUTS_PATH -Option Constant -Value "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs"
  Set-Variable -Name PROGRAM_SHORTCUTS_USER_PATH -Option Constant -Value "${USERS_FOLDER}\${sUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"

  # validate name and target path
  if ($sName -And $sTargetPath -And (Test-Path -Path $sTargetPath -PathType leaf)) {
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
    # needed for validating path where shortcut is being made at
    $sSystemLnkPWD = $sSystemLnk.Substring(0, $sSystemLnk.lastIndexOf('\'))

    # only create shortcut if path is valid, and it doesn't already exist
    if (Test-Path -Path $sSystemLnk -PathType leaf) {
      $resultMsg += "A shortcut already exists at:`n`"${sSystemLnk}`""
      $result = if ($result) { $RESULT_WARNING }
    } elseif (Test-Path -Path $sSystemLnkPWD) {
      $WScriptObj = New-Object -ComObject WScript.Shell
      $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)

      $newLNK.TargetPath = $sTargetPath
      if ($sArguments) { $newLNK.Arguments = $sArguments }
      if ($sWorkingDirectory) { $newLNK.WorkingDirectory = $sWorkingDirectory }
      if ($sDescription) { $newLNK.Description = $sDescription }
      if ($sIconLocation) { $newLNK.IconLocation = $sIconLocation }

      $newLNK.Save()
      $result = if ($? -And $result) { $RESULT_SUCCESS } else { $RESULT_FAILURE }
      [Runtime.InteropServices.Marshal]::ReleaseComObject($WScriptObj) | Out-Null

      if ($result) {
        $resultMsg += "Created shortcut at:`n`"${sSystemLnk}`""

        # set to run as admin if needed
        if ($sRunAsAdmin) {
          $bytes = [System.IO.File]::ReadAllBytes($sSystemLnk)
          $bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
          [System.IO.File]::WriteAllBytes($sSystemLnk, $bytes)
          $result = if ($? -And $result) { $RESULT_SUCCESS } else { $RESULT_FAILURE }
          if ($result) { $resultMsg += "Shortcut set to Run as Admin, at:`n`"${sSystemLnk}`"" }
          else { $errorMsg += "Failed to set shortcut to Run as Admin, at:`n`"${sSystemLnk}`"" }
        }
      } else { $errorMsg += "Failed to create shortcut, with target at:`n`"${sTargetPath}`"`nand shortcut path at:`n`"${sSystemLnk}`"" }
    } else { $warnMsg += "Can't create shortcut, when parent directory doesn't exist, at:`n`"${sSystemLnk}`"" }
  } elseif (-Not ($sName -Or $sTargetPath)) {
    # Should never end up here due to PowerShell throwing errors upon using empty strings for parameters
    if (-Not $sName) {
      $errorMsg += "Error! Name is missing!"
    } if (-Not $sTargetPath) {
      $errorMsg += "Error! Target is missing!"
    }

    $result = $RESULT_FAILURE
  } else {
    $warnMsg += "Target invalid! Doesn't exist or is spelled wrong."
  }

  Write-Host "`"${sName}`"" -ForegroundColor $(if ($result) { if ($warnMsg) { "Yellow" } else { "Green" } } else { "Red" })
  if ($resultMsg) {
    for ($msgNum = 0; $msgNum -lt $resultMsg.length; $msgNum++) {
      Write-Host $resultMsg[$msgNum]
    }
  } elseif ($errorMsg) {
    for ($msgNum = 0; $msgNum -lt $errorMsg.length; $msgNum++) {
      Write-Error $errorMsg[$msgNum]
    }
  } if ($warnMsg) {
    for ($msgNum = 0; $msgNum -lt $warnMsg.length; $msgNum++) {
      Write-Warning $warnMsg[$msgNum]
    }
    $result = if ($? -And $result) { $RESULT_SUCCESS } else { $RESULT_FAILURE }
  }

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

# Hyper-V Manager
$HyperVManager_TargetPath = "${env:windir}\System32\"
$HyperVManager_Argument_virtmgmt = "%windir%\System32\virtmgmt.msc"
$HyperVManager_TargetPath += if (Test-Path -Path $(cmd.exe /c "echo ${HyperVManager_Argument_virtmgmt}") -PathType leaf) { "mmc.exe" } else { "${NOT_INSTALLED}.exe" }
# Powershell (7 or newer)
$PowerShell_TargetPath = "${env:ProgramFiles}\PowerShell\"
$PowerShell_Version = if (Test-Path -Path $PowerShell_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Property LastWriteTime }
$PowerShell_Version = if ($PowerShell_Version) { $PowerShell_Version[0].name } else { $NOT_INSTALLED }
$PowerShell_TargetPath += "${PowerShell_Version}\pwsh.exe"
$PowerShell_32bit_TargetPath = "${env:ProgramFiles(x86)}\PowerShell\"
$PowerShell_32bit_Version = if (Test-Path -Path $PowerShell_32bit_TargetPath) { Get-ChildItem -Directory -Path $PowerShell_32bit_TargetPath | Where-Object { $_.Name -match '^[0-9]+$' } | Sort-Object -Property LastWriteTime }
$PowerShell_32bit_Version = if ($PowerShell_32bit_Version) { $PowerShell_32bit_Version[0].name } else { $NOT_INSTALLED }
$PowerShell_32bit_TargetPath += "${PowerShell32bit_Version}\pwsh.exe"
# PowerToys
$PowerToys_TargetPath = "${env:ProgramFiles}\PowerToys\PowerToys.exe"

# App names dependant on OS or app version

# Office
$O365_DatabaseCompare_Exe = "${env:ProgramFiles}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE"
$O365_DatabaseCompare_Arguments = "`"${O365_DatabaseCompare_Exe}`""
$O365_DatabaseCompare_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_DatabaseCompare_TargetPath += if (Test-Path -Path $O365_DatabaseCompare_Exe -PathType leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" } 
$O365_SpreadsheetCompare_Exe = "${env:ProgramFiles}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE"
$O365_SpreadsheetCompare_Arguments = "`"${O365_SpreadsheetCompare_Exe}`""
$O365_SpreadsheetCompare_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_SpreadsheetCompare_TargetPath += if (Test-Path -Path $O365_SpreadsheetCompare_Exe -PathType leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
$O365_DatabaseCompare_32bit_Exe = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE"
$O365_DatabaseCompare_32bit_Arguments = "`"${O365_DatabaseCompare_32bit_Exe}`""
$O365_DatabaseCompare_32bit_TargetPath = "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_DatabaseCompare_32bit_TargetPath += if (Test-Path -Path $O365_DatabaseCompare_32bit_Exe -PathType leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
$O365_SpreadsheetCompare_32bit_Exe = "${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE"
$O365_SpreadsheetCompare_32bit_Arguments = "`"${O365_SpreadsheetCompare_32bit_Exe}`""
$O365_SpreadsheetCompare_32bit_TargetPath += "${env:ProgramFiles}\Microsoft Office\root\Client\"
$O365_SpreadsheetCompare_32bit_TargetPath = if (Test-Path -Path $O365_SpreadsheetCompare_32bit_Exe -PathType leaf) { "AppVLP.exe" } else { "${NotInstalled}.exe" }
# PowerShell (7 or newer)
$PowerShell_Name = "PowerShell " + $(if ($PowerShell_Version) { $PowerShell_Version } else { $NOT_INSTALLED }) + " (x64)"
$PowerShell_32bit_Name = "PowerShell " + $(if ($PowerShell_32bit_Version) { $PowerShell_32bit_Version } else { $NOT_INSTALLED }) + " (x86)"
# PowerToys
$PowerToys_isPreview = if (Test-Path -Path $PowerToys_TargetPath -PathType leaf) { (Get-Item $PowerToys_TargetPath).VersionInfo.FileVersionRaw.Major -eq 0 }
$PowerToys_Name = "PowerToys" + $(if ($PowerToys_isPreview) { " (Preview)" })
# Windows
$WindowsMediaPlayerOld_Name = "Windows Media Player" + $(if ($isWindows11) { " Legacy" })
$ODBCDataSources_Name = "ODBC Data Sources" + $(if ([Environment]::Is64BitOperatingSystem) { " (64-bit)" })

$sysAppList = @(
  # Azure
  @{
    Name             = "Azure Data Studio"
    TargetPath       = "${env:ProgramFiles}\Azure Data Studio\azuredatastudio.exe"
    SystemLnk        = "Azure Data Studio\"
    WorkingDirectory = "${env:ProgramFiles}\Azure Data Studio" 
  },
  @{
    Name             = "Remote Desktop"
    TargetPath       = "${env:ProgramFiles}\Remote Desktop\msrdcw.exe"
    WorkingDirectory = "${env:ProgramFiles}\Remote Desktop\"
    Description      = "Microsoft Remote Desktop Client" 
  },
  @{
    Name             = "Azure Data Studio"
    TargetPath       = "${env:ProgramFiles(x86)}\Azure Data Studio\azuredatastudio.exe"
    SystemLnk        = "Azure Data Studio\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Azure Data Studio" 
  },
  @{
    Name             = "Remote Desktop"
    TargetPath       = "${env:ProgramFiles(x86)}\Remote Desktop\msrdcw.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Remote Desktop\"
    Description      = "Microsoft Remote Desktop Client" 
  },
  # Edge
  @{ # it's the only install on 32-bit
    Name             = "Microsoft Edge"
    TargetPath       = "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft\Edge\Application"
    Description      = "Browse the web" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Microsoft Edge"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
    Description      = "Browse the web" 
  },
  # Intune 
  @{ # it's the only install on 32-bit
    Name        = "Microsoft Intune Management Extension"
    TargetPath  = "${env:ProgramFiles}\Microsoft Intune Management Extension\AgentExecutor.exe"
    SystemLnk   = "Microsoft Intune Management Extension\"
    Description = "Microsoft Intune Management Extension" 
  },
  @{
    Name             = "Remote help"
    TargetPath       = "${env:ProgramFiles}\Remote help\RemoteHelp.exe"
    SystemLnk        = "Remote help\"
    WorkingDirectory = "${env:ProgramFiles}\Remote help\"
    Description      = "Remote help" 
  },
  @{ # it's the only install on 64-bit
    Name        = "Microsoft Intune Management Extension"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Intune Management Extension\AgentExecutor.exe"
    SystemLnk   = "Microsoft Intune Management Extension\"
    Description = "Microsoft Intune Management Extension" 
  },
  @{
    Name             = "Remote help"
    TargetPath       = "${env:ProgramFiles(x86)}\Remote help\RemoteHelp.exe"
    SystemLnk        = "Remote help\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Remote help\"
    Description      = "Remote help" 
  },
  # Office (note: "Database Compare" and "Spreadsheet Compare" have specialized paths that need to be accounted for)
  @{
    Name        = "Access"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\MSACCESS.EXE"
    Description = "Build a professional app quickly to manage data." 
  },
  @{
    Name        = "Excel"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\EXCEL.EXE"
    Description = "Easily discover, visualize, and share insights from your data." 
  },
  @{
    Name        = "OneNote"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\ONENOTE.EXE"
    Description = "Take notes and have them when you need them." 
  },
  @{
    Name        = "Outlook"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE"
    Description = "Manage your email, schedules, contacts, and to-dos." 
  },
  @{
    Name        = "PowerPoint"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\POWERPNT.EXE"
    Description = "Design and deliver beautiful presentations with ease and confidence." 
  },
  @{
    Name        = "Project"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINPROJ.EXE"
    Description = "Easily collaborate with others to quickly start and deliver winning projects." 
  },
  @{
    Name        = "Publisher"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\MSPUB.EXE"
    Description = "Create professional-grade publications that make an impact." 
  },
  @{
    Name        = "Skype for Business"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\LYNC.EXE"
    Description = "Connect with people everywhere through voice and video calls, Skype Meetings, and IM." 
  },
  @{
    Name        = "Visio"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\VISIO.EXE"
    Description = "Create professional and versatile diagrams that simplify complex information." 
  },
  @{
    Name        = "Word"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\WINWORD.EXE"
    Description = "Create beautiful documents, easily work with others, and enjoy the read." 
  },
  @{ # it's the only install on 32-bit
    Name        = "Database Compare"
    TargetPath  = $O365_DatabaseCompare_TargetPath
    Arguments   = $O365_DatabaseCompare_Arguments
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Access database." 
  },
  @{ # it's the only install on 64-bit
    Name        = "Database Compare"
    TargetPath  = $O365_DatabaseCompare_32bit_TargetPath
    Arguments   = $O365_DatabaseCompare_32bit_Arguments
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Access database." 
  },
  @{
    Name        = "Office Language Preferences"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\SETLANG.EXE"
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Change the language preferences for Office applications." 
  },
  @{ # it's the only install on 32-bit
    Name        = "Spreadsheet Compare"
    TargetPath  = $O365_SpreadsheetCompare_TargetPath
    Arguments   = $O365_SpreadsheetCompare_Arguments
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Excel workbook." 
  },
  @{ # it's the only install on 64-bit
    Name        = "Spreadsheet Compare"
    TargetPath  = $O365_SpreadsheetCompare_32bit_TargetPath
    Arguments   = $O365_SpreadsheetCompare_32bit_Arguments
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Excel workbook." 
  },
  @{
    Name        = "Telemetry Log for Office"
    TargetPath  = "${env:ProgramFiles}\Microsoft Office\root\Office16\msoev.exe"
    SystemLnk   = "Microsoft Office Tools\"
    Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." 
  },
  @{
    Name        = "Access"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\MSACCESS.EXE"
    Description = "Build a professional app quickly to manage data." 
  },
  @{
    Name        = "Excel"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\EXCEL.EXE"
    Description = "Easily discover, visualize, and share insights from your data." 
  },
  @{
    Name        = "OneNote"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\ONENOTE.EXE"
    Description = "Take notes and have them when you need them." 
  },
  @{
    Name        = "Outlook"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"
    Description = "Manage your email, schedules, contacts, and to-dos." 
  },
  @{
    Name        = "PowerPoint"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\POWERPNT.EXE"
    Description = "Design and deliver beautiful presentations with ease and confidence." 
  },
  @{
    Name        = "Project"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINPROJ.EXE"
    Description = "Easily collaborate with others to quickly start and deliver winning projects." 
  },
  @{
    Name        = "Publisher"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\MSPUB.EXE"
    Description = "Create professional-grade publications that make an impact." 
  },
  @{
    Name        = "Skype for Business"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\LYNC.EXE"
    Description = "Connect with people everywhere through voice and video calls, Skype Meetings, and IM." 
  },
  @{
    Name        = "Visio"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\VISIO.EXE"
    Description = "Create professional and versatile diagrams that simplify complex information." 
  },
  @{
    Name        = "Word"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\WINWORD.EXE"
    Description = "Create beautiful documents, easily work with others, and enjoy the read." 
  },
  @{
    Name        = "Database Compare"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Client\AppVLP.exe"
    Arguments   = "`"${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Access database." 
  },
  @{
    Name        = "Office Language Preferences"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\SETLANG.EXE"
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Change the language preferences for Office applications." 
  },
  @{
    Name        = "Spreadsheet Compare"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Client\AppVLP.exe"
    Arguments   = "`"${env:ProgramFiles(x86)}\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""
    SystemLnk   = "Microsoft Office Tools\"
    Description = "Compare versions of an Excel workbook." 
  },
  @{
    Name        = "Telemetry Log for Office"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\msoev.exe"
    SystemLnk   = "Microsoft Office Tools\"
    Description = "View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log." 
  },
  # OneDrive
  @{
    Name        = "OneDrive"
    TargetPath  = "${env:ProgramFiles}\Microsoft OneDrive\OneDrive.exe"
    Description = "Keep your most important files with you wherever you go, on any device." 
  },
  @{
    Name        = "OneDrive"
    TargetPath  = "${env:ProgramFiles(x86)}\Microsoft OneDrive\OneDrive.exe"
    Description = "Keep your most important files with you wherever you go, on any device." 
  },
  # Power BI Desktop
  @{
    Name             = "Power BI Desktop"
    TargetPath       = "${env:ProgramFiles}\Microsoft Power BI Desktop\bin\PBIDesktop.exe"
    SystemLnk        = "Microsoft Power BI Desktop\"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Power BI Desktop\bin\"
    Description      = "Power BI Desktop" 
  },
  @{
    Name             = "Power BI Desktop"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Power BI Desktop\bin\PBIDesktop.exe"
    SystemLnk        = "Microsoft Power BI Desktop\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Power BI Desktop\bin\"
    Description      = "Power BI Desktop" 
  },
  # PowerShell (7 or newer)
  @{
    Name        = $PowerShell_Name
    TargetPath  = $PowerShell_TargetPath
    Arguments   = "-WorkingDirectory ~"
    SystemLnk   = "PowerShell\"
    Description = $PowerShell_Name 
 
  },
  @{
    Name        = $PowerShell_32bit_Name
    TargetPath  = $PowerShell_32bit_TargetPath
    Arguments   = "-WorkingDirectory ~"
    SystemLnk   = "PowerShell\"
    Description = $PowerShell_32bit_Name 
 
  },
  # PowerToys (note: there will never be a 32-bit version)
  @{
    Name             = $PowerToys_Name
    TargetPath       = $PowerToys_TargetPath
    SystemLnk        = $PowerToys_Name + '\'
    WorkingDirectory = "${env:ProgramFiles}\PowerToys\"
    Description      = "PowerToys - Windows system utilities to maximize productivity" 
  },
  # Visual Studio
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio Code"
    TargetPath       = "${env:ProgramFiles}\Microsoft VS Code\Code.exe"
    SystemLnk        = "Visual Studio Code\"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft VS Code" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Visual Studio Installer"
    TargetPath       = "${env:ProgramFiles}\Microsoft Visual Studio\Installer\setup.exe"
    WorkingDirectory = "${env:ProgramFiles}\Microsoft Visual Studio\Installer" 
  },
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Blend for Visual Studio 2022"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2022" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Blend for Visual Studio 2019"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2019" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\devenv.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"
    Description      = "Microsoft Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Community\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Professional\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Blend for Visual Studio 2017"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\Blend.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2017\Enterprise\Common7\IDE\"
    Description      = "Microsoft Blend for Visual Studio 2017" 
  },
  @{
    Name             = "Visual Studio Code"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft VS Code\Code.exe"
    SystemLnk        = "Visual Studio Code\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft VS Code" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Visual Studio Installer"
    TargetPath       = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\setup.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer" 
  },
  # Windows (note: these following CMD variables are not a mistake, also some names may not match as per file real name vs. localized name)
  # Windows Accessibility
  @{
    Name             = "Speech Recognition"
    TargetPath       = "${env:windir}\Speech\Common\sapisvr.exe"
    Arguments        = "-SpeechUX"
    SystemLnk        = "Accessibility\"
    WorkingDirectory = "%windir%\system32\Speech\SpeechUX"
    Description      = "Dictate text and control your computer by voice."
    IconLocation     = "%windir%\system32\Speech\SpeechUX\sapi.cpl,5" 
  },
  # Windows Accessories
  @{
    Name             = "Remote Desktop Connection"
    TargetPath       = "${env:windir}\system32\mstsc.exe"
    SystemLnk        = "Accessories\"
    WorkingDirectory = "%windir%\system32\"
    Description      = "Use your computer to connect to a computer that is located elsewhere and run programs or access files."
    IconLocation     = "%windir%\system32\mstsc.exe,0" 
  },
  @{
    Name         = "Steps Recorder"
    TargetPath   = "${env:windir}\system32\psr.exe"
    SystemLnk    = "Accessories\"
    Description  = "Capture steps with screenshots to save or share."
    IconLocation = "%windir%\system32\psr.exe,0" 
  },
  @{
    Name         = "Windows Fax and Scan"
    TargetPath   = "${env:windir}\system32\WFS.exe"
    SystemLnk    = "Accessories\"
    Description  = "Send and receive faxes or scan pictures and documents."
    IconLocation = "%windir%\system32\WFSR.dll,0" 
  },
  @{ # it's the only install on 32-bit
    Name             = $WindowsMediaPlayerOld_Name
    TargetPath       = "${env:ProgramFiles}\Windows Media Player\wmplayer.exe"
    Arguments        = "/prefetch:1"
    SystemLnk        = "Accessories\"
    WorkingDirectory = "%ProgramFiles%\Windows Media Player"
    IconLocation     = "%ProgramFiles(x86)%\Windows Media Player\wmplayer.exe,0" 
  },
  @{ # it's the only install on 64-bit
    Name             = $WindowsMediaPlayerOld_Name
    TargetPath       = "${env:ProgramFiles(x86)}\Windows Media Player\wmplayer.exe"
    Arguments        = "/prefetch:1"
    SystemLnk        = "Accessories\"
    WorkingDirectory = "%ProgramFiles(x86)%\Windows Media Player"
    IconLocation     = "%ProgramFiles(x86)%\Windows Media Player\wmplayer.exe,0" 
  },
  @{
    Name         = "Wordpad"
    TargetPath   = "${env:ProgramFiles}\Windows NT\Accessories\wordpad.exe"
    SystemLnk    = "Accessories\"
    Description  = "Creates and edits text documents with complex formatting."
    IconLocation = "%ProgramFiles%\Windows NT\Accessories\wordpad.exe,0" 
  },
  @{
    Name         = "Character Map"
    TargetPath   = "${env:windir}\system32\charmap.exe"
    SystemLnk    = "Accessories\System Tools\"
    Description  = "Selects special characters and copies them to your document."
    IconLocation = "%windir%\system32\charmap.exe,0" 
  },
  # Windows Administrative Tools
  @{
    Name         = "Component Services"
    TargetPath   = "${env:windir}\system32\comexp.msc"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Manage COM+ applications, COM and DCOM system configuration, and the Distributed Transaction Coordinator."
    IconLocation = "%systemroot%\system32\comres.dll,0" 
  },
  @{
    Name             = "Computer Management"
    TargetPath       = "${env:windir}\system32\compmgmt.msc"
    Arguments        = "/s"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
    Description      = "Manages disks and provides access to other tools to manage local and remote computers."
    IconLocation     = "%windir%\system32\Mycomput.dll,2" 
  },
  @{
    Name             = "dfrgui"
    TargetPath       = "${env:windir}\system32\dfrgui.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%systemroot%\system32"
    Description      = "Optimizes files and fragments on your volumes so that your computer runs faster and more efficiently."
    IconLocation     = "%systemroot%\system32\dfrgui.exe,0" 
  },
  @{
    Name         = "Disk Cleanup"
    TargetPath   = "${env:windir}\system32\cleanmgr.exe"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Enables you to clear your disk of unnecessary files."
    IconLocation = "%windir%\system32\cleanmgr.exe,0" 
  },
  @{
    Name             = "Event Viewer"
    TargetPath       = "${env:windir}\system32\eventvwr.msc"
    Arguments        = "/s"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\system32"
    Description      = "View monitoring and troubleshooting messages from Windows and other programs."
    IconLocation     = "%windir%\system32\miguiresource.dll,0" 
  },
  @{
    Name             = "Hyper-V Manager"
    TargetPath       = $HyperVManager_TargetPath
    Arguments        = "`"${HyperVManager_Argument_virtmgmt}`""
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%ProgramFiles%\Hyper-V\"
    Description      = "Hyper-V Manager provides management access to your virtualization platform."
    IconLocation     = "%ProgramFiles%\Hyper-V\SnapInAbout.dll,0" 
  },
  @{
    Name             = "iSCSI Initiator"
    TargetPath       = "${env:windir}\system32\iscsicpl.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\system32"
    Description      = "Connect to remote iSCSI targets and configure connection settings."
    IconLocation     = "%windir%\system32\iscsicpl.dll,-1" 
  },
  @{
    Name             = "Memory Diagnostics Tool"
    TargetPath       = "${env:windir}\system32\MdSched.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\system32"
    Description      = "Check your computer for memory problems."
    IconLocation     = "%windir%\system32\MdSched.exe,0" 
  },
  @{
    Name             = $ODBCDataSources_Name
    TargetPath       = "${env:windir}\system32\odbcad32.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\system32"
    Description      = "Maintains ODBC data sources and drivers."
    IconLocation     = "%windir%\system32\odbcint.dll,-1439" 
  },
  @{
    Name             = "ODBC Data Sources (32-bit)"
    TargetPath       = "${env:windir}\syswow64\odbcad32.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\syswow64"
    IconLocation     = "%windir%\syswow64\odbcint.dll,-1439" 
  },
  @{
    Name         = "Performance Monitor"
    TargetPath   = "${env:windir}\system32\perfmon.msc"
    Arguments    = "/s"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Diagnose performance issues and collect performance data."
    IconLocation = "%windir%\system32\wdc.dll,-108" 
  },
  @{
    Name         = "Print Management"
    TargetPath   = "${env:windir}\system32\printmanagement.msc"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Manages local printers and remote print servers."
    IconLocation = "%systemroot%\system32\pmcsnap.dll,-14" 
  },
  @{
    Name         = "RecoveryDrive"
    TargetPath   = "${env:windir}\system32\RecoveryDrive.exe"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Create a recovery drive"
    IconLocation = "%windir%\system32\RecoveryDrive.exe,-100" 
  },
  @{
    Name             = "Registry Editor"
    TargetPath       = "${env:windir}\regedit.exe"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%"
    Description      = "Registry Editor"
    IconLocation     = "%windir%\regedit.exe,-100" 
  },
  @{
    Name         = "Resource Monitor"
    TargetPath   = "${env:windir}\system32\perfmon.exe"
    Arguments    = "/res"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Monitor the usage and performance of the following resources in real time: CPU, Disk, Network and Memory."
    IconLocation = "%windir%\system32\wdc.dll,-108" 
  },
  @{
    Name         = "Security Configuration Management"
    TargetPath   = "${env:windir}\system32\secpol.msc"
    Arguments    = "/s"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "View and modify local security policy, such as user rights and audit policies."
    IconLocation = "%windir%\system32\wsecedit.dll,0" 
  },
  @{
    Name             = "services"
    TargetPath       = "${env:windir}\system32\services.msc"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
    Description      = "Starts, stops, and configures Windows services."
    IconLocation     = "%windir%\system32\filemgmt.dll,0" 
  },
  @{
    Name         = "System Configuration"
    TargetPath   = "${env:windir}\system32\msconfig.exe"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Perform advanced troubleshooting and system configuration"
    IconLocation = "%windir%\system32\msconfig.exe,-3000" 
  },
  @{
    Name         = "System Information"
    TargetPath   = "${env:windir}\system32\msinfo32.exe"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Display detailed information about your computer."
    IconLocation = "%windir%\system32\msinfo32.exe,0" 
  },
  @{
    Name         = "Task Scheduler"
    TargetPath   = "${env:windir}\system32\taskschd.msc"
    Arguments    = "/s"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Schedule computer tasks to run automatically."
    IconLocation = "%windir%\system32\miguiresource.dll,1" 
  },
  @{
    Name         = "VMCreate"
    TargetPath   = "${env:ProgramFiles}\Hyper-V\VMCreate.exe"
    SystemLnk    = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    Description  = "Hyper-V Quick Create enables rapid creation of virtual machines from a gallery of curated virtual machine images."
    IconLocation = ",0" 
  },
  @{
    Name             = "Windows Defender Firewall with Advanced Security"
    TargetPath       = "${env:windir}\system32\WF.msc"
    SystemLnk        = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\Administrative Tools\"
    WorkingDirectory = "%windir%\system32"
    Description      = "Configure policies that provide enhanced network security for Windows computers."
    IconLocation     = "%SystemRoot%\System32\AuthFWGP.dll,-101" 
  },
  # Windows Powershell
  @{
    Name             = "Windows PowerShell ISE"
    TargetPath       = "${env:windir}\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
    SystemLnk        = "Windows PowerShell\"
    WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
    Description      = "Windows PowerShell Integrated Scripting Environment. Performs object-based (command-line) functions"
    IconLocation     = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe,0" 
  },
  @{
    Name         = "Windows PowerShell ISE (x86)"
    TargetPath   = "${env:windir}\syswow64\WindowsPowerShell\v1.0\PowerShell_ISE.exe"
    SystemLnk    = "Windows PowerShell\"
    Description  = "Windows PowerShell Integrated Scripting Environment. Performs object-based (command-line) functions"
    IconLocation = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe,0" 
  },
  # Windows System Tools
  @{
    Name             = "Create USB Recovery"
    TargetPath       = "${env:windir}\System32\RecoveryDrive.exe"
    SystemLnk        = "System Tools\"
    WorkingDirectory = "${env:windir}\system32"
    IconLocation     = ",0" 
  },
  @{
    Name         = "Task Manager"
    TargetPath   = "${env:windir}\system32\taskmgr.exe"
    Arguments    = "/7"
    SystemLnk    = "System Tools\"
    Description  = "Manage running apps and view system performance"
    IconLocation = "%windir%\system32\Taskmgr.exe,-30651" 
  }
  <#

  @{
    Name = "..."
    TargetPath = "${env:ProgramFiles}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  @{Name = "..."
    TargetPath = "${env:ProgramFiles(x86)}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  
  #>
)

for ($i = 0; $i -lt $sysAppList.length; $i++) {
  $app = $sysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aWorkingDirectory = if ($app.WorkingDirectory) { $app.WorkingDirectory } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $AttemptRecreation = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -wd $aWorkingDirectory -d $aDescription -il $aIconLocation -r $aRunAsAdmin
  if ($ScriptResults -And ($AttemptRecreation -ne 1)) { $ScriptResults = $AttemptRecreation }
  if ($AttemptRecreation -eq 2) { Write-Warning "Entry at `$sysAppList[$i] prompted this warning." }
  Write-Host ""
}



# OEM System Applications (e.g. Dell)

# App arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# App paths dependant on app version

## App Name
#$App_TargetPath = ...
#$App_WorkingDirectory = ...

# App names dependant on OS or app version

## App Name
#$App_Name = ...

$oemSysAppList = @(
  # Dell
  @{
    Name             = "Dell Display Manager 2.0"
    TargetPath       = "${env:ProgramFiles}\Dell\Dell Display Manager 2.0\DDM.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles}\Dell\Dell Display Manager 2.0\Prerequisites" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Dell OS Recovery Tool"
    TargetPath       = "${env:ProgramFiles}\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles}\Dell\OS Recovery Tool\" 
  },
  @{
    Name             = "Dell Peripheral Manager"
    TargetPath       = "${env:ProgramFiles}\Dell\Dell Peripheral Manager\DPM.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles}\Dell\Dell Peripheral Manager" 
  },
  @{
    Name       = "SupportAssist Recovery Assistant"
    TargetPath = "${env:ProgramFiles}\Dell\SARemediation\postosri\osrecoveryagent.exe"
    SystemLnk  = "Dell\SupportAssist\"
  },
  @{
    Name             = "Dell Display Manager 2.0"
    TargetPath       = "${env:ProgramFiles(x86)}\Dell\Dell Display Manager 2.0\DDM.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Dell\Dell Display Manager 2.0\Prerequisites" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Dell OS Recovery Tool"
    TargetPath       = "${env:ProgramFiles(x86)}\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Dell\OS Recovery Tool\" 
  },
  @{
    Name             = "Dell Peripheral Manager"
    TargetPath       = "${env:ProgramFiles(x86)}\Dell\Dell Peripheral Manager\DPM.exe"
    SystemLnk        = "Dell\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Dell\Dell Peripheral Manager" 
  },
  @{
    Name       = "SupportAssist Recovery Assistant"
    TargetPath = "${env:ProgramFiles(x86)}\Dell\SARemediation\postosri\osrecoveryagent.exe"
    SystemLnk  = "Dell\SupportAssist\"
  },
  # NVIDIA Corporation
  @{
    Name             = "GeForce Experience"
    TargetPath       = "${env:ProgramFiles}\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"
    SystemLnk        = "NVIDIA Corporation\"
    WorkingDirectory = "${env:ProgramFiles}\NVIDIA Corporation\NVIDIA GeForce Experience" 
  }
  @{
    Name             = "GeForce Experience"
    TargetPath       = "${env:ProgramFiles(x86)}\NVIDIA Corporation\NVIDIA GeForce Experience\NVIDIA GeForce Experience.exe"
    SystemLnk        = "NVIDIA Corporation\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\NVIDIA Corporation\NVIDIA GeForce Experience" 
  }
  <#

  @{
    Name = "..."
    TargetPath = "${env:ProgramFiles}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  @{Name = "..."
    TargetPath = "${env:ProgramFiles(x86)}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  
  #>
)

for ($i = 0; $i -lt $oemSysAppList.length; $i++) {
  $app = $oemSysAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aWorkingDirectory = if ($app.WorkingDirectory) { $app.WorkingDirectory } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $AttemptRecreation = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -wd $aWorkingDirectory -d $aDescription -il $aIconLocation -r $aRunAsAdmin
  if ($ScriptResults -And ($AttemptRecreation -ne 1)) { $ScriptResults = $AttemptRecreation }
  if ($AttemptRecreation -eq 2) { Write-Warning "Entry at `$sysAppList[$i] prompted this warning." }
  Write-Host ""
}



# Third-Party System Applications (not made by Microsoft)

# App arguments dependant on uninstall strings

# Egnyte Desktop App
$EgnyteDesktopApp_Uninstall_GUID = $UninstallList | Where-Object { $_.Name -match "Egnyte Desktop App" }
$EgnyteDesktopApp_Uninstall_GUID = if ($EgnyteDesktopApp_Uninstall_GUID) { $EgnyteDesktopApp_Uninstall_GUID[0].GUID } else { $null }
$EgnyteDesktopApp_Uninstall_Arguments = if ($EgnyteDesktopApp_Uninstall_GUID) { "/x ${EgnyteDesktopApp_Uninstall_GUID}" } else { "" }
$EgnyteDesktopApp_Uninstall_TargetPath = "${env:windir}\System32\" + $(if ($EgnyteDesktopApp_Uninstall_GUID) { "msiexec.exe" } else { "${NOT_INSTALLED}.exe" })
$EgnyteDesktopApp_Uninstall_32bit_GUID = $UninstallList_32bit | Where-Object { $_.Name -match "Egnyte Desktop App" }
$EgnyteDesktopApp_Uninstall_32bit_GUID = if ($EgnyteDesktopApp_Uninstall_32bit_GUID) { $EgnyteDesktopApp_Uninstall_32bit_GUID[0].GUID } else { $null }
$EgnyteDesktopApp_Uninstall_32bit_Arguments = if ($EgnyteDesktopApp_Uninstall_32bit_GUID) { "/x ${EgnyteDesktopApp_Uninstall_32bit_GUID}" } else { "" }
$EgnyteDesktopApp_Uninstall_32bit_TargetPath = "${env:windir}\System32\" + $(if ($EgnyteDesktopApp_Uninstall_32bit_GUID) { "msiexec.exe" } else { "${NOT_INSTALLED}.exe" })

# App paths dependant on app version

# Adobe Aero
$Aero_TargetPath = "${env:ProgramFiles}\Adobe\"
$Aero_Name = if (Test-Path -Path $Aero_TargetPath) { Get-ChildItem -Directory -Path $Aero_TargetPath | Where-Object { $_.Name -match '^.*Aero(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Aero_Name = if ($Aero_Name) { $Aero_Name[0].name } else { "Adobe Aero" }
$Aero_WorkingDirectory = $Aero_TargetPath + $Aero_Name
$Aero_WorkingDirectoryAlt = $Aero_WorkingDirectory + "\Support Files"
$Aero_WorkingDirectoryAlt2 = $Aero_WorkingDirectoryAlt + "\Contents\Windows"
$Aero_TargetPath = $Aero_WorkingDirectory + "\Aero.exe"
$Aero_TargetPathAlt = $Aero_WorkingDirectoryAlt + "\Aero.exe"
$Aero_TargetPathAlt2 = $Aero_WorkingDirectoryAlt2 + "\Aero.exe"
$Aero_TargetPath = if (Test-Path -Path $Aero_TargetPath -PathType leaf) { $Aero_TargetPath } elseif (Test-Path -Path $Aero_TargetPathAlt -PathType leaf) { $Aero_TargetPathAlt } else { $Aero_TargetPathAlt2 }
$Aero_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Aero_Beta_Name = if (Test-Path -Path $Aero_Beta_TargetPath) { Get-ChildItem -Directory -Path $Aero_Beta_TargetPath | Where-Object { $_.Name -match '^.*Aero.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Aero_Beta_Name = if ($Aero_Beta_Name) { $Aero_Beta_Name[0].name } else { "Adobe Aero (Beta)" }
$Aero_Beta_WorkingDirectory = $Aero_Beta_TargetPath + $Aero_Beta_Name
$Aero_Beta_WorkingDirectoryAlt = $Aero_Beta_WorkingDirectory + "\Support Files"
$Aero_Beta_WorkingDirectoryAlt2 = $Aero_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Aero_Beta_TargetPathExeAlt = $Aero_Beta_WorkingDirectory + "\Aero.exe"
$Aero_Beta_TargetPathAltExeAlt = $Aero_Beta_WorkingDirectoryAlt + "\Aero.exe"
$Aero_Beta_TargetPathAlt2ExeAlt = $Aero_Beta_WorkingDirectoryAlt2 + "\Aero.exe"
$Aero_Beta_TargetPath = $Aero_Beta_WorkingDirectory + "\Aero (Beta).exe"
$Aero_Beta_TargetPathAlt = $Aero_Beta_WorkingDirectoryAlt + "\Aero (Beta).exe"
$Aero_Beta_TargetPathAlt2 = $Aero_Beta_WorkingDirectoryAlt2 + "\Aero (Beta).exe"
$Aero_Beta_TargetPath = if (Test-Path -Path $Aero_Beta_TargetPathExeAlt -PathType leaf) { $Aero_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Aero_Beta_TargetPathAltExeAlt -PathType leaf) { $Aero_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Aero_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Aero_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Aero_Beta_TargetPath -PathType leaf) { $Aero_Beta_TargetPath } elseif (Test-Path -Path $Aero_Beta_TargetPathAlt -PathType leaf) { $Aero_Beta_TargetPathAlt } `
  else { $Aero_Beta_TargetPathAlt2 }
# Adobe After Effects
$AfterEffects_TargetPath = "${env:ProgramFiles}\Adobe\"
$AfterEffects_Name = if (Test-Path -Path $AfterEffects_TargetPath) { Get-ChildItem -Directory -Path $AfterEffects_TargetPath | Where-Object { $_.Name -match '^.*After Effects(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$AfterEffects_Name = if ($AfterEffects_Name) { $AfterEffects_Name[0].name } else { "Adobe After Effects" }
$AfterEffects_WorkingDirectory = $AfterEffects_TargetPath + $AfterEffects_Name
$AfterEffects_WorkingDirectoryAlt = $AfterEffects_WorkingDirectory + "\Support Files"
$AfterEffects_WorkingDirectoryAlt2 = $AfterEffects_WorkingDirectoryAlt + "\Contents\Windows"
$AfterEffects_TargetPath = $AfterEffects_WorkingDirectory + "\AfterFX.exe"
$AfterEffects_TargetPathAlt = $AfterEffects_WorkingDirectoryAlt + "\AfterFX.exe"
$AfterEffects_TargetPathAlt2 = $AfterEffects_WorkingDirectoryAlt2 + "\AfterFX.exe"
$AfterEffects_TargetPath = if (Test-Path -Path $AfterEffects_TargetPath -PathType leaf) { $AfterEffects_TargetPath } elseif (Test-Path -Path $AfterEffects_TargetPathAlt -PathType leaf) { $AfterEffects_TargetPathAlt } else { $AfterEffects_TargetPathAlt2 }
$AfterEffects_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$AfterEffects_Beta_Name = if (Test-Path -Path $AfterEffects_Beta_TargetPath) { Get-ChildItem -Directory -Path $AfterEffects_Beta_TargetPath | Where-Object { $_.Name -match '^.*After Effects.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$AfterEffects_Beta_Name = if ($AfterEffects_Beta_Name) { $AfterEffects_Beta_Name[0].name } else { "Adobe After Effects (Beta)" }
$AfterEffects_Beta_WorkingDirectory = $AfterEffects_Beta_TargetPath + $AfterEffects_Beta_Name
$AfterEffects_Beta_WorkingDirectoryAlt = $AfterEffects_Beta_WorkingDirectory + "\Support Files"
$AfterEffects_Beta_WorkingDirectoryAlt2 = $AfterEffects_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$AfterEffects_Beta_TargetPathExeAlt = $AfterEffects_Beta_WorkingDirectory + "\AfterFX.exe"
$AfterEffects_Beta_TargetPathAltExeAlt = $AfterEffects_Beta_WorkingDirectoryAlt + "\AfterFX.exe"
$AfterEffects_Beta_TargetPathAlt2ExeAlt = $AfterEffects_Beta_WorkingDirectoryAlt2 + "\AfterFX.exe"
$AfterEffects_Beta_TargetPath = $AfterEffects_Beta_WorkingDirectory + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPathAlt = $AfterEffects_Beta_WorkingDirectoryAlt + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPathAlt2 = $AfterEffects_Beta_WorkingDirectoryAlt2 + "\AfterFX (Beta).exe"
$AfterEffects_Beta_TargetPath = if (Test-Path -Path $AfterEffects_Beta_TargetPathExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathExeAlt } elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAltExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $AfterEffects_Beta_TargetPath -PathType leaf) { $AfterEffects_Beta_TargetPath } `
  elseif (Test-Path -Path $AfterEffects_Beta_TargetPathAlt -PathType leaf) { $AfterEffects_Beta_TargetPathAlt } else { $AfterEffects_Beta_TargetPathAlt2 }
# Adobe Animate
$Animate_TargetPath = "${env:ProgramFiles}\Adobe\"
$Animate_Name = if (Test-Path -Path $Animate_TargetPath) { Get-ChildItem -Directory -Path $Animate_TargetPath | Where-Object { $_.Name -match '^.*Animate(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Animate_Name = if ($Animate_Name) { $Animate_Name[0].name } else { "Adobe Animate" }
$Animate_WorkingDirectory = $Animate_TargetPath + $Animate_Name
$Animate_WorkingDirectoryAlt = $Animate_WorkingDirectory + "\Support Files"
$Animate_WorkingDirectoryAlt2 = $Animate_WorkingDirectoryAlt + "\Contents\Windows"
$Animate_TargetPath = $Animate_WorkingDirectory + "\Animate.exe"
$Animate_TargetPathAlt = $Animate_WorkingDirectoryAlt + "\Animate.exe"
$Animate_TargetPathAlt2 = $Animate_WorkingDirectoryAlt2 + "\Animate.exe"
$Animate_TargetPath = if (Test-Path -Path $Animate_TargetPath -PathType leaf) { $Animate_TargetPath } elseif (Test-Path -Path $Animate_TargetPathAlt -PathType leaf) { $Animate_TargetPathAlt } else { $Animate_TargetPathAlt2 }
$Animate_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Animate_Beta_Name = if (Test-Path -Path $Animate_Beta_TargetPath) { Get-ChildItem -Directory -Path $Animate_Beta_TargetPath | Where-Object { $_.Name -match '^.*Animate.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Animate_Beta_Name = if ($Animate_Beta_Name) { $Animate_Beta_Name[0].name } else { "Adobe Animate (Beta)" }
$Animate_Beta_WorkingDirectory = $Animate_Beta_TargetPath + $Animate_Beta_Name
$Animate_Beta_WorkingDirectoryAlt = $Animate_Beta_WorkingDirectory + "\Support Files"
$Animate_Beta_WorkingDirectoryAlt2 = $Animate_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Animate_Beta_TargetPathExeAlt = $Animate_Beta_WorkingDirectory + "\Animate.exe"
$Animate_Beta_TargetPathAltExeAlt = $Animate_Beta_WorkingDirectoryAlt + "\Animate.exe"
$Animate_Beta_TargetPathAlt2ExeAlt = $Animate_Beta_WorkingDirectoryAlt2 + "\Animate.exe"
$Animate_Beta_TargetPath = $Animate_Beta_WorkingDirectory + "\Animate (Beta).exe"
$Animate_Beta_TargetPathAlt = $Animate_Beta_WorkingDirectoryAlt + "\Animate (Beta).exe"
$Animate_Beta_TargetPathAlt2 = $Animate_Beta_WorkingDirectoryAlt2 + "\Animate (Beta).exe"
$Animate_Beta_TargetPath = if (Test-Path -Path $Animate_Beta_TargetPathExeAlt -PathType leaf) { $Animate_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Animate_Beta_TargetPathAltExeAlt -PathType leaf) { $Animate_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Animate_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Animate_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Animate_Beta_TargetPath -PathType leaf) { $Animate_Beta_TargetPath } `
  elseif (Test-Path -Path $Animate_Beta_TargetPathAlt -PathType leaf) { $Animate_Beta_TargetPathAlt } else { $Animate_Beta_TargetPathAlt2 }
# Adobe Audition
$Audition_TargetPath = "${env:ProgramFiles}\Adobe\"
$Audition_Name = if (Test-Path -Path $Audition_TargetPath) { Get-ChildItem -Directory -Path $Audition_TargetPath | Where-Object { $_.Name -match '^.*Audition(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Audition_Name = if ($Audition_Name) { $Audition_Name[0].name } else { "Adobe Audition" }
$Audition_WorkingDirectory = $Audition_TargetPath + $Audition_Name
$Audition_WorkingDirectoryAlt = $Audition_WorkingDirectory + "\Support Files"
$Audition_WorkingDirectoryAlt2 = $Audition_WorkingDirectoryAlt + "\Contents\Windows"
$Audition_TargetPath = $Audition_WorkingDirectory + "\Adobe Audition.exe"
$Audition_TargetPathAlt = $Audition_WorkingDirectoryAlt + "\Adobe Audition.exe"
$Audition_TargetPathAlt2 = $Audition_WorkingDirectoryAlt2 + "\Adobe Audition.exe"
$Audition_TargetPath = if (Test-Path -Path $Audition_TargetPath -PathType leaf) { $Audition_TargetPath } elseif (Test-Path -Path $Audition_TargetPathAlt -PathType leaf) { $Audition_TargetPathAlt } else { $Audition_TargetPathAlt2 }
$Audition_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Audition_Beta_Name = if (Test-Path -Path $Audition_Beta_TargetPath) { Get-ChildItem -Directory -Path $Audition_Beta_TargetPath | Where-Object { $_.Name -match '^.*Audition.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Audition_Beta_Name = if ($Audition_Beta_Name) { $Audition_Beta_Name[0].name } else { "Adobe Audition (Beta)" }
$Audition_Beta_WorkingDirectory = $Audition_Beta_TargetPath + $Audition_Beta_Name
$Audition_Beta_WorkingDirectoryAlt = $Audition_Beta_WorkingDirectory + "\Support Files"
$Audition_Beta_WorkingDirectoryAlt2 = $Audition_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Audition_Beta_TargetPathExeAlt = $Audition_Beta_WorkingDirectory + "\Adobe Audition.exe"
$Audition_Beta_TargetPathAltExeAlt = $Audition_Beta_WorkingDirectoryAlt + "\Adobe Audition.exe"
$Audition_Beta_TargetPathAlt2ExeAlt = $Audition_Beta_WorkingDirectoryAlt2 + "\Adobe Audition.exe"
$Audition_Beta_TargetPath = $Audition_Beta_WorkingDirectory + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPathAlt = $Audition_Beta_WorkingDirectoryAlt + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPathAlt2 = $Audition_Beta_WorkingDirectoryAlt2 + "\Adobe Audition (Beta).exe"
$Audition_Beta_TargetPath = if (Test-Path -Path $Audition_Beta_TargetPathExeAlt -PathType leaf) { $Audition_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Audition_Beta_TargetPathAltExeAlt -PathType leaf) { $Audition_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Audition_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Audition_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Audition_Beta_TargetPath -PathType leaf) { $Audition_Beta_TargetPath } `
  elseif (Test-Path -Path $Audition_Beta_TargetPathAlt -PathType leaf) { $Audition_Beta_TargetPathAlt } else { $Audition_Beta_TargetPathAlt2 }
# Adobe Bridge
$Bridge_TargetPath = "${env:ProgramFiles}\Adobe\"
$Bridge_Name = if (Test-Path -Path $Bridge_TargetPath) { Get-ChildItem -Directory -Path $Bridge_TargetPath | Where-Object { $_.Name -match '^.*Bridge(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Bridge_Name = if ($Bridge_Name) { $Bridge_Name[0].name } else { "Adobe Bridge" }
$Bridge_WorkingDirectory = $Bridge_TargetPath + $Bridge_Name
$Bridge_WorkingDirectoryAlt = $Bridge_WorkingDirectory + "\Support Files"
$Bridge_WorkingDirectoryAlt2 = $Bridge_WorkingDirectoryAlt + "\Contents\Windows"
$Bridge_TargetPath = $Bridge_WorkingDirectory + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt = $Bridge_WorkingDirectoryAlt + "\Adobe Bridge.exe"
$Bridge_TargetPathAlt2 = $Bridge_WorkingDirectoryAlt2 + "\Adobe Bridge.exe"
$Bridge_TargetPath = if (Test-Path -Path $Bridge_TargetPath -PathType leaf) { $Bridge_TargetPath } elseif (Test-Path -Path $Bridge_TargetPathAlt -PathType leaf) { $Bridge_TargetPathAlt } else { $Bridge_TargetPathAlt2 }
$Bridge_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Bridge_Beta_Name = if (Test-Path -Path $Bridge_Beta_TargetPath) { Get-ChildItem -Directory -Path $Bridge_Beta_TargetPath | Where-Object { $_.Name -match '^.*Bridge.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Bridge_Beta_Name = if ($Bridge_Beta_Name) { $Bridge_Beta_Name[0].name } else { "Adobe Bridge (Beta)" }
$Bridge_Beta_WorkingDirectory = $Bridge_Beta_TargetPath + $Bridge_Beta_Name
$Bridge_Beta_WorkingDirectoryAlt = $Bridge_Beta_WorkingDirectory + "\Support Files"
$Bridge_Beta_WorkingDirectoryAlt2 = $Bridge_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Bridge_Beta_TargetPathExeAlt = $Bridge_Beta_WorkingDirectory + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPathAltExeAlt = $Bridge_Beta_WorkingDirectoryAlt + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPathAlt2ExeAlt = $Bridge_Beta_WorkingDirectoryAlt2 + "\Adobe Bridge.exe"
$Bridge_Beta_TargetPath = $Bridge_Beta_WorkingDirectory + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPathAlt = $Bridge_Beta_WorkingDirectoryAlt + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPathAlt2 = $Bridge_Beta_WorkingDirectoryAlt2 + "\Adobe Bridge (Beta).exe"
$Bridge_Beta_TargetPath = if (Test-Path -Path $Bridge_Beta_TargetPathExeAlt -PathType leaf) { $Bridge_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Bridge_Beta_TargetPathAltExeAlt -PathType leaf) { $Bridge_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Bridge_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Bridge_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Bridge_Beta_TargetPath -PathType leaf) { $Bridge_Beta_TargetPath } `
  elseif (Test-Path -Path $Bridge_Beta_TargetPathAlt -PathType leaf) { $Bridge_Beta_TargetPathAlt } else { $Bridge_Beta_TargetPathAlt2 }
# Adobe Character Animator
$CharacterAnimator_TargetPath = "${env:ProgramFiles}\Adobe\"
$CharacterAnimator_Name = if (Test-Path -Path $CharacterAnimator_TargetPath) { Get-ChildItem -Directory -Path $CharacterAnimator_TargetPath | Where-Object { $_.Name -match '^.*Character Animator(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$CharacterAnimator_Name = if ($CharacterAnimator_Name) { $CharacterAnimator_Name[0].name } else { "Adobe Character Animator" }
$CharacterAnimator_WorkingDirectory = $CharacterAnimator_TargetPath + $CharacterAnimator_Name
$CharacterAnimator_WorkingDirectoryAlt = $CharacterAnimator_WorkingDirectory + "\Support Files"
$CharacterAnimator_WorkingDirectoryAlt2 = $CharacterAnimator_WorkingDirectoryAlt + "\Contents\Windows"
$CharacterAnimator_TargetPath = $CharacterAnimator_WorkingDirectory + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt = $CharacterAnimator_WorkingDirectoryAlt + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPathAlt2 = $CharacterAnimator_WorkingDirectoryAlt2 + "\Adobe Character Animator.exe"
$CharacterAnimator_TargetPath = if (Test-Path -Path $CharacterAnimator_TargetPath -PathType leaf) { $CharacterAnimator_TargetPath } elseif (Test-Path -Path $CharacterAnimator_TargetPathAlt -PathType leaf) { $CharacterAnimator_TargetPathAlt } else { $CharacterAnimator_TargetPathAlt2 }
$CharacterAnimator_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$CharacterAnimator_Beta_Name = if (Test-Path -Path $CharacterAnimator_Beta_TargetPath) { Get-ChildItem -Directory -Path $CharacterAnimator_Beta_TargetPath | Where-Object { $_.Name -match '^.*Character Animator.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$CharacterAnimator_Beta_Name = if ($CharacterAnimator_Beta_Name) { $CharacterAnimator_Beta_Name[0].name } else { "Adobe Character Animator (Beta)" }
$CharacterAnimator_Beta_WorkingDirectory = $CharacterAnimator_Beta_TargetPath + $CharacterAnimator_Beta_Name
$CharacterAnimator_Beta_WorkingDirectoryAlt = $CharacterAnimator_Beta_WorkingDirectory + "\Support Files"
$CharacterAnimator_Beta_WorkingDirectoryAlt2 = $CharacterAnimator_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$CharacterAnimator_Beta_TargetPathExeAlt = $CharacterAnimator_Beta_WorkingDirectory + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPathAltExeAlt = $CharacterAnimator_Beta_WorkingDirectoryAlt + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPathAlt2ExeAlt = $CharacterAnimator_Beta_WorkingDirectoryAlt2 + "\Adobe Character Animator.exe"
$CharacterAnimator_Beta_TargetPath = $CharacterAnimator_Beta_WorkingDirectory + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPathAlt = $CharacterAnimator_Beta_WorkingDirectoryAlt + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPathAlt2 = $CharacterAnimator_Beta_WorkingDirectoryAlt2 + "\Adobe Character Animator (Beta).exe"
$CharacterAnimator_Beta_TargetPath = if (Test-Path -Path $CharacterAnimator_Beta_TargetPathExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathExeAlt } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAltExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPath -PathType leaf) { $CharacterAnimator_Beta_TargetPath } `
  elseif (Test-Path -Path $CharacterAnimator_Beta_TargetPathAlt -PathType leaf) { $CharacterAnimator_Beta_TargetPathAlt } else { $CharacterAnimator_Beta_TargetPathAlt2 }
# Adobe Dimension
$Dimension_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dimension_Name = if (Test-Path -Path $Dimension_TargetPath) { Get-ChildItem -Directory -Path $Dimension_TargetPath | Where-Object { $_.Name -match '^.*Dimension(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Dimension_Name = if ($Dimension_Name) { $Dimension_Name[0].name } else { "Dimension" }
$Dimension_WorkingDirectory = $Dimension_TargetPath + $Dimension_Name
$Dimension_WorkingDirectoryAlt = $Dimension_WorkingDirectory + "\Support Files"
$Dimension_WorkingDirectoryAlt2 = $Dimension_WorkingDirectoryAlt + "\Contents\Windows"
$Dimension_TargetPath = $Dimension_WorkingDirectory + "\Dimension.exe"
$Dimension_TargetPathAlt = $Dimension_WorkingDirectoryAlt + "\Dimension.exe"
$Dimension_TargetPathAlt2 = $Dimension_WorkingDirectoryAlt2 + "\Dimension.exe"
$Dimension_TargetPath = if (Test-Path -Path $Dimension_TargetPath -PathType leaf) { $Dimension_TargetPath } elseif (Test-Path -Path $Dimension_TargetPathAlt -PathType leaf) { $Dimension_TargetPathAlt } else { $Dimension_TargetPathAlt2 }
$Dimension_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dimension_Beta_Name = if (Test-Path -Path $Dimension_Beta_TargetPath) { Get-ChildItem -Directory -Path $Dimension_Beta_TargetPath | Where-Object { $_.Name -match '^.*Dimension.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Dimension_Beta_Name = if ($Dimension_Beta_Name) { $Dimension_Beta_Name[0].name } else { "Dimension (Beta)" }
$Dimension_Beta_WorkingDirectory = $Dimension_Beta_TargetPath + $Dimension_Beta_Name
$Dimension_Beta_WorkingDirectoryAlt = $Dimension_Beta_WorkingDirectory + "\Support Files"
$Dimension_Beta_WorkingDirectoryAlt2 = $Dimension_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Dimension_Beta_TargetPathExeAlt = $Dimension_Beta_WorkingDirectory + "\Dimension.exe"
$Dimension_Beta_TargetPathAltExeAlt = $Dimension_Beta_WorkingDirectoryAlt + "\Dimension.exe"
$Dimension_Beta_TargetPathAlt2ExeAlt = $Dimension_Beta_WorkingDirectoryAlt2 + "\Dimension.exe"
$Dimension_Beta_TargetPath = $Dimension_Beta_WorkingDirectory + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPathAlt = $Dimension_Beta_WorkingDirectoryAlt + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPathAlt2 = $Dimension_Beta_WorkingDirectoryAlt2 + "\Dimension (Beta).exe"
$Dimension_Beta_TargetPath = if (Test-Path -Path $Dimension_Beta_TargetPathExeAlt -PathType leaf) { $Dimension_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Dimension_Beta_TargetPathAltExeAlt -PathType leaf) { $Dimension_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Dimension_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Dimension_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Dimension_Beta_TargetPath -PathType leaf) { $Dimension_Beta_TargetPath } `
  elseif (Test-Path -Path $Dimension_Beta_TargetPathAlt -PathType leaf) { $Dimension_Beta_TargetPathAlt } else { $Dimension_Beta_TargetPathAlt2 }
# Adobe Dreamweaver
$Dreamweaver_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dreamweaver_Name = if (Test-Path -Path $Dreamweaver_TargetPath) { Get-ChildItem -Directory -Path $Dreamweaver_TargetPath | Where-Object { $_.Name -match '^.*Dreamweaver(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Dreamweaver_Name = if ($Dreamweaver_Name) { $Dreamweaver_Name[0].name } else { "Adobe Dreamweaver" }
$Dreamweaver_WorkingDirectory = $Dreamweaver_TargetPath + $Dreamweaver_Name
$Dreamweaver_WorkingDirectoryAlt = $Dreamweaver_WorkingDirectory + "\Support Files"
$Dreamweaver_WorkingDirectoryAlt2 = $Dreamweaver_WorkingDirectoryAlt + "\Contents\Windows"
$Dreamweaver_TargetPath = $Dreamweaver_WorkingDirectory + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt = $Dreamweaver_WorkingDirectoryAlt + "\Dreamweaver.exe"
$Dreamweaver_TargetPathAlt2 = $Dreamweaver_WorkingDirectoryAlt2 + "\Dreamweaver.exe"
$Dreamweaver_TargetPath = if (Test-Path -Path $Dreamweaver_TargetPath -PathType leaf) { $Dreamweaver_TargetPath } elseif (Test-Path -Path $Dreamweaver_TargetPathAlt -PathType leaf) { $Dreamweaver_TargetPathAlt } else { $Dreamweaver_TargetPathAlt2 }
$Dreamweaver_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Dreamweaver_Beta_Name = if (Test-Path -Path $Dreamweaver_Beta_TargetPath) { Get-ChildItem -Directory -Path $Dreamweaver_Beta_TargetPath | Where-Object { $_.Name -match '^.*Dreamweaver.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Dreamweaver_Beta_Name = if ($Dreamweaver_Beta_Name) { $Dreamweaver_Beta_Name[0].name } else { "Adobe Dreamweaver (Beta)" }
$Dreamweaver_Beta_WorkingDirectory = $Dreamweaver_Beta_TargetPath + $Dreamweaver_Beta_Name
$Dreamweaver_Beta_WorkingDirectoryAlt = $Dreamweaver_Beta_WorkingDirectory + "\Support Files"
$Dreamweaver_Beta_WorkingDirectoryAlt2 = $Dreamweaver_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Dreamweaver_Beta_TargetPathExeAlt = $Dreamweaver_Beta_WorkingDirectory + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPathAltExeAlt = $Dreamweaver_Beta_WorkingDirectoryAlt + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPathAlt2ExeAlt = $Dreamweaver_Beta_WorkingDirectoryAlt2 + "\Dreamweaver.exe"
$Dreamweaver_Beta_TargetPath = $Dreamweaver_Beta_WorkingDirectory + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPathAlt = $Dreamweaver_Beta_WorkingDirectoryAlt + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPathAlt2 = $Dreamweaver_Beta_WorkingDirectoryAlt2 + "\Dreamweaver (Beta).exe"
$Dreamweaver_Beta_TargetPath = if (Test-Path -Path $Dreamweaver_Beta_TargetPathExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAltExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Dreamweaver_Beta_TargetPath -PathType leaf) { $Dreamweaver_Beta_TargetPath } `
  elseif (Test-Path -Path $Dreamweaver_Beta_TargetPathAlt -PathType leaf) { $Dreamweaver_Beta_TargetPathAlt } else { $Dreamweaver_Beta_TargetPathAlt2 }
# Adobe Illustrator
$Illustrator_TargetPath = "${env:ProgramFiles}\Adobe\"
$Illustrator_Name = if (Test-Path -Path $Illustrator_TargetPath) { Get-ChildItem -Directory -Path $Illustrator_TargetPath | Where-Object { $_.Name -match '^.*Illustrator(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Illustrator_Name = if ($Illustrator_Name) { $Illustrator_Name[0].name } else { "Adobe Illustrator" }
$Illustrator_WorkingDirectory = $Illustrator_TargetPath + $Illustrator_Name
$Illustrator_WorkingDirectoryAlt = $Illustrator_WorkingDirectory + "\Support Files"
$Illustrator_WorkingDirectoryAlt2 = $Illustrator_WorkingDirectoryAlt + "\Contents\Windows"
$Illustrator_TargetPath = $Illustrator_WorkingDirectory + "\Illustrator.exe"
$Illustrator_TargetPathAlt = $Illustrator_WorkingDirectoryAlt + "\Illustrator.exe"
$Illustrator_TargetPathAlt2 = $Illustrator_WorkingDirectoryAlt2 + "\Illustrator.exe"
$Illustrator_TargetPath = if (Test-Path -Path $Illustrator_TargetPath -PathType leaf) { $Illustrator_TargetPath } elseif (Test-Path -Path $Illustrator_TargetPathAlt -PathType leaf) { $Illustrator_TargetPathAlt } else { $Illustrator_TargetPathAlt2 }
$Illustrator_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Illustrator_Beta_Name = if (Test-Path -Path $Illustrator_Beta_TargetPath) { Get-ChildItem -Directory -Path $Illustrator_Beta_TargetPath | Where-Object { $_.Name -match '^.*Illustrator.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Illustrator_Beta_Name = if ($Illustrator_Beta_Name) { $Illustrator_Beta_Name[0].name } else { "Adobe Illustrator (Beta)" }
$Illustrator_Beta_WorkingDirectory = $Illustrator_Beta_TargetPath + $Illustrator_Beta_Name
$Illustrator_Beta_WorkingDirectoryAlt = $Illustrator_Beta_WorkingDirectory + "\Support Files"
$Illustrator_Beta_WorkingDirectoryAlt2 = $Illustrator_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Illustrator_Beta_TargetPathExeAlt = $Illustrator_Beta_WorkingDirectory + "\Illustrator.exe"
$Illustrator_Beta_TargetPathAltExeAlt = $Illustrator_Beta_WorkingDirectoryAlt + "\Illustrator.exe"
$Illustrator_Beta_TargetPathAlt2ExeAlt = $Illustrator_Beta_WorkingDirectoryAlt2 + "\Illustrator.exe"
$Illustrator_Beta_TargetPath = $Illustrator_Beta_WorkingDirectory + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPathAlt = $Illustrator_Beta_WorkingDirectoryAlt + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPathAlt2 = $Illustrator_Beta_WorkingDirectoryAlt2 + "\Illustrator (Beta).exe"
$Illustrator_Beta_TargetPath = if (Test-Path -Path $Illustrator_Beta_TargetPathExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Illustrator_Beta_TargetPathAltExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Illustrator_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Illustrator_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Illustrator_Beta_TargetPath -PathType leaf) { $Illustrator_Beta_TargetPath } `
  elseif (Test-Path -Path $Illustrator_Beta_TargetPathAlt -PathType leaf) { $Illustrator_Beta_TargetPathAlt } else { $Illustrator_Beta_TargetPathAlt2 }
# Adobe InCopy
$InCopy_TargetPath = "${env:ProgramFiles}\Adobe\"
$InCopy_Name = if (Test-Path -Path $InCopy_TargetPath) { Get-ChildItem -Directory -Path $InCopy_TargetPath | Where-Object { $_.Name -match '^.*InCopy(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$InCopy_Name = if ($InCopy_Name) { $InCopy_Name[0].name } else { "Adobe InCopy" }
$InCopy_WorkingDirectory = $InCopy_TargetPath + $InCopy_Name
$InCopy_WorkingDirectoryAlt = $InCopy_WorkingDirectory + "\Support Files"
$InCopy_WorkingDirectoryAlt2 = $InCopy_WorkingDirectoryAlt + "\Contents\Windows"
$InCopy_TargetPath = $InCopy_WorkingDirectory + "\InCopy.exe"
$InCopy_TargetPathAlt = $InCopy_WorkingDirectoryAlt + "\InCopy.exe"
$InCopy_TargetPathAlt2 = $InCopy_WorkingDirectoryAlt2 + "\InCopy.exe"
$InCopy_TargetPath = if (Test-Path -Path $InCopy_TargetPath -PathType leaf) { $InCopy_TargetPath } elseif (Test-Path -Path $InCopy_TargetPathAlt -PathType leaf) { $InCopy_TargetPathAlt } else { $InCopy_TargetPathAlt2 }
$InCopy_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$InCopy_Beta_Name = if (Test-Path -Path $InCopy_Beta_TargetPath) { Get-ChildItem -Directory -Path $InCopy_Beta_TargetPath | Where-Object { $_.Name -match '^.*InCopy.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$InCopy_Beta_Name = if ($InCopy_Beta_Name) { $InCopy_Beta_Name[0].name } else { "Adobe InCopy (Beta)" }
$InCopy_Beta_WorkingDirectory = $InCopy_Beta_TargetPath + $InCopy_Beta_Name
$InCopy_Beta_WorkingDirectoryAlt = $InCopy_Beta_WorkingDirectory + "\Support Files"
$InCopy_Beta_WorkingDirectoryAlt2 = $InCopy_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$InCopy_Beta_TargetPathExeAlt = $InCopy_Beta_WorkingDirectory + "\InCopy.exe"
$InCopy_Beta_TargetPathAltExeAlt = $InCopy_Beta_WorkingDirectoryAlt + "\InCopy.exe"
$InCopy_Beta_TargetPathAlt2ExeAlt = $InCopy_Beta_WorkingDirectoryAlt2 + "\InCopy.exe"
$InCopy_Beta_TargetPath = $InCopy_Beta_WorkingDirectory + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPathAlt = $InCopy_Beta_WorkingDirectoryAlt + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPathAlt2 = $InCopy_Beta_WorkingDirectoryAlt2 + "\InCopy (Beta).exe"
$InCopy_Beta_TargetPath = if (Test-Path -Path $InCopy_Beta_TargetPathExeAlt -PathType leaf) { $InCopy_Beta_TargetPathExeAlt } elseif (Test-Path -Path $InCopy_Beta_TargetPathAltExeAlt -PathType leaf) { $InCopy_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $InCopy_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $InCopy_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $InCopy_Beta_TargetPath -PathType leaf) { $InCopy_Beta_TargetPath } `
  elseif (Test-Path -Path $InCopy_Beta_TargetPathAlt -PathType leaf) { $InCopy_Beta_TargetPathAlt } else { $InCopy_Beta_TargetPathAlt2 }
# Adobe InDesign
$InDesign_TargetPath = "${env:ProgramFiles}\Adobe\"
$InDesign_Name = if (Test-Path -Path $InDesign_TargetPath) { Get-ChildItem -Directory -Path $InDesign_TargetPath | Where-Object { $_.Name -match '^.*InDesign(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$InDesign_Name = if ($InDesign_Name) { $InDesign_Name[0].name } else { "Adobe InDesign" }
$InDesign_WorkingDirectory = $InDesign_TargetPath + $InDesign_Name
$InDesign_WorkingDirectoryAlt = $InDesign_WorkingDirectory + "\Support Files"
$InDesign_WorkingDirectoryAlt2 = $InDesign_WorkingDirectoryAlt + "\Contents\Windows"
$InDesign_TargetPath = $InDesign_WorkingDirectory + "\InDesign.exe"
$InDesign_TargetPathAlt = $InDesign_WorkingDirectoryAlt + "\InDesign.exe"
$InDesign_TargetPathAlt2 = $InDesign_WorkingDirectoryAlt2 + "\InDesign.exe"
$InDesign_TargetPath = if (Test-Path -Path $InDesign_TargetPath -PathType leaf) { $InDesign_TargetPath } elseif (Test-Path -Path $InDesign_TargetPathAlt -PathType leaf) { $InDesign_TargetPathAlt } else { $InDesign_TargetPathAlt2 }
$InDesign_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$InDesign_Beta_Name = if (Test-Path -Path $InDesign_Beta_TargetPath) { Get-ChildItem -Directory -Path $InDesign_Beta_TargetPath | Where-Object { $_.Name -match '^.*InDesign.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$InDesign_Beta_Name = if ($InDesign_Beta_Name) { $InDesign_Beta_Name[0].name } else { "Adobe InDesign (Beta)" }
$InDesign_Beta_WorkingDirectory = $InDesign_Beta_TargetPath + $InDesign_Beta_Name
$InDesign_Beta_WorkingDirectoryAlt = $InDesign_Beta_WorkingDirectory + "\Support Files"
$InDesign_Beta_WorkingDirectoryAlt2 = $InDesign_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$InDesign_Beta_TargetPathExeAlt = $InDesign_Beta_WorkingDirectory + "\InDesign.exe"
$InDesign_Beta_TargetPathAltExeAlt = $InDesign_Beta_WorkingDirectoryAlt + "\InDesign.exe"
$InDesign_Beta_TargetPathAlt2ExeAlt = $InDesign_Beta_WorkingDirectoryAlt2 + "\InDesign.exe"
$InDesign_Beta_TargetPath = $InDesign_Beta_WorkingDirectory + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPathAlt = $InDesign_Beta_WorkingDirectoryAlt + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPathAlt2 = $InDesign_Beta_WorkingDirectoryAlt2 + "\InDesign (Beta).exe"
$InDesign_Beta_TargetPath = if (Test-Path -Path $InDesign_Beta_TargetPathExeAlt -PathType leaf) { $InDesign_Beta_TargetPathExeAlt } elseif (Test-Path -Path $InDesign_Beta_TargetPathAltExeAlt -PathType leaf) { $InDesign_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $InDesign_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $InDesign_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $InDesign_Beta_TargetPath -PathType leaf) { $InDesign_Beta_TargetPath } `
  elseif (Test-Path -Path $InDesign_Beta_TargetPathAlt -PathType leaf) { $InDesign_Beta_TargetPathAlt } else { $InDesign_Beta_TargetPathAlt2 }
# Adobe Lightroom
$Lightroom_TargetPath = "${env:ProgramFiles}\Adobe\"
$Lightroom_Name = if (Test-Path -Path $Lightroom_TargetPath) { Get-ChildItem -Directory -Path $Lightroom_TargetPath | Where-Object { $_.Name -match '^.*Lightroom(?!.*Classic)(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Lightroom_Name = if ($Lightroom_Name) { $Lightroom_Name[0].name } else { "Adobe Lightroom" }
$Lightroom_WorkingDirectory = $Lightroom_TargetPath + $Lightroom_Name
$Lightroom_WorkingDirectoryAlt = $Lightroom_WorkingDirectory + "\Support Files"
$Lightroom_WorkingDirectoryAlt2 = $Lightroom_WorkingDirectoryAlt + "\Contents\Windows"
$Lightroom_TargetPath = $Lightroom_WorkingDirectory + "\lightroom.exe"
$Lightroom_TargetPathAlt = $Lightroom_WorkingDirectoryAlt + "\lightroom.exe"
$Lightroom_TargetPathAlt2 = $Lightroom_WorkingDirectoryAlt2 + "\lightroom.exe"
$Lightroom_TargetPath = if (Test-Path -Path $Lightroom_TargetPath -PathType leaf) { $Lightroom_TargetPath } elseif (Test-Path -Path $Lightroom_TargetPathAlt -PathType leaf) { $Lightroom_TargetPathAlt } else { $Lightroom_TargetPathAlt2 }
$Lightroom_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Lightroom_Beta_Name = if (Test-Path -Path $Lightroom_Beta_TargetPath) { Get-ChildItem -Directory -Path $Lightroom_Beta_TargetPath | Where-Object { $_.Name -match '^.*Lightroom(?!.*Classic).*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Lightroom_Beta_Name = if ($Lightroom_Beta_Name) { $Lightroom_Beta_Name[0].name } else { "Adobe Lightroom (Beta)" }
$Lightroom_Beta_WorkingDirectory = $Lightroom_Beta_TargetPath + $Lightroom_Beta_Name
$Lightroom_Beta_WorkingDirectoryAlt = $Lightroom_Beta_WorkingDirectory + "\Support Files"
$Lightroom_Beta_WorkingDirectoryAlt2 = $Lightroom_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Lightroom_Beta_TargetPathExeAlt = $Lightroom_Beta_WorkingDirectory + "\lightroom.exe"
$Lightroom_Beta_TargetPathAltExeAlt = $Lightroom_Beta_WorkingDirectoryAlt + "\lightroom.exe"
$Lightroom_Beta_TargetPathAlt2ExeAlt = $Lightroom_Beta_WorkingDirectoryAlt2 + "\lightroom.exe"
$Lightroom_Beta_TargetPath = $Lightroom_Beta_WorkingDirectory + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPathAlt = $Lightroom_Beta_WorkingDirectoryAlt + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPathAlt2 = $Lightroom_Beta_WorkingDirectoryAlt2 + "\lightroom (Beta).exe"
$Lightroom_Beta_TargetPath = if (Test-Path -Path $Lightroom_Beta_TargetPathExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Lightroom_Beta_TargetPathAltExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Lightroom_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Lightroom_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Lightroom_Beta_TargetPath -PathType leaf) { $Lightroom_Beta_TargetPath } `
  elseif (Test-Path -Path $Lightroom_Beta_TargetPathAlt -PathType leaf) { $Lightroom_Beta_TargetPathAlt } else { $Lightroom_Beta_TargetPathAlt2 }
# Adobe Lightroom Classic
$LightroomClassic_TargetPath = "${env:ProgramFiles}\Adobe\"
$LightroomClassic_Name = if (Test-Path -Path $LightroomClassic_TargetPath) { Get-ChildItem -Directory -Path $LightroomClassic_TargetPath | Where-Object { $_.Name -match '^.*Lightroom Classic(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$LightroomClassic_Name = if ($LightroomClassic_Name) { $LightroomClassic_Name[0].name } else { "Adobe Lightroom Classic" }
$LightroomClassic_WorkingDirectory = $LightroomClassic_TargetPath + $LightroomClassic_Name
$LightroomClassic_WorkingDirectoryAlt = $LightroomClassic_WorkingDirectory + "\Support Files"
$LightroomClassic_WorkingDirectoryAlt2 = $LightroomClassic_WorkingDirectoryAlt + "\Contents\Windows"
$LightroomClassic_TargetPath = $LightroomClassic_WorkingDirectory + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt = $LightroomClassic_WorkingDirectoryAlt + "\Lightroom.exe"
$LightroomClassic_TargetPathAlt2 = $LightroomClassic_WorkingDirectoryAlt2 + "\Lightroom.exe"
$LightroomClassic_TargetPath = if (Test-Path -Path $LightroomClassic_TargetPath -PathType leaf) { $LightroomClassic_TargetPath } elseif (Test-Path -Path $LightroomClassic_TargetPathAlt -PathType leaf) { $LightroomClassic_TargetPathAlt } else { $LightroomClassic_TargetPathAlt2 }
$LightroomClassic_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$LightroomClassic_Beta_Name = if (Test-Path -Path $LightroomClassic_Beta_TargetPath) { Get-ChildItem -Directory -Path $LightroomClassic_Beta_TargetPath | Where-Object { $_.Name -match '^.*Lightroom Classic.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$LightroomClassic_Beta_Name = if ($LightroomClassic_Beta_Name) { $LightroomClassic_Beta_Name[0].name } else { "Adobe Lightroom Classic (Beta)" }
$LightroomClassic_Beta_WorkingDirectory = $LightroomClassic_Beta_TargetPath + $LightroomClassic_Beta_Name
$LightroomClassic_Beta_WorkingDirectoryAlt = $LightroomClassic_Beta_WorkingDirectory + "\Support Files"
$LightroomClassic_Beta_WorkingDirectoryAlt2 = $LightroomClassic_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$LightroomClassic_Beta_TargetPathExeAlt = $LightroomClassic_Beta_WorkingDirectory + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPathAltExeAlt = $LightroomClassic_Beta_WorkingDirectoryAlt + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPathAlt2ExeAlt = $LightroomClassic_Beta_WorkingDirectoryAlt2 + "\Lightroom.exe"
$LightroomClassic_Beta_TargetPath = $LightroomClassic_Beta_WorkingDirectory + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPathAlt = $LightroomClassic_Beta_WorkingDirectoryAlt + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPathAlt2 = $LightroomClassic_Beta_WorkingDirectoryAlt2 + "\Lightroom (Beta).exe"
$LightroomClassic_Beta_TargetPath = if (Test-Path -Path $LightroomClassic_Beta_TargetPathExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathExeAlt } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAltExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $LightroomClassic_Beta_TargetPath -PathType leaf) { $LightroomClassic_Beta_TargetPath } `
  elseif (Test-Path -Path $LightroomClassic_Beta_TargetPathAlt -PathType leaf) { $LightroomClassic_Beta_TargetPathAlt } else { $LightroomClassic_Beta_TargetPathAlt2 }
# Adobe Media Encoder
$MediaEncoder_TargetPath = "${env:ProgramFiles}\Adobe\"
$MediaEncoder_Name = if (Test-Path -Path $MediaEncoder_TargetPath) { Get-ChildItem -Directory -Path $MediaEncoder_TargetPath | Where-Object { $_.Name -match '^.*Media Encoder(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$MediaEncoder_Name = if ($MediaEncoder_Name) { $MediaEncoder_Name[0].name } else { "Adobe Media Encoder" }
$MediaEncoder_WorkingDirectory = $MediaEncoder_TargetPath + $MediaEncoder_Name
$MediaEncoder_WorkingDirectoryAlt = $MediaEncoder_WorkingDirectory + "\Support Files"
$MediaEncoder_WorkingDirectoryAlt2 = $MediaEncoder_WorkingDirectoryAlt + "\Contents\Windows"
$MediaEncoder_TargetPath = $MediaEncoder_WorkingDirectory + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt = $MediaEncoder_WorkingDirectoryAlt + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPathAlt2 = $MediaEncoder_WorkingDirectoryAlt2 + "\Adobe Media Encoder.exe"
$MediaEncoder_TargetPath = if (Test-Path -Path $MediaEncoder_TargetPath -PathType leaf) { $MediaEncoder_TargetPath } elseif (Test-Path -Path $MediaEncoder_TargetPathAlt -PathType leaf) { $MediaEncoder_TargetPathAlt } else { $MediaEncoder_TargetPathAlt2 }
$MediaEncoder_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$MediaEncoder_Beta_Name = if (Test-Path -Path $MediaEncoder_Beta_TargetPath) { Get-ChildItem -Directory -Path $MediaEncoder_Beta_TargetPath | Where-Object { $_.Name -match '^.*Media Encoder.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$MediaEncoder_Beta_Name = if ($MediaEncoder_Beta_Name) { $MediaEncoder_Beta_Name[0].name } else { "Adobe Media Encoder (Beta)" }
$MediaEncoder_Beta_WorkingDirectory = $MediaEncoder_Beta_TargetPath + $MediaEncoder_Beta_Name
$MediaEncoder_Beta_WorkingDirectoryAlt = $MediaEncoder_Beta_WorkingDirectory + "\Support Files"
$MediaEncoder_Beta_WorkingDirectoryAlt2 = $MediaEncoder_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$MediaEncoder_Beta_TargetPathExeAlt = $MediaEncoder_Beta_WorkingDirectory + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPathAltExeAlt = $MediaEncoder_Beta_WorkingDirectoryAlt + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPathAlt2ExeAlt = $MediaEncoder_Beta_WorkingDirectoryAlt2 + "\Adobe Media Encoder.exe"
$MediaEncoder_Beta_TargetPath = $MediaEncoder_Beta_WorkingDirectory + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPathAlt = $MediaEncoder_Beta_WorkingDirectoryAlt + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPathAlt2 = $MediaEncoder_Beta_WorkingDirectoryAlt2 + "\Adobe Media Encoder (Beta).exe"
$MediaEncoder_Beta_TargetPath = if (Test-Path -Path $MediaEncoder_Beta_TargetPathExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathExeAlt } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAltExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $MediaEncoder_Beta_TargetPath -PathType leaf) { $MediaEncoder_Beta_TargetPath } `
  elseif (Test-Path -Path $MediaEncoder_Beta_TargetPathAlt -PathType leaf) { $MediaEncoder_Beta_TargetPathAlt } else { $MediaEncoder_Beta_TargetPathAlt2 }
# Adobe Photoshop
$Photoshop_TargetPath = "${env:ProgramFiles}\Adobe\"
$Photoshop_Name = if (Test-Path -Path $Photoshop_TargetPath) { Get-ChildItem -Directory -Path $Photoshop_TargetPath | Where-Object { $_.Name -match '^.*Photoshop(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Photoshop_Name = if ($Photoshop_Name) { $Photoshop_Name[0].name } else { "Adobe Photoshop" }
$Photoshop_WorkingDirectory = $Photoshop_TargetPath + $Photoshop_Name
$Photoshop_WorkingDirectoryAlt = $Photoshop_WorkingDirectory + "\Support Files"
$Photoshop_WorkingDirectoryAlt2 = $Photoshop_WorkingDirectoryAlt + "\Contents\Windows"
$Photoshop_TargetPath = $Photoshop_WorkingDirectory + "\Photoshop.exe"
$Photoshop_TargetPathAlt = $Photoshop_WorkingDirectoryAlt + "\Photoshop.exe"
$Photoshop_TargetPathAlt2 = $Photoshop_WorkingDirectoryAlt2 + "\Photoshop.exe"
$Photoshop_TargetPath = if (Test-Path -Path $Photoshop_TargetPath -PathType leaf) { $Photoshop_TargetPath } elseif (Test-Path -Path $Photoshop_TargetPathAlt -PathType leaf) { $Photoshop_TargetPathAlt } else { $Photoshop_TargetPathAlt2 }
$Photoshop_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Photoshop_Beta_Name = if (Test-Path -Path $Photoshop_Beta_TargetPath) { Get-ChildItem -Directory -Path $Photoshop_Beta_TargetPath | Where-Object { $_.Name -match '^.*Photoshop.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Photoshop_Beta_Name = if ($Photoshop_Beta_Name) { $Photoshop_Beta_Name[0].name } else { "Adobe Photoshop (Beta)" }
$Photoshop_Beta_WorkingDirectory = $Photoshop_Beta_TargetPath + $Photoshop_Beta_Name
$Photoshop_Beta_WorkingDirectoryAlt = $Photoshop_Beta_WorkingDirectory + "\Support Files"
$Photoshop_Beta_WorkingDirectoryAlt2 = $Photoshop_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Photoshop_Beta_TargetPathExeAlt = $Photoshop_Beta_WorkingDirectory + "\Photoshop.exe"
$Photoshop_Beta_TargetPathAltExeAlt = $Photoshop_Beta_WorkingDirectoryAlt + "\Photoshop.exe"
$Photoshop_Beta_TargetPathAlt2ExeAlt = $Photoshop_Beta_WorkingDirectoryAlt2 + "\Photoshop.exe"
$Photoshop_Beta_TargetPath = $Photoshop_Beta_WorkingDirectory + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPathAlt = $Photoshop_Beta_WorkingDirectoryAlt + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPathAlt2 = $Photoshop_Beta_WorkingDirectoryAlt2 + "\Photoshop (Beta).exe"
$Photoshop_Beta_TargetPath = if (Test-Path -Path $Photoshop_Beta_TargetPathExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Photoshop_Beta_TargetPathAltExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Photoshop_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Photoshop_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Photoshop_Beta_TargetPath -PathType leaf) { $Photoshop_Beta_TargetPath } `
  elseif (Test-Path -Path $Photoshop_Beta_TargetPathAlt -PathType leaf) { $Photoshop_Beta_TargetPathAlt } else { $Photoshop_Beta_TargetPathAlt2 }
# Adobe Premiere Pro
$PremierePro_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremierePro_Name = if (Test-Path -Path $PremierePro_TargetPath) { Get-ChildItem -Directory -Path $PremierePro_TargetPath | Where-Object { $_.Name -match '^.*Premiere Pro(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$PremierePro_Name = if ($PremierePro_Name) { $PremierePro_Name[0].name } else { "Adobe Premiere Pro" }
$PremierePro_WorkingDirectory = $PremierePro_TargetPath + $PremierePro_Name
$PremierePro_WorkingDirectoryAlt = $PremierePro_WorkingDirectory + "\Support Files"
$PremierePro_WorkingDirectoryAlt2 = $PremierePro_WorkingDirectoryAlt + "\Contents\Windows"
$PremierePro_TargetPath = $PremierePro_WorkingDirectory + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt = $PremierePro_WorkingDirectoryAlt + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPathAlt2 = $PremierePro_WorkingDirectoryAlt2 + "\Adobe Premiere Pro.exe"
$PremierePro_TargetPath = if (Test-Path -Path $PremierePro_TargetPath -PathType leaf) { $PremierePro_TargetPath } elseif (Test-Path -Path $PremierePro_TargetPathAlt -PathType leaf) { $PremierePro_TargetPathAlt } else { $PremierePro_TargetPathAlt2 }
$PremierePro_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremierePro_Beta_Name = if (Test-Path -Path $PremierePro_Beta_TargetPath) { Get-ChildItem -Directory -Path $PremierePro_Beta_TargetPath | Where-Object { $_.Name -match '^.*Premiere Pro.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$PremierePro_Beta_Name = if ($PremierePro_Beta_Name) { $PremierePro_Beta_Name[0].name } else { "Adobe Premiere Pro (Beta)" }
$PremierePro_Beta_WorkingDirectory = $PremierePro_Beta_TargetPath + $PremierePro_Beta_Name
$PremierePro_Beta_WorkingDirectoryAlt = $PremierePro_Beta_WorkingDirectory + "\Support Files"
$PremierePro_Beta_WorkingDirectoryAlt2 = $PremierePro_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$PremierePro_Beta_TargetPathExeAlt = $PremierePro_Beta_WorkingDirectory + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPathAltExeAlt = $PremierePro_Beta_WorkingDirectoryAlt + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPathAlt2ExeAlt = $PremierePro_Beta_WorkingDirectoryAlt2 + "\Adobe Premiere Pro.exe"
$PremierePro_Beta_TargetPath = $PremierePro_Beta_WorkingDirectory + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPathAlt = $PremierePro_Beta_WorkingDirectoryAlt + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPathAlt2 = $PremierePro_Beta_WorkingDirectoryAlt2 + "\Adobe Premiere Pro (Beta).exe"
$PremierePro_Beta_TargetPath = if (Test-Path -Path $PremierePro_Beta_TargetPathExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathExeAlt } elseif (Test-Path -Path $PremierePro_Beta_TargetPathAltExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $PremierePro_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $PremierePro_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $PremierePro_Beta_TargetPath -PathType leaf) { $PremierePro_Beta_TargetPath } `
  elseif (Test-Path -Path $PremierePro_Beta_TargetPathAlt -PathType leaf) { $PremierePro_Beta_TargetPathAlt } else { $PremierePro_Beta_TargetPathAlt2 }
# Adobe Premiere Rush
$PremiereRush_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremiereRush_Name = if (Test-Path -Path $PremiereRush_TargetPath) { Get-ChildItem -Directory -Path $PremiereRush_TargetPath | Where-Object { $_.Name -match '^.*Premiere Rush(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$PremiereRush_Name = if ($PremiereRush_Name) { $PremiereRush_Name[0].name } else { "Adobe Premiere Rush" }
$PremiereRush_WorkingDirectory = $PremiereRush_TargetPath + $PremiereRush_Name
$PremiereRush_WorkingDirectoryAlt = $PremiereRush_WorkingDirectory + "\Support Files"
$PremiereRush_WorkingDirectoryAlt2 = $PremiereRush_WorkingDirectoryAlt + "\Contents\Windows"
$PremiereRush_TargetPath = $PremiereRush_WorkingDirectory + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt = $PremiereRush_WorkingDirectoryAlt + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPathAlt2 = $PremiereRush_WorkingDirectoryAlt2 + "\Adobe Premiere Rush.exe"
$PremiereRush_TargetPath = if (Test-Path -Path $PremiereRush_TargetPath -PathType leaf) { $PremiereRush_TargetPath } elseif (Test-Path -Path $PremiereRush_TargetPathAlt -PathType leaf) { $PremiereRush_TargetPathAlt } else { $PremiereRush_TargetPathAlt2 }
$PremiereRush_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$PremiereRush_Beta_Name = if (Test-Path -Path $PremiereRush_Beta_TargetPath) { Get-ChildItem -Directory -Path $PremiereRush_Beta_TargetPath | Where-Object { $_.Name -match '^.*Premiere Rush.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$PremiereRush_Beta_Name = if ($PremiereRush_Beta_Name) { $PremiereRush_Beta_Name[0].name } else { "Adobe Premiere Rush (Beta)" }
$PremiereRush_Beta_WorkingDirectory = $PremiereRush_Beta_TargetPath + $PremiereRush_Beta_Name
$PremiereRush_Beta_WorkingDirectoryAlt = $PremiereRush_Beta_WorkingDirectory + "\Support Files"
$PremiereRush_Beta_WorkingDirectoryAlt2 = $PremiereRush_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$PremiereRush_Beta_TargetPathExeAlt = $PremiereRush_Beta_WorkingDirectory + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPathAltExeAlt = $PremiereRush_Beta_WorkingDirectoryAlt + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPathAlt2ExeAlt = $PremiereRush_Beta_WorkingDirectoryAlt2 + "\Adobe Premiere Rush.exe"
$PremiereRush_Beta_TargetPath = $PremiereRush_Beta_WorkingDirectory + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPathAlt = $PremiereRush_Beta_WorkingDirectoryAlt + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPathAlt2 = $PremiereRush_Beta_WorkingDirectoryAlt2 + "\Adobe Premiere Rush (Beta).exe"
$PremiereRush_Beta_TargetPath = if (Test-Path -Path $PremiereRush_Beta_TargetPathExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathExeAlt } elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAltExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $PremiereRush_Beta_TargetPath -PathType leaf) { $PremiereRush_Beta_TargetPath } `
  elseif (Test-Path -Path $PremiereRush_Beta_TargetPathAlt -PathType leaf) { $PremiereRush_Beta_TargetPathAlt } else { $PremiereRush_Beta_TargetPathAlt2 }
# Adobe Substance 3D Designer
$Substance3dDesigner_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dDesigner_Name = if (Test-Path -Path $Substance3dDesigner_TargetPath) { Get-ChildItem -Directory -Path $Substance3dDesigner_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Designer(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Substance3dDesigner_Name = if ($Substance3dDesigner_Name) { $Substance3dDesigner_Name[0].name } else { "Adobe Substance 3D Designer" }
$Substance3dDesigner_WorkingDirectory = $Substance3dDesigner_TargetPath + $Substance3dDesigner_Name
$Substance3dDesigner_WorkingDirectoryAlt = $Substance3dDesigner_WorkingDirectory + "\Support Files"
$Substance3dDesigner_WorkingDirectoryAlt2 = $Substance3dDesigner_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dDesigner_TargetPath = $Substance3dDesigner_WorkingDirectory + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt = $Substance3dDesigner_WorkingDirectoryAlt + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPathAlt2 = $Substance3dDesigner_WorkingDirectoryAlt2 + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_TargetPath = if (Test-Path -Path $Substance3dDesigner_TargetPath -PathType leaf) { $Substance3dDesigner_TargetPath } elseif (Test-Path -Path $Substance3dDesigner_TargetPathAlt -PathType leaf) { $Substance3dDesigner_TargetPathAlt } else { $Substance3dDesigner_TargetPathAlt2 }
$Substance3dDesigner_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dDesigner_Beta_Name = if (Test-Path -Path $Substance3dDesigner_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dDesigner_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Designer.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Substance3dDesigner_Beta_Name = if ($Substance3dDesigner_Beta_Name) { $Substance3dDesigner_Beta_Name[0].name } else { "Adobe Substance 3D Designer (Beta)" }
$Substance3dDesigner_Beta_WorkingDirectory = $Substance3dDesigner_Beta_TargetPath + $Substance3dDesigner_Beta_Name
$Substance3dDesigner_Beta_WorkingDirectoryAlt = $Substance3dDesigner_Beta_WorkingDirectory + "\Support Files"
$Substance3dDesigner_Beta_WorkingDirectoryAlt2 = $Substance3dDesigner_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dDesigner_Beta_TargetPathExeAlt = $Substance3dDesigner_Beta_WorkingDirectory + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPathAltExeAlt = $Substance3dDesigner_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPathAlt2ExeAlt = $Substance3dDesigner_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Designer.exe"
$Substance3dDesigner_Beta_TargetPath = $Substance3dDesigner_Beta_WorkingDirectory + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPathAlt = $Substance3dDesigner_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPathAlt2 = $Substance3dDesigner_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Designer (Beta).exe"
$Substance3dDesigner_Beta_TargetPath = if (Test-Path -Path $Substance3dDesigner_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathExeAlt } `
  elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAltExeAlt } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAlt2ExeAlt } `
  elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPath -PathType leaf) { $Substance3dDesigner_Beta_TargetPath } elseif (Test-Path -Path $Substance3dDesigner_Beta_TargetPathAlt -PathType leaf) { $Substance3dDesigner_Beta_TargetPathAlt } else { $Substance3dDesigner_Beta_TargetPathAlt2 }
# Adobe Substance 3D Modeler
$Substance3dModeler_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dModeler_Name = if (Test-Path -Path $Substance3dModeler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dModeler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Modeler(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Substance3dModeler_Name = if ($Substance3dModeler_Name) { $Substance3dModeler_Name[0].name } else { "Adobe Substance 3D Modeler" }
$Substance3dModeler_WorkingDirectory = $Substance3dModeler_TargetPath + $Substance3dModeler_Name
$Substance3dModeler_WorkingDirectoryAlt = $Substance3dModeler_WorkingDirectory + "\Support Files"
$Substance3dModeler_WorkingDirectoryAlt2 = $Substance3dModeler_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dModeler_TargetPath = $Substance3dModeler_WorkingDirectory + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt = $Substance3dModeler_WorkingDirectoryAlt + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPathAlt2 = $Substance3dModeler_WorkingDirectoryAlt2 + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_TargetPath = if (Test-Path -Path $Substance3dModeler_TargetPath -PathType leaf) { $Substance3dModeler_TargetPath } elseif (Test-Path -Path $Substance3dModeler_TargetPathAlt -PathType leaf) { $Substance3dModeler_TargetPathAlt } else { $Substance3dModeler_TargetPathAlt2 }
$Substance3dModeler_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dModeler_Beta_Name = if (Test-Path -Path $Substance3dModeler_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dModeler_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Modeler.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Substance3dModeler_Beta_Name = if ($Substance3dModeler_Beta_Name) { $Substance3dModeler_Beta_Name[0].name } else { "Adobe Substance 3D Modeler (Beta)" }
$Substance3dModeler_Beta_WorkingDirectory = $Substance3dModeler_Beta_TargetPath + $Substance3dModeler_Beta_Name
$Substance3dModeler_Beta_WorkingDirectoryAlt = $Substance3dModeler_Beta_WorkingDirectory + "\Support Files"
$Substance3dModeler_Beta_WorkingDirectoryAlt2 = $Substance3dModeler_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dModeler_Beta_TargetPathExeAlt = $Substance3dModeler_Beta_WorkingDirectory + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPathAltExeAlt = $Substance3dModeler_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPathAlt2ExeAlt = $Substance3dModeler_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Modeler.exe"
$Substance3dModeler_Beta_TargetPath = $Substance3dModeler_Beta_WorkingDirectory + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPathAlt = $Substance3dModeler_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPathAlt2 = $Substance3dModeler_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Modeler (Beta).exe"
$Substance3dModeler_Beta_TargetPath = if (Test-Path -Path $Substance3dModeler_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPath -PathType leaf) { $Substance3dModeler_Beta_TargetPath } `
  elseif (Test-Path -Path $Substance3dModeler_Beta_TargetPathAlt -PathType leaf) { $Substance3dModeler_Beta_TargetPathAlt } else { $Substance3dModeler_Beta_TargetPathAlt2 }
# Adobe Substance 3D Painter
$Substance3dPainter_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dPainter_Name = if (Test-Path -Path $Substance3dPainter_TargetPath) { Get-ChildItem -Directory -Path $Substance3dPainter_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Painter(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Substance3dPainter_Name = if ($Substance3dPainter_Name) { $Substance3dPainter_Name[0].name } else { "Adobe Substance 3D Painter" }
$Substance3dPainter_WorkingDirectory = $Substance3dPainter_TargetPath + $Substance3dPainter_Name
$Substance3dPainter_WorkingDirectoryAlt = $Substance3dPainter_WorkingDirectory + "\Support Files"
$Substance3dPainter_WorkingDirectoryAlt2 = $Substance3dPainter_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dPainter_TargetPath = $Substance3dPainter_WorkingDirectory + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt = $Substance3dPainter_WorkingDirectoryAlt + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPathAlt2 = $Substance3dPainter_WorkingDirectoryAlt2 + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_TargetPath = if (Test-Path -Path $Substance3dPainter_TargetPath -PathType leaf) { $Substance3dPainter_TargetPath } elseif (Test-Path -Path $Substance3dPainter_TargetPathAlt -PathType leaf) { $Substance3dPainter_TargetPathAlt } else { $Substance3dPainter_TargetPathAlt2 }
$Substance3dPainter_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dPainter_Beta_Name = if (Test-Path -Path $Substance3dPainter_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dPainter_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Painter.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Substance3dPainter_Beta_Name = if ($Substance3dPainter_Beta_Name) { $Substance3dPainter_Beta_Name[0].name } else { "Adobe Substance 3D Painter (Beta)" }
$Substance3dPainter_Beta_WorkingDirectory = $Substance3dPainter_Beta_TargetPath + $Substance3dPainter_Beta_Name
$Substance3dPainter_Beta_WorkingDirectoryAlt = $Substance3dPainter_Beta_WorkingDirectory + "\Support Files"
$Substance3dPainter_Beta_WorkingDirectoryAlt2 = $Substance3dPainter_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dPainter_Beta_TargetPathExeAlt = $Substance3dPainter_Beta_WorkingDirectory + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPathAltExeAlt = $Substance3dPainter_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPathAlt2ExeAlt = $Substance3dPainter_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Painter.exe"
$Substance3dPainter_Beta_TargetPath = $Substance3dPainter_Beta_WorkingDirectory + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPathAlt = $Substance3dPainter_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPathAlt2 = $Substance3dPainter_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Painter (Beta).exe"
$Substance3dPainter_Beta_TargetPath = if (Test-Path -Path $Substance3dPainter_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPath -PathType leaf) { $Substance3dPainter_Beta_TargetPath } `
  elseif (Test-Path -Path $Substance3dPainter_Beta_TargetPathAlt -PathType leaf) { $Substance3dPainter_Beta_TargetPathAlt } else { $Substance3dPainter_Beta_TargetPathAlt2 }
# Adobe Substance 3D Sampler
$Substance3dSampler_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dSampler_Name = if (Test-Path -Path $Substance3dSampler_TargetPath) { Get-ChildItem -Directory -Path $Substance3dSampler_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Sampler(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Substance3dSampler_Name = if ($Substance3dSampler_Name) { $Substance3dSampler_Name[0].name } else { "Adobe Substance 3D Sampler" }
$Substance3dSampler_WorkingDirectory = $Substance3dSampler_TargetPath + $Substance3dSampler_Name
$Substance3dSampler_WorkingDirectoryAlt = $Substance3dSampler_WorkingDirectory + "\Support Files"
$Substance3dSampler_WorkingDirectoryAlt2 = $Substance3dSampler_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dSampler_TargetPath = $Substance3dSampler_WorkingDirectory + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt = $Substance3dSampler_WorkingDirectoryAlt + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPathAlt2 = $Substance3dSampler_WorkingDirectoryAlt2 + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_TargetPath = if (Test-Path -Path $Substance3dSampler_TargetPath -PathType leaf) { $Substance3dSampler_TargetPath } elseif (Test-Path -Path $Substance3dSampler_TargetPathAlt -PathType leaf) { $Substance3dSampler_TargetPathAlt } else { $Substance3dSampler_TargetPathAlt2 }
$Substance3dSampler_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dSampler_Beta_Name = if (Test-Path -Path $Substance3dSampler_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dSampler_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Sampler.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Substance3dSampler_Beta_Name = if ($Substance3dSampler_Beta_Name) { $Substance3dSampler_Beta_Name[0].name } else { "Adobe Substance 3D Sampler (Beta)" }
$Substance3dSampler_Beta_WorkingDirectory = $Substance3dSampler_Beta_TargetPath + $Substance3dSampler_Beta_Name
$Substance3dSampler_Beta_WorkingDirectoryAlt = $Substance3dSampler_Beta_WorkingDirectory + "\Support Files"
$Substance3dSampler_Beta_WorkingDirectoryAlt2 = $Substance3dSampler_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dSampler_Beta_TargetPathExeAlt = $Substance3dSampler_Beta_WorkingDirectory + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPathAltExeAlt = $Substance3dSampler_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPathAlt2ExeAlt = $Substance3dSampler_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Sampler.exe"
$Substance3dSampler_Beta_TargetPath = $Substance3dSampler_Beta_WorkingDirectory + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPathAlt = $Substance3dSampler_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPathAlt2 = $Substance3dSampler_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Sampler (Beta).exe"
$Substance3dSampler_Beta_TargetPath = if (Test-Path -Path $Substance3dSampler_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPath -PathType leaf) { $Substance3dSampler_Beta_TargetPath } `
  elseif (Test-Path -Path $Substance3dSampler_Beta_TargetPathAlt -PathType leaf) { $Substance3dSampler_Beta_TargetPathAlt } else { $Substance3dSampler_Beta_TargetPathAlt2 }
# Adobe Substance 3D Stager
$Substance3dStager_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dStager_Name = if (Test-Path -Path $Substance3dStager_TargetPath) { Get-ChildItem -Directory -Path $Substance3dStager_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Stager(?!.*\(Beta\)$)' } | Sort-Object -Property LastWriteTime }
$Substance3dStager_Name = if ($Substance3dStager_Name) { $Substance3dStager_Name[0].name } else { "Adobe Substance 3D Stager" }
$Substance3dStager_WorkingDirectory = $Substance3dStager_TargetPath + $Substance3dStager_Name
$Substance3dStager_WorkingDirectoryAlt = $Substance3dStager_WorkingDirectory + "\Support Files"
$Substance3dStager_WorkingDirectoryAlt2 = $Substance3dStager_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dStager_TargetPath = $Substance3dStager_WorkingDirectory + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt = $Substance3dStager_WorkingDirectoryAlt + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPathAlt2 = $Substance3dStager_WorkingDirectoryAlt2 + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_TargetPath = if (Test-Path -Path $Substance3dStager_TargetPath -PathType leaf) { $Substance3dStager_TargetPath } elseif (Test-Path -Path $Substance3dStager_TargetPathAlt -PathType leaf) { $Substance3dStager_TargetPathAlt } else { $Substance3dStager_TargetPathAlt2 }
$Substance3dStager_Beta_TargetPath = "${env:ProgramFiles}\Adobe\"
$Substance3dStager_Beta_Name = if (Test-Path -Path $Substance3dStager_Beta_TargetPath) { Get-ChildItem -Directory -Path $Substance3dStager_Beta_TargetPath | Where-Object { $_.Name -match '^.*Substance 3D Stager.*\(Beta\)$' } | Sort-Object -Property LastWriteTime }
$Substance3dStager_Beta_Name = if ($Substance3dStager_Beta_Name) { $Substance3dStager_Beta_Name[0].name } else { "Adobe Substance 3D Stager (Beta)" }
$Substance3dStager_Beta_WorkingDirectory = $Substance3dStager_Beta_TargetPath + $Substance3dStager_Beta_Name
$Substance3dStager_Beta_WorkingDirectoryAlt = $Substance3dStager_Beta_WorkingDirectory + "\Support Files"
$Substance3dStager_Beta_WorkingDirectoryAlt2 = $Substance3dStager_Beta_WorkingDirectoryAlt + "\Contents\Windows"
$Substance3dStager_Beta_TargetPathExeAlt = $Substance3dStager_Beta_WorkingDirectory + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPathAltExeAlt = $Substance3dStager_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPathAlt2ExeAlt = $Substance3dStager_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Stager.exe"
$Substance3dStager_Beta_TargetPath = $Substance3dStager_Beta_WorkingDirectory + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPathAlt = $Substance3dStager_Beta_WorkingDirectoryAlt + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPathAlt2 = $Substance3dStager_Beta_WorkingDirectoryAlt2 + "\Adobe Substance 3D Stager (Beta).exe"
$Substance3dStager_Beta_TargetPath = if (Test-Path -Path $Substance3dStager_Beta_TargetPathExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathExeAlt } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAltExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAltExeAlt } `
  elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAlt2ExeAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAlt2ExeAlt } elseif (Test-Path -Path $Substance3dStager_Beta_TargetPath -PathType leaf) { $Substance3dStager_Beta_TargetPath } `
  elseif (Test-Path -Path $Substance3dStager_Beta_TargetPathAlt -PathType leaf) { $Substance3dStager_Beta_TargetPathAlt } else { $Substance3dStager_Beta_TargetPathAlt2 }
# Autodesk
$Civil3d2023_Base_Arguments_DBX = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AecBase.dbx"
$Civil3d2013_Base_TargetPath = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\" + $(if (Test-Path -Path $Civil3d2023_Base_Arguments_DBX -PathType leaf) { "acad.exe" } else { "${NOT_INSTALLED}.exe" })
$Civil3d2023Imperial_Arguments = "/ld `"${Civil3d2023_Base_Arguments_DBX}`" /p `"&lt;&lt;C3D_Imperial&gt;&gt;`" /product C3D /language en-US"
$Civil3d2023Imperial_TargetPath = $Civil3d2013_Base_TargetPath
$Civil3d2023Metric_Arguments = "/ld `"${Civil3d2023_Base_Arguments_DBX}`" /p `"&lt;&lt;C3D_Metric&gt;&gt;`" /product C3D /language en-US"
$Civil3d2023Metric_TargetPath = $Civil3d2013_Base_TargetPath
$PostComparer2023_EXE = "${env:ProgramFiles}\Autodesk\Manufacturing Post Processor Utility 2023\PostComparer.exe"
$PostComparer2023_MakeCurrent_Arguments = "add `"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\PostComparer.exe`" /f /ve /d `"${PostComparer2023_EXE}`""
$PostComparer2023_MakeCurrent_TargetPath = "${env:windir}\System32\" + $(if (Test-Path -Path $PostComparer2023_EXE -PathType leaf) { "reg.exe" } else { "${NOT_INSTALLED}.exe" })
$EAGLE_WorkingDirectory = "${env:SystemDrive}\" # "C:\EAGLE 9.6.2"
$EAGLE_FindFolder = Get-ChildItem -Directory -Path $EAGLE_WorkingDirectory | Where-Object { $_.Name -match '^EAGLE [.0-9]+$' } | Sort-Object -Property LastWriteTime
$EAGLE_WorkingDirectory += if ($EAGLE_FindFolder) { $EAGLE_FindFolder[0].name } else { $NOT_INSTALLED }
$EAGLE_TargetPath = "${EAGLE_WorkingDirectory}\eagle.exe"
# GIMP
$GIMP_TargetPath = "${env:ProgramFiles}\"
$GIMP_FindFolder = Get-ChildItem -Directory -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Property LastWriteTime
$GIMP_FindFolder = if ($GIMP_FindFolder) { $GIMP_FindFolder[0].name } else { $NOT_INSTALLED }
$GIMP_TargetPath += "${GIMP_FindFolder}\bin\"
$GIMP_FindExe = if (Test-Path -Path $GIMP_TargetPath) { Get-ChildItem -File -Path $GIMP_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Property LastWriteTime }
$GIMP_FindExe = if ($GIMP_FindExe) { $GIMP_FindExe[0].name } else { "${NOT_INSTALLED}.exe" }
$GIMP_TargetPath += $GIMP_FindExe
$GIMP_32bit_TargetPath = "${env:ProgramFiles(x86)}\"
$GIMP_32bit_FindFolder = Get-ChildItem -Directory -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^GIMP' } | Sort-Object -Property LastWriteTime
$GIMP_32bit_FindFolder = if ($GIMP_32bit_FindFolder) { $GIMP_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$GIMP_32bit_TargetPath += "${GIMP_32bit_FindFolder}\bin\"
$GIMP_32bit_FindExe = if (Test-Path -Path $GIMP_32bit_TargetPath) { Get-ChildItem -File -Path $GIMP_32bit_TargetPath | Where-Object { $_.Name -match '^gimp\-[.0-9]+exe$' } | Sort-Object -Property LastWriteTime }
$GIMP_32bit_FindExe = if ($GIMP_32bit_FindExe) { $GIMP_32bit_FindExe[0].name } else { "${NOT_INSTALLED}.exe" }
$GIMP_32bit_TargetPath += $GIMP_32bit_FindExe
# Google
$GoogleDrive_TargetPath = "${env:ProgramFiles}\Google\Drive File Stream\"
$GoogleDrive_Version = if (Test-Path -Path $GoogleDrive_TargetPath) { Get-ChildItem -Directory -Path $GoogleDrive_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Property LastWriteTime }
$GoogleDrive_Version = if ($GoogleDrive_Version) { $GoogleDrive_Version[0].name } else { $NOT_INSTALLED }
$GoogleDrive_TargetPath += "${GoogleDrive_Version}\GoogleDriveFS.exe"
$GoogleDrive_32bit_TargetPath = "${env:ProgramFiles(x86)}\Google\Drive File Stream\"
$GoogleDrive_32bit_Version = if (Test-Path -Path $GoogleDrive_32bit_TargetPath) { Get-ChildItem -Directory -Path $GoogleDrive_32bit_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Property LastWriteTime }
$GoogleDrive_32bit_Version = if ($GoogleDrive_32bit_Version) { $GoogleDrive_32bit_Version[0].name } else { $NOT_INSTALLED }
$GoogleDrive_32bit_TargetPath += "${GoogleDrive_32bit_Version}\GoogleDriveFS.exe"
$GoogleOneVPN_TargetPath = "${env:ProgramFiles}\Google\VPN by Google One\"
$GoogleOneVPN_Version = if (Test-Path -Path $GoogleOneVPN_TargetPath) { Get-ChildItem -Directory -Path $GoogleOneVPN_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Property LastWriteTime }
$GoogleOneVPN_Version = if ($GoogleOneVPN_Version) { $GoogleOneVPN_Version[0].name } else { $NOT_INSTALLED }
$GoogleOneVPN_TargetPath += "${GoogleOneVPN_Version}\googleone.exe"
$GoogleOneVPN_32bit_TargetPath = "${env:ProgramFiles}\Google\VPN by Google One\"
$GoogleOneVPN_32bit_Version = if (Test-Path -Path $GoogleOneVPN_32bit_TargetPath) { Get-ChildItem -Directory -Path $GoogleOneVPN_32bit_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Property LastWriteTime }
$GoogleOneVPN_32bit_Version = if ($GoogleOneVPN_32bit_Version) { $GoogleOneVPN_32bit_Version[0].name } else { $NOT_INSTALLED }
$GoogleOneVPN_32bit_TargetPath += "${GoogleOneVPN_32bit_Version}\googleone.exe"
# KeePass
$KeePass_WorkingDirectory = "${env:ProgramFiles}\"
$KeePass_FindFolder = Get-ChildItem -Directory -Path $KeePass_WorkingDirectory | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Property LastWriteTime
$KeePass_FindFolder = if ($KeePass_FindFolder) { $KeePass_FindFolder[0].name } else { $NOT_INSTALLED }
$KeePass_TargetPath = "${KeePass_FindFolder}\KeePass.exe"
$KeePass_32bit_WorkingDirectory = "${env:ProgramFiles(x86)}\"
$KeePass_32bit_FindFolder = Get-ChildItem -Directory -Path $KeePass_32bit_WorkingDirectory | Where-Object { $_.Name -match '^KeePass Password Safe' } | Sort-Object -Property LastWriteTime
$KeePass_32bit_FindFolder = if ($KeePass_32bit_FindFolder) { $KeePass_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$KeePass_32bit_TargetPath = "${KeePass_32bit_FindFolder}\KeePass.exe"
# Maxon
$MaxonCinema4D_WorkingDirectory = "${env:ProgramFiles}\"
$MaxonCinema4D_FindFolder = Get-ChildItem -Directory -Path $MaxonCinema4D_WorkingDirectory | Where-Object { $_.Name -match '^Maxon Cinema 4D' } | Sort-Object -Property LastWriteTime
$MaxonCinema4D_FindFolder = if ($MaxonCinema4D_FindFolder) { $MaxonCinema4D_FindFolder[0].name } else { $NOT_INSTALLED }
$MaxonCinema4D_Version = $MaxonCinema4D_FindFolder | Select-String -pattern "\d\d\d\d$" -All
$MaxonCinema4D_Version = if ($MaxonCinema4D_Version) { $MaxonCinema4D_Version.Matches[-1].value } else { $NOT_INSTALLED }
$MaxonCinema4D_WorkingDirectory += $MaxonCinema4D_FindFolder
$MaxonCinema4D_Commandline_TargetPath = $MaxonCinema4D_WorkingDirectory + "\Commandline.exe"
$MaxonCinema4D_TargetPath = $MaxonCinema4D_WorkingDirectory + "\Cinema 4D.exe"
$MaxonCinema4D_TeamRenderClient_TargetPath = $MaxonCinema4D_WorkingDirectory + "\Cinema 4D Team Render Client.exe"
$MaxonCinema4D_TeamRenderServer_TargetPath = $MaxonCinema4D_WorkingDirectory + "\Cinema 4D Team Render Server.exe"
# VMware
$VMwareWorkstationPlayer_TargetPath = "${env:ProgramFiles}\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_Path = "${env:windir}\System32\" + $(if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType leaf) { "cmd.exe" } else { "${NOT_INSTALLED}.exe" })
$VMwareWorkstationPlayer_32bit_TargetPath = "${env:ProgramFiles(x86)}\VMware\VMware Player\vmplayer.exe"
$CommandPromptforvctl_32bit_Path = "${env:windir}\System32\" + $(if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType leaf) { "cmd.exe" } else { "${NOT_INSTALLED}.exe" })

# App names dependant on OS or app version

# GIMP
$GIMP_ProductVersion = if (Test-Path -Path $GIMP_TargetPath -PathType leaf) { (Get-Item $GIMP_TargetPath).VersionInfo.ProductVersion }
$GIMP_Version = if ($GIMP_ProductVersion) { $GIMP_ProductVersion } else { $NOT_INSTALLED }
$GIMP_Name = "GIMP ${GIMP_Version}"
$GIMP_32bit_ProductVersion = if (Test-Path -Path $GIMP_32bit_TargetPath -PathType leaf) { (Get-Item $GIMP_32bit_TargetPath).VersionInfo.ProductVersion }
$GIMP_32bit_Version = if ($GIMP_32bit_ProductVersion) { $GIMP_32bit_ProductVersion } else { $NOT_INSTALLED }
$GIMP_32bit_Name = "GIMP ${GIMP_32bit_Version}"
# KeePass
$KeePass_FileVersionRaw = if (Test-Path -Path $KeePass_TargetPath -PathType leaf) { (Get-Item $KeePass_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_Version = if ($KeePass_FileVersionRaw) { $KeePass_FileVersionRaw.Major } else { $NOT_INSTALLED }
$KeePass_Name = "KeePass ${KeePass_Version}"
$KeePass_32bit_FileVersionRaw = if (Test-Path -Path $KeePass_32bit_TargetPath -PathType leaf) { (Get-Item $KeePass_32bit_TargetPath).VersionInfo.FileVersionRaw }
$KeePass_32bit_Version = if ($KeePass_32bit_FileVersionRaw) { $KeePass_32bit_FileVersionRaw.Major } else { $NOT_INSTALLED }
$KeePass_32bit_Name = "KeePass ${KeePass_32bit_Version}"
# Maxon
$MaxonCinema4D_Commandline_Name = "Commandline" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_Name = "Maxon Cinema 4D" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderClient_Name = "Team Render Client" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
$MaxonCinema4D_TeamRenderServer_Name = "Team Render Server" + $(if ($MaxonCinema4D_Version) { " ${MaxonCinema4D_Version}" })
# VMware
$VMwareWorkstationPlayer_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_TargetPath -PathType leaf) { (Get-Item $VMwareWorkstationPlayer_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_Version = if ($VMwareWorkstationPlayer_FileVersionRaw) { $VMwareWorkstationPlayer_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NOT_INSTALLED }
$VMwareWorkstationPlayer_Name = "VMware Workstation ${VMwareWorkstationPlayer_Version} Player"
$VMwareWorkstationPlayer_32bit_FileVersionRaw = if (Test-Path -Path $VMwareWorkstationPlayer_32bit_TargetPath -PathType leaf) { (Get-Item $VMwareWorkstationPlayer_32bit_TargetPath).VersionInfo.FileVersionRaw }
$VMwareWorkstationPlayer_32bit_Version = if ($VMwareWorkstationPlayer_32bit_FileVersionRaw) { $VMwareWorkstationPlayer_32bit_FileVersionRaw.VersionInfo.FileVersionRaw.Major } else { $NOT_INSTALLED }
$VMwareWorkstationPlayer_32bit_Name = "VMware Workstation ${VMwareWorkstationPlayer_32bit_Version} Player"
# WizTree
$WizTree_64bit_TargetPath = "${env:ProgramFiles}\WizTree\WizTree64.exe"
$WizTree_32bit_TargetPath = "${env:ProgramFiles}\WizTree\WizTree.exe"
$WizTree_TargetPath = if (Test-Path -Path $WizTree_64bit_TargetPath -PathType leaf) { $WizTree_64bit_TargetPath } else { $WizTree_32bit_TargetPath }

$sys3rdPartyAppList = @(
  # 7-Zip
  @{
    Name       = "7-Zip File Manager"
    TargetPath = "${env:ProgramFiles}\7-Zip\7zFM.exe"
    SystemLnk  = "7-Zip\"
  },
  @{
    Name       = "7-Zip Help"
    TargetPath = "${env:ProgramFiles}\7-Zip\7-zip.chm"
    SystemLnk  = "7-Zip\"
  },
  @{
    Name       = "7-Zip File Manager"
    TargetPath = "${env:ProgramFiles(x86)}\7-Zip\7zFM.exe"
    SystemLnk  = "7-Zip\"
  },
  @{
    Name       = "7-Zip Help"
    TargetPath = "${env:ProgramFiles(x86)}\7-Zip\7-zip.chm"
    SystemLnk  = "7-Zip\"
  },
  # Adobe
  @{
    Name       = "Adobe Creative Cloud"
    TargetPath = "${env:ProgramFiles}\Adobe\Adobe Creative Cloud\ACC\Creative Cloud.exe"
  },
  @{
    Name             = $Aero_Name
    TargetPath       = $Aero_TargetPath
    WorkingDirectory = $Aero_WorkingDirectory
  },
  @{
    Name             = $Aero_Beta_Name
    TargetPath       = $Aero_Beta_TargetPath
    WorkingDirectory = $Aero_Beta_WorkingDirectory
  },
  @{
    Name             = $AfterEffects_Name
    TargetPath       = $AfterEffects_TargetPath
    WorkingDirectory = $AfterEffects_WorkingDirectory
  },
  @{
    Name             = $AfterEffects_Beta_Name
    TargetPath       = $AfterEffects_Beta_TargetPath
    WorkingDirectory = $AfterEffects_Beta_WorkingDirectory
  },
  @{
    Name             = $Animate_Name
    TargetPath       = $Animate_TargetPath
    WorkingDirectory = $Animate_WorkingDirectory
  },
  @{
    Name             = $Animate_Beta_Name
    TargetPath       = $Animate_Beta_TargetPath
    WorkingDirectory = $Animate_Beta_WorkingDirectory
  },
  @{
    Name             = $Audition_Name
    TargetPath       = $Audition_TargetPath
    WorkingDirectory = $Audition_WorkingDirectory
  },
  @{
    Name             = $Audition_Beta_Name
    TargetPath       = $Audition_Beta_TargetPath
    WorkingDirectory = $Audition_Beta_WorkingDirectory
  },
  @{
    Name             = $Bridge_Name
    TargetPath       = $Bridge_TargetPath
    WorkingDirectory = $Bridge_WorkingDirectory
  },
  @{
    Name             = $Bridge_Beta_Name
    TargetPath       = $Bridge_Beta_TargetPath
    WorkingDirectory = $Bridge_Beta_WorkingDirectory
  },
  @{
    Name             = $CharacterAnimator_Name
    TargetPath       = $CharacterAnimator_TargetPath
    WorkingDirectory = $CharacterAnimator_WorkingDirectory
  },
  @{
    Name             = $CharacterAnimator_Beta_Name
    TargetPath       = $CharacterAnimator_Beta_TargetPath
    WorkingDirectory = $CharacterAnimator_Beta_WorkingDirectory
  },
  @{
    Name             = $Dimension_Name
    TargetPath       = $Dimension_TargetPath
    WorkingDirectory = $Dimension_WorkingDirectory
  },
  @{
    Name             = $Dimension_Beta_Name
    TargetPath       = $Dimension_Beta_TargetPath
    WorkingDirectory = $Dimension_Beta_WorkingDirectory
  },
  @{
    Name             = $Dreamweaver_Name
    TargetPath       = $Dreamweaver_TargetPath
    WorkingDirectory = $Dreamweaver_WorkingDirectory
  },
  @{
    Name             = $Dreamweaver_Beta_Name
    TargetPath       = $Dreamweaver_Beta_TargetPath
    WorkingDirectory = $Dreamweaver_Beta_WorkingDirectory
  },
  @{
    Name             = $Illustrator_Name
    TargetPath       = $Illustrator_TargetPath
    WorkingDirectory = $Illustrator_WorkingDirectory
  },
  @{
    Name             = $Illustrator_Beta_Name
    TargetPath       = $Illustrator_Beta_TargetPath
    WorkingDirectory = $Illustrator_Beta_WorkingDirectory
  },
  @{
    Name             = $InCopy_Name
    TargetPath       = $InCopy_TargetPath
    WorkingDirectory = $InCopy_WorkingDirectory
  },
  @{
    Name             = $InCopy_Beta_Name
    TargetPath       = $InCopy_Beta_TargetPath
    WorkingDirectory = $InCopy_Beta_WorkingDirectory
  },
  @{
    Name             = $InDesign_Name
    TargetPath       = $InDesign_TargetPath
    WorkingDirectory = $InDesign_WorkingDirectory
  },
  @{
    Name             = $InDesign_Beta_Name
    TargetPath       = $InDesign_Beta_TargetPath
    WorkingDirectory = $InDesign_Beta_WorkingDirectory
  },
  @{
    Name             = $Lightroom_Name
    TargetPath       = $Lightroom_TargetPath
    WorkingDirectory = $Lightroom_WorkingDirectory
  },
  @{
    Name             = $Lightroom_Beta_Name
    TargetPath       = $Lightroom_Beta_TargetPath
    WorkingDirectory = $Lightroom_Beta_WorkingDirectory
  },
  @{
    Name             = $LightroomClassic_Name
    TargetPath       = $LightroomClassic_TargetPath
    WorkingDirectory = $LightroomClassic_WorkingDirectory
  },
  @{
    Name             = $LightroomClassic_Beta_Name
    TargetPath       = $LightroomClassic_Beta_TargetPath
    WorkingDirectory = $LightroomClassic_Beta_WorkingDirectory
  },
  @{
    Name             = $MediaEncoder_Name
    TargetPath       = $MediaEncoder_TargetPath
    WorkingDirectory = $MediaEncoder_WorkingDirectory
  },
  @{
    Name             = $MediaEncoder_Beta_Name
    TargetPath       = $MediaEncoder_Beta_TargetPath
    WorkingDirectory = $MediaEncoder_Beta_WorkingDirectory
  },
  @{
    Name             = $Photoshop_Name
    TargetPath       = $Photoshop_TargetPath
    WorkingDirectory = $Photoshop_WorkingDirectory
  },
  @{
    Name             = $Photoshop_Beta_Name
    TargetPath       = $Photoshop_Beta_TargetPath
    WorkingDirectory = $Photoshop_Beta_WorkingDirectory
  },
  @{
    Name             = $PremierePro_Name
    TargetPath       = $PremierePro_TargetPath
    WorkingDirectory = $PremierePro_WorkingDirectory
  },
  @{
    Name             = $PremierePro_Beta_Name
    TargetPath       = $PremierePro_Beta_TargetPath
    WorkingDirectory = $PremierePro_Beta_WorkingDirectory
  },
  @{
    Name             = $PremiereRush_Name
    TargetPath       = $PremiereRush_TargetPath
    WorkingDirectory = $PremiereRush_WorkingDirectory
  },
  @{
    Name             = $PremiereRush_Beta_Name
    TargetPath       = $PremiereRush_Beta_TargetPath
    WorkingDirectory = $PremiereRush_Beta_WorkingDirectory
  },
  @{
    Name             = $Substance3dDesigner_Name
    TargetPath       = $Substance3dDesigner_TargetPath
    WorkingDirectory = $Substance3dDesigner_WorkingDirectory
  },
  @{
    Name             = $Substance3dDesigner_Beta_Name
    TargetPath       = $Substance3dDesigner_Beta_TargetPath
    WorkingDirectory = $Substance3dDesigner_Beta_WorkingDirectory
  },
  @{
    Name             = $Substance3dModeler_Name
    TargetPath       = $Substance3dModeler_TargetPath
    WorkingDirectory = $Substance3dModeler_WorkingDirectory
  },
  @{
    Name             = $Substance3dModeler_Beta_Name
    TargetPath       = $Substance3dModeler_Beta_TargetPath
    WorkingDirectory = $Substance3dModeler_Beta_WorkingDirectory
  },
  @{
    Name             = $Substance3dPainter_Name
    TargetPath       = $Substance3dPainter_TargetPath
    WorkingDirectory = $Substance3dPainter_WorkingDirectory
  },
  @{
    Name             = $Substance3dPainter_Beta_Name
    TargetPath       = $Substance3dPainter_Beta_TargetPath
    WorkingDirectory = $Substance3dPainter_Beta_WorkingDirectory
  },
  @{
    Name             = $Substance3dSampler_Name
    TargetPath       = $Substance3dSampler_TargetPath
    WorkingDirectory = $Substance3dSampler_WorkingDirectory
  },
  @{
    Name             = $Substance3dSampler_Beta_Name
    TargetPath       = $Substance3dSampler_Beta_TargetPath
    WorkingDirectory = $Substance3dSampler_Beta_WorkingDirectory
  },
  @{
    Name             = $Substance3dStager_Name
    TargetPath       = $Substance3dStager_TargetPath
    WorkingDirectory = $Substance3dStager_WorkingDirectory
  },
  @{
    Name             = $Substance3dStager_Beta_Name
    TargetPath       = $Substance3dStager_Beta_TargetPath
    WorkingDirectory = $Substance3dStager_Beta_WorkingDirectory
  },
  @{
    Name             = "Adobe UXP Developer Tool"
    TargetPath       = "${env:ProgramFiles}\Adobe\Adobe UXP Developer Tool\Adobe UXP Developer Tool.exe"
    WorkingDirectory = "${env:ProgramFiles}\Adobe\Adobe UXP Developer Tool"
  },
  @{
    Name       = "Adobe Acrobat"
    TargetPath = "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
  },
  @{
    Name       = "Adobe Acrobat Distiller"
    TargetPath = "${env:ProgramFiles}\Adobe\Acrobat DC\Acrobat\acrodist.exe"
  },
  @{
    Name       = "Adobe Acrobat"
    TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
  },
  @{
    Name       = "Adobe Acrobat Distiller"
    TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat DC\Acrobat\acrodist.exe"
  },
  @{ # old version; it's the only install on 32-bit
    Name       = "Adobe Acrobat Reader"
    TargetPath = "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" 
  },
  @{ # old version; it's the only install on 32-bit
    Name       = "Adobe Acrobat Distiller"
    TargetPath = "${env:ProgramFiles}\Adobe\Acrobat Reader DC\Reader\acrodist.exe" 
  },
  @{ # old version; it's the only install on 64-bit
    Name       = "Adobe Acrobat Reader"
    TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe" 
  },
  @{ # old version; it's the only install on 64-bit
    Name       = "Adobe Acrobat Distiller"
    TargetPath = "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\acrodist.exe" 
  },
  # Altair Monarch
  @{
    Name       = "Altair Monarch 2021 Data Prep Studio"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\DPS\MonarchDataPrepStudio.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Data Prep Studio"
  },
  @{
    Name       = "Altair Monarch 2021 Learning Guide"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\Altair Monarch Learning Guide.pdf"
    SystemLnk  = "Altair Monarch 2021\"
  },
  @{
    Name       = "Altair Monarch 2021 License Manager"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\LicenseManager\Datawatch.Licensing.Manager.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 License Manager Executable"
  },
  @{
    Name       = "Altair Monarch 2021 Table Extractor"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\PDF Table Extractor\AltairTableExtractor.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Table Extractor"
  },
  @{
    Name       = "Altair Monarch 2021 Utility"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\MonarchUtility.exe"
    SystemLnk  = "Altair Monarch 2021\"
  },
  @{
    Name       = "Altair Monarch 2021"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2021\DWMonarch.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Executable"
  },
  @{
    Name       = "Altair Monarch 2021 Data Prep Studio"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\DPS\MonarchDataPrepStudio.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Data Prep Studio"
  },
  @{
    Name       = "Altair Monarch 2021 Learning Guide"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\Altair Monarch Learning Guide.pdf"
    SystemLnk  = "Altair Monarch 2021\"
  },
  @{
    Name       = "Altair Monarch 2021 License Manager"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\LicenseManager\Datawatch.Licensing.Manager.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 License Manager Executable"
  },
  @{
    Name       = "Altair Monarch 2021 Table Extractor"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\PDF Table Extractor\AltairTableExtractor.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Table Extractor"
  },
  @{
    Name       = "Altair Monarch 2021 Utility"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\MonarchUtility.exe"
    SystemLnk  = "Altair Monarch 2021\"
  },
  @{
    Name       = "Altair Monarch 2021"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2021\DWMonarch.exe"
    SystemLnk  = "Altair Monarch 2021\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2021 Executable"
  },
  @{
    Name       = "Altair Monarch 2020 Data Prep Studio"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\DPS\MonarchDataPrepStudio.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Data Prep Studio"
  },
  @{
    Name       = "Altair Monarch 2020 Learning Guide"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\Altair Monarch Learning Guide.pdf"
    SystemLnk  = "Altair Monarch 2020\"
  },
  @{
    Name       = "Altair Monarch 2020 License Manager"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\LicenseManager\Datawatch.Licensing.Manager.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 License Manager Executable"
  },
  @{
    Name       = "Altair Monarch 2020 Table Extractor"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\PDF Table Extractor\AltairTableExtractor.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Table Extractor"
  },
  @{
    Name       = "Altair Monarch 2020 Utility"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\MonarchUtility.exe"
    SystemLnk  = "Altair Monarch 2020\"
  },
  @{
    Name       = "Altair Monarch 2020"
    TargetPath = "${env:ProgramFiles}\Altair Monarch 2020\DWMonarch.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Executable"
  },
  @{
    Name       = "Altair Monarch 2020 Data Prep Studio"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\DPS\MonarchDataPrepStudio.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Data Prep Studio"
  },
  @{
    Name       = "Altair Monarch 2020 Learning Guide"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\Altair Monarch Learning Guide.pdf"
    SystemLnk  = "Altair Monarch 2020\"
  },
  @{
    Name       = "Altair Monarch 2020 License Manager"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\LicenseManager\Datawatch.Licensing.Manager.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 License Manager Executable"
  },
  @{
    Name       = "Altair Monarch 2020 Table Extractor"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\PDF Table Extractor\AltairTableExtractor.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Table Extractor"
  },
  @{
    Name       = "Altair Monarch 2020 Utility"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\MonarchUtility.exe"
    SystemLnk  = "Altair Monarch 2020\"
  },
  @{
    Name       = "Altair Monarch 2020"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\DWMonarch.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Executable"
  },
  @{
    Name       = "Altair Monarch 2020"
    TargetPath = "${env:ProgramFiles(x86)}\Altair Monarch 2020\DWMonarch.exe"
    SystemLnk  = "Altair Monarch 2020\"
    WorkingDirectory = "%tmp%"
    Description = "Altair Monarch 2020 Executable"
  },
  # Amazon
  @{
    Name             = "AWS VPN Client"
    TargetPath       = "${env:ProgramFiles}\Amazon\AWS VPN Client\AWSVPNClient.exe"
    SystemLnk        = "AWS VPN Client\"
    WorkingDirectory = "${env:ProgramFiles}\Amazon\AWS VPN Client\"
    Description      = "Client application for AWS Client VPN service"
  },
  @{
    Name             = "AWS VPN Client"
    TargetPath       = "${env:ProgramFiles(x86)}\Amazon\AWS VPN Client\AWSVPNClient.exe"
    SystemLnk        = "AWS VPN Client\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Amazon\AWS VPN Client\"
    Description      = "Client application for AWS Client VPN service"
  },
  # AmbiBox
  @{ # it's the only install on 32-bit
    Name             = "AmbiBox Web Site"
    TargetPath       = "${env:ProgramFiles}\AmbiBox\www.ambibox.ru.url"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles}\AmbiBox" 
  },
  @{ # it's the only install on 32-bit
    Name             = "AmbiBox"
    TargetPath       = "${env:ProgramFiles}\AmbiBox\AmbiBox.exe"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles}\AmbiBox" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Android AmbiBox Remote App"
    TargetPath       = "${env:ProgramFiles}\AmbiBox\Android AmbiBox Remote App"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles}\AmbiBox" 
  },
  @{ # it's the only install on 32-bit
    Name             = "MediaPortal Extension"
    TargetPath       = "${env:ProgramFiles}\AmbiBox\MediaPortal Extension"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles}\AmbiBox" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Uninstall AmbiBox"
    TargetPath       = "${env:ProgramFiles}\AmbiBox\unins000.exe"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles}\AmbiBox" 
  },
  @{ # it's the only install on 64-bit
    Name             = "AmbiBox Web Site"
    TargetPath       = "${env:ProgramFiles(x86)}\AmbiBox\www.ambibox.ru.url"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\AmbiBox" 
  },
  @{ # it's the only install on 64-bit
    Name             = "AmbiBox"
    TargetPath       = "${env:ProgramFiles(x86)}\AmbiBox\AmbiBox.exe"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\AmbiBox" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Android AmbiBox Remote App"
    TargetPath       = "${env:ProgramFiles(x86)}\AmbiBox\Android AmbiBox Remote App"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\AmbiBox" 
  },
  @{ # it's the only install on 64-bit
    Name             = "MediaPortal Extension"
    TargetPath       = "${env:ProgramFiles(x86)}\AmbiBox\MediaPortal Extension"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\AmbiBox" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Uninstall AmbiBox"
    TargetPath       = "${env:ProgramFiles(x86)}\AmbiBox\unins000.exe"
    SystemLnk        = "AmbiBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\AmbiBox" 
  },
  # Audacity
  @{
    Name             = "Audacity"
    TargetPath       = "${env:ProgramFiles}\Audacity\Audacity.exe"
    WorkingDirectory = "${env:ProgramFiles}\Audacity"
  },
  @{
    Name             = "Audacity"
    TargetPath       = "${env:ProgramFiles(x86)}\Audacity\Audacity.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Audacity"
  },
  # Autodesk
  @{
    Name             = "3ds Max 2023 - Brazilian Portuguese"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=PTB"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=ENU"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - French"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=FRA"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - German"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=DEU"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - Japanese"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=JPN"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - Korean"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=KOR"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023 - Simplified Chinese"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "/Language=CHS"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "3ds Max 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "Change Graphics Mode - 3ds Max 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\3dsmax.exe"
    Arguments        = "-h"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "MaxFind 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\3ds Max 2023\MaxFind.exe"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "VREDDesign 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64\VREDDesign.exe"
    SystemLnk        = "Autodesk VREDDesign 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64"
    Description      = "VREDDesign 2023"
  },
  @{
    Name             = "Activate Cluster Service"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\installClusterServiceAsAdmin.bat"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin"
    Description      = "Activate Cluster Service"
  },
  @{
    Name             = "Autodesk VREDDesign Readme"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\Autodesk VREDDesign Readme.html"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0"
    Description      = "Autodesk VREDPro Readme"
  },
  @{
    Name             = "Data Files"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64\datafiles.exe"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64"
    Description      = "Data Files"
  },
  @{
    Name             = "Deactivate Cluster Service"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\uninstallClusterServiceAsAdmin.bat"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin"
    Description      = "Deactivate Cluster Service"
  },
  @{
    Name             = "Disable Outbound Communication"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\disableOutboundCommunication.bat"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin"
    Description      = "Disable Outbound Communication"
  },
  @{
    Name             = "Enable Outbound Communication"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\enableOutboundCommunication.bat"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin"
    Description      = "Enable Outbound Communication"
  },
  @{
    Name             = "Log Files"
    TargetPath       = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64\logfiles.exe"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\VREDDesign-15.0\bin\WIN64"
    Description      = "Log Files"
  },
  @{
    Name             = "Autodesk Inventor Professional 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\Inventor.exe"
    Arguments        = "/language=ENU"
    SystemLnk        = "Autodesk Inventor 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
  },
  @{
    Name             = "Design Assistant 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\DtDv.exe"
    SystemLnk        = "Autodesk Inventor 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Design Assistant for Autodesk Inventor"
  },
  @{
    Name             = "Inventor Read-only Mode 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\InvRO.exe"
    Arguments        = "/language=ENU"
    SystemLnk        = "Autodesk Inventor 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Autodesk Inventor Read-only Mode"
  },
  @{
    Name             = "Add-In Manager 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\AddInMgr.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Autodesk Inventor Add-In Manager"
  },
  @{
    Name             = "Autodesk App Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\AppManager.exe"
    Arguments        = "Inventor /u  http://apps.exchange.autodesk.com/apps/v1/homepage?productline=INVPROSA&utm_source=inproduct&utm_medium=appmanager"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Launch App Manager"
  },
  @{
    Name             = "Drawing Resource Transfer Wizard 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\Drawing Resource Transfer Wizard.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Drawing Resource Transfer Wizard"
  },
  @{
    Name             = "Inventor Reset Utility"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\InventorReset.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Inventor Reset Utility"
  },
  @{
    Name             = "Project Editor 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\Ipj.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Autodesk Inventor Project Manager Utility"
  },
  @{
    Name             = "Property Mapping for Imported CAD Data"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\AnyCADPropertyMappingTool.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
  },
  @{
    Name             = "Style Library Manager 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\Style Library Manager.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Autodesk Inventor Style Library Manager"
  },
  @{
    Name             = "Task Scheduler 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\TaskScheduler.exe"
    SystemLnk        = "Autodesk Inventor 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Inventor 2023\Bin\"
    Description      = "Autodesk Inventor Task Scheduler"
  },
  @{
    Name             = "Advance Steel 2023 - Migrate Content - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\ADVS\ASMigrator.exe"
    Arguments        = " /`"en-US`""
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\ADVS\"
    Description      = "Migrate Advance Steel Content & Settings from a Previous Release"
  },
  @{
    Name             = "Attach Digital Signatures - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AcSignApply.exe"
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Attach Digital Signatures"
  },
  @{
    Name             = "AutoCAD - English - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\acad.exe"
    Arguments        = " /language `"en-US`" /product `"ADVS`" /p `"&lt;&lt;VANILLA&gt;&gt;`""
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Launch acad.exe"
  },
  @{
    Name             = "Batch Standards Checker - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\DwgCheckStandards.exe"
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Launch DwgCheckStandards.exe"
  },
  @{
    Name             = "Reference Manager - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdRefMan.exe"
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Reference Manager"
  },
  @{
    Name             = "Reset Settings to Default - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/reset /product ADVS /language `"en-US`""
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Reset Settings to Default"
  },
  @{
    Name             = "Advance Steel 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\acad.exe"
    Arguments        = " /language `"en-US`" /product `"ADVS`" /p `"&lt;&lt;ADVS&gt;&gt;`""
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Launch Advance Steel 2023 - English"
  },
  @{
    Name             = "Export AutoCAD Settings - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/e /product ADVS /language `"en-US`""
    SystemLnk        = "Advance Steel 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "AutoCAD 2023 Settings"
  },
  @{
    Name             = "Import AutoCAD Settings - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/i /product ADVS /language `"en-US`""
    SystemLnk        = "Advance Steel 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Import AutoCAD 2023 Settings"
  },
  @{
    Name             = "Migrate From a Previous Release"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/product ADVS /language `"en-US`""
    SystemLnk        = "Advance Steel 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Migrate from a Previous Release"
  },
  @{
    Name             = "Alias Concept 2023.0.1"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\bin\Alias.exe"
    Arguments        = "-a cs"
    SystemLnk        = "Autodesk Alias Concept 2023.0.1\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\"
  },
  @{
    Name             = "Exchange App Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\bin\AppManager.exe"
    Arguments        = "Alias /u http://apps.exchange.autodesk.com/apps/v1/homepage?productline=ALSCPT&release=2014&utm_source=inproduct&utm_medium=appmanager"
    SystemLnk        = "Autodesk Alias Concept 2023.0.1\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\"
  },
  @{
    Name             = "Fcheck"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\bin\fcheck.exe"
    SystemLnk        = "Autodesk Alias Concept 2023.0.1\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\"
    Description      = "Fcheck"
  },
  @{
    Name             = "Save And Exit"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\bin\MsaveAndExit.exe"
    SystemLnk        = "Autodesk Alias Concept 2023.0.1\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AliasConcept2023.0.1\"
    Description      = "Save And Exit"
  },
  @{
    Name             = "Attach Digital Signatures"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AcSignApply.exe"
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Attach Digital Signatures"
  },
  @{
    Name             = "AutoCAD 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\acad.exe"
    Arguments        = " /product ACAD /language `"en-US`""
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Launch acad.exe"
  },
  @{
    Name             = "Batch Standards Checker"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\DwgCheckStandards.exe"
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Launch DwgCheckStandards.exe"
  },
  @{
    Name             = "Reference Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdRefMan.exe"
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Reference Manager"
  },
  @{
    Name             = "Reset Settings to Default"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/reset /product ACAD /language `"en-US`""
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Reset Settings to Default"
  },
  @{
    Name             = "Export AutoCAD 2023 Settings"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/e /product ACAD /language `"en-US`""
    SystemLnk        = "AutoCAD 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "AutoCAD 2023 Settings"
  },
  @{
    Name             = "Import AutoCAD 2023 Settings"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/i /product ACAD /language `"en-US`""
    SystemLnk        = "AutoCAD 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Import AutoCAD 2023 Settings"
  },
  @{
    Name             = "Migrate From a Previous Release"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/product ACAD /language `"en-US`""
    SystemLnk        = "AutoCAD 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Migrate from a Previous Release"
  },
  @{
    Name             = "Attach Digital Signatures"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AcSignApply.exe"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Attach Digital Signatures"
  },
  @{
    Name             = "Autodesk Content Browser"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\ACA\AecCB.exe"
    Arguments        = "/Product `"C3D`" /Language `"en-US`""
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Launch Autodesk Content Browser"
  },
  @{
    Name             = "Batch Standards Checker"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\DwgCheckStandards.exe"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Launch DwgCheckStandards.exe"
  },
  @{
    Name             = "Civil 3D 2023 Imperial"
    TargetPath       = $Civil3d2023Imperial_TargetPath
    Arguments        = $Civil3d2023Imperial_Arguments
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Start menu shortcut Civil 3D 2023 Imperial"
  },
  @{
    Name             = "Civil 3D 2023 Metric"
    TargetPath       = $Civil3d2023Metric_TargetPath
    Arguments        = $Civil3d2023Metric_Arguments
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Start menu shortcut Civil 3D 2023 Metric"
  },
  @{
    Name             = "Content Catalog Editor"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\C3D\Autodesk.Aec.Content.CatalogEditor.exe"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "AutoCAD Civil 3D Content Catalog Editor"
  },
  @{
    Name             = "Data Shortcuts Editor"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\C3D\ShortcutEditor.exe"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\C3D\"
    Description      = "AutoCAD Civil 3D Data Shortcuts Editor"
  },
  @{
    Name             = "Reference Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdRefMan.exe"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\UserDataCache\"
    Description      = "Reference Manager"
  },
  @{
    Name             = "Reset Settings to Default"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\AdMigrator.exe"
    Arguments        = "/reset /product C3D /language `"en-US`""
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD 2023\"
    Description      = "Reset Settings to Default"
  },
  @{
    Name             = "Autodesk Batch Save Utility (Standalone)"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Batch Save Utility (Standalone)\C3D_BatchSave.exe"
    SystemLnk        = "Autodesk\Autodesk Batch Save Utility (Standalone)\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Batch Save Utility (Standalone)\"
    Description      = "Autodesk Batch Save Utility (Standalone)"
  },
  @{
    Name             = "Attach Digital Signatures"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\AcSignApply.exe"
    SystemLnk        = "AutoCAD LT 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\UserDataCache\"
    Description      = "Attach Digital Signatures"
  },
  @{
    Name             = "AutoCAD LT 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\acadlt.exe"
    Arguments        = "/language `"en-US`""
    SystemLnk        = "AutoCAD LT 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\UserDataCache\"
    Description      = "Launch acadlt.exe"
  },
  @{
    Name             = "Reset Settings to Default"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\AdMigrator.exe"
    Arguments        = "/reset /language `"en-US`""
    SystemLnk        = "AutoCAD LT 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\"
    Description      = "Reset Settings to Default"
  },
  @{
    Name             = "Export AutoCAD LT 2023 Settings"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\AdMigrator.exe"
    Arguments        = "/e /language `"en-US`""
    SystemLnk        = "AutoCAD LT 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\"
    Description      = "Export AutoCAD LT 2023 Settings"
  },
  @{
    Name             = "Import AutoCAD LT 2023 Settings"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\AdMigrator.exe"
    Arguments        = "/i /language `"en-US`""
    SystemLnk        = "AutoCAD LT 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\"
    Description      = "Import AutoCAD LT 2023 Settings"
  },
  @{
    Name             = "Migrate From a Previous Release"
    TargetPath       = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\AdMigrator.exe"
    Arguments        = "/language `"en-US`""
    SystemLnk        = "AutoCAD LT 2023 - English\Migrate Custom Settings\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\AutoCAD LT 2023\"
    Description      = "Migrate from a Previous Release"
  },
  @{
    Name             = "Autodesk CAMplete TruePath 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\CAMplete TruePath 2023\CAMpleteTruePath.exe"
    SystemLnk        = "Autodesk CAMplete TruePath 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\CAMplete TruePath 2023\"
    Description      = "Autodesk CAMplete TruePath 2023"
  },
  @{
    Name             = "Autodesk Desktop Connector"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Desktop Connector\DesktopConnector.Applications.Tray.exe"
    SystemLnk        = "Autodesk\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Desktop Connector\"
  },
  @{
    Name             = "Autodesk Subassembly Composer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Subassembly Composer 2023\SubassemblyComposer.exe"
    SystemLnk        = "Autodesk\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Subassembly Composer 2023\"
    Description      = "Autodesk Subassembly Composer 2023"
  },
  @{
    Name             = "Autodesk Exchange App Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\CFD 2023\AppManager.exe"
    Arguments        = "SimCFD /U http://apps.exchange.autodesk.com/apps/v1/homepage?productline=SCFD&release=2023&language=en&utm_source=inproduct&utm_medium=appstore"
    SystemLnk        = "Autodesk\CFD 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\CFD 2023\"
    Description      = "Autodesk Exchange App Manager"
  },
  @{
    Name             = "CFD 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\CFD 2023\CFD.exe"
    SystemLnk        = "Autodesk\CFD 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\CFD 2023\"
    Description      = "CFD 2023"
  },
  @{
    Name             = "CFD Viewer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\CFD Viewer 2023\AutodeskCFDViewer.exe"
    SystemLnk        = "Autodesk\CFD 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\CFD Viewer 2023\"
    Description      = "Launch CFD Viewer 2023"
  },
  @{
    Name             = "Autodesk Fabrication Migration Tool"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\fabmigrate.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Migrate Settings and Convert existing Configurations"
  },
  @{
    Name             = "CADmep 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\CADmepLauncher.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Autodesk Fabrication CADmep 2023"
  },
  @{
    Name             = "Configure Users"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\mapuser.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Multi-User Configuration"
  },
  @{
    Name             = "Dictionary Editor"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\maptext.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Translate Application Text"
  },
  @{
    Name             = "Edit Configuration"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\editmap.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Application Settings Editor"
  },
  @{
    Name             = "Product Information Editor"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\mapprod.exe"
    Arguments        = "/L=#0"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Edit Product Information"
  },
  @{
    Name             = "Product Information Viewer"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\prodview.exe"
    Arguments        = "/L=#0"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "View Product Information"
  },
  @{
    Name             = "Review 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\FABreview.exe"
    SystemLnk        = "Fabrication CADmep 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Fabrication 2023\CADmep\"
    Description      = "Review 2023"
  },
  @{
    Name             = "Autodesk InfraWorks"
    TargetPath       = "${env:ProgramFiles}\Autodesk\InfraWorks\InfraWorks.exe"
    SystemLnk        = "Autodesk\Autodesk InfraWorks\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\InfraWorks\"
    Description      = "Autodesk InfraWorks"
  },
  @{
    Name             = "Autodesk Manufacturing Data Exchange Utility 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\sys\exec64\sdx.exe"
    SystemLnk        = "Autodesk Manufacturing Data Exchange Utility 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\"
  },
  @{
    Name             = "COM Register Autodesk Manufacturing Data Exchange Utility 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\sys\exec64\sdx_com_reg.vbs"
    Arguments        = "`"${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\\sys\exec64\sdx.exe`""
    SystemLnk        = "Autodesk Manufacturing Data Exchange Utility 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\"
  },
  @{
    Name             = "Help"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\file\help\sdxdoc.chm"
    SystemLnk        = "Autodesk Manufacturing Data Exchange Utility 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Manufacturing Data Exchange Utility 2023\"
  },
  @{
    Name             = "Autodesk Manufacturing Post Processor Utility 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Manufacturing Post Processor Utility 2023\pmpost.exe"
    SystemLnk        = "Autodesk Manufacturing Post Processor Utility 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Manufacturing Post Processor Utility 2023\"
    Description      = "Autodesk Manufacturing Post Processor Utility 2023"
  },
  @{
    Name             = "PostComparer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Manufacturing Post Processor Utility 2023\PostComparer.exe"
    SystemLnk        = "Autodesk Manufacturing Post Processor Utility 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Manufacturing Post Processor Utility 2023\"
    Description      = "Option file comparer 2023"
  },
  @{
    Name        = "Make PostComparer 2023 the Current Version"
    TargetPath  = $PostComparer2023_MakeCurrent_TargetPath
    Arguments   = $PostComparer2023_MakeCurrent_Arguments
    SystemLnk   = "Autodesk Manufacturing Post Processor Utility 2023\"
    Description = "Register PostComparer 2023 as Current Version"
  },
  @{
    Name       = "Autodesk Netfabb Premium 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\Netfabb Premium 2023\netfabb.exe"
    SystemLnk  = "Autodesk\Autodesk Netfabb Premium 2023\"
  },
  @{
    Name             = "Autodesk Point Layout 2023 Plugin"
    TargetPath       = "${env:SystemDrive}\ProgramData\Autodesk\ApplicationPlugins\Autodesk_Point_Layout_2023.bundle\APL_Addon_Register.exe"
    SystemLnk        = "Autodesk\Point Layout 2023\"
    WorkingDirectory = "${env:SystemDrive}\ProgramData\Microsoft\Windows\Start Menu\Programs\Autodesk\Point Layout 2023"
  },
  @{
    Name             = "Autodesk Point Layout 2023 Preview Guide"
    TargetPath       = "${env:SystemDrive}\ProgramData\Autodesk\ApplicationPlugins\Autodesk_Point_Layout_2023.bundle\Autodesk Point Layout Preview Guide.pdf"
    SystemLnk        = "Autodesk\Point Layout 2023\"
    WorkingDirectory = "${env:SystemDrive}\ProgramData\Microsoft\Windows\Start Menu\Programs\Autodesk\Point Layout 2023"
  },
  @{
    Name             = "Uninstall Autodesk Point Layout 2023"
    TargetPath       = "${env:SystemDrive}\ProgramData\Autodesk\ApplicationPlugins\Autodesk_Point_Layout_2023.bundle\Uninstall.exe"
    SystemLnk        = "Autodesk\Point Layout 2023\"
    WorkingDirectory = "${env:SystemDrive}\ProgramData\Microsoft\Windows\Start Menu\Programs\Autodesk\Point Layout 2023"
  },
  @{
    Name             = "Autodesk PowerInspect Ultimate 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT.exe"
    Arguments        = "-license Ultimate"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\"
  },
  @{
    Name             = "Autodesk PowerInspect Ultimate Dual 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT.exe"
    Arguments        = "-license Ultimate -Dual"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\"
  },
  @{
    Name             = "Autodesk PowerInspect Ultimate Manual 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT.exe"
    Arguments        = "-license Ultimate -Manual"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\"
  },
  @{
    Name             = "Autodesk PowerInspect Ultimate Manual Dual 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT.exe"
    Arguments        = "-license Ultimate -Manual -Dual"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\"
  },
  @{
    Name             = "Autodesk PowerInspect Ultimate OMV 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT.exe"
    Arguments        = "-license Ultimate -OMV"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\"
  },
  @{
    Name       = "Batch Measurement 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PIBatchMeas.exe"
    SystemLnk  = "Autodesk PowerInspect 2023\"
  },
  @{
    Name       = "Make Autodesk PowerInspect 2023 the Current Version"
    TargetPath = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECTRegistrarExe.exe"
    Arguments  = "-file:components.txt -title:PowerInspect"
    SystemLnk  = "Autodesk PowerInspect 2023\"
  },
  @{
    Name       = "PowerInspect DRO 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\PowerINSPECT_DRO.exe"
    SystemLnk  = "Autodesk PowerInspect 2023\"
  },
  @{
    Name       = "Template Editor 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\TemplateEditor.exe"
    SystemLnk  = "Autodesk PowerInspect 2023\"
  },
  @{
    Name       = "VirtualCMM 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\PowerInspect 2023\sys\exec64\VirtualCMM.exe"
    SystemLnk  = "Autodesk PowerInspect 2023\"
  },
  @{
    Name             = "Autodesk PowerMill Modeling 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerShape 2023\sys\exec64\powershape.exe"
    Arguments        = "-license Mill"
    SystemLnk        = "Autodesk PowerShape 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerShape 2023\"
  },
  @{
    Name             = "Autodesk PowerShape Ultimate 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerShape 2023\sys\exec64\powershape.exe"
    Arguments        = "-license Ultimate"
    SystemLnk        = "Autodesk PowerShape 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerShape 2023\"
  },
  @{
    Name             = "Autodesk PowerMill Ultimate 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerMill 2023\sys\exec64\pmill.exe"
    Arguments        = "-license Ultimate"
    SystemLnk        = "Autodesk PowerMill 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerMill 2023\"
  },
  @{
    Name             = "Autodesk PowerMill Viewer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerMill 2023\sys\exec64\pmill.exe"
    Arguments        = "-viewer"
    SystemLnk        = "Autodesk PowerMill 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerMill 2023\"
  },
  @{
    Name             = "Register Tool Database Server"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PowerMill 2023\sys\tooldb\ADODC.exe"
    Arguments        = "-Regserver"
    SystemLnk        = "Autodesk PowerMill 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\PowerMill 2023\"
  },
  @{
    Name             = "Autodesk ReCap Photo"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Autodesk ReCap Photo\recapphoto.exe"
    SystemLnk        = "Autodesk ReCap\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Autodesk ReCap Photo\"
    Description      = "Autodesk ReCap Photo"
  },
  @{
    Name             = "Autodesk ReCap"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Autodesk ReCap\ReCap.exe"
    SystemLnk        = "Autodesk ReCap\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Autodesk ReCap\"
    Description      = "Autodesk ReCap"
  },
  @{
    Name             = "Calculation Engine – Component Registration"
    TargetPath       = "${env:ProgramFiles}\Common Files\Autodesk Shared\Autodesk Robot Structural Analysis Engine 2023\System\Exe\rkernel.exe"
    Arguments        = "/RegServer /Full"
    SystemLnk        = "Autodesk Robot Structural Analysis Professional 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Common Files\Autodesk Shared\Autodesk Robot Structural Analysis Engine 2023\System\Exe\"
  },
  @{
    Name             = "Delete prepared results"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\Autodesk.Common.ABufferClean.exe"
    SystemLnk        = "Autodesk Robot Structural Analysis Professional 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\"
  },
  @{
    Name             = "Robot Structural Analysis Professional - Component Registration"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\rsetup.EXE"
    Arguments        = "/ReRegServer"
    SystemLnk        = "Autodesk Robot Structural Analysis Professional 2023\Tools\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\"
  },
  @{
    Name             = "Calculation Manager"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\ACalcRMngr.exe"
    SystemLnk        = "Autodesk Robot Structural Analysis Professional 2023\Other programs\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\"
  },
  @{
    Name       = "Robot Structural Analysis Professional 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\Exe\robot.EXE"
    SystemLnk  = "Autodesk Robot Structural Analysis Professional 2023\"
  },
  @{
    Name             = "Robot Structural Analysis Professional SDK 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\SDK\ROBOTSDK.html"
    SystemLnk        = "Autodesk Robot Structural Analysis Professional 2023\SDK\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Robot Structural Analysis Professional 2023\SDK\"
  },
  @{
    Name             = "ConfigPost-EDM 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\conf-e.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-edm\"
  },
  @{
    Name             = "ConfigPost-Mill 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\conf-m.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-mill\"
  },
  @{
    Name             = "ConfigPost-SwissCAM 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\conf-sw.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-swiss\"
  },
  @{
    Name             = "ConfigPost-Turn 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\conf-t.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-turn\"
  },
  @{
    Name             = "ConfigPost-TurnMill 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\conf-tm.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-tm\"
  },
  @{
    Name             = "PartMaker Multi-Channel Editor 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\PM-MCE.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-swiss\"
  },
  @{
    Name             = "PartMaker-Mill 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\Pm-mill.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-mill\"
  },
  @{
    Name             = "PartMaker-SwissCAM 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\Pm-swiss.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-swiss\"
  },
  @{
    Name             = "PartMaker-Turn 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\Pm-turn.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-turn\"
  },
  @{
    Name             = "PartMaker-TurnMill 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\Pm-tm.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-tm\"
  },
  @{
    Name             = "PartMaker-WireEDM 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\PartMaker 2023\exec\Pm-edm.exe"
    SystemLnk        = "Autodesk PartMaker 2023\"
    WorkingDirectory = "${USERS_FOLDER}\Public\Documents\Autodesk\PartMaker\pm-edm\"
  },
  @{
    Name             = "DWG TrueView 2023 - English"
    TargetPath       = "${env:ProgramFiles}\Autodesk\DWG TrueView 2023 - English\dwgviewr.exe"
    Arguments        = "/language `"en-US`""
    SystemLnk        = "DWG TrueView 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\DWG TrueView 2023 - English\UserDataCache\"
    Description      = "Launch dwgviewr.exe"
  },
  @{
    Name             = "EAGLE"
    TargetPath       = $EAGLE_TargetPath
    WorkingDirectory = $EAGLE_WorkingDirectory
  },
  @{
    Name             = "FCheck"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Maya2023\bin\fcheck.exe"
    SystemLnk        = "Autodesk Maya 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Maya2023\bin\"
  },
  @{
    Name             = "Maya 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Maya2023\bin\maya.exe"
    SystemLnk        = "Autodesk Maya 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Maya2023\"
  },
  @{
    Name             = "FCheck"
    TargetPath       = "${env:ProgramFiles}\Autodesk\MayaCreative2023\bin\fcheck.exe"
    SystemLnk        = "Autodesk Maya Creative 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\MayaCreative2023\bin\"
  },
  @{
    Name             = "Maya Creative 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\MayaCreative2023\bin\maya.exe"
    SystemLnk        = "Autodesk Maya Creative 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\MayaCreative2023\"
  },
  @{
    Name             = "Uninstall"
    TargetPath       = "${env:ProgramFiles}\Allegorithmic\Adobe Substance 3D for Maya\unins000.exe"
    SystemLnk        = "Allegorithmic\Adobe Substance 3D for Maya\"
    WorkingDirectory = "${env:ProgramFiles}\Allegorithmic\Adobe Substance 3D for Maya"
  },
  @{
    Name             = "FeatureCAM 2023 InitDB"
    TargetPath       = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\program\initdb.exe"
    SystemLnk        = "Autodesk FeatureCAM 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\"
  },
  @{
    Name             = "FeatureCAM 2023 Viewer"
    TargetPath       = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\program\ezfm.exe"
    Arguments        = "-fcviewer"
    SystemLnk        = "Autodesk FeatureCAM 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\"
  },
  @{
    Name             = "FeatureCAM 2023 Xbuild"
    TargetPath       = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\program\xbuild.exe"
    SystemLnk        = "Autodesk FeatureCAM 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\"
  },
  @{
    Name             = "FeatureCAM Ultimate 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\program\ezfm.exe"
    Arguments        = "-license Ultimate"
    SystemLnk        = "Autodesk FeatureCAM 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\FeatureCAM 2023\"
  },
  @{
    Name       = "Manage 2023 (BIM 360)"
    TargetPath = "${env:ProgramFiles}\Autodesk\Navisworks Manage 2023\Roamer.exe"
    Arguments  = "-licensing BIM360"
    SystemLnk  = "Autodesk Navisworks Manage 2023\"
  },
  @{
    Name       = "Manage 2023"
    TargetPath = "${env:ProgramFiles}\Autodesk\Navisworks Manage 2023\Roamer.exe"
    Arguments  = "-licensing AdLM"
    SystemLnk  = "Autodesk Navisworks Manage 2023\"
  },
  @{
    Name       = "Options Editor (Manage 2023 Administrator mode)"
    TargetPath = "${env:ProgramFiles}\Autodesk\Navisworks Manage 2023\OptionsEditor.exe"
    Arguments  = "-l"
    SystemLnk  = "Autodesk Navisworks Manage 2023\English\"
  },
  @{
    Name       = "Options Editor (Manage 2023)"
    TargetPath = "${env:ProgramFiles}\Autodesk\Navisworks Manage 2023\OptionsEditor.exe"
    SystemLnk  = "Autodesk Navisworks Manage 2023\English\"
  },
  @{
    Name       = "Options Editor Help (Manage 2023)"
    TargetPath = "${env:ProgramFiles}\Autodesk\Navisworks Manage 2023\en-US\options.chm"
    SystemLnk  = "Autodesk Navisworks Manage 2023\English\"
  },
  @{
    Name             = "MotionBuilder 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\MotionBuilder 2023\bin\x64\motionbuilder.exe"
    SystemLnk        = "Autodesk\Autodesk MotionBuilder 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\MotionBuilder 2023\"
  },
  @{
    Name             = "MotionBuilder SDK Help"
    TargetPath       = "${env:ProgramFiles}\Autodesk\MotionBuilder 2023\MotionBuilder_SDK_Help.url"
    SystemLnk        = "Autodesk\Autodesk MotionBuilder 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\MotionBuilder 2023\"
    Description      = "Help for MotionBuilder SDK"
  },
  @{
    Name             = "Mudbox 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Mudbox 2023\mudbox.exe"
    SystemLnk        = "Autodesk\Autodesk Mudbox 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Mudbox 2023\"
  },
  @{
    Name             = "Worksharing Monitor for Autodesk Revit 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Worksharing Monitor for Revit 2023\WorksharingMonitor.exe"
    SystemLnk        = "Autodesk\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Worksharing Monitor for Revit 2023\"
  },
  @{
    Name             = "Revit 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Revit 2023\Revit.exe"
    Arguments        = "/language ENU"
    SystemLnk        = "Autodesk\Revit 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Revit 2023\"
  },
  @{
    Name             = "Revit Viewer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Revit 2023\Revit.exe"
    Arguments        = "/viewer /language ENU"
    SystemLnk        = "Autodesk\Revit 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Revit 2023\"
  },
  @{
    Name             = "Revit LT 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Revit LT 2023\Revit.exe"
    Arguments        = "/language ENU"
    SystemLnk        = "Autodesk\Revit LT 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Revit LT 2023\"
  },
  @{
    Name             = "Revit LT Viewer 2023"
    TargetPath       = "${env:ProgramFiles}\Autodesk\Revit LT 2023\Revit.exe"
    Arguments        = "/viewer /language ENU"
    SystemLnk        = "Autodesk\Revit LT 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\Revit LT 2023\"
  },
  @{
    Name             = "ShotGrid Create"
    TargetPath       = "${env:ProgramFiles}\Autodesk\ShotGrid Create\bin\ShotGridCreate.exe"
    SystemLnk        = "ShotGrid Create\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\ShotGrid Create\bin\"
    Description      = "ShotGrid Create 2022.03.005.165"
  },
  @{
    Name             = "Shotgun"
    TargetPath       = "${env:ProgramFiles}\Shotgun\Shotgun.exe"
    SystemLnk        = "Shotgun\"
    WorkingDirectory = "${env:ProgramFiles}\Shotgun"
  },
  @{
    Name             = "Uninstall"
    TargetPath       = "${env:ProgramFiles}\Shotgun\Uninstall.exe"
    SystemLnk        = "Shotgun\"
    WorkingDirectory = "${env:ProgramFiles}\Shotgun"
  },
  @{
    Name             = "License Transfer Utility - 3ds Max 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R24\LTU.exe"
    Arguments        = "128O1 2023.0.0.F -d SA -l en_US"
    SystemLnk        = "Autodesk\Autodesk 3ds Max 2023\"
    WorkingDirectory = "${env:ProgramFiles}\Autodesk\3ds Max 2023\"
  },
  @{
    Name             = "License Transfer Utility - VREDDesign 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R23\LTU.exe"
    Arguments        = "886O1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Autodesk VREDDesign 2023\Install\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R23"
    Description      = "License Transfer Utility - VREDDesign 2023"
  },
  @{
    Name        = "License Transfer Utility - Inventor 2023"
    TargetPath  = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\LTU.exe"
    Arguments   = "797O1 2023.0.0.F -d SA -l en-US"
    SystemLnk   = "Autodesk Inventor 2023\"
    Description = "License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - Advance Steel 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "959O1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Advance Steel 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - AutoCAD 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "001O1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "AutoCAD 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - Civil 3D 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "237O1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Autodesk Civil 3D 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - AutoCAD LT 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "057O1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "AutoCAD LT 2023 - English\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - PowerInspect Ultimate 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\LTU.exe"
    Arguments        = "A9HO1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Autodesk PowerInspect 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
  },
  @{
    Name             = "License Transfer Utility - Autodesk PowerMill Modeling 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "A9UO1 2023.0.0.F -d SA -l "
    SystemLnk        = "Autodesk PowerShape 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - Autodesk PowerShape Ultimate 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "A9LO1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Autodesk PowerShape 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
    Description      = "Launch License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - PowerMill Ultimate 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\LTU.exe"
    Arguments        = "A9PO1 2023.0.0.F -d SA -l en-US"
    SystemLnk        = "Autodesk PowerMill 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
  },
  @{
    Name             = "License Transfer Utility"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "657O1 2023.0.0.F -l en_US"
    SystemLnk        = "Autodesk Maya 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
    Description      = "License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments        = "C78O1 2023.0.0.F -l en_US"
    SystemLnk        = "Autodesk Maya Creative 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R25\"
    Description      = "License Transfer Utility"
  },
  @{
    Name       = "License Transfer Utility - FeatureCAM Ultimate 2023"
    TargetPath = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R23\LTU.exe"
    Arguments  = "A9EO1 2023.0.0.F -d SA -l en-US"
    SystemLnk  = "Autodesk FeatureCAM 2023\"
  },
  @{
    Name        = "License Transfer Utility Navisworks Manage 2023"
    TargetPath  = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments   = "507O1 2023.0.0.F -d `"SA`""
    SystemLnk   = "Autodesk Navisworks Manage 2023\"
    Description = "License Transfer Utility Navisworks Manage 2023"
  },
  @{
    Name             = "License Transfer Utility - MotionBuilder 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R17\LTU.exe"
    Arguments        = "727O1 2023.0.0.F -l "
    SystemLnk        = "Autodesk\Autodesk MotionBuilder 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R17\"
    Description      = "License Transfer Utility"
  },
  @{
    Name             = "License Transfer Utility - Mudbox 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R17\LTU.exe"
    Arguments        = "498O1 2023.0.0.F -l en-US"
    SystemLnk        = "Autodesk\Autodesk Mudbox 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\AdLM\R17\"
    Description      = "License Transfer Utility - Mudbox 2023"
  },
  @{
    Name             = "Autodesk Desktop App"
    TargetPath       = "${env:ProgramFiles(x86)}\Autodesk\Autodesk Desktop App\AutodeskDesktopApp.exe"
    SystemLnk        = "Autodesk\Autodesk Desktop App\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Autodesk\Autodesk Desktop App"
    Description      = "Autodesk Desktop App"
  },
  @{
    Name             = "Autodesk Structural Bridge Design 2023"
    TargetPath       = "${env:ProgramFiles(x86)}\Autodesk\Structural Bridge Design 2023\SBD.exe"
    SystemLnk        = "Autodesk\Autodesk Structural Bridge Design 2023\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Autodesk\Structural Bridge Design 2023\"
    Description      = "Autodesk Structural Bridge Design 2023"
  },
  @{
    Name       = "License Transfer Utility - Factory Design 2023"
    TargetPath = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments  = "P03O1 2023.0.0.F -d SA -l en-US"
    SystemLnk  = "Autodesk\Factory Design 2023\"
  },
  @{
    Name       = "License Transfer Utility - RSAPRO 2023"
    TargetPath = "${env:ProgramFiles(x86)}\Common Files\Autodesk Shared\Adlm\R25\LTU.exe"
    Arguments  = "547O1 2023.0.0.F -d SA -l en-US"
    SystemLnk  = "Autodesk\Robot Structural Analysis Professional 2023\"
  },
  # AutoHotkey V2
  @{
    Name        = "AutoHotkey Window Spy"
    TargetPath  = "${env:ProgramFiles}\AutoHotkey\UX\AutoHotkeyUX.exe"
    Arguments   = "`"${env:ProgramFiles}\AutoHotkey\UX\WindowSpy.ahk`""
    Description = "AutoHotkey Window Spy"
  },
  @{
    Name        = "AutoHotkey"
    TargetPath  = "${env:ProgramFiles}\AutoHotkey\UX\AutoHotkeyUX.exe"
    Arguments   = "`"${env:ProgramFiles}\AutoHotkey\UX\ui-dash.ahk`""
    Description = "AutoHotkey Dash"
  },
  @{
    Name        = "AutoHotkey Window Spy"
    TargetPath  = "${env:ProgramFiles(x86)}\AutoHotkey\UX\AutoHotkeyUX.exe"
    Arguments   = "`"${env:ProgramFiles(x86)}\AutoHotkey\UX\WindowSpy.ahk`""
    Description = "AutoHotkey Window Spy"
  },
  @{
    Name        = "AutoHotkey"
    TargetPath  = "${env:ProgramFiles(x86)}\AutoHotkey\UX\AutoHotkeyUX.exe"
    Arguments   = "`"${env:ProgramFiles(x86)}\AutoHotkey\UX\ui-dash.ahk`""
    Description = "AutoHotkey Dash"
  },
  # AutoHotkey
  @{
    Name       = "AutoHotkey Help File"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey.chm"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "AutoHotkey Setup"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\Installer.ahk"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "AutoHotkey"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey.exe"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Convert .ahk to .exe"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\Compiler\Ahk2Exe.exe"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Website"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\AutoHotkey Website.url"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Window Spy"
    TargetPath = "${env:ProgramFiles}\AutoHotkey\WindowSpy.ahk"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "AutoHotkey Help File"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey.chm"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "AutoHotkey Setup"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\Installer.ahk"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "AutoHotkey"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey.exe"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Convert .ahk to .exe"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\Compiler\Ahk2Exe.exe"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Website"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\AutoHotkey Website.url"
    SystemLnk  = "AutoHotkey\"
  },
  @{
    Name       = "Window Spy"
    TargetPath = "${env:ProgramFiles(x86)}\AutoHotkey\WindowSpy.ahk"
    SystemLnk  = "AutoHotkey\"
  },
  # Bulk Crap Uninstaller
  @{
    Name             = "BCUninstaller"
    TargetPath       = "${env:ProgramFiles}\BCUninstaller\BCUninstaller.exe"
    SystemLnk        = "BCUninstaller\"
    WorkingDirectory = "${env:ProgramFiles}\BCUninstaller"
  },
  @{
    Name             = "Uninstall BCUninstaller"
    TargetPath       = "${env:ProgramFiles}\BCUninstaller\unins000.exe"
    SystemLnk        = "BCUninstaller\"
    WorkingDirectory = "${env:ProgramFiles}\BCUninstaller"
  },
  @{
    Name             = "BCUninstaller"
    TargetPath       = "${env:ProgramFiles(x86)}\BCUninstaller\BCUninstaller.exe"
    SystemLnk        = "BCUninstaller\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\BCUninstaller"
  },
  @{
    Name             = "Uninstall BCUninstaller"
    TargetPath       = "${env:ProgramFiles(x86)}\BCUninstaller\unins000.exe"
    SystemLnk        = "BCUninstaller\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\BCUninstaller"
  },
  # Bytello
  @{ # it's the only install on 32-bit
    Name             = "Bytello Share"
    TargetPath       = "${env:ProgramFiles}\Bytello Share\Bytello Share.exe"
    SystemLnk        = "Bytello Share\"
    WorkingDirectory = "${env:ProgramFiles}\Bytello Share" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Bytello Share"
    TargetPath       = "${env:ProgramFiles(x86)}\Bytello Share\Bytello Share.exe"
    SystemLnk        = "Bytello Share\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Bytello Share" 
  },
  # Cisco
  @{ # it's the only install on 32-bit
    Name             = "Cisco AnyConnect Secure Mobility Client"
    TargetPath       = "${env:ProgramFiles}\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"
    SystemLnk        = "Cisco\Cisco AnyConnect Secure Mobility Client"
    WorkingDirectory = "${env:ProgramFiles}\Cisco\Cisco AnyConnect Secure Mobility Client\"
    Description      = "Cisco AnyConnect Secure Mobility Client" 
  },
  @{ # it's the only install on 32-bit
    Name        = "Cisco Jabber Problem Report"
    TargetPath  = "${env:ProgramFiles}\Cisco Systems\Cisco Jabber\CiscoJabberPrt.exe"
    SystemLnk   = "Cisco Jabber\"
    Description = "Cisco Jabber Problem Report" 
  },
  @{ # it's the only install on 32-bit
    Name        = "Cisco Jabber"
    TargetPath  = "${env:ProgramFiles}\Cisco Systems\Cisco Jabber\CiscoJabber.exe"
    SystemLnk   = "Cisco Jabber\"
    Description = "Cisco Jabber" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Cisco AnyConnect Secure Mobility Client"
    TargetPath       = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe"
    SystemLnk        = "Cisco\Cisco AnyConnect Secure Mobility Client"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Cisco\Cisco AnyConnect Secure Mobility Client\"
    Description      = "Cisco AnyConnect Secure Mobility Client" 
  },
  @{ # it's the only install on 64-bit
    Name        = "Cisco Jabber Problem Report"
    TargetPath  = "${env:ProgramFiles(x86)}\Cisco Systems\Cisco Jabber\CiscoJabberPrt.exe"
    SystemLnk   = "Cisco Jabber\"
    Description = "Cisco Jabber Problem Report" 
  },
  @{ # it's the only install on 64-bit
    Name        = "Cisco Jabber"
    TargetPath  = "${env:ProgramFiles(x86)}\Cisco Systems\Cisco Jabber\CiscoJabber.exe"
    SystemLnk   = "Cisco Jabber\"
    Description = "Cisco Jabber" 
  },
  # Citrix Workspace
  @{ # it's the only install on 32-bit
    Name             = "Citrix Workspace"
    TargetPath       = "${env:ProgramFiles}\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"
    Arguments        = "-showAppPicker"
    WorkingDirectory = "${env:ProgramFiles}\Citrix\ICA Client\SelfServicePlugin\"
    Description      = "Select applications you want to use on your computer" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Citrix Workspace"
    TargetPath       = "${env:ProgramFiles(x86)}\Citrix\ICA Client\SelfServicePlugin\SelfService.exe"
    Arguments        = "-showAppPicker"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Citrix\ICA Client\SelfServicePlugin\"
    Description      = "Select applications you want to use on your computer" 
  },
  # CodeTwo Active Directory Photos
  @{
    Name        = "CodeTwo Active Directory Photos"
    TargetPath  = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "CodeTwo Active Directory Photos"
  },
  @{
    Name        = "Go to program home page"
    TargetPath  = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "CodeTwo Active Directory Photos home page"
  },
  @{
    Name        = "User's manual"
    TargetPath  = "${env:ProgramFiles}\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "Go to User Guide"
  },
  @{
    Name        = "CodeTwo Active Directory Photos"
    TargetPath  = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "CodeTwo Active Directory Photos"
  },
  @{
    Name        = "Go to program home page"
    TargetPath  = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "CodeTwo Active Directory Photos home page"
  },
  @{
    Name        = "User's manual"
    TargetPath  = "${env:ProgramFiles(x86)}\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"
    SystemLnk   = "CodeTwo\CodeTwo Active Directory Photos\"
    Description = "Go to User Guide"
  },
  # Docker
  @{
    Name        = "Docker Desktop"
    TargetPath  = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    SystemLnk   = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\"
    Description = "Docker Desktop"
  },
  @{
    Name        = "Docker Desktop"
    TargetPath  = "${env:ProgramFiles(x86)}\Docker\Docker\Docker Desktop.exe"
    SystemLnk   = "${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\"
    Description = "Docker Desktop"
  },
  # draw.io
  @{
    Name             = "draw.io"
    TargetPath       = "${env:ProgramFiles}\draw.io\draw.io.exe"
    WorkingDirectory = "${env:ProgramFiles}\draw.io"
    Description      = "draw.io desktop"
  },
  @{
    Name             = "draw.io"
    TargetPath       = "${env:ProgramFiles(x86)}\draw.io\draw.io.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\draw.io"
    Description      = "draw.io desktop"
  },
  # DYMO
  @{ # it's the only install on 32-bit
    Name             = "DYMO Connect Web Service"
    TargetPath       = "${env:ProgramFiles}\DYMO\DYMO Connect\DYMO.WebApi.Win.Host.exe"
    SystemLnk        = "DYMO\DYMO Connect\"
    WorkingDirectory = "${env:ProgramFiles}\DYMO\DYMO Connect\"
  },
  @{ # it's the only install on 32-bit
    Name             = "DYMO Connect"
    TargetPath       = "${env:ProgramFiles}\DYMO\DYMO Connect\DYMOConnect.exe"
    SystemLnk        = "DYMO\DYMO Connect\"
    WorkingDirectory = "${env:ProgramFiles}\DYMO\DYMO Connect\"
  },
  @{ # it's the only install on 64-bit
    Name             = "DYMO Connect Web Service"
    TargetPath       = "${env:ProgramFiles(x86)}\DYMO\DYMO Connect\DYMO.WebApi.Win.Host.exe"
    SystemLnk        = "DYMO\DYMO Connect\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\DYMO\DYMO Connect\"
  },
  @{ # it's the only install on 64-bit
    Name             = "DYMO Connect"
    TargetPath       = "${env:ProgramFiles(x86)}\DYMO\DYMO Connect\DYMOConnect.exe"
    SystemLnk        = "DYMO\DYMO Connect\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\DYMO\DYMO Connect\"
  },
  # Egnyte (note: uninstaller is architecture independent)
  @{ # it's the only install on 32-bit
    Name             = "Egnyte Desktop App"
    TargetPath       = "${env:ProgramFiles}\Egnyte Connect\EgnyteClient.exe"
    Arguments        = "--short-menu"
    SystemLnk        = "Egnyte Connect\"
    WorkingDirectory = "${env:ProgramFiles}\Egnyte Connect\" 
  },
  @{
    Name        = "Uninstall Egnyte Desktop App"
    TargetPath  = $EgnyteDesktopApp_Uninstall_TargetPath
    Arguments   = $EgnyteDesktopApp_Uninstall_Arguments
    SystemLnk   = "Egnyte Connect\"
    Description = "Uninstalls Egnyte Desktop App"
  },
  @{ # it's the only install on 64-bit
    Name             = "Egnyte Desktop App"
    TargetPath       = "${env:ProgramFiles(x86)}\Egnyte Connect\EgnyteClient.exe"
    Arguments        = "--short-menu"
    SystemLnk        = "Egnyte Connect\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Egnyte Connect\" 
  },
  @{
    Name        = "Uninstall Egnyte Desktop App"
    TargetPath  = $EgnyteDesktopApp_Uninstall_32bit_TargetPath
    Arguments   = $EgnyteDesktopApp_Uninstall_32bit_Arguments
    SystemLnk   = "Egnyte Connect\"
    Description = "Uninstalls Egnyte Desktop App"
  },
  # Epson
  @{ # it's the only install on 32-bit
    Name       = "Epson Connect Printer Setup"
    TargetPath = "${env:ProgramFiles}\Epson Software\ECPrinterSetup\ENPApp.exe"
    SystemLnk  = "EPSON\Epson Connect Printer Setup\"
  },
  @{ # it's the only install on 32-bit
    Name       = "Epson Scan 2 Utility"
    TargetPath = "${env:ProgramFiles}\epson\Epson Scan 2\Core\es2utility.exe"
    SystemLnk  = "EPSON\Epson Scan 2\"
  },
  @{ # it's the only install on 32-bit
    Name       = "Epson Scan 2"
    TargetPath = "${env:ProgramFiles}\epson\Epson Scan 2\Core\es2launcher.exe"
    SystemLnk  = "EPSON\Epson Scan 2\"
  },
  @{ # it's the only install on 32-bit
    Name       = "FAX Utility"
    TargetPath = "${env:ProgramFiles}\Epson Software\FAX Utility\FUFAXCNT.exe"
    SystemLnk  = "EPSON Software\"
  },
  @{ # it's the only install on 32-bit
    Name       = "Epson ScanSmart"
    TargetPath = "${env:ProgramFiles}\Epson Software\Epson ScanSmart\ScanSmart.exe"
    SystemLnk  = "EPSON Software\"
  },
  @{ # it's the only install on 32-bit
    Name        = "Epson Software Updater"
    TargetPath  = "${env:ProgramFiles}\Epson Software\Download Navigator\EPSDNAVI.EXE"
    Arguments   = "/ST"
    SystemLnk   = "EPSON Software\"
    Description = "Epson Software Updater"
  },
  @{ # it's the only install on 64-bit
    Name       = "Epson Connect Printer Setup"
    TargetPath = "${env:ProgramFiles(x86)}\Epson Software\ECPrinterSetup\ENPApp.exe"
    SystemLnk  = "EPSON\Epson Connect Printer Setup\"
  },
  @{ # it's the only install on 64-bit
    Name       = "Epson Scan 2 Utility"
    TargetPath = "${env:ProgramFiles(x86)}\epson\Epson Scan 2\Core\es2utility.exe"
    SystemLnk  = "EPSON\Epson Scan 2\"
  },
  @{ # it's the only install on 64-bit
    Name       = "Epson Scan 2"
    TargetPath = "${env:ProgramFiles(x86)}\epson\Epson Scan 2\Core\es2launcher.exe"
    SystemLnk  = "EPSON\Epson Scan 2\"
  },
  @{ # it's the only install on 64-bit
    Name       = "FAX Utility"
    TargetPath = "${env:ProgramFiles(x86)}\Epson Software\FAX Utility\FUFAXCNT.exe"
    SystemLnk  = "EPSON Software\"
  },
  @{ # it's the only install on 64-bit
    Name       = "Epson ScanSmart"
    TargetPath = "${env:ProgramFiles(x86)}\Epson Software\Epson ScanSmart\ScanSmart.exe"
    SystemLnk  = "EPSON Software\"
  },
  @{ # it's the only install on 64-bit
    Name        = "Epson Software Updater"
    TargetPath  = "${env:ProgramFiles(x86)}\Epson Software\Download Navigator\EPSDNAVI.EXE"
    Arguments   = "/ST"
    SystemLnk   = "EPSON Software\"
    Description = "Epson Software Updater"
  },
  # GIMP
  @{
    Name             = $GIMP_Name
    TargetPath       = $GIMP_TargetPath
    WorkingDirectory = "%USERPROFILE%"
    Description      = $GIMP_Name
  },
  @{
    Name             = $GIMP_32bit_Name
    TargetPath       = $GIMP_32bit_TargetPath
    WorkingDirectory = "%USERPROFILE%"
    Description      = $GIMP_32bit_Name
  },
  # Google
  @{
    Name             = "Google Chrome"
    TargetPath       = "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe"
    WorkingDirectory = "${env:ProgramFiles}\Google\Chrome\Application"
    Description      = "Access the Internet"
  },
  @{
    Name        = "Google Drive"
    TargetPath  = $GoogleDrive_TargetPath
    Description = "Google Drive"
  },
  @{
    Name        = "VPN by Google One"
    TargetPath  = $GoogleOneVPN_TargetPath
    Description = "VPN by Google One"
  },
  @{
    Name             = "Google Chrome"
    TargetPath       = "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Google\Chrome\Application"
    Description      = "Access the Internet"
  },
  @{
    Name        = "Google Drive"
    TargetPath  = $GoogleDrive_32bit_TargetPath
    Description = "Google Drive"
  },
  @{
    Name        = "VPN by Google One"
    TargetPath  = $GoogleOneVPN_32bit_TargetPath
    Description = "VPN by Google One"
  },
  # GoTo
  @{
    Name             = "GoTo Resolve Desktop Console (64-bit)"
    TargetPath       = "${env:ProgramFiles}\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"
    WorkingDirectory = "${env:ProgramFiles}\GoTo\GoTo Resolve Desktop Console\"
  },
  @{
    Name             = "GoTo Resolve Desktop Console"
    TargetPath       = "${env:ProgramFiles(x86)}\GoTo\GoTo Resolve Desktop Console\ra-technician-console.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\GoTo\GoTo Resolve Desktop Console\"
  },
  # KC Softwares
  @{ # it's the only install on 32-bit
    Name             = "SUMo"
    TargetPath       = "${env:ProgramFiles}\KC Softwares\SUMo\SUMo.exe"
    SystemLnk        = "KC Softwares\SUMo\"
    WorkingDirectory = "${env:ProgramFiles}\KC Softwares\SUMo" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Uninstall SUMo"
    TargetPath       = "${env:ProgramFiles}\KC Softwares\SUMo\unins000.exe"
    SystemLnk        = "KC Softwares\SUMo\"
    WorkingDirectory = "${env:ProgramFiles}\KC Softwares\SUMo" 
  },
  @{ # it's the only install on 64-bit
    Name             = "SUMo"
    TargetPath       = "${env:ProgramFiles(x86)}\KC Softwares\SUMo\SUMo.exe"
    SystemLnk        = "KC Softwares\SUMo\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\KC Softwares\SUMo" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Uninstall SUMo"
    TargetPath       = "${env:ProgramFiles(x86)}\KC Softwares\SUMo\unins000.exe"
    SystemLnk        = "KC Softwares\SUMo\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\KC Softwares\SUMo" 
  },
  # Kdenlive
  @{
    Name             = "Kdenlive"
    TargetPath       = "${env:ProgramFiles}\kdenlive\bin\kdenlive.exe"
    WorkingDirectory = "{workingDirectory}"
    Description      = "Libre Video Editor, by KDE community"
  },
  @{
    Name             = "Kdenlive"
    TargetPath       = "${env:ProgramFiles(x86)}\kdenlive\bin\kdenlive.exe"
    WorkingDirectory = "{workingDirectory}"
    Description      = "Libre Video Editor, by KDE community"
  },
  # KeePass
  @{ # new version 2+
    Name             = $KeePass_Name
    TargetPath       = $KeePass_TargetPath
    WorkingDirectory = $KeePass_WorkingDirectory 
  },
  @{ # old version 1.x; it's the only install on 32-bit
    Name             = "KeePass"
    TargetPath       = "${env:ProgramFiles}\KeePass Password Safe\KeePass.exe"
    WorkingDirectory = "${env:ProgramFiles}\KeePass Password Safe" 
  },
  @{ # new version 2+
    Name             = $KeePass_32bit_Name
    TargetPath       = $KeePass_32bit_TargetPath
    WorkingDirectory = $KeePass_32bit_WorkingDirectory 
  },
  @{ # old version 1.x; it's the only install on 64-bit
    Name             = "KeePass"
    TargetPath       = "${env:ProgramFiles(x86)}\KeePass Password Safe\KeePass.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\KeePass Password Safe" 
  },
  # Ledger Live
  @{
    Name             = "Ledger Live"
    TargetPath       = "${env:ProgramFiles}\Ledger Live\Ledger Live.exe"
    WorkingDirectory = "${env:ProgramFiles}\Ledger Live"
    Description      = "Ledger Live - Desktop"
  },
  @{
    Name             = "Ledger Live"
    TargetPath       = "${env:ProgramFiles(x86)}\Ledger Live\Ledger Live.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Ledger Live"
    Description      = "Ledger Live - Desktop"
  },
  # Local Administrator Password Solution
  @{
    Name             = "LAPS UI"
    TargetPath       = "${env:ProgramFiles}\LAPS\AdmPwd.UI.exe"
    SystemLnk        = "LAPS\"
    WorkingDirectory = "${env:ProgramFiles}\LAPS\"
  },
  @{
    Name             = "LAPS UI"
    TargetPath       = "${env:ProgramFiles(x86)}\LAPS\AdmPwd.UI.exe"
    SystemLnk        = "LAPS\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\LAPS\"
  },
  # Maxon
  @{
    Name             = $MaxonCinema4D_Commandline_Name
    TargetPath       = $MaxonCinema4D_Commandline_TargetPath
    SystemLnk        = "Maxon\${MaxonCinema4D_Name}\"
    WorkingDirectory = $MaxonCinema4D_WorkingDirectory
    Description      = "Commandline"
  },
  @{
    Name             = $MaxonCinema4D_Name
    TargetPath       = $MaxonCinema4D_TargetPath
    SystemLnk        = "Maxon\${MaxonCinema4D_Name}\"
    WorkingDirectory = $MaxonCinema4D_WorkingDirectory
    Description      = "Maxon Cinema 4D"
  },
  @{
    Name             = $MaxonCinema4D_TeamRenderClient_Name
    TargetPath       = $MaxonCinema4D_TeamRenderClient_TargetPath
    SystemLnk        = "Maxon\${MaxonCinema4D_Name}\"
    WorkingDirectory = $MaxonCinema4D_WorkingDirectory
    Description      = "Team Render Client"
  },
  @{
    Name             = $MaxonCinema4D_TeamRenderServer_Name
    TargetPath       = $MaxonCinema4D_TeamRenderServer_TargetPath
    SystemLnk        = "Maxon\${MaxonCinema4D_Name}\"
    WorkingDirectory = $MaxonCinema4D_WorkingDirectory
    Description      = "Team Render Server"
  },
  # Mozilla
  @{
    Name             = "Firefox"
    TargetPath       = "${env:ProgramFiles}\Mozilla Firefox\firefox.exe"
    WorkingDirectory = "${env:ProgramFiles}\Mozilla Firefox"
  },
  @{
    Name             = "Firefox Private Browsing"
    TargetPath       = "${env:ProgramFiles}\Mozilla Firefox\private_browsing.exe"
    WorkingDirectory = "${env:ProgramFiles}\Mozilla Firefox"
    Description      = "Firefox Private Browsing"
  },
  @{
    Name             = "Thunderbird"
    TargetPath       = "${env:ProgramFiles}\Mozilla Thunderbird\thunderbird.exe"
    WorkingDirectory = "${env:ProgramFiles}\Mozilla Thunderbird"
  },
  @{
    Name             = "Firefox"
    TargetPath       = "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Mozilla Firefox"
  },
  @{
    Name             = "Firefox Private Browsing"
    TargetPath       = "${env:ProgramFiles(x86)}\Mozilla Firefox\private_browsing.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Mozilla Firefox"
    Description      = "Firefox Private Browsing"
  },
  @{
    Name             = "Thunderbird"
    TargetPath       = "${env:ProgramFiles(x86)}\Mozilla Thunderbird\thunderbird.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Mozilla Thunderbird"
  },
  # Notepad++
  @{
    Name             = "Notepad++"
    TargetPath       = "${env:ProgramFiles}\Notepad++\notepad++.exe"
    WorkingDirectory = "${env:ProgramFiles}\Notepad++"
  },
  @{
    Name             = "Notepad++"
    TargetPath       = "${env:ProgramFiles(x86)}\Notepad++\notepad++.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Notepad++"
  },
  # OpenVPN
  @{
    Name             = "OpenVPN"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\bin\openvpn-gui.exe"
    SystemLnk        = "OpenVPN\OpenVPN GUI"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\bin\"
  },
  @{
    Name             = "OpenVPN Manual Page"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\doc\openvpn.8.html"
    SystemLnk        = "OpenVPN\Documentation\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\doc\"
  },
  @{
    Name             = "OpenVPN Windows Notes"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\doc\INSTALL-win32.txt"
    SystemLnk        = "OpenVPN\Documentation\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\doc\"
  },
  @{
    Name             = "OpenVPN Configuration File Directory"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\config"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\config\"
  },
  @{
    Name             = "OpenVPN Log File Directory"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\log"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\log\"
  },
  @{
    Name             = "OpenVPN Sample Configuration Files"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\sample-config"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\sample-config\"
  },
  @{
    Name             = "Add a new TAP-Windows6 virtual network adapter"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\bin\tapctl.exe"
    Arguments        = "create --hwid root\tap0901"
    SystemLnk        = "OpenVPN\Utilities\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\bin\"
  },
  @{
    Name             = "Add a new Wintun virtual network adapter"
    TargetPath       = "${env:ProgramFiles}\OpenVPN\bin\tapctl.exe"
    Arguments        = "create --hwid wintun"
    SystemLnk        = "OpenVPN\Utilities\"
    WorkingDirectory = "${env:ProgramFiles}\OpenVPN\bin\"
  },
  @{
    Name             = "OpenVPN"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn-gui.exe"
    SystemLnk        = "OpenVPN\OpenVPN GUI"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\bin\"
  },
  @{
    Name             = "OpenVPN Manual Page"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\doc\openvpn.8.html"
    SystemLnk        = "OpenVPN\Documentation\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\doc\"
  },
  @{
    Name             = "OpenVPN Windows Notes"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\doc\INSTALL-win32.txt"
    SystemLnk        = "OpenVPN\Documentation\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\doc\"
  },
  @{
    Name             = "OpenVPN Configuration File Directory"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\config"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\config\"
  },
  @{
    Name             = "OpenVPN Log File Directory"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\log"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\log\"
  },
  @{
    Name             = "OpenVPN Sample Configuration Files"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\sample-config"
    SystemLnk        = "OpenVPN\Shortcuts\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\sample-config\"
  },
  @{
    Name             = "Add a new TAP-Windows6 virtual network adapter"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\bin\tapctl.exe"
    Arguments        = "create --hwid root\tap0901"
    SystemLnk        = "OpenVPN\Utilities\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\bin\"
  },
  @{
    Name             = "Add a new Wintun virtual network adapter"
    TargetPath       = "${env:ProgramFiles(x86)}\OpenVPN\bin\tapctl.exe"
    Arguments        = "create --hwid wintun"
    SystemLnk        = "OpenVPN\Utilities\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OpenVPN\bin\"
  },
  # Oracle
  @{
    Name             = "License (English)"
    TargetPath       = "${env:ProgramFiles}\Oracle\VirtualBox\License_en_US.rtf"
    SystemLnk        = "Oracle VM VirtualBox\"
    WorkingDirectory = "${env:ProgramFiles}\Oracle\VirtualBox\"
    Description      = "License"
  },
  @{
    Name             = "Oracle VM VirtualBox"
    TargetPath       = "${env:ProgramFiles}\Oracle\VirtualBox\VirtualBox.exe"
    SystemLnk        = "Oracle VM VirtualBox\"
    WorkingDirectory = "${env:ProgramFiles}\Oracle\VirtualBox\"
    Description      = "Oracle VM VirtualBox"
  },
  @{
    Name        = "User manual (CHM, English)"
    TargetPath  = "${env:ProgramFiles}\Oracle\VirtualBox\VirtualBox.chm"
    SystemLnk   = "Oracle VM VirtualBox\"
    Description = "User manual"
  },
  @{
    Name        = "User manual (PDF, English)"
    TargetPath  = "${env:ProgramFiles}\Oracle\VirtualBox\doc\UserManual.pdf"
    SystemLnk   = "Oracle VM VirtualBox\"
    Description = "User manual"
  },
  @{
    Name             = "License (English)"
    TargetPath       = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\License_en_US.rtf"
    SystemLnk        = "Oracle VM VirtualBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\"
    Description      = "License"
  },
  @{
    Name             = "Oracle VM VirtualBox"
    TargetPath       = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VirtualBox.exe"
    SystemLnk        = "Oracle VM VirtualBox\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\"
    Description      = "Oracle VM VirtualBox"
  },
  @{
    Name        = "User manual (CHM, English)"
    TargetPath  = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\VirtualBox.chm"
    SystemLnk   = "Oracle VM VirtualBox\"
    Description = "User manual"
  },
  @{
    Name        = "User manual (PDF, English)"
    TargetPath  = "${env:ProgramFiles(x86)}\Oracle\VirtualBox\doc\UserManual.pdf"
    SystemLnk   = "Oracle VM VirtualBox\"
    Description = "User manual"
  },
  # OSFMount
  @{
    Name             = "OSFMount Documentation"
    TargetPath       = "${env:ProgramFiles}\OSFMount\osfmount_Help.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles}\OSFMount"
  },
  @{
    Name             = "OSFMount on the Web"
    TargetPath       = "${env:ProgramFiles}\OSFMount\OSFMount.url"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles}\OSFMount"
  },
  @{
    Name             = "OSFMount"
    TargetPath       = "${env:ProgramFiles}\OSFMount\OSFMount.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles}\OSFMount"
  },
  @{
    Name             = "Uninstall OSFMount"
    TargetPath       = "${env:ProgramFiles}\OSFMount\unins000.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles}\OSFMount"
  },
  @{
    Name             = "OSFMount Documentation"
    TargetPath       = "${env:ProgramFiles(x86)}\OSFMount\osfmount_Help.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OSFMount"
  },
  @{
    Name             = "OSFMount on the Web"
    TargetPath       = "${env:ProgramFiles(x86)}\OSFMount\OSFMount.url"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OSFMount"
  },
  @{
    Name             = "OSFMount"
    TargetPath       = "${env:ProgramFiles(x86)}\OSFMount\OSFMount.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OSFMount"
  },
  @{
    Name             = "Uninstall OSFMount"
    TargetPath       = "${env:ProgramFiles(x86)}\OSFMount\unins000.exe"
    SystemLnk        = "OSFMount\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\OSFMount"
  },
  # paint.net
  @{
    Name             = "paint.net"
    TargetPath       = "${env:ProgramFiles}\paint.net\paintdotnet.exe"
    WorkingDirectory = "${env:ProgramFiles}\paint.net"
    Description      = "Create, edit, scan, and print images and photographs."
  },
  @{
    Name             = "paint.net"
    TargetPath       = "${env:ProgramFiles(x86)}\paint.net\paintdotnet.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\paint.net"
    Description      = "Create, edit, scan, and print images and photographs."
  },
  # Parallels
  @{
    Name             = "Parallels Client"
    TargetPath       = "${env:ProgramFiles}\Parallels\Client\APPServerClient.exe"
    WorkingDirectory = "${env:ProgramFiles}\Parallels\Client\"
  },
  @{
    Name             = "Parallels Client"
    TargetPath       = "${env:ProgramFiles(x86)}\Parallels\Client\APPServerClient.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Parallels\Client\"
  },
  # Pulse Secure
  @{ # it's the only install on 32-bit
    Name        = "Pulse Secure"
    TargetPath  = "${env:ProgramFiles}\Common Files\Pulse Secure\JamUI\Pulse.exe"
    Arguments   = "-show"
    SystemLnk   = "Pulse Secure\"
    Description = "Pulse Secure Desktop Client" 
  },
  @{ # it's the only install on 64-bit
    Name        = "Pulse Secure"
    TargetPath  = "${env:ProgramFiles(x86)}\Common Files\Pulse Secure\JamUI\Pulse.exe"
    Arguments   = "-show"
    SystemLnk   = "Pulse Secure\"
    Description = "Pulse Secure Desktop Client" 
  },
  # PuTTY
  @{
    Name             = "Pageant"
    TargetPath       = "${env:ProgramFiles}\PuTTY\pageant.exe"
    SystemLnk        = "PuTTY (64-bit)\"
    WorkingDirectory = "${env:ProgramFiles}\PuTTY\"
  },
  @{
    Name             = "PSFTP"
    TargetPath       = "${env:ProgramFiles}\PuTTY\psftp.exe"
    SystemLnk        = "PuTTY (64-bit)\"
    WorkingDirectory = "${env:ProgramFiles}\PuTTY\"
  },
  @{
    Name       = "PuTTY Manual"
    TargetPath = "${env:ProgramFiles}\PuTTY\putty.chm"
    SystemLnk  = "PuTTY (64-bit)\"
  },
  @{
    Name       = "PuTTY Web Site"
    TargetPath = "${env:ProgramFiles}\PuTTY\website.url"
    SystemLnk  = "PuTTY (64-bit)\"
  },
  @{
    Name             = "PuTTY"
    TargetPath       = "${env:ProgramFiles}\PuTTY\putty.exe"
    SystemLnk        = "PuTTY (64-bit)\"
    WorkingDirectory = "${env:ProgramFiles}\PuTTY\"
  },
  @{
    Name             = "PuTTYgen"
    TargetPath       = "${env:ProgramFiles}\PuTTY\puttygen.exe"
    SystemLnk        = "PuTTY (64-bit)\"
    WorkingDirectory = "${env:ProgramFiles}\PuTTY\"
  },
  @{
    Name             = "Pageant"
    TargetPath       = "${env:ProgramFiles(x86)}\PuTTY\pageant.exe"
    SystemLnk        = "PuTTY\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\PuTTY\"
  },
  @{
    Name             = "PSFTP"
    TargetPath       = "${env:ProgramFiles(x86)}\PuTTY\psftp.exe"
    SystemLnk        = "PuTTY\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\PuTTY\"
  },
  @{
    Name       = "PuTTY Manual"
    TargetPath = "${env:ProgramFiles(x86)}\PuTTY\putty.chm"
    SystemLnk  = "PuTTY\"
  },
  @{
    Name       = "PuTTY Web Site"
    TargetPath = "${env:ProgramFiles(x86)}\PuTTY\website.url"
    SystemLnk  = "PuTTY\"
  },
  @{
    Name             = "PuTTY"
    TargetPath       = "${env:ProgramFiles(x86)}\PuTTY\putty.exe"
    SystemLnk        = "PuTTY\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\PuTTY\"
  },
  @{
    Name             = "PuTTYgen"
    TargetPath       = "${env:ProgramFiles(x86)}\PuTTY\puttygen.exe"
    SystemLnk        = "PuTTY\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\PuTTY\"
  },
  # RealVNC
  @{
    Name             = "VNC Server"
    TargetPath       = "${env:ProgramFiles}\RealVNC\VNC Server\vncguihelper.exe"
    Arguments        = "vncserver.exe -_fromGui -start -showstatus"
    SystemLnk        = "RealVNC\"
    WorkingDirectory = "${env:ProgramFiles}\RealVNC\VNC Server\"
  },
  @{
    Name             = "VNC Viewer"
    TargetPath       = "${env:ProgramFiles}\RealVNC\VNC Viewer\vncviewer.exe"
    SystemLnk        = "RealVNC\"
    WorkingDirectory = "${env:ProgramFiles}\RealVNC\VNC Viewer\"
  },
  @{
    Name             = "VNC Server"
    TargetPath       = "${env:ProgramFiles(x86)}\RealVNC\VNC Server\vncguihelper.exe"
    Arguments        = "vncserver.exe -_fromGui -start -showstatus"
    SystemLnk        = "RealVNC\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\RealVNC\VNC Server\"
  },
  @{
    Name             = "VNC Viewer"
    TargetPath       = "${env:ProgramFiles(x86)}\RealVNC\VNC Viewer\vncviewer.exe"
    SystemLnk        = "RealVNC\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\RealVNC\VNC Viewer\"
  },
  # Samsung
  @{ # it's the only install on 32-bit
    Name             = "Samsung DeX"
    TargetPath       = "${env:ProgramFiles}\Samsung\Samsung DeX\SamsungDeX.exe"
    WorkingDirectory = "${env:ProgramFiles}\Samsung\Samsung DeX\" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Samsung DeX"
    TargetPath       = "${env:ProgramFiles(x86)}\Samsung\Samsung DeX\SamsungDeX.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Samsung\Samsung DeX\" 
  },
  # SAP Logon
  @{ # it's the only install on 32-bit
    Name             = "SAP Logon"
    TargetPath       = "${env:ProgramFiles}\SAP\FrontEnd\SapGui\saplogon.exe"
    SystemLnk        = "SAP Front End\"
    WorkingDirectory = "${env:ProgramFiles}\SAP\FrontEnd\SAPgui"
  },
  @{ # it's the only install on 64-bit
    Name             = "SAP Logon"
    TargetPath       = "${env:ProgramFiles(x86)}\SAP\FrontEnd\SapGui\saplogon.exe"
    SystemLnk        = "SAP Front End\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\SAP\FrontEnd\SAPgui"
  },
  # SonicWall Global VPN Client
  @{
    Name             = "Global VPN Client"
    TargetPath       = "${env:ProgramFiles}\SonicWALL\Global VPN Client\SWGVC.exe"
    WorkingDirectory = "${env:ProgramFiles}\SonicWall\Global VPN Client\"
    Description      = "Launch the Global VPN Client"
  },
  @{
    Name             = "Global VPN Client"
    TargetPath       = "${env:ProgramFiles}\Dell SonicWALL\Global VPN Client\SWGVC.exe"
    WorkingDirectory = "${env:ProgramFiles}\Dell SonicWall\Global VPN Client\"
    Description      = "Launch the Global VPN Client"
  },
  @{
    Name             = "Global VPN Client"
    TargetPath       = "${env:ProgramFiles(x86)}\SonicWALL\Global VPN Client\SWGVC.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\SonicWall\Global VPN Client\"
    Description      = "Launch the Global VPN Client"
  },
  @{
    Name             = "Global VPN Client"
    TargetPath       = "${env:ProgramFiles(x86)}\Dell SonicWALL\Global VPN Client\SWGVC.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Dell SonicWall\Global VPN Client\"
    Description      = "Launch the Global VPN Client"
  },
  # SoundSwitch
  @{
    Name             = "SoundSwitch"
    TargetPath       = "${env:ProgramFiles}\SoundSwitch\SoundSwitch.exe"
    SystemLnk        = "SoundSwitch\"
    WorkingDirectory = "${env:ProgramFiles}\SoundSwitch"
  },
  @{
    Name             = "Uninstall SoundSwitch"
    TargetPath       = "${env:ProgramFiles}\SoundSwitch\unins000.exe"
    SystemLnk        = "SoundSwitch\"
    WorkingDirectory = "${env:ProgramFiles}\SoundSwitch"
  },
  @{
    Name             = "SoundSwitch"
    TargetPath       = "${env:ProgramFiles(x86)}\SoundSwitch\SoundSwitch.exe"
    SystemLnk        = "SoundSwitch\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\SoundSwitch"
  },
  @{
    Name             = "Uninstall SoundSwitch"
    TargetPath       = "${env:ProgramFiles(x86)}\SoundSwitch\unins000.exe"
    SystemLnk        = "SoundSwitch\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\SoundSwitch"
  },
  # Team Viewer
  @{
    Name             = "TeamViewer"
    TargetPath       = "${env:ProgramFiles}\TeamViewer\TeamViewer.exe"
    WorkingDirectory = "${env:ProgramFiles}\TeamViewer"
  },
  @{
    Name             = "TeamViewer"
    TargetPath       = "${env:ProgramFiles(x86)}\TeamViewer\TeamViewer.exe"
    WorkingDirectory = "${env:ProgramFiles}\TeamViewer"
  },
  # USB Redirector TS Edition
  @{
    Name       = "USB Redirector TS Edition - Workstation"
    TargetPath = "${env:ProgramFiles}\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"
    SystemLnk  = "USB Redirector TS Edition - Workstation\"
  },
  @{
    Name       = "USB Redirector TS Edition - Workstation"
    TargetPath = "${env:ProgramFiles(x86)}\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"
    SystemLnk  = "USB Redirector TS Edition - Workstation\"
  },
  # VideoLAN
  @{
    Name             = "Documentation"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\Documentation.url"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "Release Notes"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\NEWS.txt"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "VideoLAN Website"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\VideoLAN Website.url"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player - reset preferences and cache files"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"
    Arguments        = "--reset-config --reset-plugins-cache vlc://quit"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player skinned"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"
    Arguments        = "-Iskins"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player"
    TargetPath       = "${env:ProgramFiles}\VideoLAN\VLC\vlc.exe"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles}\VideoLAN\VLC"
  },
  @{
    Name             = "Documentation"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\Documentation.url"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  @{
    Name             = "Release Notes"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\NEWS.txt"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  @{
    Name             = "VideoLAN Website"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\VideoLAN Website.url"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player - reset preferences and cache files"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"
    Arguments        = "--reset-config --reset-plugins-cache vlc://quit"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player skinned"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"
    Arguments        = "-Iskins"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  @{
    Name             = "VLC media player"
    TargetPath       = "${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe"
    SystemLnk        = "VideoLAN\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VideoLAN\VLC"
  },
  # VMware
  @{ # it's the only install on 32-bit
    Name             = "Command Prompt for vctl"
    TargetPath       = $CommandPromptforvctl_Path
    Arguments        = "/k set PATH=${env:ProgramFiles}\VMware\VMware Player\;%PATH% && vctl.exe -h"
    SystemLnk        = "VMware\"
    WorkingDirectory = "${env:ProgramFiles}\VMware\VMware Player\bin\" 
  },
  @{ # it's the only install on 32-bit
    Name             = $VMwareWorkstationPlayer_Name
    TargetPath       = $VMwareWorkstationPlayer_TargetPath
    SystemLnk        = "VMware\"
    WorkingDirectory = "${env:ProgramFiles}\VMware\VMware Player\" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Command Prompt for vctl"
    TargetPath       = $CommandPromptforvctl_32bit_Path
    Arguments        = "/k set PATH=${env:ProgramFiles(x86)}\VMware\VMware Player\;%PATH% && vctl.exe -h"
    SystemLnk        = "VMware\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VMware\VMware Player\bin\" 
  },
  @{ # it's the only install on 64-bit
    Name             = $VMwareWorkstationPlayer_32bit_Name
    TargetPath       = $VMwareWorkstationPlayer_32bit_TargetPath
    SystemLnk        = "VMware\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\VMware\VMware Player\" 
  },
  # Win32DiskImager
  @{ # it's the only install on 32-bit
    Name             = "Uninstall Win32DiskImager"
    TargetPath       = "${env:ProgramFiles}\ImageWriter\unins000.exe"
    SystemLnk        = "Image Writer\"
    WorkingDirectory = "${env:ProgramFiles}\ImageWriter" 
  },
  @{ # it's the only install on 32-bit
    Name             = "Win32DiskImager"
    TargetPath       = "${env:ProgramFiles}\ImageWriter\Win32DiskImager.exe"
    SystemLnk        = "Image Writer\"
    WorkingDirectory = "${env:ProgramFiles}\ImageWriter" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Uninstall Win32DiskImager"
    TargetPath       = "${env:ProgramFiles(x86)}\ImageWriter\unins000.exe"
    SystemLnk        = "Image Writer\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\ImageWriter" 
  },
  @{ # it's the only install on 64-bit
    Name             = "Win32DiskImager"
    TargetPath       = "${env:ProgramFiles(x86)}\ImageWriter\Win32DiskImager.exe"
    SystemLnk        = "Image Writer\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\ImageWriter" 
  },
  # Winaero
  @{
    Name             = "EULA"
    TargetPath       = "${env:ProgramFiles}\Winaero Tweaker\Winaero EULA.txt"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles}\Winaero Tweaker"
    Description      = "Read the license agreement"
  },
  @{
    Name             = "Winaero Tweaker"
    TargetPath       = "${env:ProgramFiles}\Winaero Tweaker\WinaeroTweaker.exe"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles}\Winaero Tweaker"
  },
  @{
    Name             = "Winaero Website"
    TargetPath       = "${env:ProgramFiles}\Winaero Tweaker\Winaero.url"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles}\Winaero Tweaker"
    Description      = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user."
  },
  @{
    Name             = "EULA"
    TargetPath       = "${env:ProgramFiles(x86)}\Winaero Tweaker\Winaero EULA.txt"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Winaero Tweaker"
    Description      = "Read the license agreement"
  },
  @{
    Name             = "Winaero Tweaker"
    TargetPath       = "${env:ProgramFiles(x86)}\Winaero Tweaker\WinaeroTweaker.exe"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Winaero Tweaker"
  },
  @{
    Name             = "Winaero Website"
    TargetPath       = "${env:ProgramFiles(x86)}\Winaero Tweaker\Winaero.url"
    SystemLnk        = "Winaero Tweaker\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Winaero Tweaker"
    Description      = "Winaero is about Windows 10 / 8 / 7 and covers all topics that will interest every Windows user."
  },
  # WinSCP
  @{ # it's the only install on 32-bit
    Name             = "WinSCP"
    TargetPath       = "${env:ProgramFiles}\WinSCP\WinSCP.exe"
    WorkingDirectory = "${env:ProgramFiles}\WinSCP"
    Description      = "WinSCP: SFTP, FTP, WebDAV and SCP client" 
  },
  @{ # it's the only install on 64-bit
    Name             = "WinSCP"
    TargetPath       = "${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe"
    WorkingDirectory = "${env:ProgramFiles(x86)}\WinSCP"
    Description      = "WinSCP: SFTP, FTP, WebDAV and SCP client" 
  },
  # WizTree
  @{
    Name             = "Uninstall WizTree"
    TargetPath       = "${env:ProgramFiles}\WizTree\unins000.exe"
    SystemLnk        = "WizTree\"
    WorkingDirectory = "${env:ProgramFiles}\WizTree"
  },
  @{
    Name             = "WizTree"
    TargetPath       = $WizTree_TargetPath
    SystemLnk        = "WizTree\"
    WorkingDirectory = "${env:ProgramFiles}\WizTree"
  },
  @{
    Name             = "Uninstall WizTree"
    TargetPath       = "${env:ProgramFiles(x86)}\WizTree\unins000.exe"
    SystemLnk        = "WizTree\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\WizTree"
  },
  @{
    Name             = "WizTree"
    TargetPath       = "${env:ProgramFiles(x86)}\WizTree\WizTree.exe"
    SystemLnk        = "WizTree\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\WizTree"
  },
  # Yaskawa
  @{ # it's the only install on 32-bit
    Name             = "DriveWizard Industrial"
    TargetPath       = "${env:ProgramFiles}\Yaskawa\DriveWizard Industrial\YDWI.exe"
    SystemLnk        = "Yaskawa\"
    WorkingDirectory = "${env:ProgramFiles}\Yaskawa\DriveWizard Industrial"
    Description      = "Yaskawa DriveWizard Industrial" 
  },
  @{ # it's the only install on 64-bit
    Name             = "DriveWizard Industrial"
    TargetPath       = "${env:ProgramFiles(x86)}\Yaskawa\DriveWizard Industrial\YDWI.exe"
    SystemLnk        = "Yaskawa\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\Yaskawa\DriveWizard Industrial"
    Description      = "Yaskawa DriveWizard Industrial" 
  }
  <#

  @{
    Name = "..."
    TargetPath = "${env:ProgramFiles}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  @{Name = "..."
    TargetPath = "${env:ProgramFiles(x86)}\..."
    Arguments = "..."
    SystemLnk = "...\"
    WorkingDirectory = "${env:ProgramFiles(x86)}\...\"
    Description = "..."
    IconLocation = "${env:ProgramFiles}\...\*.*,#"
    RunAsAdmin = ($true -Or $false)
  },
  
  #>
)

for ($i = 0; $i -lt $sys3rdPartyAppList.length; $i++) {
  $app = $sys3rdPartyAppList[$i]
  $aName = $app.Name
  $aTargetPath = $app.TargetPath
  $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
  $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
  $aWorkingDirectory = if ($app.WorkingDirectory) { $app.WorkingDirectory } else { "" }
  $aDescription = if ($app.Description) { $app.Description } else { "" }
  $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
  $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

  $AttemptRecreation = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -wd $aWorkingDirectory -d $aDescription -il $aIconLocation -r $aRunAsAdmin
  if ($ScriptResults -And ($AttemptRecreation -ne 1)) { $ScriptResults = $AttemptRecreation }
  if ($AttemptRecreation -eq 2) { Write-Warning "Entry at `$sysAppList[$i] prompted this warning." }
  Write-Host ""
}



# User Applications (per user installed apps)

# get all users 
$Users = (Get-ChildItem -Directory -Path "${USERS_FOLDER}\" | ForEach-Object { if (($_.name -ne "Default") -And ($_.name -ne "Public")) { $_.name } })
# if only one user, array needs to be recreated
if ($Users -And ($Users[0].length -eq 1)) { $Users = @("$Users") }

# System app arguments dependant on uninstall strings

## App Name
#$App_Arguments = ...

# System app paths dependant on app version

# Adobe
$AdobeDigitalEditions_TargetPath = "${env:ProgramFiles}\Adobe\"
$AdobeDigitalEditions_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Property LastWriteTime) }
$AdobeDigitalEditions_FindFolder = if ($AdobeDigitalEditions_FindFolders) { $AdobeDigitalEditions_FindFolders[0].name } else { $NOT_INSTALLED }
$AdobeDigitalEditions_TargetPath += "${AdobeDigitalEditions_FindFolder}\DigitalEditions.exe"
$AdobeDigitalEditions_32bit_TargetPath = "${env:ProgramFiles(x86)}\Adobe\"
$AdobeDigitalEditions_32bit_FindFolders = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath) { (Get-ChildItem -Directory -Path $AdobeDigitalEditions_32bit_TargetPath | Where-Object { $_.Name -match '^Adobe Digital Editions' } | Sort-Object -Property LastWriteTime) }
$AdobeDigitalEditions_32bit_FindFolder = if ($AdobeDigitalEditions_32bit_FindFolders) { $AdobeDigitalEditions_32bit_FindFolders[0].name } else { $NOT_INSTALLED }
$AdobeDigitalEditions_32bit_TargetPath += "${AdobeDigitalEditions_32bit_FindFolder}\DigitalEditions.exe"
# Blender
$Blender_TargetPath = "${env:ProgramFiles}\Blender Foundation\"
$Blender_FindFolder = if (Test-Path -Path $Blender_TargetPath) { Get-ChildItem -Directory -Path $Blender_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Property LastWriteTime }
$Blender_FindFolder = if ($Blender_FindFolder) { $Blender_FindFolder[0].name } else { $NOT_INSTALLED }
$Blender_WorkingDirectory = $Blender_TargetPath + "${Blender_FindFolder}\"
$Blender_TargetPath = $Blender_WorkingDirectory + "blender-launcher.exe"
$Blender_32bit_TargetPath = "${env:ProgramFiles(x86)}\Blender Foundation\"
$Blender_32bit_FindFolder = if (Test-Path -Path $Blender_32bit_TargetPath) { Get-ChildItem -Directory -Path $Blender_32bit_TargetPath | Where-Object { $_.Name -match '^Blender' } | Sort-Object -Property LastWriteTime }
$Blender_32bit_FindFolder = if ($Blender_32bit_FindFolder) { $Blender_32bit_FindFolder[0].name } else { $NOT_INSTALLED }
$Blender_32bit_WorkingDirectory = $Blender_32bit_TargetPath + "${Blender_32bit_FindFolder}\"
$Blender_32bit_TargetPath = $Blender_32bit_WorkingDirectory + "blender-launcher.exe"

# System app names dependant on OS or app version

# Adobe
$AdobeDigitalEditions_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_TargetPath -PathType leaf) { (Get-Item $AdobeDigitalEditions_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_Version = if ($AdobeDigitalEditions_FileVersionRaw) { [string]($AdobeDigitalEditions_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
$AdobeDigitalEditions_Name = "Adobe Digital Editions ${AdobeDigitalEditions_Version}"
$AdobeDigitalEditions_32bit_FileVersionRaw = if (Test-Path -Path $AdobeDigitalEditions_32bit_TargetPath -PathType leaf) { (Get-Item $AdobeDigitalEditions_32bit_TargetPath).VersionInfo.FileVersionRaw }
$AdobeDigitalEditions_32bit_Version = if ($AdobeDigitalEditions_32bit_FileVersionRaw) { [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Major) + '.' + [string]($AdobeDigitalEditions_32bit_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
$AdobeDigitalEditions_32bit_Name = "Adobe Digital Editions ${AdobeDigitalEditions_32bit_Version}"

# App names dependant on OS or app version

# Microsoft Teams
$MicrosoftTeams_Name = "Microsoft Teams" + $(if ($isWindows11) { " (work or school)" })

for ($i = 0; $i -lt $Users.length; $i++) {
  # get user
  $aUser = $Users[$i]
  $aUserFolder = "${USERS_FOLDER}\${aUser}"
  $UsersAppData = "${aUserFolder}\AppData"
  $UsersAppDataLocal = "${UsersAppData}\Local"
  $UsersAppDataRoaming = "${UsersAppData}\Roaming"
  $UsersProgramFiles = "${UsersAppDataLocal}\Programs"

  # User app paths dependant on app version

  # 1Password
  $OnePassword_TargetPath = "${UsersAppDataLocal}\1Password\app\"
  $OnePassword_FindFolder = if (Test-Path -Path $OnePassword_TargetPath) { Get-ChildItem -Directory -Path $OnePassword_TargetPath | Where-Object { $_.Name -match '^[.0-9]+$' } | Sort-Object -Property LastWriteTime }
  $OnePassword_FindFolder = if ($OnePassword_FindFolder) { $OnePassword_FindFolder[0].name } else { $NOT_INSTALLED }
  $OnePassword_TargetPath += "${OnePassword_FindFolder}\1Password.exe"
  # Adobe
  $AdobeDigitalEditions_WorkingDirectory = "${UsersAppDataLocal}\Temp"
  # Autodesk
  $FusionLauncher_TargetPath = "${UsersAppDataLocal}\Autodesk\webdeploy\production\"
  $FusionLauncher_FindFolder = $NOT_INSTALLED
  if (Test-Path -Path $FusionLauncher_TargetPath) {
    $FusionLauncher_FindFolder_Index = 0
    $FusionLauncher_FindFolder_Folders = Get-ChildItem -Directory -Path $FusionLauncher_TargetPath
    $FusionLauncher_FindFolder_Length = $FusionLauncher_FindFolder_Folders.length
    while (($FusionLauncher_FindFolder_Index -lt $FusionLauncher_FindFolder_Length) -And ($FusionLauncher_FindFolder -eq $NOT_INSTALLED)) {
      $FusionLauncher_FindFolder_Temp = $FusionLauncher_FindFolder_Folders[$FusionLauncher_FindFolder_Index]
      $FusionLauncher_TargetPath_Temp = "${FusionLauncher_TargetPath}\${FusionLauncher_FindFolder_Temp}\FusionLauncher.exe"
      if (Test-Path -Path $FusionLauncher_TargetPath_Temp -PathType leaf) { $FusionLauncher_FindFolder = $FusionLauncher_FindFolder_Temp }
      $FusionLauncher_FindFolder_Index++
    }
  }
  $FusionLauncher_TargetPath += "${FusionLauncher_FindFolder}\FusionLauncher.exe"
  # Discord
  $Discord_WorkingDirectory = "${UsersAppDataLocal}\Discord\"
  $Discord_TargetPath = $Discord_WorkingDirectory + "Update.exe"
  $Discord_FindFolder = if (Test-Path -Path $Discord_WorkingDirectory) { Get-ChildItem -Directory -Path $Discord_WorkingDirectory | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Property LastWriteTime }
  $Discord_FindFolder = if ($Discord_FindFolder) { $Discord_FindFolder[0].name } else { $NOT_INSTALLED }
  $Discord_WorkingDirectory += $Discord_FindFolder
  # GitHub
  $GitHubDesktop_WorkingDirectory = "${UsersAppDataLocal}\GitHubDesktop\"
  $GitHubDesktop_TargetPath = $GitHubDesktop_WorkingDirectory + "GitHubDesktop.exe"
  $GitHubDesktop_FindFolder = if (Test-Path -Path $GitHubDesktop_WorkingDirectory) { Get-ChildItem -Directory -Path $GitHubDesktop_WorkingDirectory | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Property LastWriteTime }
  $GitHubDesktop_FindFolder = if ($GitHubDesktop_FindFolder) { $GitHubDesktop_FindFolder[0].name } else { $NOT_INSTALLED }
  $GitHubDesktop_WorkingDirectory += $GitHubDesktop_FindFolder
  # GoTo
  $GoToResolveDesktopConsole_WorkingDirectory = "${aUserFolder}\GoTo\GoTo Resolve Desktop Console\"
  $GoToResolveDesktopConsole_Exe = $GoToResolveDesktopConsole_WorkingDirectory + "ra-technician-console.exe"
  $GoToResolveDesktopConsole_Arch = if (Test-Path -Path $GoToResolveDesktopConsole_Exe) { Get-BinaryType $GoToResolveDesktopConsole_Exe }
  $GoToResolveDesktopConsole_TargetPath = if ($GoToResolveDesktopConsole_Arch -And ($GoToResolveDesktopConsole_Arch -eq "BIT64")) { $GoToResolveDesktopConsole_Exe } else { $GoToResolveDesktopConsole_WorkingDirectory + "${NOT_INSTALLED}.exe" }
  $GoToResolveDesktopConsole_32bit_TargetPath = if ($GoToResolveDesktopConsole_Arch -And ($GoToResolveDesktopConsole_Arch -eq "BIT32")) { $GoToResolveDesktopConsole_Exe } else { $GoToResolveDesktopConsole_WorkingDirectory + "${NOT_INSTALLED}.exe" }
  # Microsoft
  $AzureIoTExplorerPreview_TargetPath = "${UsersProgramFiles}\azure-iot-explorer\Azure IoT Explorer Preview.exe"
  $AzureIoTExplorer_TargetPath = if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType leaf) { $AzureIoTExplorerPreview_TargetPath } else { "${UsersProgramFiles}\azure-iot-explorer\Azure IoT Explorer.exe" }
  # Python
  $Python_WorkingDirectory = "${UsersProgramFiles}\Python\"
  $Python_FindFolder = if (Test-Path -Path $Python_WorkingDirectory) { Get-ChildItem -Directory -Path $Python_WorkingDirectory | Where-Object { $_.Name -match '^Python[.0-9]+$' } | Sort-Object -Property LastWriteTime }
  $Python_FindFolder = if ($Python_FindFolder) { $Python_FindFolder[0].name } else { $NOT_INSTALLED }
  $Python_WorkingDirectory += "${Python_FindFolder}\"
  $PythonIDLE_TargetPath = $Python_WorkingDirectory + "Lib\idlelib\idle.pyw"
  $PythonManuals_TargetPath = $Python_WorkingDirectory + "Doc\html\index.html"
  $Python_TargetPath = $Python_WorkingDirectory + "python.exe"
  $Python_FileVersionRaw = if (Test-Path -Path $Python_TargetPath -PathType leaf) { (Get-Item $Python_TargetPath).VersionInfo.FileVersionRaw }
  $Python_Version = if ($Python_FileVersionRaw) { [string]($Python_FileVersionRaw.Major) + '.' + [string]($Python_FileVersionRaw.Minor) } else { $NOT_INSTALLED }
  $Python_SystemLnk = "Python ${Python_Version}\"
  # Slack
  $Slack_WorkingDirectory = "${UsersAppDataLocal}\slack\"
  $Slack_TargetPath = $Slack_WorkingDirectory + "slack.exe"
  $Slack_FindFolder = if (Test-Path -Path $Slack_WorkingDirectory) { Get-ChildItem -Directory -Path $Slack_WorkingDirectory | Where-Object { $_.Name -match '^app\-[.0-9]+$' } | Sort-Object -Property LastWriteTime }
  $Slack_FindFolder = if ($Slack_FindFolder) { $Slack_FindFolder[0].name } else { $NOT_INSTALLED }
  $Slack_WorkingDirectory += $Slack_FindFolder
  
  # User app names dependant on OS or app version

  # Microsoft
  $WindowsTools_TargetPath = "${env:windir}\system32\"
  $WindowsTools_TargetPath += if ($isWindows11) { "control.exe" } else { "${NOT_INSTALLED}.exe" }
  $AzureIoTExplorer_Name = "Azure IoT Explorer" + $(if (Test-Path -Path $AzureIoTExplorerPreview_TargetPath -PathType leaf) { " Preview" })
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
    @{
      Name        = "1Password"
      TargetPath  = $OnePassword_TargetPath
      Description = "1Password"
    },
    # Adobe
    @{
      Name             = $AdobeDigitalEditions_Name
      TargetPath       = $AdobeDigitalEditions_TargetPath
      WorkingDirectory = $AdobeDigitalEditions_WorkingDirectory
    },
    @{
      Name             = $AdobeDigitalEditions_32bit_Name
      TargetPath       = $AdobeDigitalEditions_32bit_TargetPath
      WorkingDirectory = $AdobeDigitalEditions_WorkingDirectory
    },
    # Autodesk (note: these paths are not a mistake, this is how it installs its shortcuts)
    @{
      Name       = "Autodesk Fusion 360"
      TargetPath = $FusionLauncher_TargetPath
      SystemLnk  = "Autodesk\"
    },
    @{
      Name             = "Meshmixer"
      TargetPath       = "${env:ProgramFiles}\Autodesk\Meshmixer\meshmixer.exe"
      SystemLnk        = "Autodesk\"
      WorkingDirectory = "${ProgramFiles}\Autodesk\Meshmixer"
    },
    @{
      Name             = "Uninstall Meshmixer"
      TargetPath       = "${env:ProgramFiles}\Autodesk\Meshmixer\Uninstall.exe"
      SystemLnk        = "Autodesk\"
      WorkingDirectory = "${ProgramFiles}\Autodesk\Meshmixer"
      Description      = "Uninstall Autodesk Meshmixer"
    },
    @{
      Name             = "Meshmixer"
      TargetPath       = "${env:ProgramFiles(x86)}\Autodesk\Meshmixer\meshmixer.exe"
      SystemLnk        = "Autodesk\"
      WorkingDirectory = "${ProgramFiles(x86)}\Autodesk\Meshmixer"
    },
    @{
      Name             = "Uninstall Meshmixer"
      TargetPath       = "${env:ProgramFiles(x86)}\Autodesk\Meshmixer\Uninstall.exe"
      SystemLnk        = "Autodesk\"
      WorkingDirectory = "${ProgramFiles(x86)}\Autodesk\Meshmixer"
      Description      = "Uninstall Autodesk Meshmixer"
    },
    # AutoHotkey V2
    @{
      Name        = "AutoHotkey Window Spy"
      TargetPath  = "${aUserFolder}\AutoHotkey\UX\AutoHotkeyUX.exe"
      Arguments   = "`"${aUserFolder}\AutoHotkey\UX\WindowSpy.ahk`""
      Description = "AutoHotkey Window Spy"
    },
    @{
      Name        = "AutoHotkey"
      TargetPath  = "${aUserFolder}\AutoHotkey\UX\AutoHotkeyUX.exe"
      Arguments   = "`"${aUserFolder}\AutoHotkey\UX\ui-dash.ahk`""
      Description = "AutoHotkey Dash"
    },
    # AutoHotkey
    @{
      Name       = "AutoHotkey Help File"
      TargetPath = "${aUserFolder}\AutoHotkey\AutoHotkey.chm"
      SystemLnk  = "AutoHotkey\"
    },
    @{
      Name       = "AutoHotkey Setup"
      TargetPath = "${aUserFolder}\AutoHotkey\Installer.ahk"
      SystemLnk  = "AutoHotkey\"
    },
    @{
      Name       = "AutoHotkey"
      TargetPath = "${aUserFolder}\AutoHotkey\AutoHotkey.exe"
      SystemLnk  = "AutoHotkey\"
    },
    @{
      Name       = "Convert .ahk to .exe"
      TargetPath = "${aUserFolder}\AutoHotkey\Compiler\Ahk2Exe.exe"
      SystemLnk  = "AutoHotkey\"
    },
    @{
      Name       = "Website"
      TargetPath = "${aUserFolder}\AutoHotkey\AutoHotkey Website.url"
      SystemLnk  = "AutoHotkey\"
    },
    @{
      Name       = "Window Spy"
      TargetPath = "${aUserFolder}\AutoHotkey\WindowSpy.ahk"
      SystemLnk  = "AutoHotkey\"
    },
    # balenaEtcher
    @{
      Name             = "balenaEtcher"
      TargetPath       = "${UsersProgramFiles}\balena-etcher\balenaEtcher.exe"
      WorkingDirectory = "${UsersProgramFiles}\balena-etcher"
      Description      = "Flash OS images to SD cards and USB drives, safely and easily."
    },
    # Blender
    @{
      Name             = "Blender"
      TargetPath       = $Blender_TargetPath
      SystemLnk        = "blender\"
      WorkingDirectory = $Blender_WorkingDirectory
    },
    @{
      Name             = "Blender"
      TargetPath       = $Blender_32bit_TargetPath
      SystemLnk        = "blender\"
      WorkingDirectory = $Blender_32bit_WorkingDirectory
    },
    # Discord
    @{
      Name             = "Discord"
      TargetPath       = $Discord_TargetPath
      Arguments        = "--processStart Discord.exe"
      SystemLnk        = "Discord Inc\"
      WorkingDirectory = $Discord_WorkingDirectory
      Description      = "Discord - https://discord.com"
    },
    # Eaton (note: these paths are not a mistake, this is how it installs its shortcuts)
    @{
      Name             = "9000XDrive"
      TargetPath       = "${env:SystemDrive}\AFEngine\AFTools\9000XDrive\9000XDrive.exe"
      SystemLnk        = "AFEngine\"
      WorkingDirectory = "${env:SystemDrive}\AFEngine\AFTools\9000XDrive"
    },
    @{
      Name             = "9000XLoad"
      TargetPath       = "${env:SystemDrive}\AFEngine\AFTools\9000XLoad\9000XLoad.exe"
      SystemLnk        = "AFEngine\"
      WorkingDirectory = "${env:SystemDrive}\AFEngine\AFTools\9000XLoad"
    },
    # GitHub
    @{
      Name             = "GitHub Desktop"
      TargetPath       = $GitHubDesktop_TargetPath
      SystemLnk        = "GitHub, Inc\"
      WorkingDirectory = $GitHubDesktop_WorkingDirectory
      Description      = "Simple collaboration from your desktop"
    },
    # Google
    @{
      Name             = "Google Chrome"
      TargetPath       = "${UsersAppDataLocal}\Google\Chrome\Application\chrome.exe"
      WorkingDirectory = "${UsersAppDataLocal}\Google\Chrome\Application"
      Description      = "Access the Internet"
    },
    # GoTo
    @{
      Name             = "GoTo Resolve Desktop Console (64-bit)"
      TargetPath       = $GoToResolveDesktopConsole_TargetPath
      WorkingDirectory = $GoToResolveDesktopConsole_WorkingDirectory
    },
    @{
      Name             = "GoTo Resolve Desktop Console"
      TargetPath       = $GoToResolveDesktopConsole_32bit_TargetPath
      WorkingDirectory = $GoToResolveDesktopConsole_WorkingDirectory
    },
    # Inkscape (note: these paths are not a mistake, this is how it installs its shortcuts)
    @{
      Name             = "Inkscape"
      TargetPath       = "${env:ProgramFiles}\Inkscape\bin\inkscape.exe"
      SystemLnk        = "Inkscape\"
      WorkingDirectory = "${env:ProgramFiles}\Inkscape\bin\"
    },
    @{
      Name             = "Inkview"
      TargetPath       = "${env:ProgramFiles}\Inkscape\bin\inkview.exe"
      SystemLnk        = "Inkscape\"
      WorkingDirectory = "${env:ProgramFiles}\Inkscape\bin\"
    },
    @{
      Name             = "Inkscape"
      TargetPath       = "${env:ProgramFiles(x86)}\Inkscape\bin\inkscape.exe"
      SystemLnk        = "Inkscape\"
      WorkingDirectory = "${env:ProgramFiles(x86)}\Inkscape\bin\"
    },
    @{
      Name             = "Inkview"
      TargetPath       = "${env:ProgramFiles(x86)}\Inkscape\bin\inkview.exe"
      SystemLnk        = "Inkscape\"
      WorkingDirectory = "${env:ProgramFiles(x86)}\Inkscape\bin\"
    },
    # Microsoft
    @{
      Name             = "Azure Data Studio"
      TargetPath       = "${UsersProgramFiles}\Azure Data Studio\azuredatastudio.exe"
      SystemLnk        = "Azure Data Studio\"
      WorkingDirectory = "${UsersProgramFiles}\Azure Data Studio"
    },
    @{
      Name             = $AzureIoTExplorer_Name
      TargetPath       = $AzureIoTExplorer_TargetPath
      WorkingDirectory = "${UsersProgramFiles}\azure-iot-explorer\"
    },
    @{
      Name             = $MicrosoftTeams_Name
      TargetPath       = "${UsersAppDataLocal}\Microsoft\Teams\Update.exe"
      Arguments        = "--processStart `"Teams.exe`""
      WorkingDirectory = "${UsersAppDataLocal}\Microsoft\Teams"
    },
    @{
      Name        = "OneDrive"
      TargetPath  = "${UsersAppDataLocal}\Microsoft\OneDrive\OneDrive.exe"
      Description = "Keep your most important files with you wherever you go, on any device."
    },
    @{
      Name             = "Remote Desktop"
      TargetPath       = "${UsersProgramFiles}\Remote Desktop\msrdcw.exe"
      WorkingDirectory = "${UsersProgramFiles}\Remote Desktop\"
      Description      = "Microsoft Remote Desktop Client"
    },
    @{
      Name             = "Visual Studio Code"
      TargetPath       = "${UsersProgramFiles}\Microsoft VS Code\Code.exe"
      SystemLnk        = "Visual Studio Code\"
      WorkingDirectory = "${UsersProgramFiles}\Microsoft VS Code"
    },
    # Windows
    @{
      Name         = "Administrative Tools"
      TargetPath   = $WindowsTools_TargetPath
      Arguments    = "/name Microsoft.AdministrativeTools"
      Description  = "Windows Tools"
      IconLocation = "%windir%\system32\imageres.dll,-114"
    },
    @{
      Name         = "LiveCaptions"
      TargetPath   = "${env:windir}\system32\LiveCaptions.exe"
      SystemLnk    = "Accessibility\"
      Description  = "Captions audio and video live on your screen."
      IconLocation = "%windir%\system32\LiveCaptions.exe,-1"
    },
    @{
      Name         = "Magnify"
      TargetPath   = "${env:windir}\system32\magnify.exe"
      SystemLnk    = "Accessibility\"
      Description  = "Enlarges selected text and other on-screen items for easier viewing."
      IconLocation = "%windir%\system32\magnify.exe,0"
    },
    @{
      Name         = "Narrator"
      TargetPath   = "${env:windir}\system32\narrator.exe"
      SystemLnk    = "Accessibility\"
      Description  = "Reads on-screen text, dialog boxes, menus, and buttons aloud if speakers or a sound output device is installed."
      IconLocation = "%windir%\system32\narrator.exe,-1"
    },
    @{
      Name         = "On-Screen Keyboard"
      TargetPath   = "${env:windir}\system32\osk.exe"
      SystemLnk    = "Accessibility\"
      Description  = "Displays a keyboard that is controlled by a mouse or switch input device."
      IconLocation = "%windir%\system32\osk.exe,-1"
    },
    @{
      Name         = "VoiceAccess"
      TargetPath   = "${env:windir}\system32\voiceaccess.exe"
      SystemLnk    = "Accessibility\"
      Description  = "Helps you to interact with your PC and dictate text with your voice."
      IconLocation = "%windir%\system32\voiceaccess.exe,-1"
    },
    @{
      Name             = "Command Prompt"
      TargetPath       = "${env:windir}\system32\cmd.exe"
      SystemLnk        = "System Tools\"
      WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
      Description      = "Performs text-based (command-line) functions."
      IconLocation     = "%windir%\system32\cmd.exe,0"
    },
    @{
      Name             = "Windows PowerShell"
      TargetPath       = "${env:windir}\System32\WindowsPowerShell\v1.0\powershell.exe"
      SystemLnk        = "Windows PowerShell\"
      WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
      Description      = "Performs object-based (command-line) functions"
      IconLocation     = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe,0"
    },
    @{
      Name             = "Windows PowerShell (x86)"
      TargetPath       = "${env:windir}\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
      SystemLnk        = "Windows PowerShell\"
      WorkingDirectory = "%HOMEDRIVE%%HOMEPATH%"
      Description      = "Performs object-based (command-line) functions"
      IconLocation     = "%SystemRoot%\syswow64\WindowsPowerShell\v1.0\powershell.exe,0"
    },
    # Mozilla
    @{
      Name             = "Firefox"
      TargetPath       = "${UsersAppDataLocal}\Mozilla Firefox\firefox.exe"
      WorkingDirectory = "${UsersAppDataLocal}\Mozilla Firefox"
    },
    # NVIDIA Corporation
    @{
      Name             = "NVIDIA GeForce NOW"
      TargetPath       = "${UsersAppDataLocal}\NVIDIA Corporation\GeForceNOW\CEF\GeForceNOW.exe"
      WorkingDirectory = "${UsersAppDataLocal}\NVIDIA Corporation\GeForceNOW\CEF"
    },
    # Python
    @{
      Name             = $PythonIDLE_Name
      TargetPath       = $PythonIDLE_TargetPath
      SystemLnk        = $Python_SystemLnk
      WorkingDirectory = $Python_WorkingDirectory
      Description      = $PythonIDLE_Description
    },
    @{
      Name             = $Python_Name
      TargetPath       = $Python_TargetPath
      SystemLnk        = $Python_SystemLnk
      WorkingDirectory = $Python_WorkingDirectory
      Description      = $Python_Description
    },
    @{
      Name             = $PythonManuals_Name
      TargetPath       = $PythonManuals_TargetPath
      SystemLnk        = $Python_SystemLnk
      WorkingDirectory = $Python_WorkingDirectory
      Description      = $PythonManuals_Description
    },
    @{
      Name             = $PythonModuleDocs_Name
      TargetPath       = $Python_TargetPath
      Arguments        = "-m pydoc -b"
      SystemLnk        = $Python_SystemLnk
      WorkingDirectory = $Python_WorkingDirectory
      Description      = $PythonModuleDocs_Description
    },
    # Slack
    @{
      Name             = "Slack"
      TargetPath       = $Slack_TargetPath
      SystemLnk        = "Slack Technologies Inc\"
      WorkingDirectory = $Slack_WorkingDirectory
      Description      = "Slack Desktop"
    },
    # Raspberry Pi Imager (note: these paths are not a mistake, this is how it installs its shortcuts)
    @{ # it's the only install on 32-bit
      Name             = "Raspberry Pi Imager"
      TargetPath       = "${env:ProgramFiles}\Raspberry Pi Imager\rpi-imager.exe"
      WorkingDirectory = "${env:ProgramFiles}\Raspberry Pi Imager" 
    },
    @{ # it's the only install on 64-bit
      Name             = "Raspberry Pi Imager"
      TargetPath       = "${env:ProgramFiles(x86)}\Raspberry Pi Imager\rpi-imager.exe"
      WorkingDirectory = "${env:ProgramFiles(x86)}\Raspberry Pi Imager" 
    },
    # RingCentral
    @{
      Name             = "RingCentral"
      TargetPath       = "${UsersProgramFiles}\RingCentral\RingCentral.exe"
      WorkingDirectory = "${UsersProgramFiles}\RingCentral"
      Description      = "RingCentral"
    },
    @{
      Name        = "RingCentral Meetings"
      TargetPath  = "${UsersAppDataRoaming}\RingCentralMeetings\bin\RingCentralMeetings.exe"
      SystemLnk   = "RingCentral Meetings\"
      Description = "RingCentral Meetings"
    },
    @{
      Name        = "Uninstall RingCentral Meetings"
      TargetPath  = "${UsersAppDataRoaming}\RingCentralMeetings\uninstall\Installer.exe"
      Arguments   = "/uninstall"
      SystemLnk   = "RingCentral Meetings\"
      Description = "Uninstall RingCentral Meetings"
    },
    # WinDirStat (note: these paths are not a mistake, this is how it installs its shortcuts)
    @{ # it's the only install on 32-bit
      Name             = "Help (ENG)"
      TargetPath       = "${env:ProgramFiles}\WinDirStat\windirstat.chm"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles}\WinDirStat" 
    },
    @{ # it's the only install on 32-bit
      Name             = "Uninstall WinDirStat"
      TargetPath       = "${env:ProgramFiles}\WinDirStat\Uninstall.exe"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles}\WinDirStat" 
    },
    @{ # it's the only install on 32-bit
      Name             = "WinDirStat"
      TargetPath       = "${env:ProgramFiles}\WinDirStat\windirstat.exe"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles}\WinDirStat" 
    },
    @{ # it's the only install on 64-bit
      Name             = "Help (ENG)"
      TargetPath       = "${env:ProgramFiles(x86)}\WinDirStat\windirstat.chm"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles(x86)}\WinDirStat" 
    },
    @{ # it's the only install on 64-bit
      Name             = "Uninstall WinDirStat"
      TargetPath       = "${env:ProgramFiles(x86)}\WinDirStat\Uninstall.exe"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles(x86)}\WinDirStat" 
    },
    @{ # it's the only install on 64-bit
      Name             = "WinDirStat"
      TargetPath       = "${env:ProgramFiles(x86)}\WinDirStat\windirstat.exe"
      SystemLnk        = "WinDirStat\"
      WorkingDirectory = "${env:ProgramFiles(x86)}\WinDirStat" 
    },
    # Zoom
    @{
      Name        = "Uninstall Zoom"
      TargetPath  = "${UsersAppDataRoaming}\Zoom\uninstall\Installer.exe"
      Arguments   = "/uninstall"
      SystemLnk   = "Zoom\"
      Description = "Uninstall Zoom"
    },
    @{
      Name        = "Zoom"
      TargetPath  = "${UsersAppDataRoaming}\Zoom\bin\Zoom.exe"
      SystemLnk   = "Zoom\"
      Description = "Zoom UMX" 
    }
    <#

    @{
      Name = "..."
      TargetPath = "${UsersProgramFiles}\..."
      Arguments = "..."
      SystemLnk = "...\"
      WorkingDirectory = "${UsersProgramFiles}\...\"
      Description = "..."
      IconLocation = "${UsersProgramFiles}\...\*.*,#"
      RunAsAdmin = ($true -Or $false)
    },
    
    #>
  )

  for ($j = 0; $j -lt $userAppList.length; $j++) {
    $app = $userAppList[$j]
    $aName = $app.Name
    $aTargetPath = $app.TargetPath
    $aArguments = if ($app.Arguments) { $app.Arguments } else { "" }
    $aSystemLnk = if ($app.SystemLnk) { $app.SystemLnk } else { "" }
    $aWorkingDirectory = if ($app.WorkingDirectory) { $app.WorkingDirectory } else { "" }
    $aDescription = if ($app.Description) { $app.Description } else { "" }
    $aIconLocation = if ($app.IconLocation) { $app.IconLocation } else { "" }
    $aRunAsAdmin = if ($app.RunAsAdmin) { $app.RunAsAdmin } else { $false }

    $AttemptRecreation = New-Shortcut -n $aName -tp $aTargetPath -a $aArguments -sl $aSystemLnk -wd $aWorkingDirectory -d $aDescription -il $aIconLocation -r $aRunAsAdmin -u $aUser
    if ($ScriptResults -And ($AttemptRecreation -ne 1)) { $ScriptResults = $AttemptRecreation }
    if ($AttemptRecreation -eq 2) { Write-Warning "Entry at `$sysAppList[$i] prompted this warning." }
    Write-Host ""
  }
}

if ($ScriptResults -eq 1) { Write-Host "Script completed successfully." }
elseif ($ScriptResults -eq 2) { Write-Warning "Script completed with some warnings." }
else { Write-Error "Script completed with some errors." }



# Logging
Stop-Transcript
