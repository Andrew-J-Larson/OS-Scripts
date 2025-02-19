<#
  .SYNOPSIS
  Prepare PC v1.5.2

  .DESCRIPTION
  Script will prepare a fresh machine all the way up to a domain joining.

  .PARAMETER Log
  Turns on logging for the script.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Successes, warnings, and errors log to the console.
  
  If logging is turned on, a log file will be created (normally at the root of the machine's drive).

  .EXAMPLE
  .\Prepare-PC.ps1

  .EXAMPLE
  .\Prepare-PC.ps1 -Help

  .EXAMPLE
  .\Prepare-PC.ps1 -h

  .EXAMPLE
  .\Prepare-PC.ps1 -FullScreen

  .EXAMPLE
  .\Prepare-PC.ps1 -f11

  .EXAMPLE
  .\Prepare-PC.ps1 -Log

  .EXAMPLE
  .\Prepare-PC.ps1 -l

  .EXAMPLE
  .\Prepare-PC.ps1 -SelectAppList "[txt file name here, DEFAULT, or NONE]"

  .EXAMPLE
  .\Prepare-PC.ps1 -a "[txt file name here, DEFAULT, or NONE]"

  .EXAMPLE
  .\Prepare-PC.ps1 -f -l -a "DEFAULT" # full screen, logging, and default app list selected

  .NOTES
  Requires admin! Due to the many system settings and configurations that have to be altered.

  Dell machines will have "Dell Command Update" installed or updated when running this script.

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Prepare-PC/Prepare-PC.ps1
#>
#Requires -RunAsAdministrator

<# Copyright (C) 2024  Andrew Larson (github@drewj.la)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>. #>

param(
  [Alias("h")]
  [switch]$Help,
  
  [Alias("f11")]
  [switch]$FullScreen,

  [Alias("l")]
  [switch]$Log,

  [Alias("a")]
  [ValidateNotNullOrEmpty()]
  [string]$SelectAppList
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}
if ($FullScreen.IsPresent) {
  # can't use wscript.shell for F11, as there is a bug when a physical keyboard is connected
  [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
  [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") | Out-Null
  # Windows 11 might randomly popup the start menu, so need to close it first
  $startMenuProcess = Get-Process -Name "StartMenuExperienceHost" -ErrorAction SilentlyContinue
  if ($startMenuProcess) { Stop-Process -Id $startMenuProcess.Id -Force }
  [Microsoft.VisualBasic.Interaction]::AppActivate($PID) | Out-Null
  [System.Windows.Forms.SendKeys]::SendWait("{F11}")
}
$logEnabled = $Log.IsPresent
# $SelectAppList is checked later in script

# Windows Defender Application Gaurd has quirks with script
$isWDAG = ($env:USERNAME -eq 'WDAGUtilityAccount')

# Only supported on 64-bit based versions of Windows
$osIsWindows = (-Not (Test-Path variable:global:isWindows)) -Or $isWindows # required for PS 5.1
$osIsARM = $env:PROCESSOR_ARCHITECTURE -match '^arm.*'
$osIs64Bit = [System.Environment]::Is64BitOperatingSystem
$osName = if ($PSVersionTable.OS) {
  $PSVersionTable.OS
} else { # required for PS 5.1
  ((([System.Environment]::OSVersion.VersionString.split() |
  Select-Object -Index 0,1,3) -join ' ').split('.') |
  Select-Object -First 3) -join '.'
}
$osArch = $(
  if ($osIsARM) { 'arm' } else { 'x' }
) + $(
  if ($osIs64Bit) { '64' } elseif (-Not $osIsARM) { '86' }
) # = x86 | x64 | arm | arm64
if (-Not ($osIsWindows -And $osIs64Bit)) {
  Write-Warning "Not supported for $(if ($osIsWindows) { $osArch } else { $osName }) operating systems. Aborting script."
  exit 1
}

# Internet connection check
$InternetAccess = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"
if (-Not $InternetAccess) {
  Write-Warning "Please connect to the internet first. Aborting script."
  exit 1
}

# Battery status check (only for laptops and other mobile devices)
$HardwareType = (Get-WmiObject -Class Win32_ComputerSystem -Property PCSystemType).PCSystemType
if ($HardwareType -eq 2) {
  # Mobile devices = 2, a.k.a. anything that charges with a battery
  $BatteryStatus = (Get-WmiObject Win32_Battery).BatteryStatus
  <#
    Other (1): The battery is discharging.
    Unknown (2): The system has access to AC so no battery is being discharged. However, the battery is not necessarily charging.
    Fully Charged (3)
    Low (4)
    Critical (5)
    Charging (6)
    Charging and High (7)
    Charging and Low (8)
    Charging and Critical (9)
    Undefined (10)
    Partially Charged (11)
  #>
  Switch ([int]$BatteryStatus) {
    { 2,6,7,8 -contains $_ } {
      # Continue without prompting user
      Out-Null
    }
    { 1,3,4,11 -contains $_ } {
      # Prompt before continuing
      $title = 'Computer is not charging.'
      $question = 'Are you sure you want to proceed?'
      $choices = '&Yes', '&No'
      $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
      if ($decision -eq 0) {
        Clear-Host # no need to keep this information on screen
      } else {
        exit 0 # user chose to exit from script
      }
    }
    { 5,9 -contains $_ } {
      # Exit and stress to user to charge their computer more
      Write-Warning "Battery status is critical, please charge your device more. Aborting script."
      exit 1
    }
    default {
      # default = 10 = Exit and warn user about undefined battery status
      Write-Warning "Battery status is undefined, please check your battery health. Aborting script."
      exit 1
    }
  }
}

# media USB dongles can cause issues with later BIOS updates
$usbMediaDevices = if (-Not $isWDAG) {
  # Windows Defender Application Gaurd will never have USB devices
  Get-PnpDevice -Class MEDIA -PresentOnly | Where-Object { ($_.Description -match '^\bUSB\b') }
}
if ($usbMediaDevices) {
  Write-Host "Found media USB devices connected to the computer:`n"
  $usbMediaDevices.FriendlyName
  Write-Host ''

  $title = 'If any of the media USB devices listed are USB dongles, please remove them now.'
  $question = 'Are all media USB dongles removed from the computer?'
  $choices = '&Yes', '&No'
  $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
  if ($decision -eq 0) {
    Clear-Host # no need to keep this information on screen
  } else {
    Write-Warning "Media USB dongles must be removed to continue. Aborting script."
    exit 1
  }
}

# Some Windows 11 builds have a preinstalled update that brake the Windows Update API (used later in script)
# - see about the known issue from Microsoft:
#   - https://learn.microsoft.com/en-us/windows/release-health/resolved-issues-windows-11-23h2#the-june-2024-preview-update-might-impact-applications-using-windows-update-apis
# - see about issue with KB5040442:
#   - https://github.com/mgajda83/PSWindowsUpdate/issues/27#issuecomment-2223311835
$isWindows11 = (Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption).Caption -like "* Windows 11 *"
$hasBadHotFixKB5040442 = (Get-CimInstance -Class Win32_QuickFixEngineering -Property HotFixID) | Where-Object { $_.HotFixID -eq "KB5043076" }
$fixedBuild = [System.Version]"10.0.22621.3958"
$checkBuild = [System.Environment]::OSVersion.Version.ToString().split('.')
$checkBuild[3] = $(Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion' UBR).UBR
$checkBuild = [System.Version]($checkBuild -Join '.')
$hasBrokenUpdateAPI = $isWindows11 -And $hasBadHotFixKB5040442 -And ($checkBuild -lt $fixedBuild)
if ($hasBrokenUpdateAPI) {
  $uninstallMsg = "faulty hotfix KB5040442"
  Write-Host "Uninstalling ${uninstallMsg} (please confirm the prompt)..."
  $UninstallBadHotFixProcess = Start-Process 'wusa.exe' -ArgumentList '/uninstall /kb:5040442 /norestart' -PassThru -Wait
  if (0 -eq $UninstallBrokenUpdateProcess.ExitCode) {
    Write-Host "Successfully uninstalled ${uninstallMsg}."
  } else {
    Write-Warning "Failed to uninstall ${uninstallMsg}, please uninstall this update manually (exit code = $($UninstallBrokenUpdateProcess.ExitCode))."
  }
  Write-Host "`nPlease reboot, and then attempt to run this script again.`n"
  Read-Host -Prompt "Press any key to reboot or CTRL+C to quit" | Out-Null
  # Reboot to finish uninstallation of bad hotfix
  Write-Host "Rebooting..."
  Restart-Computer -Force
  exit 1
}

# Check if running in Windows Terminal (determines if encoding needs to be changed when running some apps)
# code modified from https://stackoverflow.com/a/72575526
$ps = Get-Process -Id $PID
while ($ps -and 0 -eq [int] $ps.MainWindowHandle) { 
  $ps = Get-Process -ErrorAction Ignore -Id (Get-CimInstance Win32_Process -Filter "ProcessID = $($ps.Id)").ParentProcessId 
}
$runningInWindowsTerminal = $ps.ProcessName -eq 'WindowsTerminal'

# Check manufacturer (only required for using Dell Command Update on Dell computers)
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -Property Manufacturer).Manufacturer
$isDell = $manufacturer -like "Dell*"

# Required Computer Info
$serialnumber = (Get-WMIObject win32_bios).serialnumber
$computerName = @{
  new = $serialnumber
  current = (Get-WMIObject -class win32_computersystem).name
}
$pcModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$InvalidCharacterReplacement = '~'

# Logging
$scriptName = (Get-Item $PSCommandPath).Basename
$logName = ("$($computerName.new)_${pcModel}_${scriptName}.log".replace(' ', '-')).split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$logFile = "${env:SystemDrive}\${logName}"
if ($logEnabled) {
  Start-Transcript -Path $logFile
  Write-Output '' # Makes log look better
}

# Constants

$maxRetries = 5 # times to attempt Windows Updates
$loopDelay = 1 # second
$activeDirectoryDelay = 10 # seconds
$resources = "${PSScriptRoot}\resources"
$installers = "${resources}\installers"
$baseAppListFilename = "0-base.txt"
$baseAppList = "${installers}\${baseAppListFilename}"
$currentDomain = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { $computerName.current }
$currentUsername = "$(
  $testUsername = (Get-WMIObject -class win32_computersystem).username
  if ($testUsername) { $testUsername } else { $currentDomain + '\' + $env:USERNAME }
)"
$currentUser = ($currentUsername).split('\')[-1]
$currentUserSID = if (-Not $env:USERDOMAIN) { (Get-LocalUser $currentUser).SID.Value }
$shortDomainName = Get-Content "${resources}\shortDomainName.txt"
$domainName = Get-Content "${resources}\domainName.txt"
$distinguishedDomainName = @($domainName.split('.') | ForEach-Object { "DC=${_}" }) -Join ','
$domainAdminServerShare = "\\${domainName}\" + 'Admin$'
$localAdminUser = Get-Content "${resources}\localAdminUser.txt"
$localAdminPass = Get-Content "${resources}\localAdminPass.txt"
$adPathFromRootOU = Get-Content "${resources}\adPathFromRootOU.txt"
$adPathArrayFromRootOU = $adPathFromRootOU.split('/') ; [array]::Reverse($adPathArrayFromRootOU)
$distinguishedAdPathOU = "$(@($adPathArrayFromRootOU | ForEach-Object { "OU=${_}" }) -Join ','),${distinguishedDomainName}"
$timezone = Get-Content "${resources}\timezone.txt"
$RegisteredOwner = Get-Content "${resources}\RegisteredOwner.txt"
$RegisteredOrganization = Get-Content "${resources}\RegisteredOrganization.txt"
$regHKLM = "HKLM:"
$regLocalMachineSoftware = "${regHKLM}\SOFTWARE"
$regTzautoupdate = "${regHKLM}\SYSTEM\CurrentControlSet\Services\tzautoupdate"
$regCurrentVersion = "${regLocalMachineSoftware}\Microsoft\Windows NT\CurrentVersion"
$regMachinePolicies = "${regLocalMachineSoftware}\Policies\Microsoft\Windows"
$regWindowsUpdate = "${regMachinePolicies}\WindowsUpdate"
$regWinlogon = "${regCurrentVersion}\Winlogon"
$dcuEndPath = "Dell\CommandUpdate\dcu-cli.exe"
$dcuCli = "${env:ProgramFiles}\${dcuEndPath}"
$dcuCli32bit = "${env:ProgramFiles(x86)}\${dcuEndPath}" # required in the case of Dell SupportAssist OS reinstalls
$dcuCliExe = if (Test-Path -Path $dcuCli32bit -PathType Leaf) { $dcuCli32bit } else { $dcuCli }
$dcuConfigureArgs = '/configure -scheduleManual -updatesNotification=disable'
$dcuApplyArgs = '/applyUpdates' + $(if ($dcuCliExe -eq $dcuCli) { ' -forceUpdate=enable' } else { '' }) + ' -reboot=disable -autoSuspendBitLocker=enable' # if using the universal version, need forceUpdate option

# Functions

# installs WinGet from the internet: code via https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/Install-WinGet-Function.ps1
# installs WinGet from the internet
function Install-WinGet {
  # v1.2.7
  param(
    [switch]$Force
  )

  # CONSTANTS

  $osIsWindows = (-Not (Test-Path variable:global:isWindows)) -Or $isWindows # required for PS 5.1
  $osIsARM = $env:PROCESSOR_ARCHITECTURE -match '^arm.*'
  $osIs64Bit = [System.Environment]::Is64BitOperatingSystem
  $osArch = $( # architecture is required for some parts of the install process
    if ($osIsARM) { 'arm' } else { 'x' }
  ) + $(
    if ($osIs64Bit) { '64' } elseif (-Not $osIsARM) { '86' }
  ) # = x86 | x64 | arm | arm64
  $osVersion = [System.Environment]::OSVersion.Version
  $osName = if ($PSVersionTable.OS) {
    $PSVersionTable.OS
  } else { # required for PS 5.1
    ((([System.Environment]::OSVersion.VersionString.split() |
    Select-Object -Index 0,1,3) -join ' ').split('.') |
    Select-Object -First 3) -join '.'
  }
  $experimentalWindowsVersion = [System.Version]'10.0.16299.0' # first Windows version with MSIX features: https://learn.microsoft.com/en-us/windows/msix/supported-platforms
  $supportedWindowsVersion = [System.Version]'10.0.17763.0' # oldest Windows version that WinGet supports: https://github.com/microsoft/winget-cli?tab=readme-ov-file#installing-the-client
  $retiredWingetVersion = [System.Version]'1.2' # if on this version or older, WinGet must be updated, due to retired CDNs
  $experimentalWarning = "(things may not work properly)"
  $continuePrompt = "Press any key to continue or CTRL+C to quit"
  $envTEMP = (Get-Item -LiteralPath $( # Required due to PowerShell bug with shortnames appearing when they shouldn't be
    if (Test-Path variable:global:TEMP) {
      $env:TEMP
    } else { # Required for non-Windows
      [System.IO.Path]::GetTempPath().TrimEnd('\')
    }
  )).FullName 
  $loopDelay = 1 # second
  $appxInstallDelay = 3 # seconds

  # Error exit codes

  $FAILED = @{
    INSTALL                = 6
    DEPENDENCIES_CHECK     = 5
    INVALID_FILE_EXTENSION = 4
    NO_INTERNET            = 3
    NO_MSIX_FEATURE        = 2
    NOT_WINDOWS            = 1
  }

  # FUNCTIONS

  function Test-WinGet {
    return Get-Command 'winget.exe' -ErrorAction SilentlyContinue
  }

  # VARIABLES

  $forceWingetUpdate = $Force.IsPresent

  # MAIN

  # only for Windows 10 and newer
  Write-Host "Operating System = ${osName}`n"
  if (-Not $osIsWindows) {
    Write-Error "WinGet is only for Windows 10 and newer versions."
    return $FAILED.NOT_WINDOWS
  }

  # only experimental on Windows 10 (1709) and newer, where MSIX features are available
  $supportedWindowsBuild = "WinGet is only supported on Windows 10 (build $($supportedWindowsVersion.Build)) and newer versions"
  if ($experimentalWindowsVersion -gt $osVersion) {
    Write-Error "${supportedWindowsBuild}, and is only experimental on versions at or above Windows 10 (build $($experimentalWindowsVersion.Build)) ${experimentalWarning}."
    return $FAILED.NO_MSIX_FEATURE
  }

  # only supported on Windows 10 (1809) and newer, warn about unsupported Windows versions
  if ($supportedWindowsVersion -gt $osVersion) {
    Write-Warning "${supportedWindowsBuild} ${experimentalWarning}."
    Read-Host -Prompt $continuePrompt | Out-Null
    Write-Host '' # Makes log look better
  }

  # only supported on Windows (Work Station) versions, warn about unsupported Windows Server versions
  if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
    Write-Warning "WinGet isn't supported on Windows Server versions ${experimentalWarning}."
    Read-Host -Prompt $continuePrompt | Out-Null
    Write-Host '' # Makes log look better
  }

  # check for elevated powershell, and grab AppxPackage data from all users
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $elevatedPowershell = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  # Installing packages is based on the user profile currently loaded into powershell:
  #   If the original user account (without admin rights) attempts to use a second user account (with
  #   admin rights) to elevate the Install-WinGet function in any way before the automatic elevation,
  #   then it will load the profile of the second user account instead, and therefore will install
  #   WinGet to the second user's profile, instead of the original user's profile
  $appxPackagesAllUsers = $Null
  if ($elevatedPowershell) {
    # warn about running in elevated powershell as a different user
    $loggedOnUser = (Get-CimInstance Win32_ComputerSystem).Username
    $elevatedUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $wdagUtilUser = (Get-CimInstance Win32_ComputerSystem).Name + '\WDAGUtilityAccount'
    if (($loggedOnUser -ne $elevatedUser) -And ($wdagUtilUser -ne $elevatedUser)) {
      Write-Host -NoNewline "Logged in as non-admin user "
      Write-Host -NoNewline $loggedOnUser -BackgroundColor Blue
      Write-Host -NoNewline ", but elevated as admin user "
      Write-Host -NoNewline $elevatedUser -BackgroundColor DarkRed
      Write-Host "."
      Write-Warning "WinGet will be installed in the following user's profile: ${elevatedUser}"
      Write-Host -NoNewline "If this is not the intention, run the " -ForegroundColor Yellow
      Write-Host -NoNewline "script" -ForegroundColor Cyan
      Write-Host -NoNewline ", or " -ForegroundColor Yellow
      Write-Host -NoNewline "Install-WinGet" -ForegroundColor Cyan
      Write-Host " function, again, but" -ForegroundColor Yellow
      Write-Host -NoNewline "don't run it as admin" -BackgroundColor Red
      Write-Host ", to install in the following user's profile: ${loggedOnUser}`n" -ForegroundColor Yellow
      Read-Host -Prompt $continuePrompt | Out-Null
    }
    $appxPackagesAllUsers = @(Get-AppxPackage -AllUsers)
  } else {
    Write-Warning "Elevation required to install WinGet for the logged on user."
    $tempFileForElevatedData = New-TemporaryFile
    Start-Process 'powershell.exe' -ArgumentList "-command `"& { Get-AppxPackage -AllUsers | Export-Clixml '$($tempFileForElevatedData.FullName)' }`"" -Verb RunAs -Wait -WindowStyle Hidden
    $elevatedData = Import-Clixml -LiteralPath $tempFileForElevatedData
    $tempFileForElevatedData | Remove-Item -Force -ErrorAction SilentlyContinue
    $appxPackagesAllUsers = @($elevatedData)
  }

  # if we can't find WinGet, try re-registering it (only a first time logon issue)
  $desktopAppInstaller = $appxPackagesAllUsers | Where-Object { $_.Name -eq "Microsoft.DesktopAppInstaller"}
  if ($desktopAppInstaller) {
    if (-Not $(Test-WinGet)) {
      # if the version is new enough to contain WinGet, this should fix things
      Add-AppxPackage -DisableDevelopmentMode -Register "$($desktopAppInstaller.InstallLocation)\AppxManifest.xml"
      # need to wait a moment to allow Windows to recognize registration
      Start-Sleep -Seconds $appxInstallDelay
    }
    if ((-Not $forceWingetUpdate) -And $(Test-WinGet)) {
      # if WinGet version is retired, force it to update
      $currentWingetVersion = [System.Version](
        ((winget.exe -v).split('v')[1].split('.') | Select-Object -First 2) -join '.'
      )
      $forceWingetUpdate = ($currentWingetVersion -le $retiredWingetVersion)
    }
  }

  # if WinGet is still not found, download WinGet package with any dependent packages, and attempt install
  if ($forceWingetUpdate -Or (-Not $(Test-WinGet))) {
    # Internet connection check
    $InternetAccess = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"
    if (-Not $InternetAccess) {
      Write-Error "Please connect to the internet first. Aborting."
      return $FAILED.NO_INTERNET
    }

    Write-Host "Downloading WinGet...`n"
    $wingetLatestDownloadURL = "https://aka.ms/getwinget"
    $tempWingetPackage = $Null
    while (-Not $tempWingetPackage) {
      # need to loop until WinGet package is downloaded
      $PreviousProgressPreference = $ProgressPreference
      $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
      $tempWingetWebResponse = Invoke-WebRequest -Uri $wingetLatestDownloadURL -UseBasicParsing
      $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
      if ($tempWingetWebResponse.StatusCode -eq 200) {
        # confirm file extension is correct
        $tempWingetFileName = ([System.Net.Mime.ContentDisposition]$tempWingetWebResponse.Headers.'Content-Disposition').FileName
        if (-Not $tempWingetFileName.EndsWith(".msixbundle")) {
          Write-Error "File downloaded doesn't have the correct file extension."
          return $FAILED.INVALID_FILE_EXTENSION
        }
        $tempWingetPackage = $envTEMP + '\' + $tempWingetFileName
        # save to file
        $tempWingetFile = [System.IO.FileStream]::new($tempWingetPackage, [System.IO.FileMode]::Create)
        $tempWingetFile.write($tempWingetWebResponse.Content, 0, $tempWingetWebResponse.Content.Length)
        $tempWingetFile.close()
        Write-Host "Downloaded WinGet.`n"
      } else { Start-Sleep -Seconds $loopDelay }
    }

    # check for dependencies in WinGet that are not met, and only grab what we need
    Write-Host "Confirming dependencies for WinGet...`n"
    $wingetDependencies = @{
      # properties get set later
      uiXaml = @{
        # preinstalled
        # version
        # name
        # fileName
        # file
        # url
      }
      vcLibs = @{
        # preinstalled
        # version
        # name
        # fileName
        # file
        # url
      }
    }
    $wingetPackageZip = $Null
    $appManifestReader = $Null
    $appManifestStream = $Null
    $appInstallerMsixZip = $Null
    try {
      # required for checking inside packages
      Add-Type -Assembly System.IO.Compression.FileSystem

      # extract app installer msix from the WinGet package
      $appInstallerMsixFilename = 'AppInstaller_x64.msix'
      $tempAppInstallerMsix = $envTEMP + '\' + $appInstallerMsixFilename
      $wingetPackageZip = [IO.Compression.ZipFile]::OpenRead($tempWingetPackage)
      $appInstallerMsix = $wingetPackageZip.Entries | Where-Object { $_.FullName -eq $appInstallerMsixFilename }
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($appInstallerMsix, $tempAppInstallerMsix, $true)
      $wingetPackageZip.Dispose()

      # grab the app manifest from inside the app installer msix
      $appInstallerMsixZip = [IO.Compression.ZipFile]::OpenRead($tempAppInstallerMsix)
      $appxManifestXml = $appInstallerMsixZip.Entries | Where-Object { $_.FullName -eq 'AppxManifest.xml' }
      $appManifestStream = $appxManifestXml.Open()
      $appManifestReader = New-Object IO.StreamReader($appManifestStream)
      $appManifestText = $appManifestReader.ReadToEnd()
      $appManifestReader.Close()
      $appManifestStream.Close()
      $appInstallerMsixZip.Dispose()
      Remove-Item -Path $tempAppInstallerMsix -Force -ErrorAction SilentlyContinue
      $appManifest = [Xml]$appManifestText

      # setup objects in the dependencies hashtable
      $dependencyPackages = $appManifest.Package.Dependencies.PackageDependency
      if ($dependencyPackages) {
        Write-Host "Checked dependencies for WinGet.`n"
      } else { throw "missing dependency packages" }
      $dependencyPackages | ForEach-Object {
        $packageElement = $_
        $dependencyPackage = $Null
        if ($packageElement.Name -like "Microsoft.UI.Xaml*") {
          $dependencyPackage = $wingetDependencies.uiXaml
          $dependencyPackage.version = @($packageElement.Name -Split "Microsoft.UI.Xaml.")[1]
          $uiXamlLatestVersion = $Null
          while (-Not ($dependencyPackage.url -And $uiXamlLatestVersion)) {
            # grabs the latest version number of the Major.Minor build
            try {
              $uiXamlVersionsNugetUrl = 'https://packages.nuget.org/api/v2/package-versions/Microsoft.UI.Xaml'
              $uiXamlLatestVersion = @(Invoke-RestMethod -Uri $uiXamlVersionsNugetUrl -UseBasicParsing)[0] | Where-Object { $_ -like "$($dependencyPackage.version)*" } | Select-Object -Last 1
              $dependencyPackage.url = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/' + $uiXamlLatestVersion
            } catch {
              $dependencyPackage.url = $Null
              Start-Sleep -Seconds $loopDelay
            }
          }
          $dependencyPackage.fileName = 'microsoft.ui.xaml.' + $uiXamlLatestVersion + '.nupkg'
        } elseif ($packageElement.Name -like "Microsoft.VCLibs*UWPDesktop") {
          $dependencyPackage = $wingetDependencies.vcLibs
          $dependencyPackage.version = ([System.Version]$packageElement.MinVersion).Major
          $dependencyPackage.fileName = "Microsoft.VCLibs.${osArch}." + $dependencyPackage.version + '.00.Desktop.appx'
          $dependencyPackage.url = 'https://aka.ms/' + $dependencyPackage.fileName
        } else {
          Write-Warning "Unexpected new dependency found for WinGet: $($packageElement.Name))"
        }

        # if we have a known dependency, download and work on them if needed
        $dependencyPackage.name = $packageElement.Name
        if ($dependencyPackage) {
          $dependencyPackagePreinstalledList = $Null
          # only re-register newest dependency if we have an equal or newer version already installed (don't try to download package)
          $dependencyPackagePreinstalledCheckList = @(
            $appxPackagesAllUsers | Where-Object { $_.Name -eq $dependencyPackage.name} | Where-Object {
              [System.Version]($_.Version) -ge [System.Version]($packageElement.MinVersion)
            }
          )
          # only grabs the packages that match the highest version found, avoids issues with architecture guessing
          if ($dependencyPackagePreinstalledCheckList) {
            $dependencyPackagePreinstalledHighestVersion = $dependencyPackagePreinstalledCheckList | Sort-Object -Property Version | Select-Object -Last 1 -ExpandProperty Version
            $dependencyPackagePreinstalledList = @(
              $dependencyPackagePreinstalledCheckList | Where-Object {
                [System.Version]$_.Version -eq $dependencyPackagePreinstalledHighestVersion
              }
            )
          }

          # sometimes may have more than one architecture of the package that needs to be registered
          if ($dependencyPackagePreinstalledList) {
            for ($archIndex = 0; $archIndex -lt $dependencyPackagePreinstalledList.length; $archIndex++) {
              $dependencyPackagePreinstalled = $dependencyPackagePreinstalledList[$archIndex]
              $dependencyArch = $dependencyPackagePreinstalled.Architecture
              Write-Host "Registering an ${dependencyArch} dependency for WinGet...`n"
              $registeredDependency = $True
              try {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($dependencyPackagePreinstalled.InstallLocation)\AppxManifest.xml"
              } catch {
                $registeredDependency = $False
              }
              if ($registeredDependency) {
                $dependencyPackage.preinstalled = $True
                Write-Host "Successfully registered an ${dependencyArch} dependency for WinGet.`n"
              } else {
                Write-Warning "Failed to register an ${dependencyArch} dependency for WinGet. (`"$($dependencyPackage.name)`")"
                Write-Host '' # Makes log look better
              }
            }
          } else {
            # try to download dependency
            $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.fileName
            Write-Host "Downloading a dependency for WinGet...`n"
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
            while ((Invoke-WebRequest -Uri $dependencyPackage.url -OutFile $dependencyPackage.file -UseBasicParsing -PassThru).StatusCode -ne 200) {
              # need to loop until dependency package is downloaded, or we timeout
              Start-Sleep -Seconds $loopDelay
              $dependencyPackageDownloadTime += $loopDelay
            }
            $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
  
            # need to see if package is uiXaml, if so, extract dependency needed
            $packageIsUiXaml = ($dependencyPackage -eq $wingetDependencies.uiXaml) -And $dependencyPackage.file
            $successMsg = @("Successfully downloaded a ", "dependency for Winget.`n")
            if ($packageIsUiXaml) {
              Write-Host "$($successMsg -Join 'source file containing a ')"
  
              Write-Host "Extracting dependency, from downloaded source file, for WinGet...`n"
              $uiXamlNupkg = $dependencyPackage.file
              $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.name
              $uiXamlNupkgZip = $Null
              try {
                $uiXamlNupkgZip = [IO.Compression.ZipFile]::OpenRead($uiXamlNupkg)
                $uiXamlNupkgZipAppx = $uiXamlNupkgZip.Entries | Where-Object { $_.FullName -like "*/${osArch}/*/$($dependencyPackage.name).appx" }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($uiXamlNupkgZipAppx, $dependencyPackage.file, $true)
              } catch {
                $dependencyPackage.file = $Null
              }
              if ($dependencyPackage.file) {
                Write-Host "Successfully extracted dependency, from downloaded source file, for WinGet.`n"
              } else {
                Write-Warning "Failed to extract dependency, from downloaded source file, for WinGet. (`"$($dependencyPackage.name)`")"
                Write-Host '' # Makes log look better
              }
              if ($uiXamlNupkgZip) { $uiXamlNupkgZip.Dispose() }
              Remove-Item -Path $uiXamlNupkgZip -Force -ErrorAction SilentlyContinue
            } else {
              Write-Host "$($successMsg -Join '')"
            }
            if ($packageIsUiXaml -And (-Not $dependencyPackage.file)) { throw 'extracting dependency failed' }
          }
        }
      }
    } catch {
      $wingetDependencies.uiXaml = $False
      $wingetDependencies.vcLibs = $False
      if ($wingetPackageZip) { $wingetPackageZip.Dispose() }
      if ($appManifestReader) { $appManifestReader.Close() }
      if ($appManifestStream) { $appManifestStream.Close() }
      if ($appInstallerMsixZip) { $appInstallerMsixZip.Dispose() }
      Write-Error "Failed to check dependencies for WinGet."
      return $FAILED.DEPENDENCIES_CHECK
    }

    # install WinGet (updates Desktop App Installer) with any missing dependencies prior
    Write-Host "Installing WinGet...`n"
    $DesktopAppInstallerRunning = $False
    do {

      Start-Sleep -Seconds $appxInstallDelay
    } while ($DesktopAppInstallerRunning)
    $wingetInstalled = $True
    try {
      $dependencyFiles = @()
      if ($wingetDependencies.vcLibs -And $wingetDependencies.vcLibs.file) { $dependencyFiles += , ($wingetDependencies.vcLibs.file) }
      if ($wingetDependencies.uiXaml -And $wingetDependencies.uiXaml.file) { $dependencyFiles += , ($wingetDependencies.uiXaml.file) }
      $addPackageCommand = 'Add-AppxPackage -Path "' + $tempWingetPackage + '" -ForceTargetApplicationShutdown'
      if ($dependencyFiles) { $addPackageCommand += ' -DependencyPath "' + "$($dependencyFiles -Join '","')" + '"' }
      Invoke-Expression $addPackageCommand
      # need to wait a moment to allow install to register with Windows
      Start-Sleep -Seconds $appxInstallDelay
    } catch {
      $wingetInstalled = $False
    }
    # delete left over files no longer needed
    if ($dependencyFiles) { $dependencyFiles | ForEach-Object { Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue } }
    Remove-Item -Path $tempWingetPackage -Force -ErrorAction SilentlyContinue
    $result = 0
    if ($wingetInstalled -And $(Test-WinGet)) {
      Write-Host "WinGet successfully installed.`n"
    } else {
      Write-Error = "WinGet failed to install."
      $result = $FAILED.INSTALL
    }
    return $result
  } else {
    # special return of results, if a working version of WinGet is already installed
    Write-Host "WinGet is already installed.`n"
    return 0
  }
}

# strips progress spinner/blocks from WinGet outputs
# code via https://github.com/microsoft/winget-cli/issues/2582#issuecomment-1945481998
function Strip-Progress {
  param(
      [ScriptBlock]$ScriptBlock
  )

  # Regex pattern to match spinner characters and progress bar patterns
  $progressPattern = 'Γû[Æê]|^\s+[-\\|/]\s+$'

  # Corrected regex pattern for size formatting, ensuring proper capture groups are utilized
  $sizePattern = '(\d+(\.\d{1,2})?)\s+(B|KB|MB|GB|TB|PB) /\s+(\d+(\.\d{1,2})?)\s+(B|KB|MB|GB|TB|PB)'

  $previousLineWasEmpty = $false # Track if the previous line was empty

  & $ScriptBlock 2>&1 | ForEach-Object {
      if ($_ -is [System.Management.Automation.ErrorRecord]) {
          "ERROR: $($_.Exception.Message)"
      } elseif ($_ -match '^\s*$') {
          if (-not $previousLineWasEmpty) {
              Write-Output ""
              $previousLineWasEmpty = $true
          }
      } else {
          $line = $_ -replace $progressPattern, '' -replace $sizePattern, '$1 $3 / $4 $6'
          if (-not [string]::IsNullOrWhiteSpace($line)) {
              $previousLineWasEmpty = $false
              $line
          }
      }
  }
}

# MAIN

# Current user can't have the same username local admin to be setup, because of deletions
$isBuiltInAdmin = $False
if ($localAdminUser -eq $currentUser) {
  Write-Warning "Can't use the same username for local admin, as the currently logged in user!"
  Write-Output "Please use a different username for local admin, or create a new temporary admin user, and delete the currently logged in profile/data afterwards." 
  Write-Output '' # Makes log look better
  exit 1
} elseif ("Administrator" -eq $currentUser) {
  # Current user could be logged into the built-in Administrator account, but data/account shouldn't be deleted,
  # and a warning about turning off the admin account later should be given
  $isBuiltInAdmin = $True
  # Prompt before continuing
  $title = 'You are running this script from the built-in Administrator account, please advise that this might have unintended affects if ran from this account.'
  $question = 'Are you sure you want to proceed?'
  $choices = '&Yes', '&No'
  $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
  if ($decision -eq 0) {
    Clear-Host # no need to keep this information on screen
  } else {
    exit 0 # user chose to exit from script
  }
}

# Prevent computer from sleeping: code modified via https://gist.github.com/CMCDragonkai/bf8e8b7553c48e4f65124bc6f41769eb
$disabledSleep = $True
$steCode = @'
[DllImport("kernel32.dll", CharSet = CharSet.Auto,SetLastError = true)]
public static extern void SetThreadExecutionState(uint esFlags);
'@
$ste = Add-Type -MemberDefinition $steCode -Name System -Namespace Win32 -PassThru
# Requests that the other EXECUTION_STATE flags set remain in effect until
# SetThreadExecutionState is called again with the ES_CONTINUOUS flag set and
# one of the other EXECUTION_STATE flags cleared.
$ES_CONTINUOUS = [uint32]"0x80000000"
$ES_DISPLAY_REQUIRED = [uint32]"0x00000002"
$setSleep = @{
  disable = $ES_CONTINUOUS -bor $ES_DISPLAY_REQUIRED
  enable = $ES_CONTINUOUS
}
$changeSleepSettings = {
  param($setting)
  #  scriptblock to change sleep state
  $testEnabling = $setSleep.enable -eq $setting
  $stateChange = if ($testEnabling) {
    @{
      action = 'Enabling'
      fail = 'enable'
      success = 'enabled'
    }
  } else {
    @{
      action = 'Disabling'
      fail = 'disable'
      success = 'disabled'
    }
  }
  Write-Output "$($stateChange.action) default sleep settings temporarily..."
  Write-Output '' # Makes log look better
  try {
    $ste::SetThreadExecutionState($setting)
    Write-Output "Successfully $($stateChange.success) default sleep settings."
    $disabledSleep = $testEnabling
  } catch {
    Write-Warning "Failed to $($stateChange.fail) default sleep settings."
    $disabledSleep = -Not $testEnabling
  }
  Write-Output '' # Makes log look better
}
Invoke-Command -ScriptBlock $changeSleepSettings -ArgumentList $setSleep.disable
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
  # Revert changed sleep settings: code modified via https://gist.github.com/CMCDragonkai/bf8e8b7553c48e4f65124bc6f41769eb
  Invoke-Command -ScriptBlock $changeSleepSettings -ArgumentList $setSleep.enable
} -SupportEvent

# Sync time and set timezone to automatic (uses https://time.is/ for time)
# - Note: need to grab a user agent, otherwise website will shut us out for webscraping.
Write-Output "Setting timezone to automatic and syncing time..."
Write-Output '' # Makes log look better
$setTimezone = Set-TimeZone $timezone -PassThru
$regSetTzautoupdate = Set-ItemProperty -Path $regTzautoupdate -Name "Start" -Value 3 -Type Dword -PassThru -Force
$userAgentStringsURL = "https://jnrbsn.github.io/user-agents/user-agents.json"
$UserAgent = $null
$PreviousProgressPreference = $ProgressPreference
$ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
while (-Not $UserAgent) {
  # need to loop until user agent string is pulled from URL
  $getUserAgentStrings = Invoke-WebRequest -Uri $userAgentStringsURL -UseBasicParsing
  if ($getUserAgentStrings.StatusCode -eq 200) {
    $UserAgent = ($getUserAgentStrings.Content | ConvertFrom-Json)[0]
  } else {
    Start-Sleep -Seconds $loopDelay
  }
}
$timeIsURL = "https://time.is/"
$TimeHTML = $null
while (-Not $TimeHTML) {
  # need to loop until current time is pulled from URL
  $getTimeHTML = Invoke-WebRequest -Uri $timeIsURL -UserAgent $UserAgent -UseBasicParsing
  if ($getTimeHTML.StatusCode -eq 200) {
    $TimeHTML = $getTimeHTML.Content
  } else {
    Start-Sleep -Seconds $loopDelay
  }
}
$ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
$RegexClock = [Regex]::new('(?<=<time id="clock">).*(?=</time>)')
$MatchClock = $RegexClock.Match($TimeHTML)
$RegexTime = [Regex]::new('.*(?=<span)')
$MatchTime = $RegexTime.Match($MatchClock.value)
$RegexAMPM = [Regex]::new('(?<=>).*(?=<)')
$MatchAMPM = $RegexAMPM.Match($MatchClock.value)
$setDate = $null
if ($MatchClock.Success -And $MatchTime.Success -And $MatchAMPM.Success) {
  $NewTime = $MatchTime.value + $MatchAMPM.value
  $NewDate = Get-Date $NewTime
  $setDate = Set-Date $NewDate
}
if ($setTimezone -And $regSetTzautoupdate -And $setDate) {
  Write-Output "Successfully set timezone and synced time."
} else {
  Write-Warning "Failed to set timezone and sync time."
}
Write-Output '' # Makes log look better

# Reset internet connection (fixes any issues due to date change)
Write-Output "Resetting network connections and setting computer to be discoverable..."
Write-Output '' # Makes log look better
$networkAdapterConfigs = Get-WmiObject -List | Where-Object { $_.Name -eq "Win32_NetworkAdapterConfiguration" }
$releaseDHCP = $networkAdapterConfigs.InvokeMethod("ReleaseDHCPLeaseAll", $null)
$renewDHCP = $networkAdapterConfigs.InvokeMethod("RenewDHCPLeaseAll", $null)
if (-Not $isWDAG) {
  Clear-DnsClientCache
  Register-DnsClient
}
$internetReconnected = $False
while (-Not $internetReconnected) {
  $internetReconnected = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"
  Start-Sleep -Seconds $loopDelay
}
$setNetworksToPrivate = $True
$networkProfiles = Get-NetConnectionProfile | 
Where-Object { (($_.IPv4Connectivity -eq "Internet") -Or ($_.IPv6Connectivity -eq "Internet")) -And $_.NetworkCategory -eq "Public" }
for ($i = 0; $i -lt $networkProfiles.length; $i++) {
  try {
    Set-NetConnectionProfile -Name $_.name -NetworkCategory Private
  } catch {
    $setNetworksToPrivate = $False
  }
}
if ((0 -eq $releaseDHCP) -And (0 -eq $renewDHCP) -And $internetReconnected -And $setNetworksToPrivate) {
  Write-Host "Successfully reset network connections and set computer to be discoverable."
} else {
  Write-Warning "Failed to reset network connections and set computer to be discoverable, ignoring."
}
Write-Output '' # Makes log look better

# Loop until valid domain admin user credentials are used
[pscredential]$credentials = $null
$validDomainAdminUser = $False
$tempDriveLetter = 'Z'
do {
  if ($null -ne $credentials) {
    Write-Output "The user name or password is incorrect, please try again."
    Write-Output '' # Makes log look better
  }
  Write-Output "Validating the domain admin user credentials..."
  Write-Output '' # Makes log look better
  $tempCredentials = Get-Credential -Credential $null
  $tempUserName = $tempCredentials.username
  $tempPassword = $tempCredentials.password
  if (-Not($tempUserName.StartsWith("${shortDomainName}\") -Or $tempUserName.EndsWith("@${domainName}"))) {
    $tempUserName = $shortDomainName + '\' + $tempUserName
  }
  $credentials = New-Object System.Management.Automation.PSCredential($tempUserName, $tempPassword)
  $validDomainAdminUser = New-PSDrive -Name $tempDriveLetter -PSProvider FileSystem -Root $domainAdminServerShare -Credential $credentials -ErrorAction SilentlyContinue
  Remove-PSDrive -Name $tempDriveLetter -ErrorAction SilentlyContinue
} while (-Not $validDomainAdminUser)
Write-Output "Domain admin user credentials confirmed."
Write-Output '' # Makes log look better

# Set computer owner/org info
Write-Output "Setting device information..."
Write-Output '' # Makes log look better
$regSetOwner = Set-ItemProperty -Path $regCurrentVersion -Name "RegisteredOwner" -Value $RegisteredOwner -Type String -PassThru -Force
$regSetOrganization = Set-ItemProperty -Path $regCurrentVersion -Name "RegisteredOrganization" -Value $RegisteredOrganization -Type String -PassThru -Force
if ($regSetOwner -And $regSetOrganization) {
  Write-Output "Successfully set the device information."
} else {
  Write-Warning "Failed to set the device information."
}
Write-Output '' # Makes log look better

# Force the Microsoft Store to check for and install updates
# NOTE: Not useful, since this only affects the currently logged in user (which gets deleted anyways)
#       and, major updates already include updated versions of the provisioned store apps
<# Write-Output "Attempting to force the Microsoft Store to check for app updates..."
Write-Output '' # Makes log look better
$appActionDelay = 2 # seconds
Start-Process 'explorer.exe' -ArgumentList "shell:AppsFolder\Microsoft.WindowsStore_8wekyb3d8bbwe!App"
while (-Not (Get-Process 'WinStore.App' -ErrorAction SilentlyContinue)) {
  # wait for Microsoft Store to open before attempting to close it
  Start-Sleep -Seconds $loopDelay
}
Start-Sleep -Seconds $appActionDelay
$wshell = New-Object -ComObject wscript.shell
$wshell.AppActivate("Microsoft Store") | Out-Null
$wshell.SendKeys("% ")
$wshell.SendKeys("% ")
Start-Sleep -Seconds $appActionDelay
$wshell.SendKeys("%{F4}") # Close the store after it's been opened once, so that it can be accessed later to start app updates
Start-Sleep -Seconds $appActionDelay
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($wshell) | Out-Null
$forceStoreAppsUpdates = Get-CimInstance -Namespace 'root\cimv2\mdm\dmmap' -ClassName 'MDM_EnterpriseModernAppManagement_AppManagement01' | Invoke-CimMethod -MethodName UpdateScanMethod
if (0 -eq $forceStoreAppsUpdates.ReturnValue) {
  Write-Output "Successfully forced the Microsoft Store to check for updates."
} else {
  Write-Warning "Failed to force the Microsoft Store to check for updates."
}
Write-Output '' # Makes log look better #>

# Attempt automatic updates without rebooting (reboot happens at end of script)
# - Windows Update Agent (WUA) API: https://learn.microsoft.com/en-us/windows/win32/wua_sdk/portal-client
# - Note: no ComObjects need to be manually disposed, since Microsoft already handles it with the API
if (-Not $isWDGA) { # online Windows Updates are not possible in WDGA
  Write-Output "Making sure Windows Update Agent is running..."
  Write-Output '' # Makes log look better
  Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue # prevent issues by resetting WUA
  Remove-Item $regWindowsUpdate -Recurse -Force -ErrorAction SilentlyContinue
  $windowsUpdateService = Start-Service -Name wuauserv -PassThru -ErrorAction SilentlyContinue
  while ($windowsUpdateService.Status -ne 'Running') {
    # wait for Windows Update Agent to start
    Start-Sleep -Seconds $loopDelay
  }
  Write-Output "Windows Update Agent is running."
  Write-Output '' # Makes log look better
  $attemptUpdates = $True
  $updateAttempt = 1
  while ($attemptUpdates) {
    # Need to loop attempts until either succeeds with no errors, or until Windows appears already updated, to avoid breaking Dell Command Update later on
    Write-Output "$(if ($updateAttempt -gt 1) {"Attempt ${updateAttempt}: "})Searching for Windows updates..."
    Write-Output '' # Makes log look better
    $ResultCodesInt = @{ SUCCEEDED = 2 ; SUCCEEDED_WITH_ERRORS = 3 ; FAILED = 4 ; ABORTED = 5 }
    $ResultCodesIntArray = @($ResultCodesInt.Values)
    $ResultCodesIntArraySucceededOnly = @($ResultCodesInt.SUCCEEDED,$ResultCodesInt.SUCCEEDED_WITH_ERRORS)
    $ResultCodesString = @{
      ($ResultCodesInt.SUCCEEDED) = 'succeeded'
      ($ResultCodesInt.SUCCEEDED_WITH_ERRORS)  = 'succeeded with errors'
      ($ResultCodesInt.FAILED)  = 'failed'
      ($ResultCodesInt.ABORTED)  = 'aborted'
    }
    # get all updates that normally come from from auto updates (no optional updates)
    $Criteria = "IsInstalled=0 and IsHidden=0 and AutoSelectOnWebSites=1" 
    $MicrosoftUpdateSession = New-Object -ComObject 'Microsoft.Update.Session'
    $UpdateSearcher = $MicrosoftUpdateSession.CreateUpdateSearcher()
    $SearcherResults = $UpdateSearcher.Search($Criteria)
    $ResultsUpdates = $SearcherResults.Updates
    $resultMsg = "Search for Windows updates $(
      if ($ResultCodesIntArray -contains $SearcherResults.ResultCode)
      { $ResultCodesString[$SearcherResults.ResultCode] } else { 'stopped, result unknown' }
    )."
    if ($ResultsUpdates -And ($SearcherResults.ResultCode -eq $ResultCodesInt.SUCCEEDED) -And (0 -eq $ResultsUpdates.Count)) {
      $attemptUpdates = $False
      $resultMsg = "Windows is already up-to-date."
    } elseif ((-Not $ResultsUpdates) -Or (0 -gt $ResultsUpdates.Count)) {
      $resultMsg = "There was a problem searching for updates."
    }
    Switch ($SearcherResults.ResultCode) {
      ($ResultCodesInt.SUCCEEDED) { Write-Output $resultMsg }
      Default { Write-Warning $resultMsg }
    }
    Write-Output '' # Makes log look better
    if ($ResultsUpdates -And ($ResultsUpdates.Count -gt 0)) {
      # found updates to install, attempt to download
      Write-Output "Downloading Windows updates..."
      Write-Output '' # Makes log look better
      $UpdateDownloader = $MicrosoftUpdateSession.CreateUpdateDownloader()
      $UpdateDownloader.Updates = $ResultsUpdates
      $DownloaderResults = $UpdateDownloader.Download()
      $resultMsg = "Download of Windows updates $(
        if ($ResultCodesIntArray -contains $DownloaderResults.ResultCode)
        { $ResultCodesString[$DownloaderResults.ResultCode] } else { 'stopped, result unknown' }
      )."
      Switch ($DownloaderResults.ResultCode) {
        ($ResultCodesInt.SUCCEEDED) { Write-Output $resultMsg }
        Default { Write-Warning $resultMsg }
      }
      Write-Output '' # Makes log look better
      if ($ResultCodesIntArraySucceededOnly -contains $DownloaderResults.ResultCode) {
        # downloaded updates, attempt to install
        Write-Output "Installing Windows updates..."
        Write-Output '' # Makes log look better
        $UpdateInstaller = $MicrosoftUpdateSession.CreateUpdateInstaller()
        $UpdateInstaller.Updates = $ResultsUpdates
        $InstallerResults = $UpdateInstaller.Install()
        $resultMsg = "Install of Windows updates $(
          if ($ResultCodesIntArray -contains $InstallerResults.ResultCode) {
            $ResultCodesString[$InstallerResults.ResultCode] + $(if ($InstallerResults.rebootRequired) {
              ', but requires a reboot'
            })
          } else { 'stopped, result unknown' }
        )."
        Switch ($InstallerResults.ResultCode) {
          ($ResultCodesInt.SUCCEEDED) { Write-Output $resultMsg }
          # 'succeed with error' will also trigger the warning output, instead of the regular output
          Default { Write-Warning $resultMsg }
        }
        Write-Output '' # Makes log look better
        $attemptUpdates = ($ResultCodesIntArraySucceededOnly -notcontains $InstallerResults.ResultCode)
      }
    }
    $updateAttempt++
    # Unfortunately, below is needed because some Windows versions break update API all together
    # (constantly searches and fails to install on 24H2 builds of Windows 10/11)
    if ($attemptUpdates) { $attemptUpdates = $maxRetries -ne $updateAttempt }
  }
}

# Update all apps (not from the Microsoft Store)
if ($(Install-WinGet) -eq 0) { # installs/updates WinGet if needed
  Write-Output "Attempting to update all apps (not from the Microsoft Store)..."
  Write-Output '' # Makes log look better
  $wingetUpgradePSI = New-object System.Diagnostics.ProcessStartInfo
  $wingetUpgradePSI.CreateNoWindow = $true
  $wingetUpgradePSI.UseShellExecute = $false
  $wingetUpgradePSI.RedirectStandardOutput = $true
  $wingetUpgradePSI.RedirectStandardError = $false
  $wingetUpgradePSI.FileName = 'winget.exe'
  $wingetUpgradePSI.Arguments = @('upgrade --silent --all --accept-source-agreements')
  $wingetUpgradeProcess = New-Object System.Diagnostics.Process
  $wingetUpgradeProcess.StartInfo = $wingetUpgradePSI
  # if not running in Windows Terminal, need to change encoding to UTF-8 temporarily for winget
  $oldOutputEncoding = $OutputEncoding; $oldConsoleEncoding = [Console]::OutputEncoding
  if (-Not $runningInWindowsTerminal) {
    $OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.Utf8Encoding
  }
  [void]$wingetUpgradeProcess.Start()
  $wingetOutput = $wingetUpgradeProcess.StandardOutput.ReadToEnd()
  $wingetUpgradeProcess.WaitForExit()
  Strip-Progress -ScriptBlock {
    # show output after so that we at least know what went on
    Write-Output $wingetOutput
  }
  # revert any encoding changes we made from earlier if needed
  if (-Not $runningInWindowsTerminal) {
    $OutputEncoding = $oldOutputEncoding; [Console]::OutputEncoding = $oldConsoleEncoding
  }
  if (0 -eq $wingetUpgradeProcess.ExitCode) {
    Write-Output "Successfully updated all apps (not from the Microsoft Store)."
  } else {
    # Can't use exit code to determine different issues with upgrade, see https://github.com/microsoft/winget-cli/discussions/3338
    [String[]]$wingetExceptionList = @()
    if ($wingetOutput.Contains('Another version of this application is already installed.') -Or $wingetOutput.Contains('A higher version of this application is already installed.')) {
      $wingetExceptionList += "didn't update some apps that were already up-to-date"
    }
    if ($wingetOutput.Contains('Restart your PC to finish installation.')) {
      $wingetExceptionList += "some apps require a reboot to update"
    }
    if (0 -eq $wingetExceptionList.length) {
      Write-Warning "Failed to update all apps (not from the Microsoft Store)."
    } else {
      $wingetExceptionMessage = "$(
        if ($wingetOutput.Contains('An unexpected error occurred while executing the command:')) { 'Partially' } else { 'Successfully' }
      ) updated most apps (not from the Microsoft Store), but " + ($wingetExceptionList -Join ', ') + '.'
      Write-Warning $wingetExceptionMessage
    }
  }
} else {
  Write-Warning "Failed to install WinGet, skipping attempt to update all apps (not from the Microsoft Store)."
}
Write-Output '' # Makes log look better

# Suspend BitLocker (if needed, before updates)
$bitLockerVolume = (Get-BitLockerVolume | Where-Object { $_.VolumeType -eq 'OperatingSystem' })
if ($bitLockerVolume -And ($bitLockerVolume.VolumeStatus -eq 'EncryptionInProgress')) {
  Write-Output "Attempting to suspend BitLocker..."
  Write-Output '' # Makes log look better
  $RebootCount = 2 # once for the first time, second for after the updates from after reboot
  if (Suspend-BitLocker -MountPoint "$($bitLockerVolume.MountPoint)" -RebootCount $RebootCount) {
    Write-Output "Successfully suspended BitLocker."
  } else {
    Write-Warning "Failed to suspend BitLocker."
  }
  Write-Output '' # Makes log look better
}

# Run Dell Command Update (get it up-to-date) w/ reboot disabled (done at the end)
if ($isDell) {
  if ((-Not (Test-Path -Path $dcuCliExe -PathType Leaf)) -And (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
    # Need to install Dell Command Update first
    Write-Output "Attempting to install Dell Command Update..."
    Write-Output '' # Makes log look better
    $installDellCommandUpdate = Start-Process 'winget.exe' -ArgumentList 'install -h --id "Dell.CommandUpdate.Universal" --accept-package-agreements --accept-source-agreements' -NoNewWindow -PassThru -Wait
    if (0 -eq $installDellCommandUpdate.ExitCode) {
      Write-Output "Successfully installed Dell Command Update.$(if ($dcuRebootRequired) { " (reboot required)" } else { '' })"
    } else {
      Write-Warning "Failed to install Dell Command Update."
    }
    Write-Output '' # Makes log look better
  }
  if (Test-Path -Path $dcuCliExe -PathType Leaf) {
    Write-Output "Attempting to set Dell Command Update settings..."
    $dcuConfig = Start-Process -FilePath $dcuCliExe -ArgumentList $dcuConfigureArgs -NoNewWindow -PassThru -Wait
    Write-Output '' # Makes log look better
    # 0 = set settings successfully
    if (0 -eq $dcuConfig.ExitCode) {
      Write-Output "Successfully set Dell Command Update settings."
    } else {
      Write-Warning "Failed to set Dell Command Update settings."
    }
    Write-Output '' # Makes log look better
    Write-Output "Attempting to update all Dell drivers/firmwares directly from manufacturer..."
    $dcuUpdate = Start-Process -FilePath $dcuCliExe -ArgumentList $dcuApplyArgs -NoNewWindow -PassThru -Wait
    $dcuRebootRequired = (1 -eq $dcuUpdate.ExitCode) -Or (5 -eq $dcuUpdate.ExitCode)
    # 0 = updated, 500 = no updates were available, a.k.a. up-to-date
    Write-Output '' # Makes log look better
    if ((0 -eq $dcuUpdate.ExitCode) -Or (500 -eq $dcuUpdate.ExitCode)) {
      Write-Output "Successfully ran Dell Command Update to update Dell drivers/firmwares."
    } elseif ($dcuRebootRequired) {
      Write-Warning "Likely already ran Dell Command Update to update Dell drivers/firmwares, as it's pending a reboot."
    } else {
      Write-Warning "Failed to run Dell Command Update to update Dell drivers/firmwares."
    }
  } else {
    Write-Output '' # Makes log look better
    Write-Warning "Dell Command Update is missing, skipping."
  }
  Write-Output '' # Makes log look better
}

# Install additional applications
Write-Output "Checking application install list selection..."
Write-Output '' # Makes log look better
$default = "Default"
$none = "None"
[string[]]$appsToInstall = @()
$appLists = (Get-ChildItem -Path $installers -File -Force | Where-Object { $_.name -match "^((?!${baseAppListFilename}).)*\.txt$" })
$appListsNames = @($appLists.name)
$appListsNames += $default, $none
if ($SelectAppList.IsPresent) {
  if (-Not $appListsNames.contains($SelectAppList)) {
    $SelectAppList = $null
    Write-Warning "An invalid app list was choosen in parameters."
    Write-Output '' # Makes log look better
  }
}
if (-Not $SelectAppList) {
  $title = 'App List Selection'
  $question = 'Please pick an app list...'
  $choices = $appListsNames | ForEach-Object { '&' + $_ }
  $decision = $Host.UI.PromptForChoice($title, $question, $choices, ($choices.length - 1))
  $SelectAppList = $appLists[$decision]
}
if ($SelectAppList -ine $none) {
  # add apps from the default (base) app list
  $baseApps = if (Test-Path -Path $baseAppList -PathType Leaf) { Get-Content $baseAppList }
  if ($baseApps) {
    # make sure single app entries are handled
    if ($baseApps[0].length -eq 1) { $baseApps = @($baseApps) }
    $appsToInstall += $baseApps
  }

  if ($SelectAppList -ine $default) {
    # add apps from the selected (chosen) app list
    $appListChosen = ($appLists | Where-Object { $_.name -eq $SelectAppList })
    $additionalApps = Get-Content $appListChosen.fullname
    if ($additionalApps) {
      # make sure single app entries are handled
      if ($additionalApps[0].length -eq 1) { $additionalApps = @($additionalApps) }
      $appsToInstall += $additionalApps
    }
  }
}
$appFolders = Get-ChildItem -Path $installers -Directory -Force
if ($appsToInstall -And $appFolders) {
  Write-Output "Application install list selected: ${SelectAppList}"
  Write-Output '' # Makes log look better
  # Sort and remove duplicates
  $appsToInstall = $appsToInstall | Sort-Object -Unique
  # For each app, if in list of to install, then start installing app
  Write-Output '' # Makes log look better
  $appFolders | ForEach-Object {
    if ($appsToInstall.contains($_.name)) {
      $appsInstallPSI = New-Object System.Diagnostics.ProcessStartInfo
      $appsInstallPSI.CreateNoWindow = $true
      $appsInstallPSI.UseShellExecute = $false
      $appsInstallPSI.RedirectStandardOutput = $true
      $appsInstallPSI.RedirectStandardError = $true
      $appsInstallPSI.FileName = 'powershell.exe'
      $appsInstallPSI.WorkingDirectory = $_.fullname
      $appsInstallPSI.Arguments = @("-File .\install.ps1")
      $appsInstallProcess = New-Object System.Diagnostics.Process
      $appsInstallProcess.StartInfo = $appsInstallPSI
      [void]$appsInstallProcess.Start()
      $appsInstallProcess.StandardOutput.ReadToEnd()
      $appsInstallProcess.StandardError.ReadToEnd()
      $appsInstallProcess.WaitForExit()
    }
  }
} else {
  Write-Output "No application install list selected."
}
Write-Output '' # Makes log look better

# Create the local admin account
$createdLocaladmin = $False
$adminGroup = 'Administrators'
Write-Output "Creating the local admin account..."
Write-Output '' # Makes log look better
try {
  $createdLocaladmin = New-LocalUser -Name $localAdminUser -Password $(ConvertTo-SecureString -String $localAdminPass -AsPlainText -Force)
} catch {
  if ($_.Exception -match ".* already exists\.$") {
    Write-Warning "$($_.Exception | Out-String)"
    $createdLocaladmin = $True
  }
}
if ($createdLocaladmin) {
  Write-Output "Successfully created the local admin account."
  Write-Output '' # Makes log look better

  Write-Output "Setting the local admin password to never expire..."
  Write-Output '' # Makes log look better
  $localAdminPassNeverExpire = $True
  Set-LocalUser -Name $localAdminUser -PasswordNeverExpires $True
  try {
    Add-LocalGroupMember -Group $adminGroup -Member $localAdminUser
  } catch {
    if ($_.Exception -match ".* is already a member of group ${adminGroup}\.$") {
      Write-Warning "$($_.Exception | Out-String)"
    } else {
      $localAdminPassNeverExpire = $False
    }
  }
  if ($localAdminPassNeverExpire) {
    Write-Output "Successfully set the local admin password to never expire."
  } else {
    Write-Warning "Failed to set the local admin password to never expire."
  }
  Write-Output '' # Makes log look better
}

# Turn on auto logon to cache domain admin user account once (auto logon is removed later)
Write-Output "Setting the domain admin user to auto logon once on reboot..."
Write-Output '' # Makes log look better
$regSetAutoAdminLogon = Set-ItemProperty -Path $regWinlogon -Name "AutoAdminLogon" -Value "1" -Type String -PassThru -Force
$regSetDefaultUserName = Set-ItemProperty -Path $regWinlogon -Name "DefaultUserName" -Value $credentials.username -Type String -PassThru -Force
$regSetDefaultPassword = Set-ItemProperty -Path $regWinlogon -Name "DefaultPassword" -Value $credentials.GetNetworkCredential().password -Type String -PassThru -Force
$enabledAutoLogon = ($regSetAutoAdminLogon -And $regSetDefaultUserName -And $regSetDefaultPassword)
if ($enabledAutoLogon) {
  Write-Output "Successfully set the domain admin user to auto logon once on reboot."
  Write-Output '' # Makes log look better
  
  # Disable privacy experience prompt on first logon
  Write-Output "Setting the OOBE privacy experience prompt to disabled..."
  Write-Output '' # Makes log look better
  $regCreatedKeyOOBE = New-Item -Path $regMachinePolicies -Name "OOBE" -Force -ErrorAction SilentlyContinue
  if ($regCreatedKeyOOBE) {
    $regSetDisablePrivacyExperience = Set-ItemProperty -Path "${regMachinePolicies}\OOBE" -Name "DisablePrivacyExperience" -Value 1 -Type Dword -PassThru -Force
    if ($regSetDisablePrivacyExperience) {
      Write-Output "Successfully disabled the privacy experience prompt."
    } else {
      Write-Warning "Failed to disable the privacy experience prompt, skipping."
    }
  } else {
    Write-Warning "Failed to create the OOBE path in registry, skipping."
  }
} else {
  Write-Warning "Failed to set the domain admin user to auto logon once on reboot."
}
Write-Output '' # Makes log look better

# Loop until computer is bound to domain, by which then sets the new computer's name and location in AD
$joinedPC = $null
do {
  Write-Output "Binding computer to domain, and setting its new name and OU location..."
  Write-Output '' # Makes log look better
  try {
    $joinedPC = Add-Computer -DomainName $domainName -OUPath $distinguishedAdPathOU -ComputerName $computerName.current -NewName $computerName.new -Credential $credentials -PassThru -ErrorAction Stop
    if ($joinedPC.HasSucceeded) {
      $computerName.current = $joinedPC.ComputerName
      Write-Host "Computer has been bound to the domain successfully."
    }
  } catch {
    if ($_.Exception -notmatch '^The changes will take effect after you restart the computer .*$') {
      $joinedPC = $true
      $computerName.current = $joinedPC.ComputerName
      Write-Output "$($_.Exception | Out-String)"
      Start-Sleep -Seconds $activeDirectoryDelay
    } elseif ($_.Exception -notmatch '^.* because (it is already in that domain|the new name is the same as the current name)\.$') {
      $joinedPC = $False
      Write-Warning "$($_.Exception | Out-String)"
    } else { Start-Sleep -Seconds $loopDelay }
  }
  Write-Output '' # Makes log look better
} while ($Null -eq $joinedPC)

# Loop until a new description is set for the computer on the domain in AD
$ComputerDescription = "Spare ${pcModel} - Staged".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$RootDSE = $null
$RootDSE_Searcher = $null
$ComputerDSE = $null
Write-Output "Changing the description of the computer on the domain..."
Write-Output '' # Makes log look better
do {
  # wait for RootDSE to connect
  try {
    $RootDSE = New-Object DirectoryServices.DirectoryEntry(
      "LDAP://${domainName}",
      $credentials.username,
      $credentials.GetNetworkCredential().password
    ) -ErrorAction Stop
    $RootDSE.RefreshCache()
  } catch {
    $RootDSE = $null
    Start-Sleep -Seconds $loopDelay
  }
} while (-Not $RootDSE.distinguishedName)
do {
  # wait for RootDSE searcher to connect
  try {
    $RootDSE_Searcher = New-Object DirectoryServices.DirectorySearcher($RootDSE) -ErrorAction Stop
  } catch {
    $RootDSE_Searcher = $null
    Start-Sleep -Seconds $loopDelay
  }
} while (-Not $RootDSE_Searcher.SearchRoot.distinguishedName)
do {
  # try searching the RootDSE only for the matching computer
  $RootDSE_Searcher.Filter = "(&(objectCategory=Computer)(CN=$($computerName.current)))"
  try {
    $foundComputer = $RootDSE_Searcher.FindOne()
    if ($foundComputer) {
      $ComputerDSE = $foundComputer.GetDirectoryEntry()
      $ComputerDSE.RefreshCache()
    }
    if ($ComputerDSE) { Break }
  } catch {
    $foundComputer = $null
    Start-Sleep -Seconds $loopDelay
  }
} while ($True)
if ($ComputerDSE -And $ComputerDSE.distinguishedName) {
  # check description of computer
  if ($ComputerDescription -eq $ComputerDSE.description) {
    Write-Output "The computer description is already set, skipping."
  } else {
    # set the computer's new description
    $setDescription = $False
    do {
      try {
        $ComputerDSE.Put('Description', $ComputerDescription)
        $ComputerDSE.SetInfo()
        $ComputerDSE.RefreshCache()
        $setDescription = $ComputerDescription -eq $ComputerDSE.description
      } catch {
        $setDescription = $False
      }
      if (-Not $setDescription) { Start-Sleep -Seconds $activeDirectoryDelay }
    } while (-Not $setDescription)
    Write-Output "Successfully set the description for the computer."
  }
} else {
  $errorSetInfoReason = if ($ComputerDSE -eq $null) {
    "couldn't find computer"
  } else {
    "found computer, but had issues with connection"
  }
  Write-Warning "Failed to set the description for the computer, skipping (${errorSetInfoReason})."
}
Write-Output '' # Makes log look better
if ($RootDSE) {
  # these objects require to be disposed
  if ($ComputerDSE) { $ComputerDSE.Dispose() }
  $RootDSE_Searcher.Dispose()
  $RootDSE.Dispose()
}

# Set a scheduled task to run on demand of the domain admin user (elevated) ...
# - Wait for BitLocker to be done encypting (if needed),
# - Wait for a network connection,
# - Run Check for Dell updates again, as some updates only show up after the first update (only on Dell machines),
# - Lock the computer,
# - Then, delete itself (the scheduled task)
Write-Output "Scheduling final online tasks..."
Write-Output '' # Makes log look better
$taskNameFinalizeOnline = "Prepare_PC_Finalize_Online".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$actionFinalizeOnline = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($( "-c `
  `"& { $(if ($bitLockerVolume) {
    "if ((Get-BitLockerVolume -MountPoint '$($bitLockerVolume.MountPoint)').VolumeStatus -eq 'EncryptionInProgress') { `
      Write-Output 'Waiting for BitLocker encryption to complete...' ; Write-Output '' ; `
      while ((Get-BitLockerVolume -MountPoint '$($bitLockerVolume.MountPoint)').VolumeStatus -eq 'EncryptionInProgress') { Start-Sleep -Seconds ${loopDelay} } } " 
  }) `
  while (-Not ((Get-NetConnectionProfile).IPv4Connectivity -contains 'Internet' `
  -or (Get-NetConnectionProfile).IPv6Connectivity -contains 'Internet')) `
  { Start-Sleep -Seconds ${loopDelay} } ; `
  $(if ($isDell) {
    "Start-Process -FilePath '${dcuCliExe}' -ArgumentList '${dcuApplyArgs}' -NoNewWindow -Wait -ErrorAction SilentlyContinue ; "
  }) `
  Start-Process 'rundll32.exe' -ArgumentList 'user32.dll,LockWorkStation' -NoNewWindow ; `
  Unregister-ScheduledTask -TaskName '${taskNameFinalizeOnline}' -Confirm:`$False `
  }`" -NoProfile -WindowStyle Maximized "
  ).replace("`n", "")).replace("`r", "")
$settingsFinalizeOnline = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility Win8 -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$triggerFinalizeOnline = New-ScheduledTaskTrigger -AtLogon
$principalFinalizeOnline = New-ScheduledTaskPrincipal -UserId $localAdminUser -LogonType Interactive -RunLevel Highest # user id gets changed later
$definitionFinalizeOnline = New-ScheduledTask -Action $actionFinalizeOnline -Settings $settingsFinalizeOnline -Trigger $triggerFinalizeOnline -Principal $principalFinalizeOnline
$taskFinalizeOnline = Register-ScheduledTask -TaskName $taskNameFinalizeOnline -InputObject $definitionFinalizeOnline
if ($null -ne $taskFinalizeOnline) {
  Write-Output "Successfully scheduled the online tasks."
} else {
  Write-Warning "Failed to schedule the online tasks."
}
Write-Output '' # Makes log look better

# Set a scheduled task to run at startup and ...
# - Modify the online scheduled task to run as the user (elevated) then immediately run it,
# - Resume BitLocker encryption (if it was suspended),
# - Turn back on the privacy experience,
# - Turn off auto logon for domain admin user,
# - Delete temp admin user OneDrive tasks + data + account (only if not built-in Administrator),
# - Then, delete itself (the scheduled task)
Write-Output "Scheduling final offline tasks..."
Write-Output '' # Makes log look better
$taskNameFinalizeOffline = "Prepare_PC_Finalize_Offline".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$actionFinalizeOffline = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($( "-c `
  `"& { `$task = Get-ScheduledTask -TaskName '$taskNameFinalizeOnline' ; `
  `$task.Principal.UserId = '$($credentials.username)' ; `
  `$task | Set-ScheduledTask ; `
  `$task | Start-ScheduledTask ; `
  $(if ((Get-BitLockerVolume -MountPoint "$($bitLockerVolume.MountPoint)").ProtectionStatus -eq "Off") {"Resume-BitLocker -MountPoint '$($bitLockerVolume.MountPoint)' ; "} else {''}) `
  Remove-ItemProperty -Path '${regMachinePolicies}\OOBE' -Name 'DisablePrivacyExperience' -Force -ErrorAction SilentlyContinue ; `
  Remove-ItemProperty -Path '${regWinlogon}' -Name 'DefaultPassword' -Force -ErrorAction SilentlyContinue ; `
  Set-ItemProperty -Path '${regWinlogon}' -Name 'AutoAdminLogon' -Value '0' -Type String -Force ; `
  Set-ItemProperty -Path '${regWinlogon}' -Name 'DefaultUserName' -Value '' -Type String -Force ; `
  $(if (-Not $isBuiltInAdmin) {
    "Get-ScheduledTask -TaskName 'OneDrive *$currentUserSID' | Unregister-ScheduledTask -Confirm:`$False ; `
    Get-CimInstance -Class Win32_UserProfile `
    | Where-Object { `$_.LocalPath.split('\')[-1] -eq '${currentUser}' } `
    | Remove-CimInstance ; `
    Remove-LocalUser -Name '${currentUser}' -ErrorAction SilentlyContinue ; "
  }) `
  Unregister-ScheduledTask -TaskName '${taskNameFinalizeOffline}' -Confirm:`$False `
  }`" -NoProfile -WindowStyle Maximized "
  ).replace("`n", "")).replace("`r", "")
$settingsFinalizeOffline = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility Win8 -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$triggerFinalizeOffline = New-ScheduledTaskTrigger -AtLogon
$principalFinalizeOffline = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$definitionFinalizeOffline = New-ScheduledTask -Action $actionFinalizeOffline -Settings $settingsFinalizeOffline -Trigger $triggerFinalizeOffline -Principal $principalFinalizeOffline
$taskFinalizeOffline = Register-ScheduledTask -TaskName $taskNameFinalizeOffline -InputObject $definitionFinalizeOffline
if ($null -ne $taskFinalizeOffline) {
  Write-Output "Successfully scheduled the offline tasks."
} else {
  Write-Warning "Failed to schedule the offline tasks."
}
Write-Output '' # Makes log look better

# Reboot to apply changes
Write-Output "Rebooting..."
Write-Output '' # Makes log look better
Restart-Computer -Force
