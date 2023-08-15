<#
  .SYNOPSIS
  Prepare PC v1.0.0

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

<# Copyright (C) 2023  Andrew Larson (thealiendrew@gmail.com)

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
  $wshell = New-Object -ComObject wscript.shell
  $wshell.AppActivate($PID) | Out-Null
  $wshell.SendKeys("{F11}")
  [System.Runtime.Interopservices.Marshal]::ReleaseComObject($wshell) | Out-Null
}
$logEnabled = $Log.IsPresent
# $SelectAppList is checked later in script

# Only supported on 64-bit
$architecture = (Get-CimInstance Win32_operatingsystem).OSArchitecture
if ($architecture -ne '64-bit') {
  Write-Warning "Not supported for ${architecture} operating systems. Aborting script."
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
  switch ([int]$BatteryStatus) {
    { 2, 6, 7, 8 -contains $_ } {
      # Continue without prompting user
      Out-Null
    }
    { 1, 3, 4, 11 -contains $_ } {
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
    { 5, 9 -contains $_ } {
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

# Check manufacturer (only required for using Dell Command Update on Dell computers)
$manufacturer = (Get-WmiObject -Class Win32_ComputerSystem -Property Manufacturer).Manufacturer
$isDell = $manufacturer -like "Dell*"

# Required Computer Info
$serialnumber = (Get-WMIObject win32_bios).serialnumber
$pcModel = (Get-CimInstance -ClassName Win32_ComputerSystem).Model
$InvalidCharacterReplacement = '~'

# Logging
$scriptName = (Get-Item $PSCommandPath).Basename
$logName = ("${serialnumber}_${pcModel}_${scriptName}.log".replace(' ', '-')).split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$logFile = "${env:SystemDrive}\${logName}"
if ($logEnabled) {
  Start-Transcript -Path $logFile
  Write-Output '' # Makes log look better
}

# Constants

$envTEMP = (Get-Item -LiteralPath $env:TEMP).FullName # Required due to PowerShell bug with shortnames appearing when they shouldn't be
$loopDelay = 1 # second
$appxInstallDelay = 3 # seconds
$domainSyncDelay = 5 # seconds
$resources = "${PSScriptRoot}\resources"
$installers = "${resources}\installers"
$baseAppListFilename = "0-base.txt"
$baseAppList = "${installers}\${baseAppListFilename}"
$currentUser = ((Get-WMIObject -class win32_computersystem).username).split('\')[-1]
$shortDomainName = Get-Content "${resources}\shortDomainName.txt"
$domainName = Get-Content "${resources}\domainName.txt"
$adRootOU = "DC=$(${domainName}.Replace(".",",DC="))"
$mainDomainServerName = Get-Content "${resources}\mainDomainServerName.txt"
$mainDomainServerShareName = Get-Content "${resources}\mainDomainServerShareName.txt"
$mainDomainServerShare = "\\${mainDomainServerName}.${domainName}\${mainDomainServerShareName}"
$localAdminUser = Get-Content "${resources}\localAdminUser.txt"
$localAdminPass = Get-Content "${resources}\localAdminPass.txt"
$adPathFromRootOU = Get-Content "${resources}\adPathFromRootOU.txt"
$adPathArrayFromRootOU = $adPathFromRootOU.split('/') ; [array]::Reverse($adPathArrayFromRootOU)
$adPathOU = "OU=$($adPathArrayFromRootOU -Join ',OU='),${adRootOU}"
$timezone = Get-Content "${resources}\timezone.txt"
$RegisteredOwner = Get-Content "${resources}\RegisteredOwner.txt"
$RegisteredOrganization = Get-Content "${resources}\RegisteredOrganization.txt"
$regHKLM = "HKLM:"
$regLocalMachineSoftware = "${regHKLM}\SOFTWARE"
$regTzautoupdate = "${regHKLM}\SYSTEM\CurrentControlSet\Services\tzautoupdate"
$regCurrentVersion = "${regLocalMachineSoftware}\Microsoft\Windows NT\CurrentVersion"
$regMachinePolicies = "${regLocalMachineSoftware}\Policies\Microsoft\Windows"
$regWinlogon = "${regCurrentVersion}\Winlogon"
$dcuEndPath = "Dell\CommandUpdate\dcu-cli.exe"
$dcuCli = "${env:ProgramFiles}\${dcuEndPath}"
$dcuCli32bit = "${env:ProgramFiles(x86)}\${dcuEndPath}" # required in the case of Dell SupportAssist OS reinstalls
$dcuCliExe = if (Test-Path -Path $dcuCli32bit -PathType Leaf) { $dcuCli32bit } else { $dcuCli }
$dcuArgs = '/applyUpdates' + $(if ($dcuCliExe -eq $dcuCli) { ' -forceUpdate=enable' } else { '' }) + ' -reboot=disable -autoSuspendBitLocker=enable' # if using the universal version, need forceUpdate option

# Current user can't have the same username local admin to be setup, because of deletions
$isBuiltInAdmin = $False
if ($localAdminUser -eq $currentUser) {
  Write-Warning "Can't use the same username for local admin, as the currently logged in user!"
  Write-Output "Please use a different username for local admin, or create a new temporary admin user, and delete the currently logged in profile/data afterwards." 
  Write-Output '' # Makes log look better
  if ($logEnabled) {
    Stop-Transcript # Logging
  }
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
$disabledSleep = $True
Write-Output "Disabling default sleep settings temporarily..."
Write-Output '' # Makes log look better
try {
  $ste::SetThreadExecutionState($ES_CONTINUOUS -bor $ES_DISPLAY_REQUIRED)
} catch {
  $disabledSleep = $False
}
if ($disabledSleep) {
  Write-Output "Successfully disabled default sleep settings."
} else {
  Write-Warning "Failed to disable default sleep settings."
}
Write-Output '' # Makes log look better

# Sync time and set timezone to automatic (uses https://time.is/ for time)
# - Note: need to grab a user agent, otherwise website will shut us out for webscraping.
Write-Output "Setting timezone to automatic and syncing time..."
Write-Output '' # Makes log look better
$setTimezone = Set-TimeZone $timezone -PassThru
$regSetTzautoupdate = Set-ItemProperty -Path $regTzautoupdate -Name "Start" -Value 3 -Type Dword -PassThru -Force
$userAgentStringsURL = "https://jnrbsn.github.io/user-agents/user-agents.json"
$UserAgent = $null
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
Clear-DnsClientCache
Register-DnsClient
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
  $validDomainAdminUser = New-PSDrive -Name $tempDriveLetter -PSProvider FileSystem -Root $mainDomainServerShare -Credential $credentials -ErrorAction SilentlyContinue
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

# Update Windows without rebooting (reboot happens at end of script)
# - Windows Update Agent API: https://learn.microsoft.com/en-us/windows/win32/wua_sdk/portal-client
# - Note: no ComObjects need to be manually disposed, since Microsoft already handles it with the API
$attemptUpdates = $True
$updateAttempt = 0
while ($attemptUpdates) {
  # Need to loop attempts until either succeeds with no errors, or until Windows appear already updated, to avoid breaking Dell Command Update later on
  Write-Output "Attempt $($updateAttempt++; $updateAttempt): Searching for Windows updates..."
  Write-Output '' # Makes log look better
  $ResultCodes = @{0 = 'not started' ; 1 = 'in progress' ; 2 = 'succeeded' ; 3 = 'succeeded with errors' ; 4 = 'failed' ; 5 = 'aborted' }
  $Criteria = "IsInstalled=0 and IsHidden=0 and AutoSelectOnWebSites=1" # get all updates that normally from from auto updates (no optional updates)
  $Searcher = $null
  $SearchResult = $null
  $UpdatesFound = $null
  $SearchSuccess = $True
  try {
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchResult = $Searcher.Search($Criteria)
    $UpdatesFound = $SearchResult.Updates
  } catch {
    $SearchSuccess = $False
  }
  if ($SearchSuccess) {
    if ($UpdatesFound -And (0 -ne $UpdatesFound.Count)) {
      Write-Output "Windows updates were found."
      Write-Output '' # Makes log look better
      Write-Output "Attempting to download Windows updates..."
      Write-Output '' # Makes log look better
      $Session = $null
      $Downloader = $null
      $DownloadResult = $null
      $DownloadSuccess = $True
      try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $UpdatesFound
        $DownloadResult = $Downloader.Download()
      } catch {
        $DownloadSuccess = $False
      }
      if ($DownloadSuccess -And $DownloadResult) {
        Write-Output "Windows updates were downloaded."
        Write-Output '' # Makes log look better
        Write-Output "Attempting to install Windows updates..."
        Write-Output '' # Makes log look better
        $Installer = $null
        $InstallerResult = $null
        $UpdatesInstalled = $True
        try {
          $Installer = New-Object -ComObject Microsoft.Update.Installer
          $Installer.Updates = $UpdatesFound
          $InstallerResult = $Installer.Install()
        } catch {
          $UpdatesInstalled = $False
        }
        $reason = $ResultCodes[[int]$InstallerResult.ResultCode]
        if ($UpdatesInstalled) {
          if ($InstallerResult.ResultCode -eq 2) {
            $attemptUpdates = $False
            Write-Output "Successfully installed Windows updates."
          } else {
            Write-Warning "Successfully installed Windows updates (result: ${reason})."
          }
        } else {
          Write-Warning "Failed to install Windows updates (install: '${reason}'), skipping."
        }
      } else {
        $reason = $ResultCodes[[int]$DownloadResult.ResultCode]
        Write-Warning "Failed to install Windows updates (download: '${reason}'), skipping."
      }
    } else {
      $attemptUpdates = $False
      Write-Output "Windows is already up-to-date."
    }
  } else {
    $reason = $ResultCodes[[int]$SearchResult.ResultCode]
    Write-Warning "Failed to install Windows updates (search: '${reason}'), skipping."
  }
  Write-Output '' # Makes log look better
}

# Update all apps (not from the Microsoft Store)
$desktopAppInstaller = Get-AppxPackage -AllUsers -Name "Microsoft.DesktopAppInstaller"
if ($desktopAppInstaller) {
  # if we can't find WinGet, try re-registering it (only a first time logon issue)
  if (-Not (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
    # if the version is new enough to contain WinGet, this should fix things
    Add-AppxPackage -DisableDevelopmentMode -Register "$($desktopAppInstaller.InstallLocation)\AppxManifest.xml"
    # need to wait a moment to allow Windows to recognize registration
    Start-Sleep -Seconds $appxInstallDelay
  }
}
if (-Not (Get-Command 'winget.exe' -ErrorAction SilentlyContinue)) {
  # download WinGet package
  Write-Output "Downloading WinGet..."
  Write-Output '' # Makes log look better
  $wingetGitHubLatestURL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
  $wingetDownloadURL = $Null
  while (-Not $wingetDownloadURL) {
    # need to loop until download URL is pulled from GitHub
    try {
      $wingetDownloadURL = (Invoke-RestMethod -Uri $wingetGitHubLatestURL -UseBasicParsing).assets.browser_download_url | Where-Object { $_.EndsWith(".msixbundle") }
    } catch {
      $wingetDownloadURL = $Null
      Start-Sleep -Seconds $loopDelay
    }
  }
  $tempWingetPackage = $envTEMP + '\' + $wingetDownloadURL.substring($wingetDownloadURL.LastIndexOf('/') + 1)
  while ((Invoke-WebRequest -Uri $wingetDownloadURL -OutFile $tempWingetPackage -UseBasicParsing -PassThru).StatusCode -ne 200) {
    # need to loop until WinGet package is downloaded
    Start-Sleep -Seconds $loopDelay
  }
  Write-Output "Downloaded WinGet."
  Write-Output '' # Makes log look better
  # check for dependencies in WinGet that are not met
  Write-Output "Confirming dependencies for WinGet..."
  Write-Output '' # Makes log look better
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
    Add-Type -Assembly System.IO.Compression.FileSystem # required for checking inside packages
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
      Write-Output "Checked dependencies for WinGet."
      Write-Output '' # Makes log look better
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
        $dependencyPackage.fileName = 'Microsoft.VCLibs.x64.' + $dependencyPackage.version + '.00.Desktop.appx'
        $dependencyPackage.url = 'https://aka.ms/' + $dependencyPackage.fileName
      } else {
        Write-Warning "Unexpected new dependency found for WinGet: $($packageElement.Name))"
      }
      # if we have a known dependency, download and work on them if needed
      $dependencyPackage.name = $packageElement.Name
      if ($dependencyPackage) {
        # only re-register dependency if we have an equal or newer version already installed (don't try to download package)
        $dependencyPackagePreinstalledList = @(Get-AppxPackage -AllUsers -Name $dependencyPackage.name | Where-Object { [System.Version]$_.Version -ge [System.Version]$packageElement.MinVersion })
        # sometimes may have more than one architecture of the package that needs to be registered
        if ($dependencyPackagePreinstalledList) {
          for ($archIndex = 0; $archIndex -lt $dependencyPackagePreinstalledList.length; $archIndex++) {
            $dependencyPackagePreinstalled = $dependencyPackagePreinstalledList[$archIndex]
            $dependencyArch = $dependencyPackagePreinstalled.Architecture
            Write-Output "Registering an ${dependencyArch} dependency for WinGet..."
            Write-Output '' # Makes log look better
            $registeredDependency = $True
            try {
              Add-AppxPackage -DisableDevelopmentMode -Register "$($dependencyPackagePreinstalled.InstallLocation)\AppxManifest.xml"
            } catch {
              $registeredDependency = $False
            }
            if ($registeredDependency) {
              $dependencyPackage.preinstalled = $True
              Write-Output "Successfully registered an ${dependencyArch} dependency for WinGet."
            } else {
              Write-Warning "Failed to register an ${dependencyArch} dependency for WinGet."
            }
            Write-Output '' # Makes log look better
          }
          return
        }
        # try to download dependency
        $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.fileName
        Write-Output "Downloading a dependency for WinGet..."
        Write-Output '' # Makes log look better
        while ((Invoke-WebRequest -Uri $dependencyPackage.url -OutFile $dependencyPackage.file -UseBasicParsing -PassThru).StatusCode -ne 200) {
          # need to loop until dependency package is downloaded, or we timeout
          Start-Sleep -Seconds $loopDelay
          $dependencyPackageDownloadTime += $loopDelay
        }
        # need to see if package is uiXaml, if so, extract dependency needed
        $packageIsUiXaml = ($dependencyPackage -eq $wingetDependencies.uiXaml) -And $dependencyPackage.file
        $successMsg = @("Successfully downloaded a ", "dependency for Winget.")
        if ($packageIsUiXaml) {
          Write-Output "$($successMsg -Join 'source file containing a ')"
          Write-Output '' # Makes log look better
          Write-Output "Extracting dependency, from downloaded source file, for WinGet..."
          Write-Output '' # Makes log look better
          $uiXamlNupkg = $dependencyPackage.file
          $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.name
          $uiXamlNupkgZip = $Null
          try {
            $uiXamlNupkgZip = [IO.Compression.ZipFile]::OpenRead($uiXamlNupkg)
            $uiXamlNupkgZipAppx = $uiXamlNupkgZip.Entries | Where-Object { $_.FullName -like "*/x64/*/$($dependencyPackage.name).appx" }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($uiXamlNupkgZipAppx, $dependencyPackage.file, $true)
          } catch {
            $dependencyPackage.file = $Null
          }
          if ($dependencyPackage.file) {
            Write-Output "Successfully extracted dependency, from downloaded source file, for WinGet."
          } else {
            Write-Warning "Failed to extract dependency, from downloaded source file, for WinGet."
          }
          if ($uiXamlNupkgZip) { $uiXamlNupkgZip.Dispose() }
          Remove-Item -Path $uiXamlNupkgZip -Force -ErrorAction SilentlyContinue
        } else {
          Write-Output "$($successMsg -Join '')"
        }
        Write-Output '' # Makes log look better
        if ($packageIsUiXaml -And (-Not $dependencyPackage.file)) { throw 'extracting dependency failed' }
      }
    }
  } catch {
    Write-Warning "Failed to check dependencies for WinGet."
    Write-Output '' # Makes log look better
    $wingetDependencies.uiXaml = $False
    $wingetDependencies.vcLibs = $False
    if ($wingetPackageZip) { $wingetPackageZip.Dispose() }
    if ($appManifestReader) { $appManifestReader.Close() }
    if ($appManifestStream) { $appManifestStream.Close() }
    if ($appInstallerMsixZip) { $appInstallerMsixZip.Dispose() }
  }
  # install WinGet (updates Desktop App Installer) with dependencies
  Write-Output "Installing WinGet..."
  Write-Output '' # Makes log look better
  $wingetInstalled = $True
  try {
    $dependencyFiles = @()
    if ($wingetDependencies.vcLibs -And $wingetDependencies.vcLibs.file) { $dependencyFiles += , ($wingetDependencies.vcLibs.file) }
    if ($wingetDependencies.uiXaml -And $wingetDependencies.uiXaml.file) { $dependencyFiles += , ($wingetDependencies.uiXaml.file) }
    $addPackageCommand = 'Add-AppxPackage -Path "' + $tempWingetPackage + '"'
    if ($dependencyFiles) { $addPackageCommand += ' -DependencyPath "' + "$($dependencyFiles -Join '","')" + '"' }
    Invoke-Expression $addPackageCommand
    Start-Sleep -Seconds $appxInstallDelay # need to wait a moment to allow install to register with Windows
  } catch {
    $wingetInstalled = $False
  }
  if ($wingetInstalled) {
    Write-Output "Installed WinGet."
    Write-Output '' # Makes log look better
  }
  # delete left over files no longer needed
  if ($dependencyFiles) { $dependencyFiles | ForEach-Object { Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue } }
  Remove-Item -Path $tempWingetPackage -Force -ErrorAction SilentlyContinue
}
if (Get-Command 'winget.exe' -ErrorAction SilentlyContinue) {
  Write-Output "Attempting to update all apps (not from the Microsoft Store)..."
  Write-Output '' # Makes log look better
  $wingetUpgradePSI = New-object System.Diagnostics.ProcessStartInfo
  $wingetUpgradePSI.CreateNoWindow = $true
  $wingetUpgradePSI.UseShellExecute = $false
  $wingetUpgradePSI.RedirectStandardOutput = $true
  $wingetUpgradePSI.RedirectStandardError = $false
  $wingetUpgradePSI.FileName = 'winget.exe'
  $wingetUpgradePSI.Arguments = @('upgrade -hr --accept-source-agreements')
  $wingetUpgradeProcess = New-Object System.Diagnostics.Process
  $wingetUpgradeProcess.StartInfo = $wingetUpgradePSI
  [void]$wingetUpgradeProcess.Start()
  $wingetOutput = $wingetUpgradeProcess.StandardOutput.ReadToEnd()
  $wingetUpgradeProcess.WaitForExit()
  Write-Host $wingetOutput # show output after so that we at least know what went on
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
      $wingetExceptionMessage = 'Successfully updated most apps (not from the Microsoft Store), but ' + ($wingetExceptionList -Join ', ') + '.'
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
      Write-Output "Successfully installed Dell Command Update."
    } else {
      Write-Warning "Failed to install Dell Command Update."
    }
    Write-Output '' # Makes log look better
  }
  if (Test-Path -Path $dcuCliExe -PathType Leaf) {
    Write-Output "Attempting to update all Dell drivers/firmwares directly from manufacturer..."
    $dcuUpdate = Start-Process -FilePath $dcuCliExe -ArgumentList $dcuArgs -NoNewWindow -PassThru -Wait
    # 0 = updated, 500 = no updates were available, a.k.a. up-to-date
    Write-Output '' # Makes log look better
    if ((0 -eq $dcuUpdate.ExitCode) -Or (500 -eq $dcuUpdate.ExitCode)) {
      Write-Output "Successfully ran Dell Command Update to update Dell drivers/firmwares."
    } elseif (5 -eq $dcuUpdate.ExitCode) {
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
# - Note: the description for the computer, gets set after a reboot
$joinedPC = $True
do {
  Write-Output "Binding computer to domain, and setting its new name and OU location..."
  Write-Output '' # Makes log look better
  try {
    Add-Computer -DomainName $domainName -OUPath $adPathOU -ComputerName $env:computername -NewName $serialnumber -Credential $credentials
  } catch {
    if (($_.Exception -match ".* because it is already in that domain\.$") -Or ($_.Exception -match ".* because the new name is the same as the current name\.$")) {
      Write-Warning "$($_.Exception | Out-String)"
    } else {
      $joinedPC = $False
    }
  }
  Write-Output '' # Makes log look better
} while (-Not $joinedPC)

# Set a scheduled task to run at startup and ...
# - Resume BitLocker encryption (if it was suspended)
# - Turn back on the privacy experience,
# - Turn off auto logon for domain admin user,
# - Delete temp admin account + data (only if not built-in Administrator),
# - Then, delete itself (the scheduled task)
Write-Output "Scheduling final offline tasks..."
Write-Output '' # Makes log look better
$taskNameFinalizeOffline = "Prepare_PC_Finalize_Offline".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$actionFinalizeOffline = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($( "-c `
  `"& { $(if ((Get-BitLockerVolume -MountPoint "$($bitLockerVolume.MountPoint)").ProtectionStatus -eq "Off") {"Resume-BitLocker -MountPoint '$($bitLockerVolume.MountPoint)' ; "} else {''}) `
  Remove-ItemProperty -Path '${regMachinePolicies}\OOBE' -Name 'DisablePrivacyExperience' -Force -ErrorAction SilentlyContinue ; `
  Remove-ItemProperty -Path '${regWinlogon}' -Name 'DefaultPassword' -Force -ErrorAction SilentlyContinue ; `
  Set-ItemProperty -Path '${regWinlogon}' -Name 'AutoAdminLogon' -Value '0' -Type String -Force ; `
  Set-ItemProperty -Path '${regWinlogon}' -Name 'DefaultUserName' -Value '' -Type String -Force ; `
  $(if ($isBuiltInAdmin) { '' } else {
    "Get-CimInstance -Class Win32_UserProfile `
    | Where-Object { `$_.LocalPath.split('\')[-1] -eq '${currentUser}' } `
    | Remove-CimInstance ; `
    Remove-LocalUser -Name '${currentUser}' -ErrorAction SilentlyContinue ; "
  }) `
  Unregister-ScheduledTask -TaskName '${taskNameFinalizeOffline}' -Confirm:`$False `
  }`" -NoProfile -WindowStyle Maximized " `
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

# Set a scheduled task to run at startup and ...
# - Wait for BitLocker to be done encypting (if needed),
# - Wait for a network connection,
# - Set computer AD description,
# - Run Check for Dell updates again, as some updates only show up after the first update (only on Dell machines)
# - Lock the computer,
# - Then, delete itself (the scheduled task)
Write-Output "Scheduling final online tasks..."
Write-Output '' # Makes log look better
$domainAdminPasswordPath = $env:SystemDrive + '\temp-pass' # avoids issues with password containing quotes (which would break the following scheduled task)
$credentials.GetNetworkCredential().password | Out-File -FilePath $domainAdminPasswordPath # might need to change this in the future, so that clear-text password isn't being written to disk
$adObjectDescription = "Spare ${pcModel} - Staged".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$taskNameFinalizeOnline = "Prepare_PC_Finalize_Online".split([IO.Path]::GetInvalidFileNameChars()) -Join $InvalidCharacterReplacement
$actionFinalizeOnline = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($( "-c `
  `"& { $(if ($bitLockerVolume) {
    "if ((Get-BitLockerVolume -MountPoint '$($bitLockerVolume.MountPoint)').VolumeStatus -eq 'EncryptionInProgress') { `
      Write-Output 'Waiting for BitLocker encryption to complete...' ; Write-Output '' ; `
      while ((Get-BitLockerVolume -MountPoint '$($bitLockerVolume.MountPoint)').VolumeStatus -eq 'EncryptionInProgress') { Start-Sleep -Seconds ${loopDelay} } } "
  } else { '' }) `
  while (-Not ((Get-NetConnectionProfile).IPv4Connectivity -contains 'Internet' `
  -or (Get-NetConnectionProfile).IPv6Connectivity -contains 'Internet')) `
  { Start-Sleep -Seconds ${loopDelay} } ; `
  Start-Sleep -Seconds ${domainSyncDelay} ; `
  `$domainAdminPasswordPath = `"`"`"`"${domainAdminPasswordPath}`"`"`"`" ; `
  `$domainAdminPassword = Get-Content -Path `$domainAdminPasswordPath ; `
  `$psCred = New-Object System.Management.Automation.PSCredential('$($credentials.username)', `$(ConvertTo-SecureString `$domainAdminPassword -AsPlainText -Force)) ; `
  Start-Process -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList `"`"`"`"-c \`"`"`"`"& { `
  ```$ComputerSearcher = New-Object DirectoryServices.DirectorySearcher ; `
  ```$ComputerSearcher.SearchRoot = 'LDAP://${adRootOU}' ; `
  ```$ComputerSearcher.Filter = '(&(objectCategory=Computer)(CN=${serialnumber}))' ; `
  ```$computerObj = ```$null ; `
  while (```$null -eq ```$computerObj) `
  { ```$computerObj = [ADSI]```$ComputerSearcher.FindOne().Path ; `
  Start-Sleep -Seconds ${domainSyncDelay} `
  } ; ```$computerObj.Put('Description', '${adObjectDescription}') ; `
  ```$computerObj.SetInfo() ; `
  ```$computerObj.Dispose() `
  }\`"`"`"`"`"`"`"`" -Credential `$psCred -Wait ; `
  $(if ($isDell) {
    "Start-Process -FilePath '${dcuCliExe}' -ArgumentList '${dcuArgs}' -NoNewWindow -Wait -ErrorAction SilentlyContinue ; "
  } else { '' }) `
  Remove-Item -Path `$domainAdminPasswordPath -Force ; `
  Start-Process 'rundll32.exe' -ArgumentList 'user32.dll,LockWorkStation' -NoNewWindow ; `
  Unregister-ScheduledTask -TaskName '${taskNameFinalizeOnline}' -Confirm:`$False `
  }`" -NoProfile -WindowStyle Maximized " `
  ).replace("`n", "")).replace("`r", "")
$settingsFinalizeOnline = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Compatibility Win8 -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0
$triggerFinalizeOnline = New-ScheduledTaskTrigger -AtLogon
$principalFinalizeOnline = New-ScheduledTaskPrincipal -UserId $credentials.username -LogonType Interactive -RunLevel Highest
$definitionFinalizeOnline = New-ScheduledTask -Action $actionFinalizeOnline -Settings $settingsFinalizeOnline -Trigger $triggerFinalizeOnline -Principal $principalFinalizeOnline
$taskFinalizeOnline = Register-ScheduledTask -TaskName $taskNameFinalizeOnline -InputObject $definitionFinalizeOnline
if ($null -ne $taskFinalizeOnline) {
  Write-Output "Successfully scheduled the online tasks."
} else {
  Write-Warning "Failed to schedule the online tasks."
}
Write-Output '' # Makes log look better

# Revert changed sleep settings: code modified via https://gist.github.com/CMCDragonkai/bf8e8b7553c48e4f65124bc6f41769eb
if ($disabledSleep) {
  $disabledSleep = $False
  Write-Output "Enabling default sleep settings..."
  Write-Output '' # Makes log look better
  try {
    $ste::SetThreadExecutionState($ES_CONTINUOUS)
  } catch {
    $disabledSleep = $True
  }
  if ($disabledSleep) {
    Write-Warning "Failed to enable default sleep settings."
  } else {
    Write-Output "Successfully enabled default sleep settings."
  }
  Write-Output '' # Makes log look better
}

# Reboot to apply changes
Write-Output "Rebooting..."
Write-Output '' # Makes log look better
if ($logEnabled) {
  Stop-Transcript # Logging
}
Restart-Computer -Force
