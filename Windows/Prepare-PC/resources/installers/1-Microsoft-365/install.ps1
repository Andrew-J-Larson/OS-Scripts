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

# If needed, removes the annoying Microsoft 365 trial/buy prompt and the standalone SfB install, and installs/configures (will remove old version of OneDrive and SfB)/updates Microsoft 365
$envTEMP = (Get-Item -LiteralPath $env:TEMP).FullName # Required due to PowerShell bug with shortnames appearing when they shouldn't be
$loopDelay = 1 # second
$appTitle = 'Microsoft 365'
$channel = 'Current'
$installconfigXML = "${PSScriptRoot}\installconfig.xml"
$officeRoot = "${env:ProgramFiles}\Microsoft Office\root\Office16"
$regOfficeOEM = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Common\OEM"
$officeReleasehistoryDownloadURL = 'https://officecdn.microsoft.com/pr/wsus/releasehistory.cab'
$officeInstallerDownloadURL = 'https://officecdn.microsoft.com/pr/wsus/setup.exe'
# need to remove possible separate Microsoft OneNote install first
$officeOneNoteIsSeparate = @(Get-Package -Name "Microsoft OneNote*" -ErrorAction SilentlyContinue)
if ($officeOneNoteIsSeparate) {
  Write-Output "Uninstalling ${appTitle} - OneNote..."
  Write-Output '' # Makes log look better
  $Apps = @()
  $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
  $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"             # 64 Bit
  $uninstallerOneNote = @($Apps | Where-Object {
    ($_.DisplayName -And $_.Publisher) -And
    ($_.DisplayName -like 'Microsoft OneNote*') -And
    ($_.Publisher -eq 'Microsoft Corporation') -And $_.UninstallString
  })
  if ($uninstallerOneNote.length) {
    for ($i = 0; $i -lt $uninstallerOneNote.length; $i++) {
        $UninstallString = $uninstallerOneNote[$i].UninstallString
        $splitUninstallString = @($UninstallString -split 'OfficeClickToRun.exe',2)
        $exePath = $splitUninstallString[0].substring(1, $splitUninstallString[0].length - 1) + 'OfficeClickToRun.exe'
        $exeArgs = $splitUninstallString[1].substring(2) + ' DisplayLevel=False'
        $uninstallOneNote = Start-Process $exePath -ArgumentList $exeArgs -PassThru -Wait
        if (0 -eq $uninstallOneNote.ExitCode) {
          Write-Output "Successfully uninstalled ${appTitle} - OneNote."
        } else {
          Write-Warning "Failed to uninstall ${appTitle} - OneNote."
        }
        Write-Output '' # Makes log look better
    }
  }
}
# continue with normal installation/configure
$officeWasPreinstalled = @(Get-Package -Name "Microsoft 365*" -ErrorAction SilentlyContinue)
$officeCameFromOEM = Test-Path -Path $regOfficeOEM
$officeIncludesSfB = Test-Path -Path "${officeRoot}\lync.exe" -PathType Leaf
$officeNeedsConfiguring = $officeWasPreinstalled -And ($officeCameFromOEM -Or $officeIncludesSfB)
$officeNeedsUpdate = $False
if ($officeWasPreinstalled) {
  $officeWasPreinstalled = $officeWasPreinstalled[0]
  $currentVersion = [System.Version]$officeWasPreinstalled.Version
  # need to grab the releasehistory cab file to check for latest version
  $tempReleasehistoryCAB = $envTEMP + '\' + $officeReleasehistoryDownloadURL.substring($officeReleasehistoryDownloadURL.LastIndexOf('/') + 1)
  $PreviousProgressPreference = $ProgressPreference
  $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
  while ((Invoke-WebRequest -Uri $officeReleasehistoryDownloadURL -OutFile $tempReleasehistoryCAB -UseBasicParsing -PassThru).StatusCode -ne 200) {
    # need to loop until the releasehistory CAB file is downloaded
    Start-Sleep -Seconds $loopDelay
  }
  $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
  # must extract the ReleaseHistory XML from inside
  $xmlFilename = 'ReleaseHistory.xml'
  $tempReleaseHistoryXML = $envTEMP + '\' + $xmlFilename
  expand $tempReleasehistoryCAB $tempReleaseHistoryXML -f:$xmlFilename | Out-Null
  Remove-Item -Path $tempReleasehistoryCAB -Force -ErrorAction SilentlyContinue
  # find latest version
  $latestVersion = $Null
  if (Test-Path $tempReleaseHistoryXML -PathType Leaf) {
    [xml]$releaseHistoryXML = Get-Content $tempReleaseHistoryXML
    Remove-Item -Path $tempReleaseHistoryXML -Force -ErrorAction SilentlyContinue
    $updateChannels = $releaseHistoryXML.ReleaseHistory.UpdateChannel
    $updates = $updateChannels | Where-Object { ($_.name -like $channel) -Or ($_.ID -like $channel) }
    if ($updates.Update) {
      $latestVersion = [System.Version]($(if ($updates.Update.count -gt 0) {$updates.Update[0]} else {$updates.Update}).LegacyVersion)
    }
  }
  # check version to see if we need to update
  $officeNeedsUpdate = if ($latestVersion) { $currentVersion -lt $latestVersion } else { $True }
}
if ($officeWasPreinstalled -And (-Not $officeNeedsConfiguring) -And (-Not $officeNeedsUpdate)) {
  Write-Output "${appTitle} is already installed and up-to-date, skipped."
} else {
  Write-Output "Downloading ${appTitle}..."
  Write-Output '' # Makes log look better
  $tempSetupEXE = $envTEMP + '\' + $officeInstallerDownloadURL.substring($officeInstallerDownloadURL.LastIndexOf('/') + 1)
  $PreviousProgressPreference = $ProgressPreference
  $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
  while ((Invoke-WebRequest -Uri $officeInstallerDownloadURL -OutFile $tempSetupEXE -UseBasicParsing -PassThru).StatusCode -ne 200) {
    # need to loop until Microsoft 365 installer is downloaded
    Start-Sleep -Seconds $loopDelay
  }
  $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
  Write-Output "Downloaded ${appTitle}."
  Write-Output '' # Makes log look better
  if ($officeCameFromOEM) {
    Write-Output "Removing OEM trial prompt from ${appTitle}..."
    Write-Output '' # Makes log look better
    $removedTrial = $True
    try {
      Remove-Item -Path $regOfficeOEM -Force
    } catch {
      $removedTrial = $False
    }
    if ($removedTrial) {
      Write-Output "Successfully removed OEM trial prompt from ${appTitle}."
    } else {
      Write-Warning "Failed to remove OEM trial prompt from ${appTitle}."
    }
    Write-Output '' # Makes log look better
  }
  Write-Output "$(if ($officeNeedsConfiguring) {"Configuring"} elseif ($officeWasPreinstalled) {"Updating"} else {"Installing"}) ${appTitle}..."
  Write-Output '' # Makes log look better
  Stop-Process -Name 'lync' -Force -ErrorAction SilentlyContinue # Skype for Business (deprecated)
  Stop-Process -Name 'winword' -Force -ErrorAction SilentlyContinue # Word
  Stop-Process -Name 'excel' -Force -ErrorAction SilentlyContinue # Excel
  Stop-Process -Name 'msaccess' -Force -ErrorAction SilentlyContinue # Access
  Stop-Process -Name 'mstore' -Force -ErrorAction SilentlyContinue # Clip Organizer
  Stop-Process -Name 'infopath' -Force -ErrorAction SilentlyContinue # Info Path
  Stop-Process -Name 'setlang' -Force -ErrorAction SilentlyContinue # Langauge Configuration Utility
  Stop-Process -Name 'msouc' -Force -ErrorAction SilentlyContinue # Upload Center
  Stop-Process -Name 'ois' -Force -ErrorAction SilentlyContinue # Picture Manager
  Stop-Process -Name 'onenote' -Force -ErrorAction SilentlyContinue # OneNote
  Stop-Process -Name 'outlook' -Force -ErrorAction SilentlyContinue # Outlook (old)
  Stop-Process -Name 'powerpnt' -Force -ErrorAction SilentlyContinue # PowerPoint
  Stop-Process -Name 'mspub' -Force -ErrorAction SilentlyContinue # Publisher
  Stop-Process -Name 'groove' -Force -ErrorAction SilentlyContinue # OneDrive for Business (deprecated)
  Stop-Process -Name 'visio' -Force -ErrorAction SilentlyContinue # Visio
  Stop-Process -Name 'winproj' -Force -ErrorAction SilentlyContinue # Project
  Stop-Process -Name 'graph' -Force -ErrorAction SilentlyContinue # Graph Facility
  Stop-Process -Name 'onedrive' -Force -ErrorAction SilentlyContinue # OneDrive
  Stop-Process -Name 'teams' -Force -ErrorAction SilentlyContinue # Teams (old)
  Stop-Process -Name 'ms-teams' -Force -ErrorAction SilentlyContinue # Teams
  Stop-Process -Name 'olk' -Force -ErrorAction SilentlyContinue # Outlook
  $officeInstall = Start-Process -FilePath $tempSetupEXE -ArgumentList "/configure `"${installconfigXML}`"" -NoNewWindow -PassThru -Wait
  Remove-Item -Path $tempSetupEXE -Force
  if (0 -eq $officeInstall.ExitCode) {
    Write-Output "Successfully $(if ($officeNeedsConfiguring) { "configured" } elseif ($officeWasPreinstalled) { "updated" } else { "installed" }) ${appTitle}."
  } else {
    throw "Failed to $(if ($officeNeedsConfiguring) { "configure" } elseif ($officeWasPreinstalled) { "update" } else { "install" }) ${appTitle} (exit code: $($officeInstall.ExitCode))."
  }
}
Write-Output '' # Makes log look better
