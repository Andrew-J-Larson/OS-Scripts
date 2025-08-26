<#
  .SYNOPSIS
  DSIA Get Docks Example v1.0.2

  .DESCRIPTION
  This script will attempt to check DSIA for docking stations (certain models only).

  If needed, the DSIA software will be temporarily installed, and uninstalled after use.

  View and modify the source code to fit your needs.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Just an example of listing docking station serials, and some warnings/errors log to the console.

  .EXAMPLE
  .\DSIA-Get-Docks-Example.ps1

  .EXAMPLE
  .\DSIA-Get-Docks-Example.ps1 -Help

  .EXAMPLE
  .\DSIA-Get-Docks-Example.ps1 -h

  .NOTES
  Requires admin! Due to needing access to namespaces that require admin access, and the potential need to install DSIA!

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Dell/DSIA-Get-Docks-Example.ps1
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
  [switch]$Help
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}

# FUNCTIONS

# waits for current installations to finish
function Wait-ForMsiexecSilently {
  $MutexName = "Global\_MSIExecute"
  #Write-Host "Checking for a busy Windows Installer..." -NoNewline
  while ($true) {
    # Attempt to open the global MSI mutex.
    # If it exists, another installation is in progress.
    try {
      $Mutex = [System.Threading.Mutex]::OpenExisting($MutexName)
      $Mutex.Dispose()
      #Write-Host "." -NoNewline # Show progress with a dot
      Start-Sleep -Seconds 1
    }
    catch {
      #Write-Host " Done."
      # Mutex does not exist, safe to proceed
      return
    }
  }
}

# winget can't normally be ran under system, unless it's specifically called by the EXE
# code via https://github.com/Romanitho/Winget-Install/blob/main/winget-install.ps1
function Get-WingetCmd {
  $WingetCmd = $null

  #Get WinGet Path
  try {
    #Get Admin Context Winget Location
    $WingetInfo = (Get-Item "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe").VersionInfo | Sort-Object -Property FileVersionRaw
    #If multiple versions, pick most recent one
    $WingetCmd = $WingetInfo[-1].FileName
  } catch {
    #Get User context Winget Location
    if (Test-Path "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe") {
      $WingetCmd = "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe"
    }
  }

  return $WingetCmd
}

$ScriptIsSystem = ($env:userdomain -eq 'NT AUTHORITY') -Or ($env:username).EndsWith('$')

# makes sure that winget can work properly (when ran from user profiles)
if (-Not $ScriptIsSystem) {
  try {
    $wingetAppxPackages = @('Microsoft.DesktopAppInstaller', 'Microsoft.Winget.Source')
    ForEach ($package in $wingetAppxPackages) {
      if (-Not (Get-AppxPackage -Name $package)) {
        Get-AppxPackage -Name $package -AllUsers | ForEach-Object {
          Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" | Out-Null
        }
      }
    }
  } catch {
    Write-Warning "Issues activating Winget."
  }
}

# CONSTANTS

# Required due to PowerShell bug with shortnames appearing when they shouldn't be
$envTEMP = (Get-Item -LiteralPath $env:TEMP).FullName

# contains an XML file, which subsequently contains the MSI download link for Dell System/OpenManage Inventory Agent (DSIA)
$URL_CAB_DellSDPCatalogPC = "https://downloads.dell.com/catalog/DellSDPCatalogPC.cab"

# temporary paths
$CAB_DellSDPCatalogPC = "${envTEMP}\DellSDPCatalogPC.cab"
$XML_DellSDPCatalogPC = "${envTEMP}\DellSDPCatalogPC.xml"
$LOG_MSI_DSIAPC = "${envTEMP}\DSIAPC.log"

# used during install/uninstall of DSIA
$RegexDSIA = '^Dell (OpenManage|(Client )?System) Inventory Agent.*$'

# VARIABLES

$cleanupFiles = @($CAB_DellSDPCatalogPC, $XML_DellSDPCatalogPC) # could have an additional files tacked on later for cleanup

# MAIN

$results = 0

$msiErrorSuccessCodes = @(0, 1641, 3010) # https://learn.microsoft.com/en-us/windows/win32/msi/error-codes

$msiexecEXE = (Split-Path $env:ComSpec) + '\msiexec.exe'
$wingetEXE = (Get-WingetCmd)

$AppName = 'Dell System Inventory Agent'

$appWingetName = $Null # gets set later

# Test to see if we really need to download and install DSIA first
$Dell_SoftwareIdentity = Get-CimInstance -Namespace root\dell\sysinv -ClassName dell_softwareidentity -ErrorAction SilentlyContinue
$PreInstalled = $True
if (-Not $Dell_SoftwareIdentity) {
  $PreInstalled = $False
  # Download URL_DellSDPCatalogPC CAB file
  $PreviousProgressPreference = $ProgressPreference
  $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
  $WebRequestDownloadDSIAPC = Invoke-WebRequest -URI $URL_CAB_DellSDPCatalogPC -UseBasicParsing -OutFile $CAB_DellSDPCatalogPC -PassThru
  $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
  if (200 -ne $WebRequestDownloadDSIAPC.StatusCode) {
    Throw "Unable to download file at the following URL: ${URL_CAB_DellSDPCatalogPC}"
  }
  # Extract DellSDPCatalogPC.xml from the CAB file
  $extractArgs = "/Y /L `"${envTEMP}`" `"${CAB_DellSDPCatalogPC}`" `"$($XML_DellSDPCatalogPC.split('\')[-1])`""
  $extractCAB = Start-Process 'extrac32.exe' -ArgumentList $extractArgs -PassThru -Wait
  if (0 -ne $extractCAB.ExitCode) {
    Throw "Failed to extract items from the CAB file at: ${CAB_DellSDPCatalogPC}"
  }
  # Read the XML
  [xml]$DATA_XML_DellSDPCatalogPC = Get-Content -Path $XML_DellSDPCatalogPC

  # Grab the URL for the DSIA installer MSI
  $DATA_SPD_DSIAPC = @(
    $DATA_XML_DellSDPCatalogPC.SystemsManagementCatalog.SoftwareDistributionPackage | Where-Object {
      $_.LocalizedProperties.Title -match $RegexDSIA
    }
  )[0]
  $URL_MSI_DSIAPC = $DATA_SPD_DSIAPC.InstallableItem.OriginFile.OriginUri
  # Install DSIA (directly from the URL for the MSI)
  $installMsiArgs = "/i `"${URL_MSI_DSIAPC}`" /qn /l*v `"${LOG_MSI_DSIAPC}`""
  Wait-ForMsiexecSilently
  $ProcessInstallDSIAPC = Start-Process $msiexecEXE -ArgumentList $installMsiArgs -PassThru -Wait
  # If install was successful...
  if ($msiErrorSuccessCodes -contains $ProcessInstallDSIAPC.ExitCode) {
    Write-Host "${AppName} was installed."
    # Include LOG in temp files to delete
    $cleanupFiles += @($LOG_MSI_DSIAPC)
  }

  # Dispose of temporary files not needed anymore
  Remove-Item $cleanupFiles -Force

  # Make sure to force exit if the install was a fail
  if ($msiErrorSuccessCodes -notcontains $ProcessInstallDSIAPC.ExitCode) {
    Throw "Exit code = $($ProcessInstallDSIAPC.ExitCode), see log file at: ${LOG_MSI_DSIAPC}"
  }
}

# NOTE: We get here if DSIA is installed

# Wait for the namespace to become available to the system
do {
  Start-Sleep -Seconds 1
  $Dell_SoftwareIdentity = Get-CimInstance -Namespace root\dell\sysinv -ClassName dell_softwareidentity -ErrorAction SilentlyContinue
} while (-Not $Dell_SoftwareIdentity)

# ==================== READY: Do something with `Dell_SoftwareIdentity`

# Find all docks (only WD19S and WD19DCS models)
$Docks = @(
  $Dell_SoftwareIdentity | Where-Object {
    $_.ElementName -And ($_.ElementName -match '^.*WD19(DC)?S.*$')
  }
)

# Do something with docks found
if ($Docks) {
  $msgFound = "Found $($Docks.Length) dock$(if ($Docks.Length -ne 1) { 's' })"
  # List serial numbers of all docks found
  $dockSerialNumbers = @($Docks | Select-Object -ExpandProperty SerialNumber)
  if ($dockSerialNumbers) {
    $msgFound = "${msgFound}$(if ($Docks.Length -ne $dockSerialNumbers.Length) { " total, but only $($dockSerialNumbers.Length)" })"
    Write-Host "${msgFound} with serial number$(if ($dockSerialNumbers.Length -gt 1) { 's' }):`n"
    Write-Host $dockSerialNumbers
  } else {
    Write-Warning "${msgFound} with no serial numbers."
  }
} else {
  Write-Warning "No docks found."
}

# ==================== DONE: ready to remove DSIA if needed

if (-Not $PreInstalled) {
  # Uninstall DSIA (assuming we don't want to leave it on the computer forgetting to update it)
  $Apps = @()
  $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" # 32 Bit
  $Apps += Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"             # 64 Bit

  $uninstaller = @($Apps | Where-Object {
    # has a display name matching the regex, with a valid uninstall string
    $_.DisplayName -And ($_.DisplayName -match $RegexDSIA) -And $_.UninstallString
  }) | Sort-Object -Property InstallDate -Descending
  if ($uninstaller.length) { $uninstaller = $uninstaller[0] }

  # If found, uninstall
  if ($uninstaller) {
    $appWingetName = $uninstaller.DisplayName
    Wait-ForMsiexecSilently
    $uninstallAppPSI = New-object System.Diagnostics.ProcessStartInfo
    $uninstallAppPSI.CreateNoWindow = $true
    $uninstallAppPSI.UseShellExecute = $false
    $uninstallAppPSI.RedirectStandardOutput = $true
    $uninstallAppPSI.RedirectStandardError = $false
    $uninstallAppPSI.WorkingDirectory = (Split-Path $wingetEXE) # required, when app is launched in System context in some instances
    $uninstallAppPSI.FileName = $wingetEXE
    $uninstallAppPSI.Arguments = @('uninstall --name "' + $appWingetName + '" --silent --scope machine')
    $uninstallApp = New-Object System.Diagnostics.Process
    $uninstallApp.StartInfo = $uninstallAppPSI
    [void]$uninstallApp.Start()
    $wingetOutput = $uninstallApp.StandardOutput.ReadToEnd()
    $uninstallApp.WaitForExit()

    if (0 -ne $uninstallApp.ExitCode) {
      # Can't use exit code to determine different issues with uninstalls, see https://github.com/microsoft/winget-cli/discussions/3338
      # - $wingetOutput can be checked for exit codes

      # special circumstance with silent uninstall showing up as fail when it actually succeeded
      $wingetOutputErrorMessage = $wingetOutput | Select-Object -Last 1
      $wingetOutputErrorCode = ($wingetOutputErrorMessage -split ' ')[-1]
      if ($msiErrorSuccessCodes -notcontains $wingetOutputErrorCode) {
        $results = $wingetOutputErrorCode

        Write-Warning "Failed to uninstall ${AppName}, due to the uninstaller failing (exit code: ${wingetOutputErrorCode})."
      }
    }
    if (0 -eq $results) {
      Write-Host "Successfully uninstalled ${AppName}."
    }
  } else {
    Write-Host "${AppName} is already uninstalled."
  }
}

Exit $results
