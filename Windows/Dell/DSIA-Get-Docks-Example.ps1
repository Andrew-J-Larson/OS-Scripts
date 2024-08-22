<#
  .SYNOPSIS
  DSIA Get Docks Example v1.0.0

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

<# Copyright (C) 2024  Andrew Larson (github@andrew-larson.dev)

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
  [xml]$DATA_XML_DellSDPCatalogPC = Get-Content $XML_DellSDPCatalogPC

  # Grab the URL for the DSIA installer MSI
  $DATA_SPD_DSIAPC = @(
    $DATA_XML_DellSDPCatalogPC.SystemsManagementCatalog.SoftwareDistributionPackage | Where-Object {
      $_.LocalizedProperties.Title -match $RegexDSIA
    }
  )[0]
  $URL_MSI_DSIAPC = $DATA_SPD_DSIAPC.InstallableItem.OriginFile.OriginUri
  # Install DSIA (directly from the URL for the MSI)
  $installMsiArgs = "/i `"${URL_MSI_DSIAPC}`" /qn /l*v `"${LOG_MSI_DSIAPC}`""
  $ProcessInstallDSIAPC = Start-Process 'msiexec.exe' -ArgumentList $installMsiArgs -PassThru -Wait
  # If install was successful...
  if (0 -eq $ProcessInstallDSIAPC.ExitCode) {
    Write-Host "DSIA was installed."
    # Include LOG in temp files to delete
    $cleanupFiles += @($LOG_MSI_DSIAPC)
  }

  # Dispose of temporary files not needed anymore
  Remove-Item $cleanupFiles -Force

  # Make sure to force exit if the install was a fail
  if (0 -ne $ProcessInstallDSIAPC.ExitCode) {
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
  }) | Sort-Object -Property InstallDate -Descending | Select-Object -First 1
  $uninstallMsiArgs = ($uninstaller.UninstallString -split 'msiexec.exe ',2)[1] + ' /qn /noreboot'
  $uninstallDSIA = Start-Process 'msiexec.exe' -ArgumentList $uninstallMsiArgs -PassThru -Wait
  if (0 -eq $uninstallDSIA.ExitCode) {
    Write-Host "DSIA was uninstalled."
  } else {
    Write-Warning "DSIA couldn't be uninstalled (exit code = $($uninstallDSIA.ExitCode))."
  }
}

Exit 0
