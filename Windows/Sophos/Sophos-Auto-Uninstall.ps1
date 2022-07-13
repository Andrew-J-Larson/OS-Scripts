<#
  .SYNOPSIS
  Script that aids in the mass uninstallation of Sophos.

  .DESCRIPTION
  This script is meant to be used in aid of mass uninstallation of Sophos anti-virus in any organization,
  per computer. It should be able to be ran in the background, as long as a computer has internet access,
  and the required API information has been filled out below in the constants.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .PARAMETER Restart
  Makes the script instantly restart the computer after a successful uninstall.

  .INPUTS
  None. You cannot pipe objects to Sophos-Auto-Uninstall.ps1.

  .OUTPUTS
  Script will throw errors where needed, and output any text when using some of the Sophos exe's.

  .EXAMPLE
  PS> .\Sophos-Auto-Uninstall.ps1

  .EXAMPLE
  PS> .\Sophos-Auto-Uninstall.ps1 -restart

  .EXAMPLE
  PS> .\Sophos-Auto-Uninstall.ps1 -r

  .EXAMPLE
  PS> .\Sophos-Auto-Uninstall.ps1 -help

  .EXAMPLE
  PS> .\Sophos-Auto-Uninstall.ps1 -h

  .LINK
  Sophos API Token Management: https://docs.sophos.com/central/Customer/help/en-us/ManageYourProducts/Overview/GlobalSettings/ApiTokenManagement/index.html

  .LINK
  Sophos API Developer Docs: https://developer.sophos.com/intro

  .LINK
  Script downloaded from: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Sophos/Sophos-Auto-Uninstall.ps1
#>

#Requires -RunAsAdministrator
# Version 1.0.0

# Copyright (C) 2020  Andrew Larson (thealiendrew@gmail.com)
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
  [switch]$Help,

  [Alias("r")]
  [switch]$Restart
)

# Constants
Set-Variable -Name SEDcliExe -Value "C:\Program Files\Sophos\Endpoint Defense\SEDcli.exe" -Option Constant
Set-Variable -Name uninstallcliExe -Value "C:\Program Files\Sophos\Sophos Endpoint Agent\uninstallcli.exe" -Option Constant
Set-Variable -Name EndpointIdentityTxt -Value "C:\ProgramData\Sophos\Management Communications System\Endpoint\Persist\EndpointIdentity.txt" -Option Constant

# Sophos API Constants: the following NEEDS to be filled out BEFORE the script can work
# see https://docs.sophos.com/central/Customer/help/en-us/ManageYourProducts/Overview/GlobalSettings/ApiTokenManagement/index.html
Set-Variable -Name tenantID -Value "" -Option Constant
Set-Variable -Name authToken -Value "" -Option Constant
Set-Variable -Name dataRegion -Value "" -Option Constant # this can be determined from https://developer.sophos.com/intro

# Other Sophos API Constants (no changes need to be made here)
Set-Variable -Name apiURL -Value "https://api-${dataRegion}.central.sophos.com/endpoint/v1/endpoints" -Option Constant

# check for parameters and execute accordingly
if ($Help.IsPresent -Or $H.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}
$Restart = $Restart.IsPresent

# exit if any of the API constants are empty (or else script doesn't function)
if ([string]::IsNullOrEmpty($tenantID) -Or [string]::IsNullOrEmpty($authToken) -Or [string]::IsNullOrEmpty($dataRegion)) {
  throw "One or more constants have been left empty, please edit the script and fill in your Sophos API information."
}

# exit if we are missing required exe's
if (-Not ($(Test-Path "$SEDcliExe") -And $(Test-Path "$uninstallcliExe"))) {
  throw "One or more required exe files are missing. (Has Sophos already been uninstalled? You might need to use SophosZap.exe for this machine)"
}

# exit if we are denied access to check status (not admin)
if (& "$SEDcliExe" -s | Select-String -Pattern "denied" -SimpleMatch -Quiet) {
  throw "This script requires being ran as admin."
}

# set headers required to GET data from Soghos API later
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("X-Tenant-ID", "${tenantID}")
$headers.Add("Authorization", "Bearer ${authToken} ")

# get per computer specific information

$endpointID = ""
if (Test-Path "$EndpointIdentityTxt") {
  $endpointID = Get-Content "$EndpointIdentityTxt"
}

# if endpoint ID wasn't found, attempt getting endpoint ID from API
if ([string]::IsNullOrEmpty($endpointID)) {
  $hostname = [System.Net.Dns]::GetHostName()

  # find endpoint ID per computer hostname in Sophos
  $response = Invoke-RestMethod "${apiURL}?hostnameContains=${hostname}" -Method 'GET' -Headers $headers

  $endpointID = $response.items[0]
  if ($endpointID) {
    $endpointID = $endpointID.id
  }

  # if still can't get endpoint ID, may have to work with machine manually
  if ([string]::IsNullOrEmpty($endpointID)) {
    throw "Couldn't find endpoint ID on the local machine or in Sophos API."
  }
}

# grab tamper protection password from Sophos

$response = Invoke-RestMethod "${apiURL}/${endpointID}/tamper-protection" -Method 'GET' -Headers $headers

$tpPassword = $response.password

# disable tamper protection on computer

& "$SEDcliExe" -OverrideTPoff $tpPassword
if (-Not (& "$SEDcliExe" -s | Select-String -Pattern "disabled" -SimpleMatch -Quiet)) {
  throw $(& "$SEDcliExe" -s)
}

# finally, initiate Sophos uninstall

& "$uninstallcliExe"
if ($? -And $restartPC) {Restart-Computer -Force}