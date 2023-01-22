<#
  .SYNOPSIS
  Script that aids in the mass uninstallation of Sophos anti-virus.

  .DESCRIPTION
  Version 1.1.0
  
  This script is meant to be used in aid of mass uninstallation of Sophos anti-virus in any organization,
  per computer. It should be able to be ran in the background, as long as a computer has internet access,
  and the required API information has been filled out below in the constants. Make sure the API constants
  have been filled in prior to running the script.

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
  [switch]$Help,

  [Alias("r")]
  [switch]$Restart
)

# Constants
Set-Variable -Name apiSophosIdURL -Value "https://id.sophos.com/api/v2/oauth2/token" -Option Constant
Set-Variable -Name apiSophosGlobalURL -Value "https://api.central.sophos.com" -Option Constant
Set-Variable -Name SEDcliExe -Value "C:\Program Files\Sophos\Endpoint Defense\SEDcli.exe" -Option Constant
Set-Variable -Name uninstallcliExe -Value "C:\Program Files\Sophos\Sophos Endpoint Agent\uninstallcli.exe" -Option Constant
Set-Variable -Name EndpointIdentityTxt -Value "C:\ProgramData\Sophos\Management Communications System\Endpoint\Persist\EndpointIdentity.txt" -Option Constant

# Sophos API Constants: the following NEEDS to be filled out BEFORE the script can work
# see https://docs.sophos.com/central/Customer/help/en-us/ManageYourProducts/Overview/GlobalSettings/ApiTokenManagement/index.html
Set-Variable -Name tenantClientID -Value "" -Option Constant
Set-Variable -Name tenantClientSecret -Value "" -Option Constant

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}
$Restart = $Restart.IsPresent

# exit if we are missing required exe's
if (-Not ($(Test-Path "$SEDcliExe") -And $(Test-Path "$uninstallcliExe"))) {
  throw "One or more required exe files are missing. (Has Sophos already been uninstalled? You might need to use SophosZap.exe for this machine)"
}

# exit if we are denied access to check status (not admin)
if (& "$SEDcliExe" -s | Select-String -Pattern "denied" -SimpleMatch -Quiet) {
  throw "This script requires being ran as admin."
}

# authenticate to Sophos ID and get tenant auth token

$tenantAuthToken = ""
$response = Invoke-RestMethod "$apiSophosIdURL" -Method 'POST' -Body "grant_type=client_credentials&client_id=${tenantClientID}&client_secret=${tenantClientSecret}&scope=token"
if ($response.errorCode -eq "success") {
  $tenantAuthToken = $response.access_token
}
if ([string]::IsNullOrEmpty($tenantAuthToken)) {
  throw "Couldn't authenticate, please make sure you're using the correct credentials for your tenant."
}

# get the tenant ID and API region url to make requests to the tenant

$tenantID = ""
$apiSophosRegionURL = ""
$apiSophosRegionEndpointsURL = ""
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer ${tenantAuthToken} ")
$response = Invoke-RestMethod "${apiSophosGlobalURL}/whoami/v1" -Method 'GET' -Headers $headers
if ([string]::IsNullOrEmpty($response.idType)) {
  throw "Couldn't connect to API" # shouldn't ever get here
} elseif ($response.idType -eq "tenant") {
  $tenantID = $response.id
  $apiSophosRegionURL = $response.apiHosts.dataRegion
  $apiSophosRegionEndpointsURL = "${apiSophosRegionURL}/endpoint/v1/endpoints"
} else {
  throw "Authenticated, but wrong credentials were used! Please make sure you are using the tenant's credentials."
}

# get per computer specific information

$headers.Add("X-Tenant-ID", "${tenantID}")

$endpointID = ""
if (Test-Path "$EndpointIdentityTxt") {
  $endpointID = Get-Content "$EndpointIdentityTxt"
}

# if endpoint ID wasn't found, attempt getting endpoint ID from API
if ([string]::IsNullOrEmpty($endpointID)) {
  $hostname = [System.Net.Dns]::GetHostName()

  # find endpoint ID per computer hostname in Sophos
  $response = Invoke-RestMethod "${apiSophosRegionEndpointsURL}?hostnameContains=${hostname}" -Method 'GET' -Headers $headers
  if (-Not $response.items -Or -Not $response.items[0]) {
    throw "Couldn't retrieve endpoint ID for local machine or from API search results." # shouldn't ever get here
  }
  $endpointID = $response.items[0].id
}

# get tamper protection password

$response = Invoke-RestMethod "${apiSophosRegionEndpointsURL}/${endpointID}/tamper-protection" -Method 'GET' -Headers $headers
$tpPassword = $response.password
if ([string]::IsNullOrEmpty($tpPassword)) {
  throw "Unable to get tamper protection password." # shouldn't ever get here
}

# disable tamper protection on computer

& "$SEDcliExe" -OverrideTPoff $tpPassword
if (-Not (& "$SEDcliExe" -s | Select-String -Pattern "disabled" -SimpleMatch -Quiet)) {
  throw $(& "$SEDcliExe" -s)
}

# finally, initiate Sophos uninstall

& "$uninstallcliExe"
if ($? -And $Restart) {Restart-Computer -Force}
