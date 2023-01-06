<#
  .SYNOPSIS
  Script downloads and installs all extensions needed for viewing/editing HEIF/HEVC/HEIC file types.

  .DESCRIPTION
  Version 1.0.4
  
  Since updated versions of Windows installations don't always include this support, this script is handy to turn
  on HEIC extension feature.
  
  NOTE: This is a per user profile thing, so this needs to be done in all profiles where .HEIC aren't working.
  
  * Some Windows computers (e.g. Dell) support installation of the "HEVC Video Extensions from Device Manufacturer"
    app for free from the app store, but it's not something you can search for to install.
  * HEIC is a proprietary file type by Apple which combines the use of HEIF/HEVC in an HEIC container.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Only takes one argument: the product ID as a string

  .OUTPUTS
  Display errors if any, otherwise, should return boolean result of script.

  .EXAMPLE
  PS> .\Enable-HEIC-Extension-Feature.ps1

  .LINK
  Third-Party API for Downloading Microsoft Store Apps: https://store.rg-adguard.net/

  .LINK
  Script downloaded from: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Enable-HEIC-Extension-Feature.ps1
#>

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
  [switch]$Help
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}

# Constants
Set-Variable HEIF_MSSTORE_APP_ID -Option Constant -Value "9PMMSR1CGPWG"
Set-Variable HEVC_MSSTORE_APP_ID -Option Constant -Value "9N4WGH0Z6VHQ"

# Functions

# Input = Product ID of Microsoft Store app
# Output = Array of paths to successfully downloaded packages
# Errors  = Display in console
function Download-AppxPackage {
  $DownloadedFiles = @()
  $errored = $false
  $allFilesDownloaded = $true

  $apiUrl = "https://store.rg-adguard.net/api/GetFiles"
  $versionRing = "Retail"

  $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "x86" {"x86"}
    "AMD64" {"x64"}
    "ARM64" {"arm64"}
    default {"neutral"}
  }

  $ProductId = $args[0]

  $downloadFolder = Join-Path $env:TEMP "StoreDownloads"
  if(!(Test-Path $downloadFolder -PathType Container)) {
    New-Item $downloadFolder -ItemType Directory -Force
  }

  $body = @{
    type = 'ProductId'
    url  = $ProductId
    ring = $versionRing
    lang = 'en-US'
  }

  $raw = $null
  try {
    $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -ContentType 'application/x-www-form-urlencoded' -Body $body
  } catch {$errored = $true}

  $useArch = if ($packages -match ".*_${arch}_.*") {$arch} else {"neutral"}

  $raw | Select-String '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches | % { $_.Matches } |
   % { $url = $_.Groups[1].Value
       $text = $_.Groups[2].Value

       if($text -match "_${useArch}_.*`.appx(|bundle)$") {
         $downloadFile = Join-Path $downloadFolder $text

         # If file already exists, ask to replace it
         if(Test-Path $downloadFile) {
           Write-Host "`"${text}`" already exists at `"${downloadFile}`"."
           $confirmation = ''
           while (!(($confirmation -eq 'Y') -Or ($confirmation -eq 'N'))) {
             $confirmation = Read-Host "Would you like to re-download and overwrite the file at `"${downloadFile}`" (Y/N)?"
             $confirmation = $confirmation.ToUpper()
           }
           if ($confirmation -eq 'Y') {
             Remove-Item -Path $downloadFile -Force
           } else {
             $DownloadedFiles += $downloadFile
           }
         }

         if (!(Test-Path $downloadFile)) {
           Write-Host "Attempting download of `"${text}`" to `"${downloadFile}`" . . ."
           $fileDownloaded = $null
           try {
             Invoke-WebRequest -Uri $url -OutFile $downloadFile
             $fileDownloaded = $?
           } catch {$errored = $true}
           if ($fileDownloaded) {$DownloadedFiles += $downloadFile}
           else {$allFilesDownloaded = $false}
         }
       }
     }

  If ($errored) {Write-Host "Completed with some errors."}
  if $(-Not $allFilesDownloaded) {Write-Host "Warning: Not all packages could be downloaded."}
  return $DownloadedFiles
}

# MAIN

# make sure we are online first
if (-Not $(Test-NetConnection -InformationLevel Quiet)) {
  throw "Please make sure you're connected to the internet, then try again."
  return $false
}

# need to make sure the logged in user is running the script
$powershellUser = $(whoami)
$loggedInUser = $(Get-WMIObject -class Win32_ComputerSystem).username.toString()
if ($powershellUser -ne $loggedInUser) {
  throw "Please make sure the script is running as user (e.g. don't run as admin)."
  return $false
}

# Now we just need the HEIF and HEVC extension apps installed
try {
  # need HEIF installed first, if not already
  if (Get-AppxPackage -Name "Microsoft.HEIFImageExtension") {
    Write-Host '"HEIF Image Extensions" already installed.'
  } else {
    $appxPackagesHEIF = Download-AppxPackage ${HEIF_MSSTORE_APP_ID}
    Write-Host 'Installing "HEIF Image Extensions"...'
    for ($i = 0; $i -lt $appxPackagesHEIF.count; $i++) {
      $appxFilePath = $appxPackagesHEIF[$i]
      $appxFileName = Split-Path $appxFilePath -leaf
      Add-AppxPackage -Path $appxFile
      if ($?) {Write-Host "`"$appxFileName`" installed successfully."}
    }
  }
  # need HEVC (device manufacturer version) installed after
  if (Get-AppxPackage -Name "Microsoft.HEVCVideoExtension") {
    Write-Host '"HEVC Video Extensions from Device Manufacturer" already installed.'
  } else {
    $appxPackagesHEVC = Download-AppxPackage ${HEVC_MSSTORE_APP_ID}
    Write-Host 'Installing "HEVC Video Extensions from Device Manufacturer"...'
    for ($i = 0; $i -lt $appxPackagesHEVC.count; $i++) {
      $appxFilePath = $appxPackagesHEVC[$i]
      $appxFileName = Split-Path $appxFilePath -leaf
      Add-AppxPackage -Path $appxFile
      if ($?) {Write-Host "`"$appxFileName`" installed successfully."}
    }
  }
} catch {
  throw "Error occured"
  return $false
}

Write-Host "HEIC extension feature enabled successfully."
return $true