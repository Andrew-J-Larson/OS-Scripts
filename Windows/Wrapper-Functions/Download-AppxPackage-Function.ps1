<#
  .SYNOPSIS
  Script that helps facilitate downloading Microsoft Store apps from their servers (via third-party API's).

  .DESCRIPTION
  Version 1.0.6
  
  This script is meant to be used as an alternative from the Microsoft Store and winget, to download application
  packages, for installation, such as in the case where an app is blocked from being downloaded directly from
  the store (e.g. HEVC Video Extensions from Device Manufacturer).
  
  By default, the script downloads the the Retail version of the .appx files (as architecture of OS if available).

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Script: None. You cannot pipe objects to this script.
  Function: Only takes one argument, the product ID as a string

  .OUTPUTS
  Script: Only will activate the function in the current PowerShell session.
  Function: Display errors if any, but returned is an array of paths to successfully downloaded files.

  .EXAMPLE
  PS> [Array]$packages = Download-AppxPackage 9P1J8S7CCWWT # Product ID for "Clipchamp - Video Editor"

  .LINK
  Third-Party API for Downloading Microsoft Store Apps: https://store.rg-adguard.net/

  .LINK
  Script downloaded from: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Wrapper-Functions/Download-AppxPackage-Function.ps1
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

# MAIN function
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

  $packageList = $raw | Select-String '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches | % { $_.Matches } | % { $_.Groups[2].Value }

  $useArch = if ($packageList -match ".*_${arch}_.*") {$arch} else {"neutral"}

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

  if ($errored) {Write-Host "Completed with some errors."}
  if (-Not $allFilesDownloaded) {Write-Host "Warning: Not all packages could be downloaded."}
  return $DownloadedFiles
}

