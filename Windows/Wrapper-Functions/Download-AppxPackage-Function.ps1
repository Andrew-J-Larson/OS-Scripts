<#
  .SYNOPSIS
  Download AppxPackage Function v2.0.3

  .DESCRIPTION
  Script that contains a function which helps facilitate downloading Microsoft Store apps from their servers (via third-party API's).
  
  The function is meant to be used as an alternative from the Microsoft Store and winget, to download application
  packages, for installation, such as in the case where an app is blocked from being downloaded directly from
  the store (e.g. HEVC Video Extensions from Device Manufacturer).
  
  By default, the function downloads the latest Retail version of the .msixbundle/.appxbundle/.msix/.appx files, for your
  system's architecture. That means internet access is required.

  The script doesn't automatically start the function.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Script: None. You cannot pipe objects to this script.
  Function: Only takes one argument, the PackageFamilyName as a string

  .OUTPUTS
  Script: Only will activate the function in the current PowerShell session.
  Function: Display errors if any, but returned is an array of paths to successfully downloaded files.

  .EXAMPLE
  PS> [Array]$packages = Download-AppxPackage "Clipchamp.Clipchamp_yxz26nhyzhsrt"

  .LINK
  Third-Party API for Downloading Microsoft Store Apps: https://store.rg-adguard.net/

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/Download-AppxPackage-Function.ps1
#>

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

# MAIN function
function Download-AppxPackage {
  $DownloadedFiles = @()
  $errored = $false
  $allFilesDownloaded = $true

  $apiUrl = "https://store.rg-adguard.net/api/GetFiles"
  $versionRing = "Retail"

  $architecture = switch ($env:PROCESSOR_ARCHITECTURE) {
    "x86" { "x86" }
    { @("x64", "amd64") -contains $_ } { "x64" }
    "arm" { "arm" }
    "arm64" { "arm64" }
    default { "neutral" } # should never get here
  }

  $AppxPackageFamilyName = $args[0]
  # $AppxName = $AppxPackageFamilyName.split('_')[0]

  $downloadFolder = Join-Path $env:TEMP "StoreDownloads"
  if (!(Test-Path $downloadFolder -PathType Container)) {
    [void](New-Item $downloadFolder -ItemType Directory -Force)
  }

  $body = @{
    type = 'PackageFamilyName'
    url  = $AppxPackageFamilyName
    ring = $versionRing
    lang = 'en-US'
  }

  $raw = $null
  try {
    $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -ContentType 'application/x-www-form-urlencoded' -Body $body
  } catch {
    $errorMsg = "An error occurred: " + $_
    Write-Host $errorMsg
    $errored = $true
    return $false
  }

  # hashtable of packages by $name
  #  > values = hashtables of packages by $version
  #    > values = arrays of packages as objects (containing: url, filename, name, version, arch, publisherId, type)
  [Collections.Generic.Dictionary[string, Collections.Generic.Dictionary[string, array]]] $packageList = @{}
  # populate $packageList
  $patternUrlAndText = '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*\.(app|msi)x.*)<\/a>'
  $raw | Select-String $patternUrlAndText -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object {
    $url = ($_.Groups['url']).Value
    $text = ($_.Groups['text']).Value
    $textSplitUnderscore = $text.split('_')
    $name = $textSplitUnderscore.split('_')[0]
    $version = $textSplitUnderscore.split('_')[1]
    $arch = ($textSplitUnderscore.split('_')[2]).ToLower()
    $publisherId = ($textSplitUnderscore.split('_')[4]).split('.')[0]
    $textSplitPeriod = $text.split('.')
    $type = ($textSplitPeriod[$textSplitPeriod.length - 1]).ToLower()

    # create $name hash key hashtable, if it doesn't already exist
    if (!($packageList.keys -match ('^' + [Regex]::escape($name) + '$'))) {
      $packageList["$name"] = @{}
    }
    # create $version hash key array, if it doesn't already exist
    if (!(($packageList["$name"]).keys -match ('^' + [Regex]::escape($version) + '$'))) {
      ($packageList["$name"])["$version"] = @()
    }
 
    # add package to the array in the hashtable
    ($packageList["$name"])["$version"] += @{
      url         = $url
      filename    = $text
      name        = $name
      version     = $version
      arch        = $arch
      publisherId = $publisherId
      type        = $type
    }
  }

  # an array of packages as objects, meant to only contain one of each $name
  $latestPackages = @()
  # grabs the most updated package for $name and puts it into $latestPackages
  $packageList.GetEnumerator() | ForEach-Object { ($_.value).GetEnumerator() | Select-Object -Last 1 } | ForEach-Object {
    $packagesByType = $_.value
    $msixbundle = ($packagesByType | Where-Object { $_.type -match "^msixbundle$" })
    $appxbundle = ($packagesByType | Where-Object { $_.type -match "^appxbundle$" })
    $msix = ($packagesByType | Where-Object { ($_.type -match "^msix$") -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
    $appx = ($packagesByType | Where-Object { ($_.type -match "^appx$") -And ($_.arch -match ('^' + [Regex]::Escape($architecture) + '$')) })
    if ($msixbundle) { $latestPackages += $msixbundle }
    elseif ($appxbundle) { $latestPackages += $appxbundle }
    elseif ($msix) { $latestPackages += $msix }
    elseif ($appx) { $latestPackages += $appx }
  }

  # download packages
  $latestPackages | ForEach-Object {
    $url = $_.url
    $filename = $_.filename
    # TODO: may need to include detection in the future of expired package download URLs..... in the case that downloads take over 10 minutes to complete

    $downloadFile = Join-Path $downloadFolder $filename

    # If file already exists, ask to replace it
    if (Test-Path $downloadFile) {
      Write-Host "`"${filename}`" already exists at `"${downloadFile}`"."
      $confirmation = ''
      while (!(($confirmation -eq 'Y') -Or ($confirmation -eq 'N'))) {
        $confirmation = Read-Host "`nWould you like to re-download and overwrite the file at `"${downloadFile}`" (Y/N)?"
        $confirmation = $confirmation.ToUpper()
      }
      if ($confirmation -eq 'Y') {
        Remove-Item -Path $downloadFile -Force
      } else {
        $DownloadedFiles += $downloadFile
      }
    }

    if (!(Test-Path $downloadFile)) {
      Write-Host "Attempting download of `"${filename}`" to `"${downloadFile}`" . . ."
      $fileDownloaded = $null
      try {
        Invoke-WebRequest -Uri $url -OutFile $downloadFile
        $fileDownloaded = $?
      } catch {
        $errorMsg = "An error occurred: " + $_
        Write-Host $errorMsg
        $errored = $true
        break $false
      }
      if ($fileDownloaded) { $DownloadedFiles += $downloadFile }
      else { $allFilesDownloaded = $false }
    }
  }

  if ($errored) { Write-Host "Completed with some errors." }
  if (-Not $allFilesDownloaded) { Write-Host "Warning: Not all packages could be downloaded." }
  return $DownloadedFiles
}
