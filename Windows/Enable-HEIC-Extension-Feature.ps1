# 1/06/2023
# This powershell script automatically goes through the process of installing the needed extension apps from the Microsoft Store (servers) to have support for viewing/editing HEIF/HEVC/HEIC file types.
# * Dell machines support installation of the "HEVC Video Extensions from Device Manufacturer" app for free from the app store, but it's not something you can search for to install.
# * HEIC is a proprietary file type by Apple which combines the use of HEIF/HEVC in an HEIC container.

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

# Constants
Set-Variable HEIF_MSSTORE_APP_ID -Option Constant -Value "9PMMSR1CGPWG"
Set-Variable HEVC_MSSTORE_APP_ID -Option Constant -Value "9N4WGH0Z6VHQ"

# Functions

# Only takes a single argument as the ProductId of an application in the Microsoft Store
function Download-AppxPackage {
  $apiUrl = "https://store.rg-adguard.net/api/GetFiles"

  $ProductId = $args[0]

  $downloadFolder = Join-Path $env:TEMP "StoreDownloads"
  if(!(Test-Path $downloadFolder -PathType Container)) {
    New-Item $downloadFolder -ItemType Directory -Force
  }

  $body = @{
    type = 'ProductId'
    url  = $ProductId
    ring = 'Retail'
    lang = 'en-US'
  }

  $raw = Invoke-RestMethod -Method Post -Uri $apiUrl -ContentType 'application/x-www-form-urlencoded' -Body $body

  $raw | Select-String '<tr style.*<a href=\"(?<url>.*)"\s.*>(?<text>.*)<\/a>' -AllMatches|
   % { $_.Matches } |
   % { $url = $_.Groups[1].Value
       $text = $_.Groups[2].Value

       if($text -match "_x64.*`.appx(|bundle)$") {
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
             Remove-Item –Path $downloadFile -Force
           } else {
             return $downloadFile
           }
         }

         if (!(Test-Path $downloadFile)) {
           Write-Host "Attempting download of `"${text}`" to `"${downloadFile}`" . . ."
           Invoke-WebRequest -Uri $url -OutFile $downloadFile
           return $downloadFile
         }
       }
     }
}

# MAIN

# make sure we are online first
if (-Not $(Test-NetConnection -InformationLevel Quiet)) {
    throw "Please make sure you're connected to the internet, then try again."
}

# need to make sure the logged in user is running the script
$powershellUser = $(whoami)
$loggedInUser = $(Get-WMIObject -class Win32_ComputerSystem).username.toString()
if ($powershellUser -ne $loggedInUser) {
    throw "Please make sure the script is running as user (e.g. don't run as admin)."
}

# Now we just need the HEIF and HEVC extension apps installed
try {
  # need HEIF installed first, if not already
  if (Get-AppxPackage -Name "Microsoft.HEIFImageExtension") {
    Write-Host '"HEIF Image Extensions" already installed.'
  } else {
    $appxHEIF = Download-AppxPackage ${HEIF_MSSTORE_APP_ID}
    Write-Host 'Installing "HEIF Image Extensions"...'
    Add-AppxPackage -Path $appxHEIF
    if ($?) {Write-Host '"HEIF Image Extensions" installed successfully.'}
  }
  # need HEVC (device manufacturer version) installed after
  if (Get-AppxPackage -Name "Microsoft.HEVCVideoExtension") {
    Write-Host '"HEVC Video Extensions from Device Manufacturer" already installed.'
  } else {
    $appxHEVC = Download-AppxPackage ${HEVC_MSSTORE_APP_ID}
    Write-Host 'Installing "HEVC Video Extensions from Device Manufacturer"...'
    Add-AppxPackage -Path $appxHEVC
    if ($?) {Write-Host '"HEVC Video Extensions from Device Manufacturer" installed successfully.'}
  }
} catch {
  throw "Error occured"
}

Write-Host "HEIC extension feature installed successfully."
