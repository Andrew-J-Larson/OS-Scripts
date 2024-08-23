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

# Install OpenVPN along with the config file
$envTEMP = (Get-Item -LiteralPath $env:TEMP).FullName # Required due to PowerShell bug with shortnames appearing when they shouldn't be
$loopDelay = 1 # second
$maxTries = 10 # times before aborting failed attempt to find download
$appTitle = 'OpenVPN'
$configOVPN = "${PSScriptRoot}\example-config.ovpn"
$ovpnFolder = $env:ProgramFiles + "\OpenVPN"
$ovpnConfigFolder = $ovpnFolder + "\config"
$ovpnBinEXE = $ovpnFolder + "\bin\openvpn.exe"
$ovpnDownloadsURL = 'https://openvpn.net/community-downloads/'
$ovpnDownloadPattern = '(?<=<a href=")[^"]*\-amd64\.msi(?=")'
Write-Output "Attempting to install ${appTitle}..."
Write-Output '' # Makes log look better
$ovpnWasPreinstalled = (Get-Package -Name "OpenVPN *" -ErrorAction SilentlyContinue) -And (Test-Path -Path $ovpnBinEXE -PathType Leaf)
if ($ovpnWasPreinstalled) {
  Write-Output "${appTitle} is already installed, skipped."
} else {
  Write-Output "Downloading ${appTitle}..."
  Write-Output '' # Makes log look better
  # need to download the installer first
  $ovpnDownloadURL = $Null
  $ovpnDownloadAttempt = 0
  while (($ovpnDownloadAttempt -lt $maxTries) -And (-Not $ovpnDownloadURL)) {
    # need to loop until an MSI download URL is pulled from downloads
    $PreviousProgressPreference = $ProgressPreference
    $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
    $ovpnDownloadsGET = Invoke-WebRequest -Uri $ovpnDownloadsURL -UseBasicParsing
    $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
    if ($ovpnDownloadsGET.StatusCode -eq 200) {
      $ovpnDownloadURL = [Regex]::Matches($ovpnDownloadsGET.Content, $ovpnDownloadPattern)[0].Value
    } else {
      $ovpnDownloadAttempt++
      Start-Sleep -Seconds $loopDelay
    }
  }
  if ($ovpnDownloadURL) {
    $tempOvpnMSI = $envTEMP + '\' + $ovpnDownloadURL.substring($ovpnDownloadURL.LastIndexOf('/') + 1)
    $PreviousProgressPreference = $ProgressPreference
    $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
    while ((Invoke-WebRequest -Uri $ovpnDownloadURL -OutFile $tempOvpnMSI -UseBasicParsing -PassThru).StatusCode -ne 200) {
      # need to loop until OpenVPN installer is downloaded
      Start-Sleep -Seconds $loopDelay
    }
    $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
    Write-Output "Downloaded ${appTitle}."
    Write-Output '' # Makes log look better
    Write-Output "Installing ${appTitle}..."
    Write-Output '' # Makes log look better
    New-Item -ItemType Directory -Force -Path $ovpnConfigFolder -ErrorAction SilentlyContinue | Out-Null
    $configCopied = Copy-Item -Path $configOVPN -Destination $ovpnConfigFolder -PassThru -Force
    $setupArgs = "/i `"${tempOvpnMSI}`" /qn"
    $ovpnInstall = Start-Process 'msiexec.exe' -ArgumentList $setupArgs -NoNewWindow -PassThru -Wait
    Remove-Item -Path $tempOvpnMSI -Force -ErrorAction SilentlyContinue
    if ($configCopied -And (0 -eq $ovpnInstall.ExitCode)) {
      Write-Output "Successfully installed ${appTitle}."
    } else {
      $ovpnInstallError = ""
      if ($configCopied) {
        $ovpnInstallError += "the config being unable to copy"
        if ($ovpnInstall) { $ovpnInstallError += ' ' }
      }
      if (0 -ne $ovpnInstall.ExitCode) { $ovpnInstallError += "the installer failing (exit code: $($ovpnInstall.ExitCode))" }
      throw "Failed to install ${appTitle}, due to ${ovpnInstallError}."
    }
  } else {
    throw "Failed to download installer for ${appTitle}, the API or website might be down."
  }
}
Write-Output '' # Makes log look better
