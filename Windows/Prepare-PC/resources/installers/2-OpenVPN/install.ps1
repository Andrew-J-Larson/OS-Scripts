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

# Install OpenVPN along with the config file
$AppName = "OpenVPN"
$configOVPN = "${PSScriptRoot}\example-config.ovpn"
$ovpnFolder = $env:ProgramFiles + "\OpenVPN"
$ovpnConfigFolder = $ovpnFolder + "\config"
$ovpnBinEXE = $ovpnFolder + "\bin\openvpn.exe"
$ovpnWingetID = 'OpenVPNTechnologies.OpenVPN'
Write-Output "Attempting to install ${AppName}..."
Write-Output '' # Makes log look better
$ovpnWasPreinstalled = (Get-Package -Name "OpenVPN *" -ErrorAction SilentlyContinue) -And (Test-Path -Path $ovpnBinEXE -PathType Leaf)
if ($ovpnWasPreinstalled) {
  Write-Output "${AppName} is already installed, skipped."
} else {
  # copy config first
  New-Item -ItemType Directory -Force -Path $ovpnConfigFolder -ErrorAction SilentlyContinue | Out-Null
  $configCopied = Copy-Item -Path $configOVPN -Destination $ovpnConfigFolder -PassThru -Force
  # use winget to install
  $wingetArgs = 'install --id "' + $ovpnWingetID + '" --silent --accept-package-agreements --accept-source-agreements'
  $ovpnInstall = Start-Process 'winget.exe' -ArgumentList $wingetArgs -NoNewWindow -PassThru -Wait
  if ($configCopied -And (0 -eq $ovpnInstall.ExitCode)) {
    Write-Output "Successfully installed ${AppName}."
  } else {
    $ovpnInstallError = ""
    if (-Not $configCopied) {
      $ovpnInstallError += "the config being unable to copy"
      if (0 -ne $ovpnInstall.ExitCode) { $ovpnInstallError += ' and ' }
    }
    if (0 -ne $ovpnInstall.ExitCode) { $ovpnInstallError += "the installer failing (exit code: $($ovpnInstall.ExitCode))" }
    throw "Failed to install ${AppName}, due to ${ovpnInstallError}."
  }
}
Write-Output '' # Makes log look better
