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
$configFile = "${PSScriptRoot}\example-config.ovpn"
$appFolder = $env:ProgramFiles + "\OpenVPN"
$appConfigFolder = $appFolder + "\config"
$appEXE = $appFolder + "\bin\openvpn.exe"
$appWingetID = 'OpenVPNTechnologies.OpenVPN'
Write-Output "Attempting to install ${AppName}..."
Write-Output '' # Makes log look better
$appWasPreinstalled = (Get-Package -Name "OpenVPN *" -ErrorAction SilentlyContinue) -And (Test-Path -Path $appEXE -PathType Leaf)
if ($appWasPreinstalled) {
  Write-Output "${AppName} is already installed, skipped."
} else {
  # copy config first
  New-Item -ItemType Directory -Force -Path $appConfigFolder -ErrorAction SilentlyContinue | Out-Null
  $configCopied = Copy-Item -Path $configFile -Destination $appConfigFolder -PassThru -Force
  # use winget to install
  $wingetArgs = 'install --id "' + $appWingetID + '" --silent --scope machine --accept-package-agreements --accept-source-agreements'
  $appInstall = Start-Process 'winget.exe' -ArgumentList $wingetArgs -NoNewWindow -PassThru -Wait
  if ($configCopied -And (0 -eq $appInstall.ExitCode)) {
    Write-Output "Successfully installed ${AppName}."
  } else {
    $appInstallError = ""
    if (-Not $configCopied) {
      $appInstallError += "the config being unable to copy"
      if (0 -ne $appInstall.ExitCode) { $appInstallError += ' and ' }
    }
    if (0 -ne $appInstall.ExitCode) { $appInstallError += "the installer failing (exit code: $($appInstall.ExitCode))" }
    throw "Failed to install ${AppName}, due to ${appInstallError}."
  }
}
Write-Output '' # Makes log look better
