#Requires -RunAsAdministrator

<# Copyright (C) 2024  Andrew Larson (andrew.j.larson18+github@gmail.com)

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

# Provisions Microsoft Accessory Center
$appTitle = 'Microsoft Accessory Center'
$packageFolder = $PSScriptRoot + '\package'
$dependencyPackagesFolder = $packageFolder + '\dependency_packages'
$provisioned = $Null
$canSkip = $False
$reason = "unknown"
Write-Output "Attempting to provision ${appTitle}..."
Write-Output '' # Makes log look better
if (Test-Path -Path $packageFolder) {
    $package = Get-ChildItem -Path $packageFolder -File
    if ($package) {
        $appPackageName = ($package.BaseName -Split '_')[0]
        # check if package is already provisioned
        $appAlreadyProvisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appPackageName }
        if ($appAlreadyProvisioned) {
            $reason = "already provisioned"
            $canSkip = $True
        } else {
            # setup provision command
            $provisionCommand = 'Add-AppxProvisionedPackage -Online -PackagePath "' + $package.FullName + '"'
            # check for and add dependencies if needed
            if (Test-Path -Path $dependencyPackagesFolder) {
                $dependencyPackages = @(Get-ChildItem -Path $dependencyPackagesFolder -File)
                if ($dependencyPackages) {
                    $dependencyPaths = @()
                    $dependencyPackages | ForEach-Object {
                        $reqPackageName = ($_.BaseName -Split '_')[0]
                        # only require dependency if it's not already provisioned
                        $reqAlreadyProvisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $reqPackageName }
                        if (-Not $reqAlreadyProvisioned) {
                            $dependencyPaths += , ('"' + $_.FullName + '"')
                        }
                    }
                    $provisionCommand += (' -DependencyPackagePath ' + ($dependencyPaths -join ','))
                }
            }
            $provisionCommand += ' -SkipLicense' # required, or else it won't provision

            # provision the package
            try {
                $provisioned = $True
                Invoke-Expression $provisionCommand | Out-Null
            } catch {
                $provisioned = $False
            }
        }
    } else {
        $reason = "package file missing"
    }
} else {
    $reason = "packages folder missing"
}
if ($provisioned -Or $canSkip) {
    if ($canSkip) {
        Write-Output "${appTitle} is ${reason}, skipped."
    } else {
        Write-Output "Successfully provisioned ${appTitle}."
    }
} else {
    throw "Failed to provision ${appTitle} (result: ${reason})."
}
Write-Output '' # Makes log look better

# --- NEW WIP CODE, WAITING ON FEATURE TO BE ADDED IN WINGET ---
# https://github.com/microsoft/winget-cli/issues/4154
# will need to modify code in the else (not provisioned) area
<# 
# Functions

function Test-WinGet { return Get-Command 'winget.exe' -ErrorAction SilentlyContinue }

# MAIN

# requires WinGet
if (-Not $(Test-WinGet)) {
  throw "Failed to provision ${appTitle}, WinGet needs to be installed first."
  return 1
}

# Provisions Microsoft Accessory Center if not already
$appTitle = 'Microsoft Accessory Center'
$appPackageName = 'Microsoft.MicrosoftAccessoryCenter'
$appStoreID = '9N013P0KR5VX'

# check if package is already provisioned
$appAlreadyProvisioned = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -eq $appPackageName }
if ($appAlreadyProvisioned) {
  Write-Output "${appTitle} is already provisioned."
} else {
  # check if package is already installed
  $appAlreadyInstalled = Get-AppxPackage -AllUsers $appPackageName
  if (-Not $appAlreadyInstalled) {
    Write-Output "Attempting to install ${appTitle}..."
    Write-Output '' # Makes log look better
    $installAppPackage = Start-Process 'winget.exe' -ArgumentList "install -h --id $appStoreID --accept-package-agreements --accept-source-agreements" -NoNewWindow -PassThru -Wait
    $appAlreadyInstalled = Get-AppxPackage -AllUsers $appPackageName
    if ($appAlreadyInstalled) {
      Write-Output "Successfully installed ${appTitle}."
      Write-Output '' # Makes log look better
    } else {
      throw "Failed to install ${appTitle}."
      Write-Output '' # Makes log look better
      return 1
    }
  }
  # attempt provision
  $provisioned = $True
  try {
    Add-AppxProvisionedPackage -Online -FolderPath $appAlreadyInstalled.InstallLocation
  } catch {
    $provisioned = $False
  }
  if ($provisioned) {
    Write-Output "Successfully provisioned ${appTitle}."
  } else {
    throw "Failed to provision ${appTitle}."
  }
  Write-Output '' # Makes log look better
}
 #>