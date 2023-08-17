#Requires -RunAsAdministrator

<# Copyright (C) 2023  Andrew Larson (andrew.j.larson18+github@gmail.com)

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
if ($provisioned) {
    Write-Output "Successfully provisioned ${appTitle}."
} else {
    Write-Warning "Failed to provision ${appTitle} (result: ${reason})."
}
Write-Output '' # Makes log look better
