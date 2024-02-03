<#
  .SYNOPSIS
  Install WinGet Function v1.0.0

  .DESCRIPTION
  Script contains a function which can be used to install WinGet (to current user profile) automatically.
  
  The function is meant to be used as an automated means of getting WinGet installed, including right after
  the OOBE setup. All quirks of getting WinGet install on a first startup are handled with this script
  (that includes grabbing all the required packages it relies on to work properly).
  
  By default, the function downloads the latest versions of packages required for WinGet to work, and the
  the latest version of WinGet itself. That means internet access is required.

  The script doesn't automatically start the function.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Script: None. You cannot pipe objects to this script.
  Function: Force switch (forcefully install WinGet).
            By default, without the force switch, WinGet won't be updated when a working version is detected.

  .OUTPUTS
  Script: Only will activate the function in the current PowerShell session.
  Function: Display errors if any, but returned is boolean based on if WinGet installed properly

  .EXAMPLE
  PS> Install-WinGet

  .EXAMPLE
  PS> Install-WinGet -Force

  .LINK
  winget-cli (WinGet source): https://github.com/microsoft/winget-cli

  .LINK
  Microsoft.UI.Xaml (WinGet requirement): https://www.nuget.org/packages/Microsoft.UI.Xaml/
  
  .LINK
  Microsoft.VCLibs (WinGet requirement): https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/libraries/c-runtime-packages-desktop-bridge

  .LINK
  Script downloaded from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/Install-WinGet-Function.ps1
#>

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
function Install-WinGet {
  param(
    [switch]$Force
  )

  # Constants
  
  $envTEMP = (Get-Item -LiteralPath $env:TEMP).FullName # Required due to PowerShell bug with shortnames appearing when they shouldn't be
  $loopDelay = 1 # second
  $appxInstallDelay = 3 # seconds
  $faultyWingetVersion = 'v1.2.10691'

  # Variables

  $forceWingetUpdate = $Force.IsPresent

  # Functions

  function Test-WinGet {
    return Get-Command 'winget.exe' -ErrorAction SilentlyContinue
  }

  # if we can't find WinGet, try re-registering it (only a first time logon issue)
  $desktopAppInstaller = Get-AppxPackage -AllUsers -Name "Microsoft.DesktopAppInstaller"
  if ($desktopAppInstaller) {
    if (-Not $(Test-WinGet)) {
      # if the version is new enough to contain WinGet, this should fix things
      Add-AppxPackage -DisableDevelopmentMode -Register "$($desktopAppInstaller.InstallLocation)\AppxManifest.xml"
      # need to wait a moment to allow Windows to recognize registration
      Start-Sleep -Seconds $appxInstallDelay
    } elseif ($faultyWingetVersion -eq $(winget -v)) {
      # if winget is a faulty version, it'll require a forced update
      $forceWingetUpdate = $True
    }
  }

  # if WinGet is still not found, download WinGet package with any dependent packages, and attempt install
  if ($forceWingetUpdate -Or (-Not $(Test-WinGet))) {
    # Internet connection check
    $InternetAccess = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"
    if (-Not $InternetAccess) {
      Write-Error "Please connect to the internet first. Aborting."
      exit 1
    }

    Write-Output "Downloading WinGet..."
    Write-Output '' # Makes log look better
    $wingetGitHubLatestURL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
    $wingetDownloadURL = $Null
    while (-Not $wingetDownloadURL) {
      # need to loop until download URL is pulled from GitHub
      try {
        $wingetDownloadURL = (Invoke-RestMethod -Uri $wingetGitHubLatestURL -UseBasicParsing).assets.browser_download_url | Where-Object { $_.EndsWith(".msixbundle") }
      } catch {
        $wingetDownloadURL = $Null
        Start-Sleep -Seconds $loopDelay
      }
    }
    $tempWingetPackage = $envTEMP + '\' + $wingetDownloadURL.substring($wingetDownloadURL.LastIndexOf('/') + 1)
    while ((Invoke-WebRequest -Uri $wingetDownloadURL -OutFile $tempWingetPackage -UseBasicParsing -PassThru).StatusCode -ne 200) {
      # need to loop until WinGet package is downloaded
      Start-Sleep -Seconds $loopDelay
    }
    Write-Output "Downloaded WinGet."
    Write-Output '' # Makes log look better

    # check for dependencies in WinGet that are not met, and only grab what we need
    Write-Output "Confirming dependencies for WinGet..."
    Write-Output '' # Makes log look better
    $wingetDependencies = @{
      # properties get set later
      uiXaml = @{
        # preinstalled
        # version
        # name
        # fileName
        # file
        # url
      }
      vcLibs = @{
        # preinstalled
        # version
        # name
        # fileName
        # file
        # url
      }
    }
    $wingetPackageZip = $Null
    $appManifestReader = $Null
    $appManifestStream = $Null
    $appInstallerMsixZip = $Null
    try {
      # required for checking inside packages
      Add-Type -Assembly System.IO.Compression.FileSystem

      # extract app installer msix from the WinGet package
      $appInstallerMsixFilename = 'AppInstaller_x64.msix'
      $tempAppInstallerMsix = $envTEMP + '\' + $appInstallerMsixFilename
      $wingetPackageZip = [IO.Compression.ZipFile]::OpenRead($tempWingetPackage)
      $appInstallerMsix = $wingetPackageZip.Entries | Where-Object { $_.FullName -eq $appInstallerMsixFilename }
      [System.IO.Compression.ZipFileExtensions]::ExtractToFile($appInstallerMsix, $tempAppInstallerMsix, $true)
      $wingetPackageZip.Dispose()

      # grab the app manifest from inside the app installer msix
      $appInstallerMsixZip = [IO.Compression.ZipFile]::OpenRead($tempAppInstallerMsix)
      $appxManifestXml = $appInstallerMsixZip.Entries | Where-Object { $_.FullName -eq 'AppxManifest.xml' }
      $appManifestStream = $appxManifestXml.Open()
      $appManifestReader = New-Object IO.StreamReader($appManifestStream)
      $appManifestText = $appManifestReader.ReadToEnd()
      $appManifestReader.Close()
      $appManifestStream.Close()
      $appInstallerMsixZip.Dispose()
      Remove-Item -Path $tempAppInstallerMsix -Force -ErrorAction SilentlyContinue
      $appManifest = [Xml]$appManifestText

      # setup objects in the dependencies hashtable
      $dependencyPackages = $appManifest.Package.Dependencies.PackageDependency
      if ($dependencyPackages) {
        Write-Output "Checked dependencies for WinGet."
        Write-Output '' # Makes log look better
      } else { throw "missing dependency packages" }
      $dependencyPackages | ForEach-Object {
        $packageElement = $_
        $dependencyPackage = $Null
        if ($packageElement.Name -like "Microsoft.UI.Xaml*") {
          $dependencyPackage = $wingetDependencies.uiXaml
          $dependencyPackage.version = @($packageElement.Name -Split "Microsoft.UI.Xaml.")[1]
          $uiXamlLatestVersion = $Null
          while (-Not ($dependencyPackage.url -And $uiXamlLatestVersion)) {
            # grabs the latest version number of the Major.Minor build
            try {
              $uiXamlVersionsNugetUrl = 'https://packages.nuget.org/api/v2/package-versions/Microsoft.UI.Xaml'
              $uiXamlLatestVersion = @(Invoke-RestMethod -Uri $uiXamlVersionsNugetUrl -UseBasicParsing)[0] | Where-Object { $_ -like "$($dependencyPackage.version)*" } | Select-Object -Last 1
              $dependencyPackage.url = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/' + $uiXamlLatestVersion
            } catch {
              $dependencyPackage.url = $Null
              Start-Sleep -Seconds $loopDelay
            }
          }
          $dependencyPackage.fileName = 'microsoft.ui.xaml.' + $uiXamlLatestVersion + '.nupkg'
        } elseif ($packageElement.Name -like "Microsoft.VCLibs*UWPDesktop") {
          $dependencyPackage = $wingetDependencies.vcLibs
          $dependencyPackage.version = ([System.Version]$packageElement.MinVersion).Major
          $dependencyPackage.fileName = 'Microsoft.VCLibs.x64.' + $dependencyPackage.version + '.00.Desktop.appx'
          $dependencyPackage.url = 'https://aka.ms/' + $dependencyPackage.fileName
        } else {
          Write-Warning "Unexpected new dependency found for WinGet: $($packageElement.Name))"
        }

        # if we have a known dependency, download and work on them if needed
        $dependencyPackage.name = $packageElement.Name
        if ($dependencyPackage) {
          # only re-register dependency if we have an equal or newer version already installed (don't try to download package)
          $dependencyPackagePreinstalledList = @(Get-AppxPackage -AllUsers -Name $dependencyPackage.name | Where-Object { [System.Version]$_.Version -ge [System.Version]$packageElement.MinVersion })

          # sometimes may have more than one architecture of the package that needs to be registered
          if ($dependencyPackagePreinstalledList) {
            for ($archIndex = 0; $archIndex -lt $dependencyPackagePreinstalledList.length; $archIndex++) {
              $dependencyPackagePreinstalled = $dependencyPackagePreinstalledList[$archIndex]
              $dependencyArch = $dependencyPackagePreinstalled.Architecture
              Write-Output "Registering an ${dependencyArch} dependency for WinGet..."
              Write-Output '' # Makes log look better
              $registeredDependency = $True
              try {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($dependencyPackagePreinstalled.InstallLocation)\AppxManifest.xml"
              } catch {
                $registeredDependency = $False
              }
              if ($registeredDependency) {
                $dependencyPackage.preinstalled = $True
                Write-Output "Successfully registered an ${dependencyArch} dependency for WinGet."
              } else {
                Write-Warning "Failed to register an ${dependencyArch} dependency for WinGet."
              }
              Write-Output '' # Makes log look better
            }
            return
          }

          # try to download dependency
          $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.fileName
          Write-Output "Downloading a dependency for WinGet..."
          Write-Output '' # Makes log look better
          while ((Invoke-WebRequest -Uri $dependencyPackage.url -OutFile $dependencyPackage.file -UseBasicParsing -PassThru).StatusCode -ne 200) {
            # need to loop until dependency package is downloaded, or we timeout
            Start-Sleep -Seconds $loopDelay
            $dependencyPackageDownloadTime += $loopDelay
          }

          # need to see if package is uiXaml, if so, extract dependency needed
          $packageIsUiXaml = ($dependencyPackage -eq $wingetDependencies.uiXaml) -And $dependencyPackage.file
          $successMsg = @("Successfully downloaded a ", "dependency for Winget.")
          if ($packageIsUiXaml) {
            Write-Output "$($successMsg -Join 'source file containing a ')"
            Write-Output '' # Makes log look better

            Write-Output "Extracting dependency, from downloaded source file, for WinGet..."
            Write-Output '' # Makes log look better
            $uiXamlNupkg = $dependencyPackage.file
            $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.name
            $uiXamlNupkgZip = $Null
            try {
              $uiXamlNupkgZip = [IO.Compression.ZipFile]::OpenRead($uiXamlNupkg)
              $uiXamlNupkgZipAppx = $uiXamlNupkgZip.Entries | Where-Object { $_.FullName -like "*/x64/*/$($dependencyPackage.name).appx" }
              [System.IO.Compression.ZipFileExtensions]::ExtractToFile($uiXamlNupkgZipAppx, $dependencyPackage.file, $true)
            } catch {
              $dependencyPackage.file = $Null
            }
            if ($dependencyPackage.file) {
              Write-Output "Successfully extracted dependency, from downloaded source file, for WinGet."
            } else {
              Write-Warning "Failed to extract dependency, from downloaded source file, for WinGet."
            }
            if ($uiXamlNupkgZip) { $uiXamlNupkgZip.Dispose() }
            Remove-Item -Path $uiXamlNupkgZip -Force -ErrorAction SilentlyContinue
          } else {
            Write-Output "$($successMsg -Join '')"
          }
          Write-Output '' # Makes log look better
          if ($packageIsUiXaml -And (-Not $dependencyPackage.file)) { throw 'extracting dependency failed' }
        }
      }
    } catch {
      Write-Error "Failed to check dependencies for WinGet."
      Write-Output '' # Makes log look better
      $wingetDependencies.uiXaml = $False
      $wingetDependencies.vcLibs = $False
      if ($wingetPackageZip) { $wingetPackageZip.Dispose() }
      if ($appManifestReader) { $appManifestReader.Close() }
      if ($appManifestStream) { $appManifestStream.Close() }
      if ($appInstallerMsixZip) { $appInstallerMsixZip.Dispose() }
    }

    # install WinGet (updates Desktop App Installer) with any missing dependencies prior
    Write-Output "Installing WinGet..."
    Write-Output '' # Makes log look better
    $wingetInstalled = $True
    try {
      $dependencyFiles = @()
      if ($wingetDependencies.vcLibs -And $wingetDependencies.vcLibs.file) { $dependencyFiles += , ($wingetDependencies.vcLibs.file) }
      if ($wingetDependencies.uiXaml -And $wingetDependencies.uiXaml.file) { $dependencyFiles += , ($wingetDependencies.uiXaml.file) }
      $addPackageCommand = 'Add-AppxPackage -Path "' + $tempWingetPackage + '"'
      if ($dependencyFiles) { $addPackageCommand += ' -DependencyPath "' + "$($dependencyFiles -Join '","')" + '"' }
      Invoke-Expression $addPackageCommand
      # need to wait a moment to allow install to register with Windows
      Start-Sleep -Seconds $appxInstallDelay
    } catch {
      $wingetInstalled = $False
    }
    if ($wingetInstalled) {
      Write-Output "Installed WinGet."
      Write-Output '' # Makes log look better
    }
    # delete left over files no longer needed
    if ($dependencyFiles) { $dependencyFiles | ForEach-Object { Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue } }
    Remove-Item -Path $tempWingetPackage -Force -ErrorAction SilentlyContinue
  } else {
    # special return of results, if a working version of WinGet is already installed
    Write-Output "WinGet is already installed."
    return 0
  }

  # return results from install attempt
  $noErrors = $error.count -eq 0
  $executableFound = $(Test-WinGet)
  if ($noErrors -And $executableFound) {
    Write-Output "WinGet successfully installed."
  } else {
    $errorMsg = "WinGet failed to install."

    $reasons = @()
    if (-Not $noErrors) {
      $reasons += @("some errors occured")
    }
    if (-Not $executableFound) {
      $reasons += @("executable couldn't be found")
    }
    if ($reasons.length -gt 0) {
      $errorMsg += " ($($reasons -join ', '))"
    }
    Write-Error $errorMsg
  }
  return $LastExitCode
}
