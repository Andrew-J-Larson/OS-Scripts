<#
  .SYNOPSIS
  Install WinGet Function v1.3.1

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
  Windows Package Manager (WinGet): https://github.com/microsoft/winget-cli

  .LINK
  Microsoft.UI.Xaml (WinGet requirement): https://www.nuget.org/packages/Microsoft.UI.Xaml/
  
  .LINK
  Microsoft.VCLibs (WinGet requirement): https://learn.microsoft.com/en-us/troubleshoot/developer/visualstudio/cpp/libraries/c-runtime-packages-desktop-bridge

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Wrapper-Functions/Install-WinGet-Function.ps1
#>

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

  # CONSTANTS

  $osIsWindows = (-Not (Test-Path variable:global:isWindows)) -Or $isWindows # required for PS 5.1
  $osIsARM = $env:PROCESSOR_ARCHITECTURE -match '^arm.*'
  $osIs64Bit = [System.Environment]::Is64BitOperatingSystem
  $osArch = $( # architecture is required for some parts of the install process
    if ($osIsARM) { 'arm' } else { 'x' }
  ) + $(
    if ($osIs64Bit) { '64' } elseif (-Not $osIsARM) { '86' }
  ) # = x86 | x64 | arm | arm64
  $osVersion = [System.Environment]::OSVersion.Version
  $osName = if ($PSVersionTable.OS) {
    $PSVersionTable.OS
  } else { # required for PS 5.1
    ((([System.Environment]::OSVersion.VersionString.split() |
    Select-Object -Index 0,1,3) -join ' ').split('.') |
    Select-Object -First 3) -join '.'
  }
  $experimentalWindowsVersion = [System.Version]'10.0.16299.0' # first Windows version with MSIX features: https://learn.microsoft.com/en-us/windows/msix/supported-platforms
  $supportedWindowsVersion = [System.Version]'10.0.17763.0' # oldest Windows version that WinGet supports: https://github.com/microsoft/winget-cli?tab=readme-ov-file#installing-the-client
  $retiredWingetVersion = [System.Version]'1.2' # if on this version or older, WinGet must be updated, due to retired CDNs
  $experimentalWarning = "(things may not work properly)"
  $continuePrompt = "Press any key to continue or CTRL+C to quit"
  $envTEMP = (Get-Item -LiteralPath $( # Required due to PowerShell bug with shortnames appearing when they shouldn't be
    if (Test-Path variable:global:TEMP) {
      $env:TEMP
    } else { # Required for non-Windows
      [System.IO.Path]::GetTempPath().TrimEnd('\')
    }
  )).FullName 
  $loopDelay = 1 # second
  $appxInstallDelay = 3 # seconds

  # Error exit codes

  $FAILED = @{
    INSTALL                = 6
    DEPENDENCIES_CHECK     = 5
    INVALID_FILE_EXTENSION = 4
    NO_INTERNET            = 3
    NO_MSIX_FEATURE        = 2
    NOT_WINDOWS            = 1
  }

  # FUNCTIONS

  # winget can't normally be ran under system, unless it's specifically called by the EXE
  # code via https://github.com/Romanitho/Winget-Install/blob/main/winget-install.ps1
  function Get-WingetCmd {

      $WingetCmd = $null

      #Get WinGet Path
      try {
          #Get Admin Context Winget Location
          $WingetInfo = (Get-Item "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_8wekyb3d8bbwe\winget.exe").VersionInfo | Sort-Object -Property FileVersionRaw
          #If multiple versions, pick most recent one
          $WingetCmd = $WingetInfo[-1].FileName
      }
      catch {
          #Get User context Winget Location
          if (Test-Path "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe") {
              $WingetCmd = "$env:LocalAppData\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\winget.exe"
          }
      }

      return $WingetCmd
  }

  function Test-WinGet {
    # makes sure that winget can work properly (when ran from user profiles)
    if ($env:username -ne 'SYSTEM') {
      try {
        $wingetAppxPackages = @('Microsoft.DesktopAppInstaller', 'Microsoft.Winget.Source')
        ForEach ($package in $wingetAppxPackages) {
          if (-Not (Get-AppxPackage -Name $package)) {
            Get-AppxPackage -Name $package -AllUsers | ForEach-Object {
              Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml" | Out-Null
            }
          }
        }
      } catch {
        Write-Warning "Issues activating Winget."
      }
    }

    $exists = (Get-Command 'winget.exe' -ErrorAction SilentlyContinue) -Or (Get-WingetCmd)
    return $exists
  }

  # VARIABLES

  $forceWingetUpdate = $Force.IsPresent

  # MAIN

  # only for Windows 10 and newer
  Write-Host "Operating System = ${osName}`n"
  if (-Not $osIsWindows) {
    Write-Error "WinGet is only for Windows 10 and newer versions."
    return $FAILED.NOT_WINDOWS
  }

  # only experimental on Windows 10 (1709) and newer, where MSIX features are available
  $supportedWindowsBuild = "WinGet is only supported on Windows 10 (build $($supportedWindowsVersion.Build)) and newer versions"
  if ($experimentalWindowsVersion -gt $osVersion) {
    Write-Error "${supportedWindowsBuild}, and is only experimental on versions at or above Windows 10 (build $($experimentalWindowsVersion.Build)) ${experimentalWarning}."
    return $FAILED.NO_MSIX_FEATURE
  }

  # only supported on Windows 10 (1809) and newer, warn about unsupported Windows versions
  if ($supportedWindowsVersion -gt $osVersion) {
    Write-Warning "${supportedWindowsBuild} ${experimentalWarning}."
    Read-Host -Prompt $continuePrompt | Out-Null
    Write-Host '' # Makes log look better
  }

  # only supported on Windows (Work Station) versions, warn about unsupported Windows Server versions
  if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 1) {
    Write-Warning "WinGet isn't supported on Windows Server versions ${experimentalWarning}."
    Read-Host -Prompt $continuePrompt | Out-Null
    Write-Host '' # Makes log look better
  }

  # check for elevated powershell, and grab AppxPackage data from all users
  $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  $elevatedPowershell = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  # Installing packages is based on the user profile currently loaded into powershell:
  #   If the original user account (without admin rights) attempts to use a second user account (with
  #   admin rights) to elevate the Install-WinGet function in any way before the automatic elevation,
  #   then it will load the profile of the second user account instead, and therefore will install
  #   WinGet to the second user's profile, instead of the original user's profile
  $appxPackagesAllUsers = $Null
  if ($elevatedPowershell) {
    # warn about running in elevated powershell as a different user
    $loggedOnUser = (Get-CimInstance Win32_ComputerSystem).Username
    $elevatedUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $wdagUtilUser = (Get-CimInstance Win32_ComputerSystem).Name + '\WDAGUtilityAccount'
    if (($loggedOnUser -ne $elevatedUser) -And ($wdagUtilUser -ne $elevatedUser)) {
      Write-Host -NoNewline "Logged in as non-admin user "
      Write-Host -NoNewline $loggedOnUser -BackgroundColor Blue
      Write-Host -NoNewline ", but elevated as admin user "
      Write-Host -NoNewline $elevatedUser -BackgroundColor DarkRed
      Write-Host "."
      Write-Warning "WinGet will be installed in the following user's profile: ${elevatedUser}"
      Write-Host -NoNewline "If this is not the intention, run the " -ForegroundColor Yellow
      Write-Host -NoNewline "script" -ForegroundColor Cyan
      Write-Host -NoNewline ", or " -ForegroundColor Yellow
      Write-Host -NoNewline "Install-WinGet" -ForegroundColor Cyan
      Write-Host " function, again, but" -ForegroundColor Yellow
      Write-Host -NoNewline "don't run it as admin" -BackgroundColor Red
      Write-Host ", to install in the following user's profile: ${loggedOnUser}`n" -ForegroundColor Yellow
      Read-Host -Prompt $continuePrompt | Out-Null
    }
    $appxPackagesAllUsers = @(Get-AppxPackage -AllUsers)
  } else {
    Write-Warning "Elevation required to install WinGet for the logged on user."
    $tempFileForElevatedData = New-TemporaryFile
    Start-Process 'powershell.exe' -ArgumentList "-command `"& { Get-AppxPackage -AllUsers | Export-Clixml '$($tempFileForElevatedData.FullName)' }`"" -Verb RunAs -Wait -WindowStyle Hidden
    $elevatedData = Import-Clixml -LiteralPath $tempFileForElevatedData
    $tempFileForElevatedData | Remove-Item -Force -ErrorAction SilentlyContinue
    $appxPackagesAllUsers = @($elevatedData)
  }

  # if we can't find WinGet, try re-registering it (only a first time logon issue)
  $desktopAppInstaller = $appxPackagesAllUsers | Where-Object { $_.Name -eq "Microsoft.DesktopAppInstaller"}
  if ($desktopAppInstaller) {
    if (-Not (Test-WinGet)) {
      # if the version is new enough to contain WinGet, this should fix things
      Add-AppxPackage -DisableDevelopmentMode -Register "$($desktopAppInstaller.InstallLocation)\AppxManifest.xml"
      # need to wait a moment to allow Windows to recognize registration
      Start-Sleep -Seconds $appxInstallDelay
    }
    if ((-Not $forceWingetUpdate) -And (Test-WinGet)) {
      # if WinGet version is retired, force it to update
      $currentWingetVersion = [System.Version](
        ((& (Get-WingetCmd) -v).split('v')[1].split('.') | Select-Object -First 2) -join '.'
      )
      $forceWingetUpdate = ($currentWingetVersion -le $retiredWingetVersion)
    }
  }

  # if WinGet is still not found, download WinGet package with any dependent packages, and attempt install
  if ($forceWingetUpdate -Or (-Not (Test-WinGet))) {
    # Internet connection check
    $InternetAccess = (Get-NetConnectionProfile).IPv4Connectivity -contains "Internet" -or (Get-NetConnectionProfile).IPv6Connectivity -contains "Internet"
    if (-Not $InternetAccess) {
      Write-Error "Please connect to the internet first. Aborting."
      return $FAILED.NO_INTERNET
    }

    Write-Host "Downloading WinGet...`n"
    $wingetLatestDownloadURL = "https://aka.ms/getwinget"
    $tempWingetPackage = $Null
    while (-Not $tempWingetPackage) {
      # need to loop until WinGet package is downloaded
      $PreviousProgressPreference = $ProgressPreference
      $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
      $tempWingetWebResponse = Invoke-WebRequest -Uri $wingetLatestDownloadURL -UseBasicParsing
      $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
      if ($tempWingetWebResponse.StatusCode -eq 200) {
        # confirm file extension is correct
        $tempWingetFileName = ([System.Net.Mime.ContentDisposition]$tempWingetWebResponse.Headers.'Content-Disposition').FileName
        if (-Not $tempWingetFileName.EndsWith(".msixbundle")) {
          Write-Error "File downloaded doesn't have the correct file extension."
          return $FAILED.INVALID_FILE_EXTENSION
        }
        $tempWingetPackage = $envTEMP + '\' + $tempWingetFileName
        # save to file
        $tempWingetFile = [System.IO.FileStream]::new($tempWingetPackage, [System.IO.FileMode]::Create)
        $tempWingetFile.write($tempWingetWebResponse.Content, 0, $tempWingetWebResponse.Content.Length)
        $tempWingetFile.close()
        Write-Host "Downloaded WinGet.`n"
      } else { Start-Sleep -Seconds $loopDelay }
    }

    # check for dependencies in WinGet that are not met, and only grab what we need
    Write-Host "Confirming dependencies for WinGet...`n"
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
        Write-Host "Checked dependencies for WinGet.`n"
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
          $dependencyPackage.fileName = "Microsoft.VCLibs.${osArch}." + $dependencyPackage.version + '.00.Desktop.appx'
          $dependencyPackage.url = 'https://aka.ms/' + $dependencyPackage.fileName
        } else {
          Write-Warning "Unexpected new dependency found for WinGet: $($packageElement.Name))"
        }

        # if we have a known dependency, download and work on them if needed
        $dependencyPackage.name = $packageElement.Name
        if ($dependencyPackage) {
          $dependencyPackagePreinstalledList = $Null
          # only re-register newest dependency if we have an equal or newer version already installed (don't try to download package)
          $dependencyPackagePreinstalledCheckList = @(
            $appxPackagesAllUsers | Where-Object { $_.Name -eq $dependencyPackage.name} | Where-Object {
              [System.Version]($_.Version) -ge [System.Version]($packageElement.MinVersion)
            }
          )
          # only grabs the packages that match the highest version found, avoids issues with architecture guessing
          if ($dependencyPackagePreinstalledCheckList) {
            $dependencyPackagePreinstalledHighestVersion = $dependencyPackagePreinstalledCheckList | Sort-Object -Property Version | Select-Object -Last 1 -ExpandProperty Version
            $dependencyPackagePreinstalledList = @(
              $dependencyPackagePreinstalledCheckList | Where-Object {
                [System.Version]$_.Version -eq $dependencyPackagePreinstalledHighestVersion
              }
            )
          }

          # sometimes may have more than one architecture of the package that needs to be registered
          if ($dependencyPackagePreinstalledList) {
            for ($archIndex = 0; $archIndex -lt $dependencyPackagePreinstalledList.length; $archIndex++) {
              $dependencyPackagePreinstalled = $dependencyPackagePreinstalledList[$archIndex]
              $dependencyArch = $dependencyPackagePreinstalled.Architecture
              Write-Host "Registering an ${dependencyArch} dependency for WinGet...`n"
              $registeredDependency = $True
              try {
                Add-AppxPackage -DisableDevelopmentMode -Register "$($dependencyPackagePreinstalled.InstallLocation)\AppxManifest.xml"
              } catch {
                $registeredDependency = $False
              }
              if ($registeredDependency) {
                $dependencyPackage.preinstalled = $True
                Write-Host "Successfully registered an ${dependencyArch} dependency for WinGet.`n"
              } else {
                Write-Warning "Failed to register an ${dependencyArch} dependency for WinGet. (`"$($dependencyPackage.name)`")"
                Write-Host '' # Makes log look better
              }
            }
          } else {
            # try to download dependency
            $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.fileName
            Write-Host "Downloading a dependency for WinGet...`n"
            $PreviousProgressPreference = $ProgressPreference
            $ProgressPreference = "SilentlyContinue" # avoids slow download when using Invoke-WebRequest
            while ((Invoke-WebRequest -Uri $dependencyPackage.url -OutFile $dependencyPackage.file -UseBasicParsing -PassThru).StatusCode -ne 200) {
              # need to loop until dependency package is downloaded, or we timeout
              Start-Sleep -Seconds $loopDelay
              $dependencyPackageDownloadTime += $loopDelay
            }
            $ProgressPreference = $PreviousProgressPreference # return ProgressPreference back to normal
  
            # need to see if package is uiXaml, if so, extract dependency needed
            $packageIsUiXaml = ($dependencyPackage -eq $wingetDependencies.uiXaml) -And $dependencyPackage.file
            $successMsg = @("Successfully downloaded a ", "dependency for Winget.`n")
            if ($packageIsUiXaml) {
              Write-Host "$($successMsg -Join 'source file containing a ')"
  
              Write-Host "Extracting dependency, from downloaded source file, for WinGet...`n"
              $uiXamlNupkg = $dependencyPackage.file
              $dependencyPackage.file = $envTEMP + '\' + $dependencyPackage.name
              $uiXamlNupkgZip = $Null
              try {
                $uiXamlNupkgZip = [IO.Compression.ZipFile]::OpenRead($uiXamlNupkg)
                $uiXamlNupkgZipAppx = $uiXamlNupkgZip.Entries | Where-Object { $_.FullName -like "*/${osArch}/*/$($dependencyPackage.name).appx" }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($uiXamlNupkgZipAppx, $dependencyPackage.file, $true)
              } catch {
                $dependencyPackage.file = $Null
              }
              if ($dependencyPackage.file) {
                Write-Host "Successfully extracted dependency, from downloaded source file, for WinGet.`n"
              } else {
                Write-Warning "Failed to extract dependency, from downloaded source file, for WinGet. (`"$($dependencyPackage.name)`")"
                Write-Host '' # Makes log look better
              }
              if ($uiXamlNupkgZip) { $uiXamlNupkgZip.Dispose() }
              Remove-Item -Path $uiXamlNupkgZip -Force -ErrorAction SilentlyContinue
            } else {
              Write-Host "$($successMsg -Join '')"
            }
            if ($packageIsUiXaml -And (-Not $dependencyPackage.file)) { throw 'extracting dependency failed' }
          }
        }
      }
    } catch {
      $wingetDependencies.uiXaml = $False
      $wingetDependencies.vcLibs = $False
      if ($wingetPackageZip) { $wingetPackageZip.Dispose() }
      if ($appManifestReader) { $appManifestReader.Close() }
      if ($appManifestStream) { $appManifestStream.Close() }
      if ($appInstallerMsixZip) { $appInstallerMsixZip.Dispose() }
      Write-Error "Failed to check dependencies for WinGet."
      return $FAILED.DEPENDENCIES_CHECK
    }

    # install WinGet (updates Desktop App Installer) with any missing dependencies prior
    Write-Host "Installing WinGet...`n"
    $DesktopAppInstallerRunning = $False
    do {

      Start-Sleep -Seconds $appxInstallDelay
    } while ($DesktopAppInstallerRunning)
    $wingetInstalled = $True
    try {
      $dependencyFiles = @()
      if ($wingetDependencies.vcLibs -And $wingetDependencies.vcLibs.file) { $dependencyFiles += , ($wingetDependencies.vcLibs.file) }
      if ($wingetDependencies.uiXaml -And $wingetDependencies.uiXaml.file) { $dependencyFiles += , ($wingetDependencies.uiXaml.file) }
      $addPackageCommand = 'Add-AppxPackage -Path "' + $tempWingetPackage + '" -ForceTargetApplicationShutdown'
      if ($dependencyFiles) { $addPackageCommand += ' -DependencyPath "' + "$($dependencyFiles -Join '","')" + '"' }
      Invoke-Expression $addPackageCommand
      # need to wait a moment to allow install to register with Windows
      Start-Sleep -Seconds $appxInstallDelay
    } catch {
      $wingetInstalled = $False
    }
    # delete left over files no longer needed
    if ($dependencyFiles) { $dependencyFiles | ForEach-Object { Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue } }
    Remove-Item -Path $tempWingetPackage -Force -ErrorAction SilentlyContinue
    $result = 0
    if ($wingetInstalled -And (Test-WinGet)) {
      Write-Host "WinGet successfully installed.`n"
    } else {
      Write-Error = "WinGet failed to install."
      $result = $FAILED.INSTALL
    }
    return $result
  } else {
    # special return of results, if a working version of WinGet is already installed
    Write-Host "WinGet is already installed.`n"
    return 0
  }
}
