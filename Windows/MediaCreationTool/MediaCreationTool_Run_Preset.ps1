<#
  .SYNOPSIS
  MediaCreationTool Run Preset v1.0.4

  .DESCRIPTION
  Script helps to automate a part of the process needed to generate single edition ISOs.
  It'll automatically grab the latest Media Creation Tool (if there is a new version).
  Supports both Windows 10 and Windows 11 media creation.

  .PARAMETER OS
  Either 10 or 11 (default), to pick Windows 10 or Windows 11 respectively.

  .PARAMETER LangCode
  Defaults to en-US, but any support lang code can be used, see:
  https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/available-language-packs-for-windows?view=windows-11#language-packs

  .PARAMETER Edition
  Defaults to Home, but could be any of the base tier editions, including Enterprise.

  .PARAMETER Arch
  Either x86 or x64 (default), but will throw an error if attempting to use x86 for Windows 11 (or newer when Windows 12 comes out).

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Successes, warnings, and errors log to the console.

  .EXAMPLE
  .\Prepare-PC.ps1 # generates Windows 11 Home en-US

  .EXAMPLE
  .\Prepare-PC.ps1 -OS 10 # generates Windows 10 Home en-US x64

  .EXAMPLE
  .\Prepare-PC.ps1 -OS 10 -Arch x86 # generates Windows 10 Home en-US x86

  .EXAMPLE
  .\Prepare-PC.ps1 -OS 10 -Edition Pro # generates Windows 10 Pro en-US x64

  .EXAMPLE
  .\Prepare-PC.ps1 -OS 10 -Edition Edu # generates Windows 10 Education en-US x64

  .EXAMPLE
  .\Prepare-PC.ps1 -Edition Ent # generates Windows 11 Enterprise en-US

  .EXAMPLE
  .\Prepare-PC.ps1 -Help

  .EXAMPLE
  .\Prepare-PC.ps1 -h

  .NOTES
  Requires admin! Due to the Media Creation Tool requiring the signed in user to be admin, or ran inside Windows Sandbox.

  Primarily created as an alternative to https://github.com/AveYo/MediaCreationTool.bat (`MediaCreationTool.bat` usually sets off Defender).

  .LINK
  Having issues?: https://github.com/Andrew-J-Larson/OS-Scripts/issues/new?title=%5BBug%5D%20MediaCreationTool_Run_Preset.ps1&body=%3C%21--%20Please%20describe%20the%20issue%28s%29%20you%20are%20having%20below%2C%20and%20include%20steps%20to%20reproduce%20them%20--%3E%0A%0A

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/MediaCreationTool/MediaCreationTool_Run_Preset.ps1
#>
#Requires -RunAsAdministrator

<# Copyright (C) 2023  Andrew Larson (thealiendrew@gmail.com)

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

param (
    [Alias("h")]
    [switch]$Help,

    [Parameter(Mandatory = $False)]
    [ValidateSet(10, 11)]
    [Int]$OS = 11,

    [Parameter(Mandatory = $False)]
    [ValidateSet(
        "ar-SA", "eu-ES", "bg-BG", "ca-ES", "zh-TW", "zh-CN", "zh-TW", "hr-HR", "cs-CZ", "da-DK", "nl-NL",
        "en-US", "en-GB", "et-EE", "fi-FI", "fr-CA", "fr-FR", "gl-ES", "de-DE", "el-GR", "he-IL", "hu-HU",
        "id-ID", "it-IT", "ja-JP", "ko-KR", "lv-LV", "lt-LT", "nb-NO", "pl-PL", "pt-BR", "pt-PT", "ro-RO",
        "ru-RU", "sr-Latn-RS", "sk-SK", "sl-SI", "es-MX", "es-ES", "sv-SE", "th-TH", "tr-TR", "uk-UA", "vi-VN")]
    [String]$LangCode = "en-US",

    [Parameter(Mandatory = $False)]
    [ValidateSet( # `N` means 'Not with Media Player'
        # Home editions
        "Home", "HomeN",
        "HomeSL", # `SL` means 'Single Language'
        "HomeCS", # `CS` means 'Country Specific' (Windows 11+ only)
        # Pro editions
        "Pro", "ProN",
        "ProW", "ProWN", # `W` means 'for Workstations'
        # Education editions
        "Edu", "EduN",
        "EduP", "EduPN", # `P` means 'Pro'
        # Enterprise editions
        "Ent", "EntN",
        "EntG", "EntGN")] # `G` means 'Government'
    [String]$Edition = "Home",

    [Parameter(Mandatory = $False)]
    [ValidateSet("x86", "x64")]
    [String]$Arch = "x64"
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
    Get-Help $MyInvocation.MyCommand.Path
    exit
}

# CONSTANTS

# Error exit codes
$FAILED = @{
    INVALID_EDITION     = 6
    INVALID_ARCH        = 5
    INIT_MCT            = 4
    RUNNING_MCT         = 3
    ALREADY_RUNNING     = 2
    ADMIN_NOT_LOGGED_ON = 1
}

# FUNCTIONS

# modified code via https://devblogs.microsoft.com/powershell/show-powershell-hide-powershell/
# Show the powershell window maximized
$script:showWindowAsync = Add-Type -memberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -name "Win32ShowWindowAsync" -namespace Win32Functions -passThru
function Show-MaximizedPowerShell() {
    $null = $showWindowAsync::ShowWindowAsync((Get-Process -id $pid).MainWindowHandle, 3)
}

# modified code via https://stackoverflow.com/a/48622585/7312536
# Write host in center of console window, with color support
function Write-HostCenter {
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [Alias('Msg', 'Message')]
        [System.Object[]]$Object,
        [System.Object]$Separator,
        [System.ConsoleColor]$ForegroundColor,
        [System.ConsoleColor]$BackgroundColor,
        [switch]$NoNewline
    )
    $objectString = [String]$Object
    $arguments = @{
        Object          = if ($Object) {
            $pureString = "${objectString}" -replace '\x1b\[[0-9;]*m'
            ("{0}{1}" -f (' ' * (([Math]::Max(0, $Host.UI.RawUI.BufferSize.Width / 2) - [Math]::Floor($pureString.Length / 2)))), $objectString)
        } else { $Object }
        Separator       = $Separator
        ForegroundColor = $ForegroundColor
        BackgroundColor = $BackgroundColor
        NoNewline       = $NoNewline.IsPresent
    }
    # splat only arguments that are set
    if (-Not ($arguments.Object)) { $arguments.Remove('Object') }
    if (-Not ($arguments.Separator)) { $arguments.Remove('Separator') }
    if (-Not ($arguments.ForegroundColor)) { $arguments.Remove('ForegroundColor') }
    if (-Not ($arguments.BackgroundColor)) { $arguments.Remove('BackgroundColor') }
    if (-Not ($arguments.NoNewline)) { $arguments.Remove('NoNewline') }
    Write-Host @arguments
}
# Write warning in center of console window
function Write-WarningCenter {
    param($Message)
    $Message = "Warning: " + $Message
    Write-HostCenter $Message -ForegroundColor YELLOW
}

# Pause for Powershell
function Wait-Host {
    Write-Host -NoNewLine 'Press any key to continue...';
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');
}

# Creates a deep copy of a hashtable
# code via https://powershellexplained.com/2016-11-06-powershell-hashtable-everything-you-wanted-to-know-about/#deep-copies
function Get-DeepClone {
    [cmdletbinding()]
    param(
        $InputObject
    )
    process {
        if ($InputObject -is [hashtable]) {
            $clone = @{}
            foreach ($key in $InputObject.keys) {
                $clone[$key] = Get-DeepClone $InputObject[$key]
            }
            return $clone
        } else {
            return $InputObject
        }
    }
}

# Download latest MCT (if needed), and set exe value in object
function Initialize-MCT([Hashtable]$winVersionMCT) {
    # Make sure folder exists to place generate image at
    if (-Not (Test-Path -Path $winVersionMCT.folder)) {
        if (-Not (New-Item -Path $winVersionMCT.folder -ItemType Directory -ErrorAction SilentlyContinue)) {
            $errorMessage = "Something went wrong creating the following folder: " + $winVersionMCT.folder
            Write-Error $errorMessage
            return $False
        }
    }

    # Then grab new version of MCT, if needed
    Write-Host '' # text formatting
    Write-HostCenter "Checking if the $($winVersionMCT.os) Media Creation Tool has a new version..."
    $get_win_MCT = Invoke-WebRequest -Method Head -MaximumRedirection 0 -Uri $winVersionMCT.url -UseBasicParsing -ErrorAction SilentlyContinue
    if ((302 -eq $get_win_MCT.StatusCode) -And $get_win_MCT.Headers -And $get_win_MCT.Headers.Location) {
        $oldVersions = @(Get-ChildItem -Path $winVersionMCT.folder -Filter MediaCreationTool*.exe)
        $winVersionMCT_redirectURL = $get_win_MCT.Headers.Location
        $winVersionMCT.exe = $winVersionMCT.folder + '\' + ([uri]($winVersionMCT_redirectURL)).Segments[-1]
        $get_win_MCT_redirect = Invoke-WebRequest -Method Head -MaximumRedirection 0 -Uri $winVersionMCT_redirectURL -UseBasicParsing -ErrorAction SilentlyContinue
        
        # only download if we don't already have the file, or hosted version is newer
        $shouldDownload = -Not (Test-Path -Path $winVersionMCT.exe -PathType Leaf)
        $hostedFileTimestamp = '' # only gets set if we have a new version

        # if we couldn't get Last-Modified date, assume new version
        if ((200 -eq $get_win_MCT_redirect.StatusCode) -And $get_win_MCT_redirect.Headers -And $get_win_MCT_redirect.Headers.'Last-Modified') {
            $hostedFileTimestamp = $get_win_MCT_redirect.Headers.'Last-Modified'
            # compare local timestamp file if one exists, assume new version if it doesn't exist
            if (Test-Path -Path $winVersionMCT.timestampFile -PathType Leaf) {
                $localFileTimestamp = Get-Content -Path $winVersionMCT.timestampFile
                # compare, if mismatch, need to download
                if ($hostedFileTimestamp -eq $localFileTimestamp) {
                    $shouldDownload = $False
                } else {
                    $shouldDownload = $True
                }
            } else {
                $shouldDownload = $True
            }
        } else { $shouldDownload = $True }

        # download newest MCT
        if ($shouldDownload) {
            Clear-Host
            Write-Host '' # text formatting
            Write-HostCenter "Downloading the lastest $($winVersionMCT.os) Media Creation Tool..."
            $download_win_MCT = Invoke-WebRequest -Uri $winVersionMCT.url -OutFile $winVersionMCT.exe -UseBasicParsing -PassThru -ErrorAction SilentlyContinue
            $mctExists = Test-Path -Path $winVersionMCT.exe -PathType Leaf
            if ((200 -eq $download_win_MCT.StatusCode) -And $mctExists) {
                # if download succeeded...

                # if we have old versions, delete them
                if ($oldVersions.length -gt 0) {
                    $oldVersions | ForEach-Object {
                        Remove-Item -Path $_.FullName -Force -Confirm:$false
                    }
                }

                # if we were able to get a new timestamp, overwrite the timestamp file
                if ($hostedFileTimestamp) { Set-Content -Path $winVersionMCT.timestampFile -Value $hostedFileTimestamp }
            } else {
                # if download failed, and we have a partial download, delete it
                if ($mctExists) {
                    Remove-Item -Path $winVersionMCT.exe -Force -Confirm:$false
                }
                $errorMsg = "Failed to download the lastest $($winVersionMCT.os) Media Creation Tool."
                Write-Error $errorMsg
                return $False
            }
        }
        # find latest release string available, if not already set
        if (-Not $winVersionMCT.release) {
            $releaseHealthURL = "https://learn.microsoft.com/en-us/windows/release-health/"
            $releaseHealthRegex = '(?<=>' + $winVersionMCT.os + ', version )([a-zA-Z0-9]+)(?=<)'
            $getReleaseHealth = Invoke-WebRequest -Uri $releaseHealthURL -UseBasicParsing -ErrorAction SilentlyContinue
            $release = $Null
            $errored = $False
            if (200 -eq $getReleaseHealth.StatusCode) {
                $release = ($getReleaseHealth.content | Select-String $releaseHealthRegex).Matches
                if ($release) { $release = $release[0].Value }
            } else { $errored = $True }
            if ($release) {
                $winVersionMCT.release = $release
            } else { $errored = $True }
            if ($errored) {
                $errorMsg = "Failed to retrieve the latest release info for $($winVersionMCT.os)."
                Write-Error $errorMsg
                return $False
            }
        }
        return $True
    }
}

# OBJECTS

# Editions mapped to their license keys:
# - all are valid and legal, they still require that you activate Windows with a real key
# - all keys are to be assumed as RTM generic MAK's, unless otherwise specified
$WIN_EDITION_KEYS = @{
    win10 = @{
        Home = @{
            0  = "YTMG3-N6DKC-DKB77-7M9GH-8HVX7"
            N  = "4CPRK-NM3K3-X6XXQ-RXX86-WXCHW"
            SL = "BT79Q-G7N6G-PGBYW-4YWX6-6F4BT" # Single Language
        }
        Pro  = @{ # Professional
            0 = "VK7JG-NPHTM-C97JM-9MPGT-3V66T"
            N = "2B87N-8KFHP-DKV6R-Y2C8J-PKCKT"
            W = @{ # for Workstations
                0 = "DXG7C-N36C4-C4HTG-X4T3X-2YV77"
                N = "WYPNQ-8C467-V2W6J-TX4WX-WT2RQ"
            }
        }
        Edu  = @{ # Education
            0 = "YNMGQ-8RYV3-4PGQ3-C8XTP-7CFBY"
            N = "84NGF-MHBT6-FXBX8-QWJK7-DRR8H"
            P = @{ # Pro
                0 = "8PTT6-RNW4C-6V7J2-C2D3X-MHBPB"
                N = "GJTYN-HDMQY-FRR76-HVGC7-QPF8P"
            }
        }
        Ent  = @{ # Enterprise
            0 = "XGVPP-NMH47-7TTHJ-W3FW7-8HV2C"
            N = "WGGHN-J84D6-QYCPR-T7PJ7-X766F"
            G = @{ # Government
                0 = <#KMS#> "YYVX9-NTFWV-6MDM3-9PT4T-4M68B"
                N = "FW7NV-4T673-HF4VX-9X4MM-B4H4T"
            }
        }
    }
    # win11: gets set below
}
# all win10 keys work with win11
$WIN_EDITION_KEYS.win11 = Get-DeepClone $WIN_EDITION_KEYS.win10
$WIN_EDITION_KEYS.win11.Home.CS = "N2434-X9D7W-8PF6X-8DV9T-8TYMD" # Country Specific

# Contains link and info related to MCT version used depending on OS
$WIN_VERSION_MCT = @{
    win10 = @{
        url         = "https://go.microsoft.com/fwlink/?LinkId=691209"
        os          = "Windows 10"
        x86_support = $True
        release     = "22H2" # used to generate a suggested ISO name; this is the final os release, won't get new major releases
        # timestampFile: needed to check for new versions without downloading; gets set after object creation
        # folder: the folder to download the tool to; gets set after object creation
        # exe: the path to the exe after downloaded; gets set later
    }
    win11 = @{
        url         = "https://go.microsoft.com/fwlink/?linkid=2156295"
        os          = "Windows 11"
        x86_support = $False
        # release: used to generate a suggested ISO name; is dynamically found
        # timestampFile: needed to check for new versions without downloading; gets set after object creation
        # folder: the folder to download the tool to; gets set after object creation
        # exe: the path to the exe after downloaded; gets set later
    }
}
$WIN_VERSION_MCT.win10.folder = $PSScriptRoot + '\' + $WIN_VERSION_MCT.win10.os
$WIN_VERSION_MCT.win10.timestampFile = $WIN_VERSION_MCT.win10.folder + "\timestamp_DO-NOT-DELETE"
$WIN_VERSION_MCT.win11.folder = $PSScriptRoot + '\' + $WIN_VERSION_MCT.win11.os
$WIN_VERSION_MCT.win11.timestampFile = $WIN_VERSION_MCT.win11.folder + "\timestamp_DO-NOT-DELETE"

# MAIN

# MCT won't work unless:
#  1. Current logged in user is an admin
#  2. The program is elevated
#  3. Only one instance of program is started
$loggedOnUser = (Get-WMIObject -class Win32_ComputerSystem).Username
$elevatedUser = $env:USERDOMAIN + '\' + $env:USERNAME
$wdagUtilUser = (Get-WMIObject -class Win32_ComputerSystem).Name + '\WDAGUtilityAccount'
if (-Not (($loggedOnUser -eq $elevatedUser) -or ($wdagUtilUser -eq $elevatedUser))) {
    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction SilentlyContinue
    [Microsoft.VisualBasic.Interaction]::MsgBox('Must be signed in as an admin, or ran inside Windows Sandbox, to use this tool.', 'OKOnly,SystemModal,Information', $MyInvocation.MyCommand.Name) | Out-Null
    exit $FAILED.ADMIN_NOT_LOGGED_ON
}
Show-MaximizedPowerShell
if (Get-Process -Name "MediaCreationTool*") {
    Write-Error "Can only run one instance of the Media Creation Tool at a time."
    Wait-Host
    exit $FAILED.ALREADY_RUNNING
}

# Select version of Windows we'll be using to create an image for
$MCT = $Null
$winEditionKeys = $Null
$warnings = ""
Switch ($OS) {
    10 {
        # Warn about using x86
        if ($Arch -eq "x86") {
            $warnings = "Microsoft no longer supports the x86 (32-bit) architecture for Windows 10."
        }
        $MCT = $WIN_VERSION_MCT.win10; $winEditionKeys = $WIN_EDITION_KEYS.win10; Break
    }
    11 {
        # Confirm arch is valid
        if ($Arch -eq "x86") {
            Write-Error "Microsoft only built x86 (32-bit) images for Windows 10."
            Wait-Host
            exit $FAILED.INVALID_ARCH
        }
        $MCT = $WIN_VERSION_MCT.win11; $winEditionKeys = $WIN_EDITION_KEYS.win11; Break
    }
}

# Initalize MCT (gets latest version if needed)
if (-Not (Initialize-MCT -winVersionMCT $MCT)) {
    $errorMessage = "Something went wrong initializing MCT for $($MCT.os)."
    Write-Error $errorMessage
    Wait-Host
    exit $FAILED.INIT_MCT
}

# Setup arguments for MCT
$BaseEdition = $Null
Switch -Wildcard ($Edition) {
    "Home*" {
        # Confirm OS is valid
        if ($OS -lt 11) {
            Write-Error "Microsoft does not build CS (Country Specific) editions for Windows 10."
            Wait-Host
            exit $FAILED.INVALID_EDITION
        }
        $BaseEdition = "Home"; Break
    }
    "Pro*" { $BaseEdition = "Professional"; Break }
    "Edu*" { $BaseEdition = "Education"; Break }
    "Ent*" { $BaseEdition = "Enterprise"; Break }
}
$argumentsMCT = @(
    "/Download",
    "/Web",
    "/Retail",
    "/Eula Accept",
    "/MediaLangCode ${LangCode}",
    "/MediaEdition ${BaseEdition}",
    "/MediaArch ${Arch}",
    "/Action CreateMedia"
)
# changed back to shortened variant, since that's what it's referred to officially
if ($BaseEdition -eq "Professional") { $BaseEdition = "Pro" }

# Select the edition MAK to be copied into the clipboard later,
# and set the edition type for displaying a possible file name to user
$EditionKey = $Null
$EditionType = $BaseEdition
Switch -Wildcard ($Edition) {
    "Home" {
        $EditionKey = $winEditionKeys.Home[0];
        Break 
    }
    "HomeN" {
        $EditionType += ' N'
        $EditionKey = $winEditionKeys.Home.N;
        Break 
    }
    "HomeSL" {
        $EditionType += ' Single Language'
        $EditionKey = $winEditionKeys.Home.SL;
        Break 
    }
    "HomeCS" {
        $EditionType += ' Country Specific'
        $EditionKey = $winEditionKeys.Home.CS;
        Break 
    }
    "Pro" {
        $EditionKey = $winEditionKeys.Pro[0];
        Break 
    }
    "ProN" {
        $EditionType += ' N'
        $EditionKey = $winEditionKeys.Pro.N;
        Break 
    }
    "ProW" {
        $EditionType += ' for Workstations'
        $EditionKey = $winEditionKeys.Pro.W[0];
        Break 
    }
    "ProWN" {
        $EditionType += ' for Workstations N'
        $EditionKey = $winEditionKeys.Pro.W.N;
        Break 
    }
    "Edu" {
        $EditionKey = $winEditionKeys.Edu[0];
        Break 
    }
    "EduN" {
        $EditionType += ' N'
        $EditionKey = $winEditionKeys.Edu.N;
        Break 
    }
    "EduP" {
        $EditionType = 'Pro ' + $EditionType
        $EditionKey = $winEditionKeys.Edu.P[0];
        Break 
    }
    "EduPN" {
        $EditionType = 'Pro ' + $EditionType + ' N'
        $EditionKey = $winEditionKeys.Edu.P.N;
        Break 
    }
    "Ent" {
        $EditionKey = $winEditionKeys.Ent[0];
        Break 
    }
    "EntN" {
        $EditionType += ' N'
        $EditionKey = $winEditionKeys.Ent.N;
        Break 
    }
    "EntG" {
        $EditionType += ' G'
        $EditionKey = $winEditionKeys.Ent.G[0];
        Break 
    }
    "EntGN" {
        $EditionType += ' G N'
        $EditionKey = $winEditionKeys.Ent.G.N;
        Break 
    }
}
$TargetSelectionStrings = @(
    $MCT.os, $MCT.release, $EditionType, $LangCode
)
if ($MCT.x86_support) { $TargetSelectionStrings += , $Arch }
Set-Clipboard -Value $EditionKey

# Notify of options selected
$e = [char]0x1b # ansi escape
Clear-Host
Write-Host '' # formatting
Write-HostCenter "${e}[94mTargeting: ${e}[92m$($TargetSelectionStrings -Join ' ')${e}[22m"
Write-HostCenter "${e}[94mFilename Format (not auto filled): ${e}[96m$(($TargetSelectionStrings -Join '_').Replace(' ' , '-')).iso${e}[22m"
if ($warnings) { Write-WarningCenter $warnings }
# Warn user about needing to paste in product key
Write-HostCenter "The generic product key for selected edition has been copied to clipboard. If prompted to enter product key, just paste from the clipboard, then continue."

# Start MCT with arguments to create image
$generateISO = Start-Process $MCT.exe -ArgumentList $argumentsMCT -PassThru -Wait
if (-2147023673 -eq $generateISO.ExitCode) {
    # User aborted MCT
    exit
}
if (0 -ne $generateISO.ExitCode) {
    $errorMessage = "Something went wrong running the $($MCT.os) Media Creation Tool."
    Write-Error $errorMessage
    Wait-Host
    exit $FAILED.RUNNING_MCT
}
