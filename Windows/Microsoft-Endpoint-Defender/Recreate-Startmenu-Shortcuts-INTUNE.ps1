<#
  .SYNOPSIS
  Recreate Startmenu Shortcuts (Intune) v1.0.9

  .DESCRIPTION
  This is just a wrapper script (made for Intune), to download and run the full script (bypasses the "script is too large" issue for Intune).

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Creates shortcuts (if they don't already exist).
  Successes, warnings, and errors log to the console (this also logs to the file at `${env:SystemDrive}\Recreate-Startmenu-Shortcuts.log`).
  
  Returns $true or $false if script ran successfully.

  If there is no internet access to download the rest of the script, then it'll also return $false.

  .EXAMPLE
  .\Recreate-Startmenu-Shortcuts-INTUNE.ps1

  .NOTES
  Requires admin! Because VBscript (used to create shortcuts) requires admin to create shortcuts in system folders.
  
  If you're going to edit the script to manually include more apps, then here's how the application objects are setup:
  
  @{
    Name = "[name of shortcut here]"
    TargetPath = "[path to exe/url/folder here]"
    Arguments = "[any arguments that an app starts with here]"
    SystemLnk = "[path to lnk or name of app here]"
    WorkingDirectory = "[start in path, if needed, here]"
    Description = "[comment, that shows up in tooltip, here]"
    IconLocation = "[path to ico|exe|ico w/ index]"
    RunAsAdmin = "[true or false, if needed]"
  }

  .LINK
  About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

  .LINK
  Full script at: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Microsoft-Endpoint-Defender/Recreate-Startmenu-Shortcuts.ps1

  .LINK
  Need an app added?: https://github.com/Andrew-J-Larson/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Startmenu-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20--%3E%0A%0A

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Microsoft-Endpoint-Defender/Recreate-Startmenu-Shortcuts-INTUNE.ps1
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

param(
  [Alias("h")]
  [switch]$Help
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}



# Constants

Set-Variable -Name REMOTE_SCRIPT_LOCATION -Option Constant -Value "https://raw.githubusercontent.com/TheAlienDrew/OS-Scripts/main/Windows/Microsoft-Endpoint-Defender/Recreate-Startmenu-Shortcuts.ps1" -ErrorAction SilentlyContinue



# MAIN

# Make sure we have internet access
if (-Not (Get-NetRoute | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected')) {
  Write-Error "This wrapper script requires internet access to start."
  exit 1
}

# Download and execute script code
Write-Host "Downloading and executing `"${REMOTE_SCRIPT_LOCATION}`" shortly..."
. { Invoke-WebRequest -useb $REMOTE_SCRIPT_LOCATION } | Invoke-Expression
