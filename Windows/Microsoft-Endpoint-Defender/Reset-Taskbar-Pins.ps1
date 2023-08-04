<#
  .SYNOPSIS
  Reset Taskbar Pins (Fixes Duplicate Pins) v1.0.1

  .DESCRIPTION
  Script only resets the taskbar pins for the current user running the script.
  
  Pins will have to be recreated afterwards, so make sure to take note of what is currently pinned.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  None. (script will always run successfully or fail in the cases where things are already reset)

  .EXAMPLE
  .\Reset-Taskbar-Pins.ps1

  .NOTES
  Shouldn't be ran as admin, as it doesn't require extra permissions to work.

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Microsoft-Endpoint-Defender/Reset-Taskbar-Pins.ps1
#>

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

Write-Host "Please make note of the applications that the current user has pinned before continuing!"
Pause

$UserPinned = "${env:APPDATA}\Microsoft\Internet Explorer\Quick Launch\User Pinned"

# Code to reference, in case it comes up that deleting User Pinned breaks anything,
# will need to revert to the below commands
#$ImplicitAppShortcuts = "${UserPinned}\ImplicitAppShortcuts"
#$TaskBar = "${UserPinned}\TaskBar"
#if (Test-Path -Path ${ImplicitAppShortcuts}) {Remove-Item -Path "${ImplicitAppShortcuts}\*" -Recurse -Force}
#if (Test-Path -Path ${TaskBar}) {Remove-Item -Path "${TaskBar}\*" -Recurse -Force}

if (Test-Path -Path ${UserPinned}) { Remove-Item -Path "${UserPinned}\*" -Recurse -Force }
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Force -Recurse
Stop-Process -Name explorer -Force

Write-Host "You may now repin any applications that the current user had on the taskbar."
Pause
