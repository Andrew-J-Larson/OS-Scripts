<#
  .SYNOPSIS
  Recreate Base Shortcuts (Intune) v1.0.1

  .DESCRIPTION
  This is just a wrapper script (made for Intune), to download and run the full script (bypasses the "script is too large" issue for Intune).

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  Creates shortcuts (if they don't already exist).
  Successes, warnings, and errors log to the console (this also logs to the file at `${env:SystemDrive}\Recreate-Base-Shortcuts.log`).
  
  Returns $true or $false if script ran successfully.

  If there is no internet access to download the rest of the script, then it'll also return $false.

  .EXAMPLE
  .\Recreate-Base-Shortcuts.ps1

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
  Full script at: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1

  .LINK
  Need an app added?: https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20--%3E%0A%0A

  .LINK
  Script from: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts-INTUNE.ps1
#>


<# Recreate Base Shortcuts (Intune) v1.0.0 - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts-INTUNE.ps1
   , the full script can be found at: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1

   About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/
#>
#Requires -RunAsAdministrator

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

Set-Variable REMOTE_SCRIPT_LOCATION -Option Constant -Value "https://github.com/TheAlienDrew/OS-Scripts/raw/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts-INTUNE.ps1"



# MAIN

# Make sure we have internet access
if (-Not (Get-NetRoute | Where-Object DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected')) {
    Write-Error "This wrapper script requires internet access to start."
    exit 1
}

# Download and execute script code
Write-Host "Downloading and executing `"${REMOTE_SCRIPT_LOCATION}`" shortly..."
. { Invoke-WebRequest -useb $REMOTE_SCRIPT_LOCATION } | Invoke-Expression
