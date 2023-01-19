#Requires -RunAsAdministrator
# Recreate Base Shortcuts (Intune) v1.0.0 - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts-INTUNE.ps1
# This is just a wrapper script made only for Intune, to download and run the full script (to bypass the script being too large for Intune), the full script can be found at: https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1

# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/



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
