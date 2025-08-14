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

# these functions fixes compatibility with older/newer versions of the Sandbox app

function Get-WindowsSandboxClientProcess {
  $process = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'WindowsSandbox(Client|RemoteSession)'
  })[0]
  return $process
}
function Get-WindowsSandboxVmProcess {
  $process = @(Get-Process -Name 'vmmem*Sandbox' -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'vmmem(Windows)?Sandbox'
  })[0]
  return $process
}

# Capture previous clipboard, in order to set it back to normal later, and clear the clipboard to prepare for below

$PreviousClipboard = Get-Clipboard
Set-Clipboard -Value $Null

# Dynamically create "WindowsSandboxDarkTheme.wsb" config file, so that mapped folders work properly

$envTEMP = Get-Item -LiteralPath $env:TEMP # Required due to PowerShell bug with shortnames appearing when they shouldn't be
$PathDarkThemeWSB = "${envTEMP}\WindowsSandboxDarkTheme.wsb"

# Uses the LogonCommand to execute change to dark theme, close the Settings app (opens after theme change), restarts Windows
# Explorer (to let theme fully propigate), and finally closes the last File Explorer window (which opens after the restart)
$DarkThemeWSB = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$((Get-Item "${PSScriptRoot}\Sandbox").FullName)</HostFolder>
      <SandboxFolder>C:\VM-Sandbox</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File "C:\VM-Sandbox\DarkThemeLogonCommand.ps1"</Command>
  </LogonCommand>
</Configuration>
"@
$DarkThemeWSB | Out-File -FilePath $PathDarkThemeWSB

# Launch Windows Sandbox with the dark theme

Start-Process $PathDarkThemeWSB

# Minimize the Sandbox window until the theme fully applies (to prevent blinding eyes)

$DisplayBugDelay = 500 # ms; prevents white screen flashes between window state changes

$WindowStates = @{
  'HIDE' = 0 # plays nicer with the windows, preventing a blank screen bug on restore
  'SHOWMINIMIZED' = 2 # without this, the restore will not properly reactivate the window
  'RESTORE'  = 9
}
$Win32Functions = Add-Type -memberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -name "Win32Functions" -PassThru

$clientProcess = $Null # need to track for compatibility reasons
$MainWindowHandle = $Null
Do {
  $clientProcess = (Get-WindowsSandboxClientProcess)
  $MainWindowHandle = $clientProcess.MainWindowHandle
} Until ($MainWindowHandle -And (0 -ne $MainWindowHandle))

if ('WindowsSandboxRemoteSession' -eq $clientProcess.Name) {
  # extra quirks with new version require detecting a change of MainWindowHandle after collecting it the first time

  $OldMainWindowHandle = $MainWindowHandle
  $MainWindowHandle = $Null
  Do {
    $clientProcess = (Get-WindowsSandboxClientProcess)
    $MainWindowHandle = $clientProcess.MainWindowHandle
  } Until ($MainWindowHandle -And (0 -ne $MainWindowHandle) -And ($OldMainWindowHandle -ne $MainWindowHandle))
  
  # needs additional sleep time to prevent blinding white window flash bug
  Start-Sleep -Milliseconds $DisplayBugDelay
}

$Win32Functions::ShowWindowAsync($MainWindowHandle, $WindowStates['HIDE']) | Out-Null

# Restore the Sandbox window after theme is fully applied (by monitoring the the clipboard for boolean)

Do { <# nothing #> } Until (Get-Clipboard)

Set-Clipboard -Value $PreviousClipboard # restore what was originally in the clipboard
$Win32Functions::ShowWindowAsync($MainWindowHandle, $WindowStates['SHOWMINIMIZED']) | Out-Null
$Win32Functions::ShowWindowAsync($MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
