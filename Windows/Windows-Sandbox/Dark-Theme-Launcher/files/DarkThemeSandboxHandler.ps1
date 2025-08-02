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

$VisualDelay = 200 # ms; usually the fastest visual detection an eye can detect
# Note: making VisualDelay too short can cause the window to not get minimized

$WindowStates = @{
  'MINIMIZE' = 6
  'RESTORE'  = 9
}
$Win32ShowWindowAsync = Add-Type -memberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -name "Win32ShowWindowAsync" -namespace Win32Functions -PassThru

$clientProcess = $Null # need to track for compatibility reasons
$MainWindowHandle = $Null
Do {
  Start-Sleep -Milliseconds $VisualDelay
  $clientProcess = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Where-Object {
    # fixes compatibility with older/newer version of the Sandbox app
    $_.Name -match 'WindowsSandbox(Client|RemoteSession)'
  })[0]
  $MainWindowHandle = $clientProcess.MainWindowHandle
} Until ($MainWindowHandle -And (0 -ne $MainWindowHandle))

if ('WindowsSandboxRemoteSession' -eq $clientProcess.Name) {
  # extra quirks with new version require detecting a change of MainWindowHandle after collecting it the first time

  $OldMainWindowHandle = $MainWindowHandle
  $MainWindowHandle = $Null
  Do {
    Start-Sleep -Milliseconds $VisualDelay
    $clientProcess = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Where-Object {
      # fixes compatibility with older/newer version of the Sandbox app
      $_.Name -match 'WindowsSandbox(Client|RemoteSession)'
    })[0]
    $MainWindowHandle = $clientProcess.MainWindowHandle
  } Until ($MainWindowHandle -And (0 -ne $MainWindowHandle) -And ($OldMainWindowHandle -ne $MainWindowHandle))
  
  # needs additional sleep time to prevent display bug
  Start-Sleep -Milliseconds $VisualDelay
}

$Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates['MINIMIZE']) | Out-Null

# Restore the Sandbox window after theme is fully applied (by monitoring memory usage of Sandbox starting up)

$OneGB = 1073741824 # bytes
$MagicMultiplier = 1 + (2/3) # educated guess, see below
$vmProcessOperationalGB = $OneGB * $MagicMultiplier # rough value of peak memory in use once sandbox is fully loaded
$PeakWorkingSet64 = -1
Do {
  Start-Sleep -Milliseconds $VisualDelay
  $vmProcess = @(Get-Process -Name 'vmmem*Sandbox' -ErrorAction SilentlyContinue | Where-Object {
    # fixes compatibility with older/newer version of the Sandbox app
    $_.Name -match 'vmmem(Windows)?Sandbox'
  })[0]
  $PeakWorkingSet64 = $vmProcess.PeakWorkingSet64
} Until ($PeakWorkingSet64 -ge $vmProcessOperationalGB)

# Basically a magic number, there is no easy way to guess how much time it'll take Windows Sandbox to perform
# the LogonCommand, and apply the dark theme, but this is a good estimate after peak memory (noted earlier) is reached
$MagicDelayThemeFullyApplied = 13600 # ms
Start-Sleep -Milliseconds $MagicDelayThemeFullyApplied
$Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
