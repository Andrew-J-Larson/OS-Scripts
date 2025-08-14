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

# This function fixes compatibility with older/newer versions of the Sandbox app

function Get-WindowsSandboxClientProcess {
  $process = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Where-Object {
    $_.Name -match 'WindowsSandbox(Client|RemoteSession)'
  })[0]
  return $process
}

# Constants

$DarkWallpaperFilename = 'img19.jpg'
$HostFolder = (Get-Item $PSScriptRoot).FullName
$SandboxFolder = 'C:\VM-Sandbox'
$SandboxFolderDarkWallpaperPath = $SandboxFolder,$DarkWallpaperFilename -Join '\'
$DefaultWindowsWallpapersPath = 'C:\Windows\Web\Wallpaper\Windows'
$DefaultWindowsDarkWallpaperPath = $DefaultWindowsWallpapersPath,$DarkWallpaperFilename -Join '\'

# Capture previous clipboard, in order to set it back to normal later, and clear the clipboard to prepare for below

$PreviousClipboard = Get-Clipboard
$ThemeLoadedClipboard = 'WindowsSandbox_' + ([System.Guid]::NewGuid()).ToString()
# Write-Host "`$ThemeLoadedClipboard = '${ThemeLoadedClipboard}'" # in case we need to manually make the window show up

# Encode loggon script first, which is required before starting up Windows Sandbox

$LoggonCommandScriptContent = @'
# Track if VM is Windows 10

$IsWindows10 = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption).StartsWith("Microsoft Windows 10")

# Set dark mode for apps and system

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0

# Set dark wallpaper

$WallpaperPath = if ($IsWindows10) {
'@ + "  '${SandboxFolderDarkWallpaperPath}'" + @'
} else {
'@ + "  '${DefaultWindowsDarkWallpaperPath}'" + @'
}
$SPI_SETDESKWALLPAPER = 0x0014
$UPDATE_INI_FILE = 0x01
$SEND_CHANGE = 0x02
$Win32Functions = Add-Type -memberDefinition @"
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
"@ -name "Win32Functions" -PassThru
$Win32Functions::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $WallpaperPath, ($UPDATE_INI_FILE -bor $SEND_CHANGE))

# Windows 11+ needs explorer to be restarted for the rest of the system to recognize the theme changes

if (-Not $IsWindows10) {
  Stop-Process -Name "explorer" -Force ; Wait-Process -Name "explorer"
  Start-Process "explorer"
  $Shell = New-Object -ComObject Shell.Application
  While (-Not ($Shell.Windows()).Count) { Start-Sleep -Milliseconds 1 }
  $Shell.Windows() | % { $_.quit() }
}
'@ + "Set-Clipboard '${ThemeLoadedClipboard}' # used to set off theme loaded detection `n"
$EncodedLoggonCommandScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($LoggonCommandScriptContent))
$Command = "powershell.exe -ExecutionPolicy Bypass -EncodedCommand ${EncodedLoggonCommandScript}"

# Then, dynamically create the Windows Sandbox config file, so that mapped folders work properly

$envTEMP = Get-Item -LiteralPath $env:TEMP # Required due to PowerShell bug with shortnames appearing when they shouldn't be
$PathDarkThemeWSB = "${envTEMP}\WindowsSandboxDarkTheme.wsb"

# Uses the LogonCommand to execute change to dark theme, restarts Windows Explorer (to let theme fully propagate),
# and finally closes the last File Explorer window (which opens after the restart) unless it's Windows 10 (where it doesn't happen)
$DarkThemeWSB = @"
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>${HostFolder}</HostFolder>
      <SandboxFolder>${SandboxFolder}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>${Command}</Command>
  </LogonCommand>
</Configuration>
"@
$DarkThemeWSB | Out-File -FilePath $PathDarkThemeWSB

# Launch Windows Sandbox with the dark theme

Start-Process $PathDarkThemeWSB

# Hide the window until the theme fully applies (to prevent blinding eyes)

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

# Show minimized then restore the window after theme is fully applied (by monitoring the the clipboard for boolean)

Do { <# nothing #> } Until ($ThemeLoadedClipboard -eq (Get-Clipboard))

Set-Clipboard -Value $PreviousClipboard # restore what was originally in the clipboard
$Win32Functions::ShowWindowAsync($MainWindowHandle, $WindowStates['SHOWMINIMIZED']) | Out-Null
$Win32Functions::ShowWindowAsync($MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
