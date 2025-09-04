# Windows Sandbox Theme Launcher - v1.0.0

<# Copyright (C) 2025  Andrew Larson (github@drewj.la)

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

function Show-CenteredFrame {
  param([string]$Frame)

  $width = $Host.UI.RawUI.WindowSize.Width
  $height = $Host.UI.RawUI.WindowSize.Height

  $leftPad = [Math]::Max(0, ($width - $Frame.Length) / 2)
  $topPad = [Math]::Max(0, [Math]::Floor(($height - 1) / 2))

  Clear-Host
  for ($i = 0; $i -lt $topPad; $i++) {
    Write-Host ""
  }

  Write-Host (' ' * $leftPad + $Frame)
}

function Show-CenteredLoadingAnimation {
  param([ScriptBlock]$Task)

  $text = "LOADING"  # All caps version
  $maxInnerPad = 4
  $frames = @()

  # Build frames with symmetrical inner padding
  for ($pad = $maxInnerPad; $pad -ge 1; $pad--) {
    $innerPad = ' ' * $pad
    $frame = ">$innerPad$text$innerPad<"
    $frames += $frame
  }

  # Normalize frame width
  $maxLength = ($maxInnerPad * 2) + $text.Length + 2
  $frames = $frames | ForEach-Object {
    $_.PadLeft($_.Length + [Math]::Floor(($maxLength - $_.Length) / 2)).PadRight($maxLength)
  }

  # Start background task
  $job = Start-Job -ScriptBlock $Task
  $frameIndex = 0

  while ($job.State -eq 'Running') {
    Show-CenteredFrame $frames[$frameIndex]
    $frameIndex = ($frameIndex + 1) % $frames.Count
    Start-Sleep -Milliseconds 400
  }

  Clear-Host
  Receive-Job $job
  Remove-Job $job
}

# MAIN
Show-CenteredLoadingAnimation {
  function Start-WindowsSandbox {
    Start-Process "explorer" -ArgumentList "shell:Appsfolder\MicrosoftWindows.WindowsSandbox_cw5n1h2txyewy!App"
  }

  # this function fixes compatibility with older/newer versions of the Sandbox app
  function Get-WindowsSandboxClientProcess {
    $process = @(Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Where-Object {
      $_.Name -match 'WindowsSandbox(Client|RemoteSession)'
    })[0]
    return $process
  }

  # Constants

  $ScriptName = Split-Path -Leaf $Using:PSCommandPath
  $AppxPackageName = 'MicrosoftWindows.WindowsSandbox'
  $CurrentThemeFilePath = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes" | Select-Object -ExpandProperty CurrentTheme
  $CurrentThemeSandboxFilePath = $Null
  $CurrentThemeSandboxFileBase64 = $Null

  # Check if even installed and working
  Add-Type -AssemblyName System.Windows.Forms
  if (-Not (Get-AppxPackage -Name $AppxPackageName)) {
    [System.Windows.Forms.MessageBox]::Show(
      "Windows Sandbox is not installed, so it can't be launched! Make sure you are running a Pro version of Windows or newer, and have the optional feature turned on.",
      "Error: `"${ScriptName}`"",
      [System.Windows.Forms.MessageBoxButtons]::OK,
      [System.Windows.Forms.MessageBoxIcon]::Error
    )
    Exit 1
  }

  # Check for any other running instances first
  if (& 'wsb.exe' list) {
    # start Sandbox, only to have it show the themed WinUI error, instead of serving an old unthemed dialog
    Start-WindowsSandbox
    Exit 1
  }

  Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WinAPI {
  [DllImport("user32.dll")]
  public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

  [DllImport("user32.dll")]
  public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

  [DllImport("user32.dll")]
  public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

  public struct RECT {
    public int Left;
    public int Top;
    public int Right;
    public int Bottom;
  }
}
"@
  $WindowStates = @{
    'HIDE' = 0 # plays nicer with the windows, preventing a blank screen bug on restore
    'SHOWMINIMIZED' = 2 # without this, the restore will not properly reactivate the window
    'RESTORE'  = 9
  }

  # Check user/system theme

  if ($CurrentThemeFilePath -like "*:\Windows\*") {
    # system (user never customized theme)
    $CurrentThemeSandboxFilePath = $CurrentThemeFilePath
  } else {
    # user (has customized theme)
    $CurrentThemeSandboxFilePath = "`${env:LOCALAPPDATA}\Microsoft\Windows\Themes\$(Split-Path -Path $CurrentThemeFilePath -Leaf)"
    $CurrentThemeSandboxFileBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($CurrentThemeFilePath))
  }

  # Capture previous clipboard, in order to set it back to normal later, and clear the clipboard to prepare for below

  $PreviousClipboard = & "powershell.exe" -STA -Command "Get-Clipboard"
  $ThemeLoadedClipboard = "WindowsSandbox_",([System.Guid]::NewGuid()).ToString() -Join ''
  # loaded into clipboard history for easier debugging
  & "powershell.exe" -STA -Command "Set-Clipboard -Value '${ThemeLoadedClipboard}'"
  & "powershell.exe" -STA -Command "Set-Clipboard -Value `$Null"

  # Uses the LogonCommand to execute change to user theme, restarts Windows Explorer (to let theme fully propagate),
  # and finally closes the last File Explorer window (which opens after the restart) unless it's Windows 10 (where it doesn't happen)
  $UserThemeWSB = [xml]@'
<Configuration>
  <LogonCommand>
  </LogonCommand>
</Configuration>
'@

  # Encode loggon script first, which is required before starting up Windows Sandbox

  $LauncherScriptContent = @"
# Track if VM is Windows 10

`$IsWindows10 = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption).StartsWith("Microsoft Windows 10")

# Set user theme

`$CurrentThemeFilePath = "${CurrentThemeSandboxFilePath}"

# need to confirm if we have base64 data (user theme) or path (system theme)

`$ClipboardData = `$(Get-Clipboard) # empty clipboard means system theme
if (`$ClipboardData) {
  New-Item -ItemType Directory -Path `$(Split-Path -Path `$CurrentThemeFilePath) -Force -ErrorAction SilentlyContinue | Out-Null
  # grabs the theme base64 string from the clipboard, and drops the theme on the VM
  `$bytes = [System.Convert]::FromBase64String(`$ClipboardData)
  [System.IO.File]::WriteAllBytes(`$CurrentThemeFilePath, `$bytes)
} # else, means it's a path to a system theme instead
Start-Process `$CurrentThemeFilePath

# Windows 11+ needs explorer to be restarted for the rest of the system to recognize the theme changes + close windows afterwards

if (-Not `$IsWindows10) {
  # And need to close the Settings window that auto opens
  Add-Type -AssemblyName UIAutomationClient
  `$root = [System.Windows.Automation.AutomationElement]::RootElement
  `$condition = [System.Windows.Automation.Condition]::TrueCondition
  `$settingsActive = `$False
  `$windows = `$Null
  Do {
    `$windows = @(
      `$root.FindAll([System.Windows.Automation.TreeScope]::Children, `$condition) | Where-Object {
        (`$_.Current.Name -eq 'Settings')
      }
    )
    `$windows | ForEach-Object {
      try {
        `$pattern = `$_.GetCurrentPattern([System.Windows.Automation.WindowPatternIdentifiers]::Pattern)
        `$state = `$pattern.Current.WindowVisualState
        if (`$state -ne 2) { # window is visible if true
          `$settingsActive = `$True
          try { `$pattern.Close() } catch { <# nothing #> }
        }
      } catch { <# nothing #> }
      Start-Sleep -Milliseconds 1
    }
  } While ((-Not `$settingsActive) -Or `$windows)
  # It might seem like this could start at the beginning, but race conditions occur with the theme file otherwise
  Stop-Process -Name "explorer" -Force ; Wait-Process -Name "explorer"
  Start-Process "explorer"
  # And need to close the File Explorer window that auto opens
  `$Shell = New-Object -ComObject Shell.Application
  While (-Not (`$Shell.Windows()).Count) { Start-Sleep -Milliseconds 1 }
  `$Shell.Windows() | % { `$_.quit() }
}
Set-Clipboard '${ThemeLoadedClipboard}' # used to set off theme loaded detection
"@
  $EncodedLauncherScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($LauncherScriptContent))
  $LauncherCommand = "powershell.exe -ExecutionPolicy Unrestricted -EncodedCommand ${EncodedLauncherScript}"
  $LauncherCommandXML = $UserThemeWSB.CreateElement('Command')
  $LauncherCommandXML.InnerText = $LauncherCommand
  $UserThemeWSB.SelectSingleNode("//LogonCommand").AppendChild($LauncherCommandXML)

  # Then, dynamically create the Windows Sandbox config file

  $envTEMP = Get-Item -LiteralPath $env:TEMP # Required due to PowerShell bug with shortnames appearing when they shouldn't be
  $PathUserThemeWSB = "${envTEMP}\WindowsSandboxUserTheme.wsb"
  $UserThemeWSB.OuterXml | Out-File -FilePath $PathUserThemeWSB

  # Launch Windows Sandbox with the user theme

  # transfers theme the fastest without using a mounted folder
  & "powershell.exe" -STA -Command "Set-Clipboard -Value '${CurrentThemeSandboxFileBase64}'"

  Start-Process $PathUserThemeWSB

  # Hide the window until the theme fully applies (to prevent blinding eyes)

  $DisplayBugDelay = 500 # ms; prevents white screen flashes between window state changes

  $clientProcess = $Null # need to track for compatibility reasons
  $MainWindowHandle = $Null
  Do {
    $clientProcess = (Get-WindowsSandboxClientProcess)
    $MainWindowHandle = $clientProcess.MainWindowHandle
  } Until (
    ($clientProcess -And $clientProcess.HasExited) -Or ($MainWindowHandle -And (0 -ne $MainWindowHandle))
  )

  $OldMainWindowHandle = $Null
  if ('WindowsSandboxRemoteSession' -eq $clientProcess.Name) {
    # extra quirks with new version require detecting a change of MainWindowHandle after collecting it the first time

    $OldMainWindowHandle = $MainWindowHandle
    $MainWindowHandle = $Null
    Do {
      $clientProcess = (Get-WindowsSandboxClientProcess)
      $MainWindowHandle = $clientProcess.MainWindowHandle
    } Until (
      ($clientProcess -And $clientProcess.HasExited) -Or (
        $MainWindowHandle -And (0 -ne $MainWindowHandle) -And ($OldMainWindowHandle -ne $MainWindowHandle)
      )
    )
  }

  # needs additional sleep time to prevent blinding white window flash bug + task directly below
  Start-Sleep -Milliseconds $DisplayBugDelay

  # move parent console window infront of the sandbox window and resize it (visually gives the impression of a loading screen)
  try {
    $rect = New-Object WinAPI+RECT
    [WinAPI]::GetWindowRect($MainWindowHandle, [ref]$rect) | Out-Null
    $x = $rect.Left
    $y = $rect.Top
    $width = $rect.Right - $rect.Left
    $height = $rect.Bottom - $rect.Top
    $parentProcess = Get-Process -Id $Using:PID
    [WinAPI]::ShowWindowAsync($parentProcess.MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
    [WinAPI]::MoveWindow($parentProcess.MainWindowHandle, $x, $y, $width, $height, $true)
  } catch { <# nothing #> }

  try {
    if ($MainWindowHandle) { [WinAPI]::ShowWindowAsync($MainWindowHandle, $WindowStates['HIDE']) | Out-Null }
  } catch { <# nothing #> }

  # Show minimized then restore the window after theme is fully applied (by monitoring the the clipboard for boolean)

  Do { <# nothing #> } Until ($ThemeLoadedClipboard -eq (& "powershell.exe" -STA -Command "Get-Clipboard"))

  & "powershell.exe" -STA -Command "Set-Clipboard -Value '${PreviousClipboard}'"
  
  try {
    if ($MainWindowHandle) { 
      [WinAPI]::ShowWindowAsync($MainWindowHandle, $WindowStates['SHOWMINIMIZED']) | Out-Null
      [WinAPI]::ShowWindowAsync($MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
    }
  } catch { <# nothing #> }
}