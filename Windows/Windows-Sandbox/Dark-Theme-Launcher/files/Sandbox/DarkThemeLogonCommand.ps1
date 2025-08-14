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

# Track if VM is Windows 10

$IsWindows10 = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption).StartsWith("Microsoft Windows 10")

# Set dark mode for apps and system

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0

# Set dark wallpaper

$DarkWallpaperPath = $(if ($IsWindows10) { "C:\VM-Sandbox" } else { "C:\Windows\Web\Wallpaper\Windows" }),'img19.jpg' -Join '\'
$SPI_SETDESKWALLPAPER = 0x0014
$UPDATE_INI_FILE = 0x01
$SEND_CHANGE = 0x02
$Win32Functions = Add-Type -memberDefinition @"
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
"@ -name "Win32Functions" -PassThru
$Win32Functions::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $DarkWallpaperPath, ($UPDATE_INI_FILE -bor $SEND_CHANGE))
if (-Not $IsWindows10) {
  # Windows 11+ needs explorer to be restarted for the rest of the system to recognize the theme change
  Stop-Process -Name "explorer" -Force ; Wait-Process -Name "explorer"
  Start-Process "explorer"
  $Shell = New-Object -ComObject Shell.Application
  While (-Not ($Shell.Windows()).Count) { Start-Sleep -Milliseconds 1 }
  $Shell.Windows() | % { $_.quit() }
}
Set-Clipboard $True # used to set off theme loaded detection
