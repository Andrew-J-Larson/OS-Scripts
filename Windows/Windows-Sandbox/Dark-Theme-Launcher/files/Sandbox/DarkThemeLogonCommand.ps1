<# Copyright (C) 2024  Andrew Larson (github@andrew-larson.dev)

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

$DarkThemeLocation = "C:\Windows\Resources\Themes\dark.theme"
$IsWindows10 = ((Get-CimInstance -ClassName Win32_OperatingSystem).Caption).StartsWith("Microsoft Windows 10")
if ($IsWindows10) {
  $DarkThemeLocation = "C:\Resources\Windows (dark).deskthemepack"
}
Start-Process $DarkThemeLocation -Wait
"systemsettings","explorer" | % { Stop-Process -Name $_ -Force ; Wait-Process -Name $_ }
Start-Process "explorer"
$Shell = New-Object -ComObject Shell.Application
While (-Not ($Shell.Windows()).Count) { Start-Sleep -Milliseconds 1 }
$Shell.Windows() | % { $_.quit() }
