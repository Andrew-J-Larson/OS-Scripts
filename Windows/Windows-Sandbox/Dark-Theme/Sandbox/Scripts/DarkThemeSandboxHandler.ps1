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

$WindowStates = @{
  'MINIMIZE' = 6
  'RESTORE'  = 9
}

$Win32ShowWindowAsync = Add-Type -memberDefinition @"
[DllImport("user32.dll")]
public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);
"@ -name "Win32ShowWindowAsync" -namespace Win32Functions -PassThru

$MainWindowHandle = $Null
Do {
  Start-Sleep -Milliseconds 200
  $MainWindowHandle = (Get-Process -Name "WindowsSandboxClient" -ErrorAction SilentlyContinue).MainWindowHandle
} Until ($MainWindowHandle -And (0 -ne $MainWindowHandle))

$Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates['MINIMIZE']) | Out-Null
Start-Sleep -Seconds 15 # Seems to be the best magic number to use here
$Win32ShowWindowAsync::ShowWindowAsync($MainWindowHandle, $WindowStates['RESTORE']) | Out-Null
