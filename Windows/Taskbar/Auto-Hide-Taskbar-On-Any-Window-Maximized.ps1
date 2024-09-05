<#
  .SYNOPSIS
  Auto Hide Taskbar On Any Window Maximized v1.0.1

  .DESCRIPTION
  This script will automatically turn on/off the taskbar auto hide setting, when a maximized
  window is detected.
  
  When a maximized window if found, auto hide is turned on.

  When no maximized windows are found, auto hide is turned off.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  None.

  .OUTPUTS
  None.

  .EXAMPLE
  .\Auto-Hide-Taskbar-On-Any-Window-Maximized.ps1

  .EXAMPLE
  .\Auto-Hide-Taskbar-On-Any-Window-Maximized.ps1 -Help

  .EXAMPLE
  .\Auto-Hide-Taskbar-On-Any-Window-Maximized.ps1 -h

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Taskbar/Auto-Hide-Taskbar-On-Any-Window-Maximized.ps1
#>

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

param(
  [Alias("h")]
  [switch]$Help
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}

# CONSTANTS

$LOOP_SECONDS = 1

# IMPORTS

Add-Type -TypeDefinition @"
  /// code below includes modifications from:
  /// - https://stackoverflow.com/q/44389752/7312536
  /// - https://github.com/gfody/ToggleTaskbar/blob/8ddf69ec2a8f3eb53208322073f51f5ca89a00f1/Program.cs

  using System;
  using System.Collections.Generic;
  using System.Runtime.InteropServices;

  public class Taskbar
  {
    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
      public int left;
      public int top;
      public int right;
      public int bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct APPBARDATA
    {
      public int cbSize;
      public IntPtr hWnd;
      public uint uCallbackMessage;
      public uint uEdge;
      public RECT rc;
      public int lParam;
    }

    [DllImport("shell32.dll")]
    private static extern int SHAppBarMessage(int msg, ref APPBARDATA data);
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    private static extern IntPtr SetForegroundWindow(IntPtr hWnd);

    private const int ABS_AUTOHIDE = 1;
    private const int ABS_ALWAYSONTOP = 2;
    private const int ABM_GETSTATE = 4;
    private const int ABM_SETSTATE = 10;

    public static bool GetTaskbarAutoHide()
    {
      var data = new APPBARDATA { cbSize = Marshal.SizeOf(typeof(APPBARDATA)) };
      return SHAppBarMessage(ABM_GETSTATE, ref data) == ABS_AUTOHIDE ? true : false;
    }

    public static void SetTaskbarAutoHide(bool enableAutoHide)
    {
      var data = new APPBARDATA { cbSize = Marshal.SizeOf(typeof(APPBARDATA)) };
      if (enableAutoHide)
      {
        data.lParam = ABS_AUTOHIDE;
        SHAppBarMessage(ABM_SETSTATE, ref data);
      }
      else
      {
        var foregroundWindow = GetForegroundWindow();
        data.lParam = ABS_ALWAYSONTOP;
        SHAppBarMessage(ABM_SETSTATE, ref data);
        SetForegroundWindow(foregroundWindow);
      }
    }
  }

  /// code below includes modifications from:
  /// - https://stackoverflow.com/a/11065126/7312536
  /// - https://pinvoke.net/default.aspx/user32.EnumDesktopWindows

  public class Window
  {
    private delegate bool EnumDesktopWindowsDelegate(IntPtr hWnd, int lParam);

    [DllImport("user32.dll")]
    private static extern bool EnumDesktopWindows(IntPtr hDesktop,
   EnumDesktopWindowsDelegate lpfn, IntPtr lParam);
    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError=true)]
    private static extern int GetWindowLong(IntPtr hWnd, int nIndex);

    private const int GWL_STYLE = -16;
    private const long WS_MAXIMIZE = 0x01000000L;

    private static bool IsWindowMaximized(IntPtr hWnd)
    {
      int windowStyle = GetWindowLong(hWnd, GWL_STYLE);
      return (windowStyle & WS_MAXIMIZE) == WS_MAXIMIZE;
    }

    public static bool AnyWindowsMaximized()
    {
      var allHwnd = new List<IntPtr>();
      EnumDesktopWindowsDelegate filter = delegate(IntPtr hWnd, int lParam)
      {
        if (Window.IsWindowMaximized(hWnd))
        {
          allHwnd.Add(hWnd);
        }
        return true;
      };

      if (EnumDesktopWindows(IntPtr.Zero, filter, IntPtr.Zero))
      {
        return allHwnd.Count > 0;
      }
      return false;
    }
  }
"@

# MAIN

# constantly check for maximized windows
while ($True) {
  # logic to turn taskbar auto hide on/off based on conditions of previous variables
  if ([Window]::AnyWindowsMaximized() -And (-Not [Taskbar]::GetTaskbarAutoHide())) {
    [Taskbar]::SetTaskbarAutoHide($True)
  } elseif ((-Not [Window]::AnyWindowsMaximized()) -And [Taskbar]::GetTaskbarAutoHide()) {
    [Taskbar]::SetTaskbarAutoHide($false)
  }
  Start-Sleep -Seconds $LOOP_SECONDS
}
