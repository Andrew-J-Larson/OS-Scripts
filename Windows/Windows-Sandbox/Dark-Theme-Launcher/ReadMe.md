# Windows Sandbox - Dark Theme Launcher
A launcher for Windows Sandbox to start using the dark theme.

## Instructions

Determine which version you're going to use, dark theme or system theme, below uses steps for the system theme version.

Launch the system themed version by using the shortcut file, `Windows Sandbox`, in this project. The entire folder should be portable, so can place it anywhere on your computer to use.

It launches the `SystemThemeNewSandbox.ps1` script which helps to dynamically run either the light theme or to create the working config file to run Windows Sandbox with the dark theme.

If you want to put the shortcut somewhere else on your computer, without moving the files (e.g. just a shortcut on the desktop), then make sure to move the `SystemThemeNewSandbox.ps1` script to a good location on your computer and modify the `Start in` parameter in the shortcut to the parent directory (e.g.):
1. Moved `SystemThemeNewSandbox.ps1` script to: `C:\CustomSandboxTheme\SystemThemeNewSandbox.ps1`
2. Set shortcut `Start in` to: `C:\CustomSandboxTheme`

NOTE: Same thing applies to the `DarkThemeNewSandbox.ps1` script and `Windows Sandbox (Dark Theme)` shortcut.

## Extra Info

I've also included fancy logic (utilizing the clipboard) to handle hiding the sandbox window until the theme is fully loaded, so that your eyes aren't blinded during the app startup.

The `embedded-resources` contains only files that were used to embed into the script (they aren't read by the script, and doesn't need to be downloaded).
The `img0_3840x2160.jpg` wallpaper inside that folder is for the **Windows 10** sandbox version, as the launch version of the desktop background had a nicer darker appearance.
- The clipboard is also utilized in order to load in the wallpaper without mounting any folders

## Standalone version

A working standalone shortcut is possible, but not recommended (it will likely trip your anti-virus software due to the nature with how the shortcut was created).
s