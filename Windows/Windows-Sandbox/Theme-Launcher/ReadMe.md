# Windows Sandbox - Theme Launcher
A theme launcher for Windows Sandbox.

## Instructions

Launch the user themed version by using the shortcut file, `Windows Sandbox`, in this project. The entire folder should be portable, so you can place it anywhere on your computer to use.

It launches the `ThemedSandbox.ps1` script which helps to dynamically run the sandbox with your main user theme.

If you want to put the shortcut somewhere else on your computer, without moving the files (e.g. just a shortcut on the desktop), then make sure to move the `ThemedSandbox.ps1` script to a good location on your computer and modify the `Start in` parameter in the shortcut to the parent directory (e.g.):
1. Moved `ThemedSandbox.ps1` script to: `C:\SandboxThemeLauncher\ThemedSandbox.ps1`
2. Set shortcut `Start in` to: `C:\SandboxThemeLauncher`
- NOTE: The clipboard is utilized in order to load in the theme without mounting any folders

## Standalone Version

A working standalone shortcut is possible, but not recommended (it will likely trip your anti-virus software due to the nature with how the shortcut was created).

## Older Versions

They exist, but not as useful as the latest version. Instructions for shortcut setup also applies for them.
