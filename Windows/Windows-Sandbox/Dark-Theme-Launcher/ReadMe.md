# Windows Sandbox - Dark Theme Launcher
A launcher for Windows Sandbox to start using the dark theme.

## Instructions

Launch the dark theme by using the shortcut file `Windows Sandbox (Dark Theme)`. The entire folder should be portable, so can place it anywhere on your computer to use.

It launches the `DarkThemeSandboxHandler.ps1` script which helps to dynamically create the working config file to run Windows Sandbox with the dark theme.

If you want to put the shortcut somewhere else on your computer, without moving the files (e.g. just a shortcut on the desktop), then make sure to move the `files` folder to a good location on your computer and modify the `Start in` parameter in the shortcut to the parent directory (e.g.):
1. Moved `files` folder to: `C:\CustomSandboxTheme\files`
2. Set shortcut `Start in` to: `C:\CustomSandboxTheme`

## Extra Info

I've also tried to include logic to handle hiding the sandbox window until the theme is fully loaded, so that eyes aren't blinded during the app startup.

The `Windows (dark).deskthemepack` helps to theme the Windows 10 sandbox version with dark mode, and replaces the background with the original Windows 10 launch version of the desktop background for a darker appearance.
