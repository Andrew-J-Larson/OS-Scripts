## Standalone Version

This version of the shortcut uses steganography to merge the shortcut and the script into one file, and the shortcut parameters have been tweaked to read the PowerShell code from within.
- This was done using the following command (in CMD) `copy /b "..\Windows Sandbox (Dark Theme).lnk" + ..\DarkThemeNewSandbox.ps1 "Windows Sandbox (Dark Theme).lnk"`

However, most modern virus protection software will likely see this file as a threat, and quarantine it, so that's why this version isn't as recommended.

Additional note, attempting to modify any of the properties on the shortcut will shed away the bundled script file, breaking the file. So, if you want to modify the properties, you'll have to recreate the shortcut like so:
- `copy /b "Windows Sandbox (Dark Theme).lnk" + ..\DarkThemeNewSandbox.ps1 "Windows Sandbox (Dark Theme) - Fixed.lnk"`
