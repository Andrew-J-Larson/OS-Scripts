## Supported Applications

Use the following script to recreate the app shortcuts:
 - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1

If deploying via Intune, please instead using the following script (requires internet access):
 - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts-INTUNE.ps1

By default, a shortcut won't be made for programs that aren't installed, so rest assured, you won't have random app shortcuts created.

The script does make a log at the root of the machine it was ran on, likely located at `C:\Recreate-Base-Shortcuts.log`. If you are going to submit a bug report, please include this file, as it's generally very handy for me to diagnose the issue.

If you wish to contribute, either look at the code and add in entries manually, or you can look at [this script I made (Function-Generate-Lnk-Info.ps1)](https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Function-Generate-Lnk-Info.ps1), that has functions for generating shortcut(s) info in a format compatible with this recreation script.

### Here's a list of all of the current supported applications:
 - Microsoft
   - Azure Data Studio
   - Azure IoT Explorer
   - Edge
   - Microsoft Intune Management Extension
   - Office (entire suite)
   - OneDrive
   - Teams
   - Power BI Desktop
   - PowerShell 7 (or whatever is the newest installed on your machine)
   - PowerToys
   - Remote Desktop (Azure Virtual Desktop)
   - Remote help
   - Visual Studio Code
   - Visual Studio 2022 / 2019 / 2017
     - Python installs through Visual Studio **NOT** supported!
   - Visual Studio Installer
   - Windows
     - Accessibility (e.g. Narrator)
     - Accessories (e.g. Remote Desktop Connection)
     - Administrative Tools (e.g. Computer Management)
     - PowerShell (the one built into Windows)
     - System Tools (e.g. Command Prompt)
 - Adobe
   - Creative Cloud (entire suite + Maxon Cinema 4D)
   - Acrobat
   - Acrobat Reader (old)
   - Digital Editions 4.5 (or whatever is the newest installed on your machine)
 - Autodesk
   - Meshmixer
 - Google
   - Chrome
   - Google Drive
   - VPN by GoogleOne
 - Mozilla
   - Firefox
   - Thunderbird
 - Dell
   - Dell OS Recovery Tool
   - SupportAssist Recovery Assistant
 - NVIDIA
   - GeForce Experience
   - GeForce NOW
 - RealVNC
   - VNC Server
   - VNC Viewer
 - KeePass
   - KeePass (2.x versions or newer)
   - KeePass (1.x versions)
 - RingCentral
   - RingCentral App
   - RingCentral Meetings
 - Cisco
   - Cisco AnyConnect Secure Mobility Client
   - Cisco Jabber
 - Altair
   - Monarch 2021
   - Monarch 2020
 - Eaton
   - 9000XDrive
   - 9000XLoad
 - Epson Software
   - Epson Scan 2
   - FAX Utility)
 - Others
   - 1Password
   - 7-Zip
   - AmbiBox
   - Audacity
   - AutoHotkey + AutoHotkey V2
   - AWS VPN Client
   - balenaEtcher
   - BCUninstaller (Bulk Crap Uninstaller)
   - Blender
   - Bytello Share
   - Citrix Workspace
   - CodeTwo Active Directory Photos
   - Discord
   - Docker Desktop
   - draw.io
   - Egnyte Desktop App
   - GIMP (GNU Image Manipulation Program)
   - GitHub Desktop
   - GoTo Resolve Desktop Console
   - Inkscape
   - KC Softwares SUMo
   - Kdenlive
   - LAPS UI (Local Administrator Password Solution)
   - Ledger Live
   - Notepad++
   - OpenVPN
   - OSFMount
   - paint.net
   - Parallels Client
   - Pulse Secure
   - PuTTY
   - Python 3.11 (or whatever is the newest installed on your machine)
   - Raspberry Pi Imager
   - Samsung DeX
   - Slack
   - SonicWall Global VPN Client
   - SoundSwitch
   - Team Viewer
   - USB Redirector TS Edition - Workstation
   - VirtualBox
   - VLC media player
   - VMware Workstation 16 Player
   - Win32DiskImager
   - Winaero
   - WinDirStat
   - WinSCP
   - Yaskawa DriveWizard Industrial
   - Zoom
