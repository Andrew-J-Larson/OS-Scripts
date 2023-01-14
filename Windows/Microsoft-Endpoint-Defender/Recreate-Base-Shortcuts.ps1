#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1
# Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
# If a program you use isn't in any of the lists here, either fork/edit/push, or create an issue at: https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20%28or%20more%20preferably%2C%20the%20installer%20location%20on%20the%20PC%2C%20and%20where%20the%20shortcut%20normally%20resides%20--%3E%0A%0A
# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

# Application objects are setup like so:
<# @{
       Name='[name of shortcut here]';
       Target='[path to exe here]';
       Arguments='[any arguments that an app starts with here]';
       SystemLnk='[path to lnk or name of app here]';
       StartIn='[start in path if needed, here]'
   } #>

function Recreate-Shortcut {
  Set-Variable ProgramShortcutsPath -Option Constant -Value 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'

  $sName = $args[0] # Required
  $sTarget = $args[2] # Required
  $sArguments = $args[3] # Optional (for special shortcuts)
  $sSystemLnk = $args[1] # Optional (for if name / path is different from normal)
  $sStartIn = $args[4] # Optional (for special shortcuts)

  if (Test-Path $sTarget -PathType leaf) {
    $WScriptObj = New-Object -ComObject ('WScript.Shell')

    # if shortcut path not given, create one at default location with $sName
    if (-Not ($sSystemLnk)) {$sSystemLnk = $sName}
    # if doesn't have $ProgramShortcutsPath path included (and not start with drive letter), it'll assume to create path there
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^'+[Regex]::Escape($ProgramShortcutsPath)+'.*'))) {
      $sSystemLnk = ($ProgramShortcutsPath+'\'+$sSystemLnk)
    }
    # if doesn't end with .lnk, add it
    if (-Not ($sSystemLnk -match '.*\.lnk$')) {$sSystemLnk = $sSystemLnk+'.lnk'}
    $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)

    $newLNK.TargetPath = $sTarget

    if ($sArguments) {$newLNK.Arguments = $sArguments}

    if ($sStartIn) {$newLNK.WorkingDirectory = $sStartIn}

    $newLNK.Save()
  }
}

# System Applications

$sysAppList = @(
  @{Name='Microsoft Edge'; Target='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'}
  @{Name='OneDrive'; Target='C:\Program Files\Microsoft OneDrive\OneDrive.exe'},
  @{Name='Access'; Target='C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE'},
  @{Name='Excel'; Target='C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE'},
  @{Name='OneNote'; Target='C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'},
  @{Name='Outlook'; Target='C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE'},
  @{Name='PowerPoint'; Target='C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE'},
  @{Name='Publisher'; Target='C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE'},
  @{Name='Word'; Target='C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'}#,
#  @{Name=''; Target=''},
#  @{Name=''; Target=''; Arguments=''; SystemLnk=''; StartIn=''}
)

for ($i = 0; $i -lt $sysAppList.length; $i++) {
  $app = $sysAppList[$i]
  $aName = $app.Name
  $aSystemLnk = $app.SystemLnk
  $aTarget = $app.Target
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn
}

# OEM System Applications (e.g. Dell)

<# $oemSysAppList = @(
  @{Name=''; Target=''; Arguments=''; SystemLnk=''; StartIn=''}
)

for ($i = 0; $i -lt $oemSysAppList.length; $i++) {
  $app = $oemSysAppList[$i]
  $aName = $app.Name
  $aSystemLnk = $app.SystemLnk
  $aTarget = $app.Target
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn
} #>

# Third-Party System Applications (not made by Microsoft)

$sys3rdPartyAppList = @(
  @{Name='Google Chrome'; Target='C:\Program Files\Google\Chrome\Application\chrome.exe'},
  @{Name='Google Chrome (32-bit)'; Target='C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'},
  @{Name='Firefox'; Target='C:\Program Files\Mozilla Firefox\firefox.exe'},
  @{Name='Global VPN Client'; Target='C:\Program Files\SonicWALL\Global VPN Client\SWGVC.exe'},
  @{Name='OpenVPN'; SystemLnk='OpenVPN\OpenVPN GUI'; Target='C:\Program Files\OpenVPN\bin\openvpn-gui.exe'},
  @{Name='Adobe Acrobat'; Target='C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'},
  @{Name='Adobe Acrobat (32-bit)'; Target='C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe'},
  @{Name='Epson Scan 2'; SystemLnk='EPSON\Epson Scan 2\Epson Scan 2'; Target='C:\Program Files (x86)\epson\Epson Scan 2\Core\es2launcher.exe'},
  @{Name='FAX Utility'; SystemLnk='EPSON Software\FAX Utility'; Target='C:\Program Files (x86)\Epson Software\FAX Utility\FUFAXCNT.exe'},
  @{Name='Altair Monarch 2020'; SystemLnk='Altair Monarch 2020\Altair Monarch 2020'; Target='C:\Program Files\Altair Monarch 2020\DWMonarch.exe'},
  @{Name='USB Redirector TS Edition - Workstation'; SystemLnk='USB Redirector TS Edition - Workstation\USB Redirector TS Edition - Workstation'; Target='C:\Program Files\USB Redirector TS Edition - Workstation\usbredirectortsw.exe'}
#  @{Name=''; Target=''; Arguments=''; SystemLnk=''; StartIn=''}
)

for ($i = 0; $i -lt $sys3rdPartyAppList.length; $i++) {
  $app = $sys3rdPartyAppList[$i]
  $aName = $app.Name
  $aSystemLnk = $app.SystemLnk
  $aTarget = $app.Target
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn
}

# User Applications (per user installed apps)

$userAppList = @( # all instances of '%username%' get's replaced with the username
  @{Name='OneDrive'; Target='C:\Users\%username%\AppData\Local\Microsoft\OneDrive\OneDrive.exe'},
  @{Name='Microsoft Teams'; Target='C:\Users\%username%\AppData\Local\Microsoft\Teams\Update.exe'; Arguments='--processStart "Teams.exe"'},
  @{Name='Google Chrome'; Target='C:\Users\%username%\AppData\Local\Google\Chrome\Application\chrome.exe'},
  @{Name='Firefox'; Target='C:\Users\%username%\AppData\Local\Mozilla Firefox\firefox.exe'},
  @{Name='RingCentral'; Target='C:\Users\%username%\AppData\Local\Programs\RingCentral\RingCentral.exe'},
  @{Name='RingCentral Meetings'; SystemLnk='RingCentral Meetings\RingCentral Meetings'; Target='C:\Users\%username%\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe'},
  @{Name='Uninstall RingCentral Meetings'; SystemLnk='RingCentral Meetings\Uninstall RingCentral Meetings'; Target='C:\Users\Andrew\AppData\Roaming\RingCentralMeetings\uninstall\Installer.exe'; Arguments='/uninstall'}
#  @{Name=''; Target=''; Arguments=''; SystemLnk=''; StartIn=''}
)

# get all users 
$Users = (Get-ChildItem 'C:\Users\' | % { $_.name })
if ($Users[0].length -eq 1) {$Users = @("$Users")} # if only one user, array needs to be recreated

for ($i = 0; $i -lt $userAppList.length; $i++) {
  $app = $userAppList[$i]
  $aName = $app.Name
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  for ($j = 0; $j -lt $Users.length; $j++) {
    $aUser = $Users[$j]
    $aSystemLnk = ("C:\Users\${aUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"+$app.SystemLnk)
    $aTarget = ($app.Target).replace('%username%', $aUser)
    Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn
  }
}
