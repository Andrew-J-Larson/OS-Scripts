#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender/Recreate-Base-Shortcuts.ps1
# Script only recreates shortcuts to applications it knows are installed, and also works for user profile installed applications.
# If a program you use isn't in any of the lists here, either fork/edit/push, or create an issue at: https://github.com/TheAlienDrew/OS-Scripts/issues/new?title=%5BAdd%20App%5D%20Recreate-Base-Shortcuts.ps1&body=%3C%21--%20Please%20enter%20the%20app%20you%20need%20added%20below%2C%20and%20a%20link%20to%20the%20installer%20%28or%20more%20preferably%2C%20the%20installer%20location%20on%20the%20PC%2C%20and%20where%20the%20shortcut%20normally%20resides%20--%3E%0A%0A
# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

# Application objects are setup like so:
<# @{
       Name="[name of shortcut here]";
       Target="[path to exe here]";
       Arguments="[any arguments that an app starts with here]";
       SystemLnk="[path to lnk or name of app here]";
       StartIn="[start in path if needed, here]";
       Description="[comment that shows up in tooltip, here]"
   } #>

function Recreate-Shortcut {
  Set-Variable ProgramShortcutsPath -Option Constant -Value "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"

  $sName = $args[0] # Required
  $sTarget = $args[1] # Required
  $sArguments = $args[2] # Optional (for special shortcuts)
  $sSystemLnk = $args[3] # Optional (for if name / path is different from normal)
  $sStartIn = $args[4] # Optional (for special shortcuts)
  $sDescription = $args[5] # Optional (some shortcuts have comments for tooltips)

  if ($sName -And $sTarget -And Test-Path $sTarget -PathType leaf) {
    $WScriptObj = New-Object -ComObject ("WScript.Shell")

    # if shortcut path not given, create one at default location with $sName
    if (-Not ($sSystemLnk)) {$sSystemLnk = $sName}
    # if doesn't have $ProgramShortcutsPath path included (and not start with drive letter), it'll assume to create path there
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^'+[Regex]::Escape($ProgramShortcutsPath)+'.*'))) {
      $sSystemLnk = $ProgramShortcutsPath+'\'+$sSystemLnk
    }
    # if it ends with '\', then we append the name to the end
    if ($sSystemLnk.EndsWith('\')) {$sSystemLnk = $sSystemLnk+$sName}
    # if doesn't end with .lnk, add it
    if (-Not ($sSystemLnk -match '.*\.lnk$')) {$sSystemLnk = $sSystemLnk+'.lnk'}
    $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)

    $newLNK.TargetPath = $sTarget

    if ($sArguments) {$newLNK.Arguments = $sArguments}

    if ($sStartIn) {$newLNK.WorkingDirectory = $sStartIn}

    if ($sDescription) {$newLNK.Description = $sDescription}

    $newLNK.Save()
    if ($?) {
      Write-Host "Created shortcut at: ${sSystemLnk}"
      return $true
    }
    else {
      Write-Error "Failed to create shortcut, with target at: ${sTarget}"
      return $false
    }
  } else if (-Not ($sName -Or $sTarget)) {
    if (-Not $sName) {
      Write-Error "Error! Name is missing!"
      return $false
    }
    if (-Not $sTarget) {
      Write-Error "Error! Target is missing!"
      return $false
    }
  } else {
    Write-Error "Target invalid! Doesn't exist or is spelled wrong: ${sTarget}"
    return $false
  }
}

# System Applications

$sysAppList = @(
  @{Name="Microsoft Edge"; Target="C:\Program Files\Microsoft\Edge\Application\msedge.exe"; StartIn="C:\Program Files\Microsoft\Edge\Application"; Description="Browse the web"} # it's the only install on 32-bit
  @{Name="Microsoft Edge"; Target="C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"; StartIn="C:\Program Files (x86)\Microsoft\Edge\Application"; Description="Browse the web"} # it's the only install on 64-bit
  @{Name="OneDrive"; Target="C:\Program Files\Microsoft OneDrive\OneDrive.exe"; Description="Keep your most important files with you wherever you go, on any device."},
  @{Name="Access"; Target="C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE"; Description="Build a professional app quickly to manage data."},
  @{Name="Excel"; Target="C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"; Description="Easily discover, visualize, and share insights from your data."},
  @{Name="OneNote"; Target="C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE"; Description="Take notes and have them when you need them."},
  @{Name="Outlook"; Target="C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"; Description="Manage your email, schedules, contacts, and to-dos."},
  @{Name="PowerPoint"; Target="C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE"; Description="Design and deliver beautiful presentations with ease and confidence."},
  @{Name="Publisher"; Target="C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE"; Description="Create professional-grade publications that make an impact."},
  @{Name="Word"; Target="C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"; Description="Create beautiful documents, easily work with others, and enjoy the read."},
  @{Name="Database Compare"; Target="C:\Program Files\Microsoft Office\root\Client\AppVLP.exe"; Arguments="`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\DATABASECOMPARE.EXE`""; SystemLnk="Microsoft Office Tools\"; Description="Compare versions of an Access database."},
  @{Name="Office Language Preferences"; Target="C:\Program Files\Microsoft Office\root\Office16\SETLANG.EXE"; SystemLnk="Microsoft Office Tools\"; Description="Change the language preferences for Office applications."},
  @{Name="Spreadsheet Compare"; Target="C:\Program Files\Microsoft Office\root\Client\AppVLP.exe" ; Arguments="`"C:\Program Files (x86)\Microsoft Office\Office16\DCF\SPREADSHEETCOMPARE.EXE`""; SystemLnk="Microsoft Office Tools\"; Description="Compare versions of an Excel workbook."},
  @{Name="Telemetry Log for Office"; Target="C:\Program Files\Microsoft Office\root\Office16\msoev.exe"; SystemLnk="Microsoft Office Tools\"; Description="View critical errors, compatibility issues and workaround information for your Office solutions by using Office Telemetry Log."}
#  @{Name=""; Target=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""}
)

for ($i = 0; $i -lt $sysAppList.length; $i++) {
  $app = $sysAppList[$i]
  $aName = $app.Name
  $aTarget = $app.Target
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}

  $Result = Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn $aDescription
}

# OEM System Applications (e.g. Dell)

$oemSysAppList = @(
  @{Name="Dell OS Recovery Tool"; Target="C:\Program Files (x86)\Dell\OS Recovery Tool\DellOSRecoveryTool.exe"; SystemLnk="Dell\"; StartIn="C:\Program Files (x86)\Dell\OS Recovery Tool\"},
  @{Name="SupportAssist Recovery Assistant"; Target="C:\Program Files\Dell\SARemediation\postosri\osrecoveryagent.exe"; SystemLnk="Dell\SupportAssist\"}
#  @{Name=""; Target=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""}
)

for ($i = 0; $i -lt $oemSysAppList.length; $i++) {
  $app = $oemSysAppList[$i]
  $aName = $app.Name
  $aTarget = $app.Target
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}

  $Result = Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn $aDescription
}

# Third-Party System Applications (not made by Microsoft)

$sys3rdPartyAppList = @(
  @{Name="Google Chrome"; Target="C:\Program Files\Google\Chrome\Application\chrome.exe"; StartIn="C:\Program Files\Google\Chrome\Application"; Description="Access the Internet"},
  @{Name="Google Chrome (32-bit)"; Target="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"; StartIn="C:\Program Files (x86)\Google\Chrome\Application"; Description="Access the Internet"},
  @{Name="Firefox"; Target="C:\Program Files\Mozilla Firefox\firefox.exe"; StartIn="C:\Program Files\Mozilla Firefox"},
  @{Name="Firefox (32-bit)"; Target="C:\Program Files (x86)\Mozilla Firefox\firefox.exe"; StartIn="C:\Program Files (x86)\Mozilla Firefox"},
  @{Name="Adobe Acrobat"; Target="C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"},
  @{Name="Adobe Acrobat (32-bit)"; Target="C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe"},
  @{Name="Global VPN Client"; Target="C:\Program Files\SonicWALL\Global VPN Client\SWGVC.exe"},
  @{Name="OpenVPN"; Target="C:\Program Files\OpenVPN\bin\openvpn-gui.exe"; SystemLnk="OpenVPN\OpenVPN GUI"},
  @{Name="CodeTwo Active Directory Photos"; Target="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\CodeTwo Active Directory Photos.exe"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="CodeTwo Active Directory Photos"},
  @{Name="Go to program home page"; Target="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\HomePage.url"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="CodeTwo Active Directory Photos home page"},
  @{Name="User's manual"; Target="C:\Program Files\CodeTwo\CodeTwo Active Directory Photos\Data\User's manual.url"; SystemLnk="CodeTwo\CodeTwo Active Directory Photos\"; Description="Go to User Guide"},
  @{Name="LAPS UI"; Target="C:\Program Files\LAPS\AdmPwd.UI.exe"; SystemLnk="LAPS\"; StartIn="C:\Program Files\LAPS\"},
  @{Name="Microsoft Intune Management Extension"; Target="C:\Program Files (x86)\Microsoft Intune Management Extension\AgentExecutor.exe"; SystemLnk="Microsoft Intune Management Extension\"; Description="Microsoft Intune Management Extension"},
#  @{Name=""; Target=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""},
  @{Name="Epson Scan 2"; Target="C:\Program Files (x86)\epson\Epson Scan 2\Core\es2launcher.exe"; SystemLnk="EPSON\Epson Scan 2\"},
  @{Name="FAX Utility"; Target="C:\Program Files (x86)\Epson Software\FAX Utility\FUFAXCNT.exe"; SystemLnk="EPSON Software\"},
  @{Name="Altair Monarch 2020"; Target="C:\Program Files\Altair Monarch 2020\DWMonarch.exe"; SystemLnk="Altair Monarch 2020\"},
  @{Name="USB Redirector TS Edition - Workstation"; Target="C:\Program Files\USB Redirector TS Edition - Workstation\usbredirectortsw.exe"; SystemLnk="USB Redirector TS Edition - Workstation\"}
#  @{Name=""; Target=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""}
)

for ($i = 0; $i -lt $sys3rdPartyAppList.length; $i++) {
  $app = $sys3rdPartyAppList[$i]
  $aName = $app.Name
  $aTarget = $app.Target
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aSystemLnk = if ($app.SystemLnk) {$app.SystemLnk} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}

  $Result = Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn $aDescription
}

# User Applications (per user installed apps)

$userAppList = @( # all instances of "%username%" get's replaced with the username
  @{Name="OneDrive"; Target="C:\Users\%username%\AppData\Local\Microsoft\OneDrive\OneDrive.exe"},
  @{Name="Microsoft Teams"; Target="C:\Users\%username%\AppData\Local\Microsoft\Teams\Update.exe"; Arguments="--processStart `"Teams.exe`""},
  @{Name="Google Chrome"; Target="C:\Users\%username%\AppData\Local\Google\Chrome\Application\chrome.exe"; StartIn="C:\Users\%username%\AppData\Local\Google\Chrome\Application"; Description="Access the Internet"},
  @{Name="Firefox"; Target="C:\Users\%username%\AppData\Local\Mozilla Firefox\firefox.exe"; StartIn="C:\Users\%username%\AppData\Local\Mozilla Firefox"},
  @{Name="RingCentral"; Target="C:\Users\%username%\AppData\Local\Programs\RingCentral\RingCentral.exe"},
  @{Name="RingCentral Meetings"; Target="C:\Users\%username%\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe"; SystemLnk="RingCentral Meetings\"},
  @{Name="Uninstall RingCentral Meetings"; Target="C:\Users\Andrew\AppData\Roaming\RingCentralMeetings\uninstall\Installer.exe"; Arguments="/uninstall"; SystemLnk="RingCentral Meetings\"}
#  @{Name=""; Target=""; Arguments=""; SystemLnk=""; StartIn=""; Description=""}
)

# get all users 
$Users = (Get-ChildItem "C:\Users\" | % { $_.name })
if ($Users[0].length -eq 1) {$Users = @("$Users")} # if only one user, array needs to be recreated

for ($i = 0; $i -lt $userAppList.length; $i++) {
  $app = $userAppList[$i]
  $aName = $app.Name
  $aTarget = $app.Target
  $aArguments = if ($app.Arguments) {$app.Arguments} else {""}
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {""}
  $aDescription = if ($app.Description) {$app.Description} else {""}

  for ($j = 0; $j -lt $Users.length; $j++) {
    $aUser = $Users[$j]
    $aTarget = $aTarget.replace("%username%", $aUser)
    $aStartIn = $aStartIn.replace("%username%", $aUser)
    $aSystemLnk = "C:\Users\${aUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"+$(if ($app.SystemLnk) {$app.SystemLnk} else {$aName})

    $Result = Recreate-Shortcut $aName $aTarget $sArguments $aSystemLnk $aStartIn $aDescription
  }
}
