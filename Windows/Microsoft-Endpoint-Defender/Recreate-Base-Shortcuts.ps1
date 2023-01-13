#Requires -RunAsAdministrator
# Recreate Base Shortcuts - https://github.com/TheAlienDrew/OS-Scripts/blob/master/Windows/Microsoft-Endpoint-Defender\Recreate-Base-Shortcuts.ps1
# About the issue: https://www.bleepingcomputer.com/news/microsoft/buggy-microsoft-defender-asr-rule-deletes-windows-app-shortcuts/

function Recreate-Shortcut {
  Set-Variable ProgramShortcutsPath -Option Constant -Value 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs'

  $sName = $args[0] # Required
  $sSystemLnk = $args[1] # Required
  $sTarget = $args[2] # Required
  $sArguments = $args[3] # Optional (for special shortcuts)
  $sStartIn = $args[4] # Optional (for special shortcuts)

  if (Test-Path $sTarget -PathType leaf) {
    $WScriptObj = New-Object -ComObject ('WScript.Shell')
    # if doesn't have $ProgramShortcutsPath path included (and not start with drive letter), it'll assume to create path there
    if (-Not ($sSystemLnk -match '^[a-zA-Z]:\\.*' -Or $sSystemLnk -match ('^'+[Regex]::Escape($ProgramShortcutsPath)+'.*'))) {
      $sSystemLnk = ($ProgramShortcutsPath+'\'+$sSystemLnk)
    }
    # if doesn't end with .lnk, add it
    if (-Not ($sSystemLnk -match '.*\.lnk$')) {
      $sSystemLnk = $sSystemLnk+'.lnk'
    }
    $newLNK = $WscriptObj.CreateShortcut($sSystemLnk)
    $newLNK.TargetPath = $sTarget
    if ($sArguments) {$newLNK.Arguments = $sArguments}
    if ($sStartIn) {$newLNK.WorkingDirectory = $sStartIn}
    $newLNK.Save()
  }
}

# All User Applications

#  @{Name='[name of shortcut here]'; SystemLnk='[path to lnk or name of app here]'; Target='[path to exe here]'; StartIn='[start in path if needed, here]'}
#  @{Name=''; SystemLnk=''; Target=''; StartIn=''}
$appList = @(
  @{Name='Microsoft Edge'; SystemLnk='Microsoft Edge'; Target='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'},
  @{Name='Access'; SystemLnk='Access'; Target='C:\Program Files\Microsoft Office\root\Office16\MSACCESS.EXE'},
  @{Name='Excel'; SystemLnk='Excel'; Target='C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE'},
  @{Name='OneNote'; SystemLnk='OneNote'; Target='C:\Program Files\Microsoft Office\root\Office16\ONENOTE.EXE'},
  @{Name='Outlook'; SystemLnk='Outlook'; Target='C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE'},
  @{Name='PowerPoint'; SystemLnk='PowerPoint'; Target='C:\Program Files\Microsoft Office\root\Office16\POWERPNT.EXE'},
  @{Name='Publisher'; SystemLnk='Publisher'; Target='C:\Program Files\Microsoft Office\root\Office16\MSPUB.EXE'},
  @{Name='Word'; SystemLnk='Word'; Target='C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE'},
  @{Name='Google Chrome'; SystemLnk='Google Chrome'; Target='C:\Program Files\Google\Chrome\Application\chrome.exe'},
  @{Name='Google Chrome (32-bit)'; SystemLnk='Google Chrome (32-bit)'; Target='C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'},
  @{Name='Firefox'; SystemLnk='Firefox'; Target='C:\Program Files\Mozilla Firefox\firefox.exe'},
  @{Name='Global VPN Client'; SystemLnk='Global VPN Client'; Target='C:\Program Files\SonicWALL\Global VPN Client\SWGVC.exe'},
  @{Name='OpenVPN'; SystemLnk='OpenVPN\OpenVPN GUI'; Target='C:\Program Files\OpenVPN\bin\openvpn-gui.exe'},
  @{Name='Adobe Acrobat'; SystemLnk='Adobe Acrobat'; Target='C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe'},
  @{Name='Adobe Acrobat (32-bit)'; SystemLnk='Adobe Acrobat (32-bit)'; Target='C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe'}
)

for ($i = 0; $i -lt $appList.length; $i++) {
  $app = $appList[$i]
  $aName = $app.Name
  $aSystemLnk = $app.SystemLnk
  $aTarget = $app.Target
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  Recreate-Shortcut $aName $aSystemLnk $aTarget $sArguments $aStartIn
}

# User Profile Applications

$Users = (Get-ChildItem 'C:\Users\' | % { $_.name })
# only one user
if ($Users[0].length -eq 0) {$Users = @("$Users")}

#  @{Name='[name of shortcut here]'; SystemLnk='[path to lnk or name of app here]'; Target='[path to exe here]'; StartIn='[start in path if needed, here]'}
#  @{Name=''; SystemLnk=''; Target=''; StartIn=''}
$userAppList = @( # all instances of '%username%' get's replaced with the username
  @{Name='Microsoft Teams'; SystemLnk='Microsoft Teams'; Target='C:\Users\%username%\AppData\Local\Microsoft\Teams\Update.exe'; Arguments='--processStart "Teams.exe"'},
  @{Name='Google Chrome'; SystemLnk='Google Chrome'; Target='C:\Users\%username%\AppData\Local\Programs\Chrome\Application\chrome.exe'},
  @{Name='Firefox'; SystemLnk='Firefox'; Target='C:\Users\%username%\AppData\Local\Programs\Mozilla Firefox\firefox.exe'},
  @{Name='RingCentral'; SystemLnk='RingCentral'; Target='C:\Users\%username%\AppData\Local\Programs\RingCentral\RingCentral.exe'},
  @{Name='RingCentral Meetings'; SystemLnk='RingCentral Meetings\RingCentral Meetings'; Target='C:\Users\%username%\AppData\Roaming\RingCentralMeetings\bin\RingCentralMeetings.exe'}
)

for ($i = 0; $i -lt $userAppList.length; $i++) {
  $app = $userAppList[$i]
  $aName = $app.Name
  $aArguments = $app.Arguments
  $aStartIn = if ($app.StartIn) {$app.StartIn} else {''}

  for ($j = 0; $j -lt $Users.length; $j++) {
    $aUser = $Users[$j]
    $aSystemLnk = ("C:\Users\${aUser}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"+$app.SystemLnk)
    $aTarget = ($app.Target).replace('%username%', $aUser)
    Recreate-Shortcut $aName $aSystemLnk $aTarget $aArguments $aStartIn
  }
}
