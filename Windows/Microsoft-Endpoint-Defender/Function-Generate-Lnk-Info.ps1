$USERNAME = ((Get-WMIObject -ClassName Win32_ComputerSystem | select username).username).split('\')[1]

# USE THIS FUNCTION ON .LNK FILES
function genLnkInfo {
    $shortcutFile = Get-ChildItem $args[0]

    $WshShell = New-Object -comObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut($shortcutFile.FullName)

    $TargetPath = $shortcut.TargetPath
    $Arguments = $shortcut.Arguments
    $WorkingDirectory = $shortcut.WorkingDirectory
    $Description = $shortcut.Description
    $IconLocation = $shortcut.IconLocation
        
    $shortcut.Save()
    [Runtime.InteropServices.Marshal]::ReleaseComObject($WshShell) | Out-Null

    $bytes = [System.IO.File]::ReadAllBytes($shortcutFile.FullName)
    $RunAsAdmin = if ($bytes[0x15] -eq 32) {'$true'}

    $Name = $shortcutFile.BaseName
    $lnkFile = $Name + ".lnk"
        
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}"), '${env:HOMEDRIVE}\USERS\${aUser}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS"), '${USERS_FOLDER}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
    $Entry = "@{Name = `"${Name}`"; TargetPath = `"${TargetPath}`"; "

    if ($Arguments) {
        $Arguments = ($Arguments).replace('`', '``')
        $Arguments = ($Arguments).replace('"', '`"')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}"), '${env:HOMEDRIVE}\USERS\${aUser}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS"), '${USERS_FOLDER}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
        $Entry += "Arguments = `"${Arguments}`"; "
    }
    $SystemLnk = ($shortcutFile.FullName).replace($lnkFile, "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\"), "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"), "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}"), '${env:HOMEDRIVE}\USERS\${aUser}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS"), '${USERS_FOLDER}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
    $Entry += "SystemLnk = `"${SystemLnk}`"; "
    if ($WorkingDirectory) {
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}"), '${env:HOMEDRIVE}\USERS\${aUser}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS"), '${USERS_FOLDER}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
        $Entry += "WorkingDirectory = `"${WorkingDirectory}`"; "
    }
    if ($Description) {
        $Description = ($Description).replace('`', '``')
        $Description = ($Description).replace('"', '`"')
        $Entry += "Description = `"${Description}`"; "
    }
    if ($IconLocation) {
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS\${USERNAME}"), '${env:HOMEDRIVE}\USERS\${aUser}')
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:HOMEDRIVE}\USERS"), '${USERS_FOLDER}')
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
        $Entry += "IconLocation = `"${IconLocation}`"; "
    }
    if ($RunAsAdmin) {
        $Entry += "RunAsAdmin = ${IconLocation}; "
    }
    $Entry += "},"
    $Entry = $Entry.replace("; },", " },")

    Write-Output $Entry
}

# DON'T USE THIS FUNCTION
function GEN_LNK_INFO_BASE {
    Get-ChildItem $args[0] -Recurse -Filter *.lnk | 
    Foreach-Object {
        genLnkInfo $_
    }
}

# USE THIS FUNCTION ON DIRECTORIES
function genLnkRecurseInfo {
    if ($args.length -ge 1) {
        for ($i = 0; $i -lt $args.length; $i++) {
            GEN_LNK_INFO_BASE $args[$i]
        }
    } else {
        GEN_LNK_INFO_BASE $PWD
    }
}

# genLnkRecurseInfo
<# OR #>
# genLnkRecurseInfo [path or paths in quotes]

<# e.g. #>
# genLnkRecurseInfo ; <# is same as #> ; genLnkRecurseInfo $PWD
# genLnkRecurseInfo "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
# genLnkRecurseInfo "C:\ProgramData\Microsoft\Windows\Start Menu\Programs" "C:\Users\${USERNAME}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"

<# creates output ready to be put directly into script, with all or fewer fields #>
# @{Name = "..."; TargetPath = "..."; Arguments = "..."; SystemLnk = "..."; WorkingDirectory = "..."; Description = "..."; IconLocation = "..."; RunAsAdmin = ($true -Or $false) },

<# copy to clipboard #>
# genLnkRecurseInfo | Set-Clipboard