<#
  .SYNOPSIS
  Generate Shortcuts (Functions) v1.0.6

  .DESCRIPTION
  Script only enables the functions genLnkInfo and genLnkRecurseInfo.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Script: None. You cannot pipe objects to this script.
  Functions: See notes.

  .OUTPUTS
  Script: None.
  Functions: See notes.

  .EXAMPLE
  .\Function-Generate-Lnk-Info.ps1

  .NOTES
  Requires admin! Because VBscript (used to read shortcuts) requires admin to read some shortcut attributes.

  After running the script you should have access to functions:
   - genLnkInfo : creates LNK info for shortcut
    - e.g. `PS > genLnkInfo "C:\path\to\shortcut.lnk"`
   - genLnkRecurseInfo : creates LNK info for all shortcuts in folder
    - e.g. `PS > genLnkRecurseInfo "C:\path\to\shortcuts\folder"`
    - e.g. `PS > genLnkRecurseInfo "C:\folder\one" "C:\another\folder"`
    - `genLnkRecurseInfo` is same as `genLnkRecurseInfo $PWD`
  
  Pairs well when piping commands to `Set-Clipboard` or `Out-File`.
  
  Format of output that these commands create
   - @{Name = "..."; TargetPath = "..."; Arguments = "..."; SystemLnk = "..."; WorkingDirectory = "..."; Description = "..."; IconLocation = "..."; RunAsAdmin = ($true -Or $false) },

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Microsoft-Endpoint-Defender/Function-Generate-Lnk-Info.ps1
#>
#Requires -RunAsAdministrator

<# Copyright (C) 2023  Andrew Larson (andrew.j.larson18@gmail.com)

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



# Constants

Set-Variable -Name USERNAME -Option Constant -Value "$(((Get-WMIObject -ClassName Win32_ComputerSystem | Select-Object username).username).split('\')[1])"



# Functions

# USE THIS FUNCTION ON .LNK FILES
function genLnkInfo {
    $shortcutFile = if ($args[0].FullName) { $args[0].FullName } else { $args[0] }
    $shortcutFile = Get-ChildItem $shortcutFile

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
    $RunAsAdmin = if ($bytes[0x15] -eq 32) { '$true' }

    $Name = $shortcutFile.BaseName
    $lnkFile = $Name + ".lnk"
        
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}"), '${USERS_FOLDER}\${aUser}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:SystemDrive}\USERS"), '${USERS_FOLDER}')
    $TargetPath = ($TargetPath -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
    $Entry = "@{Name = `"${Name}`"; TargetPath = `"${TargetPath}`"; "

    if ($Arguments) {
        $Arguments = ($Arguments).replace('`', '``')
        $Arguments = ($Arguments).replace('"', '`"')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}"), '${USERS_FOLDER}\${aUser}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:SystemDrive}\USERS"), '${USERS_FOLDER}')
        $Arguments = ($Arguments -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
        $Entry += "Arguments = `"${Arguments}`"; "
    }
    $SystemLnk = ($shortcutFile.FullName).replace($lnkFile, "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ALLUSERSPROFILE}\Microsoft\Windows\Start Menu\Programs\"), "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\"), "")
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}"), '${USERS_FOLDER}\${aUser}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:SystemDrive}\USERS"), '${USERS_FOLDER}')
    $SystemLnk = ($SystemLnk -ireplace [regex]::Escape("${env:windir}"), '${env:windir}')
    if ($SystemLnk) { $Entry += "SystemLnk = `"${SystemLnk}`"; " }
    if ($WorkingDirectory) {
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:ProgramFiles(x86)}"), '${env:ProgramFiles(x86)}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:ProgramFiles}"), '${env:ProgramFiles}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}"), '${USERS_FOLDER}\${aUser}')
        $WorkingDirectory = ($WorkingDirectory -ireplace [regex]::Escape("${env:SystemDrive}\USERS"), '${USERS_FOLDER}')
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
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:SystemDrive}\USERS\${USERNAME}"), '${USERS_FOLDER}\${aUser}')
        $IconLocation = ($IconLocation -ireplace [regex]::Escape("${env:SystemDrive}\USERS"), '${USERS_FOLDER}')
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
            Write-Output ""
        }
    } else {
        GEN_LNK_INFO_BASE $PWD
    }
}



# MAIN

# there is nothing here
