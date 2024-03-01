<#
  .SYNOPSIS
  Fix UTF-8 Bytes Interpretted as Windows-1252 v1.0.0

  .DESCRIPTION
  When a file's encoding has been improperly interpretted with the wrong encoding (in this case Windows-1252), it
  may show strange extended latin characters in front of some symbols. Using this script should revert the issue.

  Two folders will be created, 'debug' and 'fixed' (if they don't already exist), in the same directory the script
  was ran from. You'll want to place all affected files in the 'debug' folder, then run the script. When the script
  gets done processing, all files should copied to the 'fixed' folder with the right encodings.

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Reads files from 'debug' folder. No other flags other than the help flag.

  .OUTPUTS
  Outputs files to 'fixed' folder. Display errors if any.

  .EXAMPLE
  PS> .\Fix-UTF8-Bytes-Interpretted-as-Windows1252.ps1

  .LINK
  Why this happens, so you can prevent the malformed UTF-8 files: https://www.i18nqa.com/debug/bug-utf-8-latin1.html

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/UTF8-Debugging/Fix-UTF8-Bytes-Interpretted-as-Windows1252.ps1
#>

<# Copyright (C) 2024  Andrew Larson (github@andrew-larson.dev)

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

$Windows1252Encoding = 1252
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False

$Path = $(if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) {
  Split-Path -Parent $MyInvocation.MyCommand.Path
} else { $PWD.Path }).trimend('\')
$debugPath = "${Path}\debug"
$fixedPath = "${Path}\fixed"

# MAIN

# Creates folders if needed
$debugFolder = New-Item -LiteralPath $debugPath -ItemType Directory -Force
$fixedFolder = New-Item -LiteralPath $fixedPath -ItemType Directory -Force

# Recurse and loop through all files in the debug folder
$debugFiles = Get-ChildItem -LiteralPath $debugFolder -File -Recurse
$debugFiles | ForEach-Object {
  # in PS 5.1, Unicode is UTF-16 LE, which is what we need the file interpretted as originally for PowerShell
  # to get the correct bytes needed to revert the problem, else it'll assume the wrong encoding and lose data
  $brokenEncoding = Get-Content -LiteralPath $_.FullName -Raw -Encoding Unicode
  # with the original bytes, the encoding can be fixed
  $originalBytes = [System.Text.Encoding]::GetEncoding($Windows1252Encoding).GetBytes($brokenEncoding)
  $fixedEncoding = [System.Text.Encoding]::UTF8.GetString($originalBytes)

  # Need to export file in UTF-8 (without BOM, but PS 5.1 doesn't do that normally)
  [System.IO.File]::WriteAllLines("$($fixedFolder.FullName)\$($_.Name)", $fixedEncoding, $Utf8NoBomEncoding)
}
