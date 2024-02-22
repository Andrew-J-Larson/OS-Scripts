@echo off

REM Copyright (C) 2024  Andrew Larson (github@andrew-larson.dev)
REM
REM This program is free software: you can redistribute it and/or modify
REM it under the terms of the GNU General Public License as published by
REM the Free Software Foundation, either version 3 of the License, or
REM (at your option) any later version.
REM
REM This program is distributed in the hope that it will be useful,
REM but WITHOUT ANY WARRANTY; without even the implied warranty of
REM MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM GNU General Public License for more details.
REM
REM You should have received a copy of the GNU General Public License
REM along with this program.  If not, see <https://www.gnu.org/licenses/>.

setlocal

set "scriptName=MediaCreationTool_Run_Preset.ps1"
set "scriptLocation=%~dp0%scriptName%"
set "args=-OS 10 -Edition Ent -Arch x86"
powershell.exe -WindowStyle Hidden -c "Start-Process 'powershell.exe' -ArgumentList '-ExecutionPolicy Bypass -c \". \\\"%scriptLocation%\\\" %args%\"' -Verb RunAs -WindowStyle Minimized"