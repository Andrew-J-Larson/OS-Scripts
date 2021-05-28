#!/bin/sh
##########################################################################################################
###################################### CURRENTLY A WORK IN PROGRESS ######################################
##########################################################################################################

# This script will help install the following as needed:
#  - HomeBrew or MacPorts (package manager, only if installing to user account on a supported version)
#  - QEMU
#  - Ventoy LiveCD (as VM in QEMU)
# The aim is to simulate the `Ventoy2Disk.sh` script used on Linux.
# (which isn't compatible with MacOS at the time of writing this, 5/26/2021)

# Copyright (C) 2020  Andrew Larson (thealiendrew@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# CONSTANTS
Package_Managers="brew port" # HomeBrew and MacPorts
QEMU_Releases="https://api.github.com/repos/qemu/qemu/releases"
Ventoy_Releases="https://api.github.com/repos/ventoy/Ventoy/releases"
User_Install="~/Ventoy"
# TODO: any other constants needed

# VARIABLES
macVersion= # this and the following 2 get in the compatibility check
majVer=
minVer=
packageManager= # if permanent install is chosen, this will get set

# Ensure that we are running on a MacOS system
if [ "$(uname -s)" = "Darwin" ]; then
  macVersion="$(sw_vers -productVersion)"
  majVer="$(echo "$macVersion" | cut -d'.' -f1)"
  minVer="$(echo "$macVersion" | cut -d'.' -f2)"
else # not a mac
  echo "Sorry, not running on a MacOS system, aborting."
  exit 1
fi

# Query user about local or permanent install
while true; do
    read -p "Would you like to install to [U]ser account or [L]ocally? " ul
    case $ul in
        [Uu]* ) ...; break;; # TODO:
        [Ll]* ) ...; break;; # TODO:
        * ) echo "Please answer with U (User account) or L (Locally).";;
    esac
done
# TODO: (check for user account Ventoy installation first)
#   - If a user install is detected, prompt for uninstallation or repair
#   - Locally: Will need to download QEMU source then compile binaries manaually for MacOS (see https://wiki.qemu.org/Hosts/Mac#Building_QEMU_for_macOS),
#              and then setup the VM in that. Will need a package manager to install the resources needed to compile.
#      * If location selected has an install, prompt for removal or repair
#   - User account:
#      * HomeBrew: Only supports Mojave (10.14)+, but ARM (M1 Macs) are supported
#      * MacPorts: Supports Sierra (10.12)+, but doesn't support ARM (M1 Macs)
#      * Check if qemu is already installed, check for package manager (if found, run updates), then use the installed qemu version
#        else, check for a package manager and ask to install qemu from there
#        else prompt to install a package manager of choice to get qemu installed (and then rerun the checks)
#        otherwise, show a message about being unable to continue until a package manager is installed (because managing qemu updates without a package manager wouldn't be fun to code)

# If Ventoy LiveCD virtual machine is not already setup do that
# TODO: + will need to save the general command to start the VM without USB drives to work with later
#   * live cd download naming scheme is `ventoy-[version]-livecd.iso`
