#!/bin/sh
# This script will automatically download and run qemu (since it is portable) and create a VM to run
# Ventoy LiveCD, simulating the same result of the `ventoy2disk.sh` script on Linux (which isn't compatible
# with MacOS at the time of writing this, 5/26/2021).

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
# TODO: QEMU portable download URL constants needed
Package_Managers="brew port fink"
# TODO: NOTES: Aiming to support High Sierra (10.13)+ (if I can)
#    - HomeBrew: Only supports Mojave (10.14)+, but ARM (M1 Macs) are supported
#    - MacPorts: Supports Sierra (10.12)+, but doesn't support ARM (M1 Macs)
#    - Fink: Appears to support from Tiger (10.4) up to Catalina (10.15)
Ventoy_Releases="https://api.github.com/repos/ventoy/Ventoy/releases/latest"
# TODO: any other constants needed

# Query user on portable or permanent QEMU install
# TODO: (check if an instance of the Ventoy LiveCD virtual machine has already been created, to ignore this query)
#   - Portable: Will need to download QEMU source then compile binaries manaually for MacOS, and then setup the VM in that.
#   - Permanent: 
#      * Check if qemu is already installed, check for package manager (if found, run updates), then use the installed qemu version
#        else, check for a package manager and ask to install qemu from there
#        else prompt to install a package manager of choice to get qemu installed (and then rerun the checks)
#        otherwise, show a message about being unable to continue until a package manager is installed (because managing qemu updates without a package manager wouldn't be fun to code)

# if Ventoy LiveCD virtual machine is not already setup do that
# else, make sure the .iso file is latest
# TODO: + will need to save the general command to start the VM without USB drives to work with later
#   * live cd download naming scheme is `ventoy-[version]-livecd.iso`

# Prompt for USB drive(s) selection to use with Ventoy LiveCD VM
# TODO: need to list connected USB drives and need to support selecting 1 or more drives

# Start the VM, and make sure it outputs to terminal (shouldn't need a virtual display)
# TODO: from here, normal steps for using ventoy2disk.sh should all that be needed

# (might need to detect when qemu shutsdown?)
# TODO: not sure if shutting down qemu VM's will let USB drives automatically remount back in MacOS, so I'll need to do some testing
