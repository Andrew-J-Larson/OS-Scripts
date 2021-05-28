#!/bin/sh
##########################################################################################################
###################################### CURRENTLY A WORK IN PROGRESS ######################################
##########################################################################################################

# This script will help install the following as needed:
#  - Xcode (with CLI tools)
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
Xcode_Install="/Applications/Xcode.app"
Xcode_App_URL="https://apps.apple.com/app/id497799835"
QEMU_Releases="https://api.github.com/repos/qemu/qemu/releases"
Ventoy_Releases="https://api.github.com/repos/ventoy/Ventoy/releases"
User_Install="~/Ventoy"
# TODO: any other constants needed

# VARIABLES
macVersion= # this and the following 2 get set in the compatibility check
majVer=
minVer=
packageManager= # needed for any install/compilation
folderInstall= # gets set to choosen directory if installing to folder

# Ensure that we are running on a supported MacOS system
if [ "$(uname -s)" = "Darwin" ]; then
  macVersion="$(sw_vers -productVersion)"
  majVer="$(echo "${macVersion}" | cut -d'.' -f1)"
  minVer="$(echo "${macVersion}" | cut -d'.' -f2)"
  if [ -z "${minVer}" ]; then minVer="0"; fi

  # check version: QEMU is only supported on 10.5+,
  # but I'm only going to support the top 3 major Mac versions
  if [ "${majVer}" -le 10 ]; then
    unsupported=0
    if [ "${majVer}" -eq 10 ] && [ "${minVer}" -lt 14 ]; then unsupported=1; fi
    if [ "${majVer}" -lt 10 ]; then unsupported=1; fi

    if [ "${unsupported}" -eq 1 ]; then
      echo "Sorry, but this version of MacOS (${macVersion}) is not supported."
      exit 1
    fi
  fi
else # not a mac
  echo "Sorry, not running on a MacOS system, aborting."
  exit 1
fi

# Internet connection required
connected=1
case "$(curl -s --max-time 2 -I https://google.com | sed 's/^[^ ]*  *\([0-9]\).*/\1/; 1q')" in
  [23]) connected=0;;
  5) echo "Sorry, but the web proxy won't let us through.";;
  *) echo "Sorry, but the network is down or very slow.";;
esac
if [ "$connected" -eq 1 ]; then
  echo "Please make sure you are connected to a network that has internet access."
  exit 1
fi

# Make sure Xcode is installed with CLI tools
if [ ! -f "${Xcode_Install}" ]; then
  printf "Xcode isn't installed, but required.\nPlease go to ${Xcode_App_URL} and install the Xcode app.\n\n"
  read -p "Then, press any key to continue."
fi # second if is to check if it was installed before the end of the read command
if [ -f "${Xcode_Install}" ]; then
  XCODE_VERSION=`xcodebuild -version | grep '^Xcode\s' | sed -E 's/^Xcode[[:space:]]+([0-9\.]+)/\1/'`
  ACCEPTED_LICENSE_VERSION=`defaults read /Library/Preferences/com.apple.dt.Xcode 2> /dev/null | grep IDEXcodeVersionForAgreedToGMLicense | cut -d '"' -f 2`

  # Accept Xcode license, if not already
  if [ "${XCODE_VERSION}" != "${ACCEPTED_LICENSE_VERSION}" ]; then
    echo "Please accept the Xcode license..."
    sudo xcodebuild -license
    if [ $? -eq 1 ]; then
      echo "Xcode license not accepted, aborting."
      exit 1
    fi
    echo "Xcode license accepted."
  fi

  # Install CLI tools, if not already installed.
  xcode-select -p 1>/dev/null
  if [ $? -eq 2 ]; then
    echo "Installing Xcode CLI tools..."
    sudo xcode-select --install
    if [ $? -ne 0 ]; then
      echo "Xcode CLI tools couldn't install, aborting."
      exit 1
    fi
    echo "Xcode CLI Tools installed."
  fi
else
  echo "Xcode not installed, aborting."
  exit 1
fi

# Check for package manager
if command -v brew &> /dev/null; then
  packageManager="brew"
elif command -v port &> /dev/null; then
  packageManager="port"
else # prompt to install a package manager
  echo "No package manager installed."
  while true; do
    read -p "Would you like to install the [H]omeBrew or [M]acPorts package manager, or [C]ancel installation? " hm
    case ${hm} in
      [Hh]* ) /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; break;;
      [Mm]* ) echo "Please go to https://www.macports.org/install.php and download/install the package for your system."; break;;
      [Cc]* ) exit 1; break;;
      * ) echo "Please answer with H (HomeBrew) or M (MacPorts), or C (Cancel installation).";;
    esac
    read -p "Then, press any key to continue."
    if command -v brew &> /dev/null; then
      packageManager="brew"
    elif command -v port &> /dev/null; then
      packageManager="port"
    else
      echo "Package manager couldn't be installed."
      exit 1
    fi
  done
fi

# Choose between user or folder install
installType=
while true; do
  read -p "Would you like to install to [U]ser account or [F]older, or [C]ancel installation?" uf
  case ${uf} in
    [Uu]* ) installType="U"; break;;
    [Ff]* ) installType="F"; break;;
    [Cc]* ) exit 1; break;;
    * ) echo "Please answer with U (User account) or F (Folder), or C (Cancel installation).";;
  esac
done
if [ "${installType}" = "U" ]; then
  # install to user's folder
  # TODO: ...
elif [ "${installType}" = "F" ]; then
  # install to specific folder (doesn't install QEMU to system, or create VM in user folder)
  # TODO: ...
fi
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
