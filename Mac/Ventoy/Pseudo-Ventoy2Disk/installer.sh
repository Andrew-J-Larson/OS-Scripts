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

# Copyright (C) 2023  Andrew Larson (thealiendrew@gmail.com)
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

# Conditionally start script in zsh or bash
if [ "$SHELL" = "/bin/sh" ]; then
  # preferably start in zsh
  shell=
  if [ -f /bin/zsh ]; then
    shell=/bin/zsh
  elif [ -f /bin/bash ]; then
    shell=/bin/bash
  fi

  # execute in shell or warn that we can't execute
  if [ -n "$shell" ]; then
    exec $shell "$0"
    exit
  else
    printf "Can't execute script, can't find a required shell environment:\n - zsh (missing)\n - bash (missing)\n"
    exit 1
  fi
fi

# CONSTANTS
Xcode_Install="/Applications/Xcode.app"
Xcode_App_URL="https://apps.apple.com/app/id497799835"
QEMU_Releases="https://api.github.com/repos/qemu/qemu/releases"
Ventoy_Releases="https://api.github.com/repos/ventoy/Ventoy/releases"

# VARIABLES
macVersion= # this and the following 4 get set in the OS check
majVer=
minVer=
macCodename=
macArch=
packageManager= # needed for any install/compilation
folderInstall= # gets set to choosen directory if installing to folder

# Ensure that we are running on a supported MacOS system
if [ "$(uname -s)" = "Darwin" ]; then
  macVersion="$(sw_vers -productVersion)"
  majVer="$(echo "$macVersion" | cut -d'.' -f1)"
  minVer="$(echo "$macVersion" | cut -d'.' -f2)"
  macCodename="$(awk '/SOFTWARE LICENSE AGREEMENT FOR macOS/' '/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf' | awk -F 'macOS ' '{print $NF}' | awk '{print substr($0, 0, length($0)-1)}')"
  macArch="$(/usr/bin/arch)"
  if [ -z "$minVer" ]; then minVer="0"; fi

  # check version: QEMU is only supported on 10.5+,
  # but I'm only going to support the top 3 major Mac versions
  if [ "$majVer" -le 10 ]; then
    unsupported=0
    if [ "$majVer" -eq 10 ] && [ "$minVer" -lt 14 ]; then unsupported=1; fi
    if [ "$majVer" -lt 10 ]; then unsupported=1; fi

    if [ "$unsupported" -eq 1 ]; then
      echo "Sorry, but MacOS $macVersion $macCodename is not currently supported."
      exit 1
    fi
  fi
else # not a mac
  echo "Sorry, not running on a MacOS system, aborting."
  exit 1
fi

# We don't want to run as root
if [ "$EUID" -eq 0 ]; then
  echo "Please don't run this script as root."
  exit 1
fi

# Internet connection required
echo "Checking internet connection..."
curl -s https://www.google.com -o /dev/null
if [ $? -eq 1 ]; then
  echo "Please make sure you are connected to a network that has internet access."
  exit 1
fi

# Check system updates first
echo "Checking for system updates..."
if softwareupdate -l | grep -q "Action: restart"; then
  echo "MacOS needs some updates first before we can continue with this script. Enter your password when prompted."
  sudo softwareupdate --install --restart --all
  exit 1
fi

# arm64 MacOS specific things
brewQemuStateArm64=
portQemuStateArm64=
if [ "$macArch" = "arm64" ]; then
  # TODO: TEMP: check to see if at least one or both package managers has resolved the M1 mac compile issue
  brewQemuIssueArm64="https://api.github.com/repos/Homebrew/homebrew-core/issues/73286"
  portQemuPullArm64="https://api.github.com/repos/macports/macports-ports/pulls/9955"
  # get current states
  brewQemuStateArm64="$(curl -s "$brewQemuIssueArm64" | grep '"state"' | cut -d : -f 2,3 | tr -d \" | tr -d ' ' | cut -d , -f 1)"
  portQemuStateArm64="$(curl -s "$portQemuPullArm64" | grep '"state"' | cut -d : -f 2,3 | tr -d \" | tr -d ' ' | cut -d , -f 1)"
  if [ "$brewQemuStateArm64" = "open" ] && [ "$portQemuStateArm64" = "open" ]; then
    echo "Not supported on ARM yet. (QEMU doesn't work yet)"
    exit 1
  fi

  # M1 macs will need Rosetta (for brew or macports)
  if [[ ! -f "/Library/Apple/System/Library/LaunchDaemons/com.apple.oahd.plist" ]]; then
    echo "Rosetta may need to be required. Enter your password when prompted."
    sudo softwareupdate –install-rosetta –agree-to-license
  fi
  if [[ -f "/Library/Apple/System/Library/LaunchDaemons/com.apple.oahd.plist" ]]; then
    echo "Verified that Rosetta is installed"
  else
    echo "Failed to install Rosetta."
    exit 1
  fi
fi

# Make sure Xcode is installed with CLI tools
if [ ! -d "${Xcode_Install}" ] || [ -z "$(xcode-select -p 2>/dev/null)" ]; then
  echo "Xcode isn't installed, but required.\nPlease go to ${Xcode_App_URL} and install the Xcode app."
  read -p "Then, press any key to continue."
fi # check if it was installed before the end of the read command
if [ -d "${Xcode_Install}" ]; then
  echo "Verified that Xcode is installed."

  # Make sure we actually need to install the CLI
  if [ -z "$(xcode-select -p 2>/dev/null)" ]; then
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
    echo "Verified that Xcode CLI Tools are installed."
  fi
else
  echo "Xcode not installed, aborting."
  exit 1
fi

# Check for package manager, and make sure QEMU is installed
doChoice=1
if command -v brew 2>&1 >/dev/null; then
  echo "HomeBrew detected."
  # force choice
  if [ "$macArch" = "arm64" ] && [ "$brewQemuStateArm64" = "open"]; then
    doChoice=0
  elif [ -z "$packageManager" ]; then
    packageManager="brew"
  fi
fi
if command -v port 2>&1 >/dev/null; then
  echo "MacPorts detected."
  # force choice
  if [ "$macArch" = "arm64" ] && [ "$portQemuStateArm64" = "open"]; then
    doChoice=0
  elif [ -z "$packageManager" ]; then
    packageManager="port"
  fi
fi
if [ -z "$packageManager" ] # prompt to install a package manager
  echo "No package manager installed, but one is required."

  # can't allow picking of package manager when there is only one available
  allowPick=0
  if [ "$macArch" = "arm64" ]; then
    if [ "$brewQemuStateArm64" = "open" ] || [ "$portQemuStateArm64" = "open" ]; then
      allowPick=1
    fi
  fi

  if [ "$allowPick" -eq 0 ]; then
    while true; do
      read -p "Would you like to install the [H]omeBrew or [M]acPorts package manager, or [C]ancel installation? " hm
      case ${hm} in
        [Hh]* ) $SHELL -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; break;;
        [Mm]* ) $SHELL -c "$(curl -fsSL https://raw.githubusercontent.com/TheAlienDrew/OS-Scripts/main/Mac/MacPorts/installer.sh)"; break;;
        [Cc]* ) exit 1; break;;
        * ) echo "Please answer with H (HomeBrew) or M (MacPorts), or C (Cancel installation).";;
      esac
      read -p "Then, press any key to continue."
      if command -v brew 2>&1 >/dev/null; then
        packageManager="brew"
      elif command -v port 2>&1 >/dev/null; then
        packageManager="port"
      fi
    done
  else # Ask to install only package manager compatible
    if [ "$brewQemuStateArm64" != "open" ] && [ "$portQemuStateArm64" = "open" ]; then
      # brew has qemu ARM
  
      while true; do
        read -p "Would you like to install the HomeBrew package manager? (only one supported with Ventoy at this time) " yn
        case ${yn} in
          [Yy]* ) $SHELL -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; break;;
          [Nn]* ) exit 1; break;;
          * ) echo "Please answer yes or no..";;
        esac
        read -p "Then, press any key to continue."
        if command -v brew 2>&1 >/dev/null; then
          packageManager="brew"
        fi
      done
    elif [ "$brewQemuStateArm64" = "open" ] && [ "$portQemuStateArm64" != "open" ]; then
      # port has qemu ARM

      while true; do
        read -p "Would you like to install the MacPorts package manager? (only one supported with Ventoy at this time) " yn
        case ${yn} in
          [Yy]* ) $SHELL -c "$(curl -fsSL https://raw.githubusercontent.com/TheAlienDrew/OS-Scripts/main/Mac/MacPorts/installer.sh)"; break;;
          [Nn]* ) exit 1; break;;
          * ) echo "Please answer yes or no..";;
        esac
        read -p "Then, press any key to continue."
        if command -v port 2>&1 >/dev/null; then
          packageManager="port"
        fi
      done
    fi
  fi
fi
if [ -z "$packageManager" ]; then
  echo "Package manager couldn't be installed."
  exit 1
fi
# update specific package manager, and maybe install qemu
if [ "$packageManager" = "brew" ]; then
  echo "Updating HomeBrew packages..."
  brew update
  brew upgrade
  if ! brew list qemu 2>&1 >/dev/null; then
    echo "Installing QEMU via HomeBrew..."
    brew install qemu
  fi
elif [ "$packageManager" = "port" ]; then
  echo "Updating MacPorts packages..."
  sudo port selfupdate
  sudo port upgrade outdated
  if ! port installed qemu 2>&1 >/dev/null; then
    echo "Installing QEMU via MacPorts..."
    sudo port install qemu
  fi
fi

# Choose between user or folder install
needQemuPackage=0 # used to optionally prompt to uninstall from package manager when folder install is used
while true; do
  read -p "Would you like to install to [U]ser account or [F]older, or [C]ancel installation?" uf
  case ${uf} in
    [Uu]* ) folderInstall="~/Ventoy"; mkdir -p "$folderInstall"; break;;
    [Ff]* ) folderInstall=`/usr/bin/osascript << EOT
                tell application "Finder"
                    activate
                    set folderInstall to choose folder with prompt "Select the folder you want to install Ventoy to"
                end tell
                return (posix path of folderInstall)
EOT`; if [ -z "$folderInstall" ]; then echo "No folder selected, aborted."; exit 1;
            else folderInstall+="Ventoy"; mkdir -p "$folderInstall" 2>/dev/null && break || echo "No write permissions for that folder, please choose a different directory."; fi;;
    [Cc]* ) exit 1; break;;
    * ) echo "Please answer with U (User account) or F (Folder), or C (Cancel installation).";;
  esac
done

# Check if location already has install
# confirm all required files are installed
# TODO: (doesn't install QEMU to system, or create VM in user folder)
# TODO: (check for user account Ventoy installation first)
#   - If a user account install is detected, prompt for uninstallation or repair
#   - Locally: Will need to download QEMU source then compile binaries manaually for MacOS (see https://wiki.qemu.org/Hosts/Mac#Building_QEMU_for_macOS),
#              and then setup the VM in that. Will need a package manager to install the resources needed to compile.
#      * If location selected has an install, prompt for removal or repair
#   - User account:
#      * HomeBrew: Only supports Mojave (10.14)+
#      * MacPorts: Supports Sierra (10.12)+
#      * Check if qemu is already installed, check for package manager (if found, run updates), then use the installed qemu version
#        else, check for a package manager and ask to install qemu from there
#        else prompt to install a package manager of choice to get qemu installed (and then rerun the checks)
#        otherwise, show a message about being unable to continue until a package manager is installed (because managing qemu updates without a package manager wouldn't be fun to code)

# If Ventoy LiveCD virtual machine is not already setup do that
# TODO: + will need to save the general command to start the VM without USB drives to work with later
#   * live cd download naming scheme is `ventoy-[version]-livecd.iso`
