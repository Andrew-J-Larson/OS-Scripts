#!/bin/sh
# Auto installs the MacPorts package manager.

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
MacPorts_Releases="https://api.github.com/repos/macports/macports-base/releases"

# VARIABLES
macVersion= # this and the following 3 get set in the OS check
majVer=
minVer=
macCodename=

# Ensure that we are running on a supported MacOS system
if [ "$(uname -s)" = "Darwin" ]; then
  macVersion="$(sw_vers -productVersion)"
  majVer="$(echo "$macVersion" | cut -d'.' -f1)"
  minVer="$(echo "$macVersion" | cut -d'.' -f2)"
  macCodename="$(awk '/SOFTWARE LICENSE AGREEMENT FOR macOS/' '/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/en.lproj/OSXSoftwareLicense.rtf' | awk -F 'macOS ' '{print $NF}' | awk '{print substr($0, 0, length($0)-1)}')"
  if [ -z "$minVer" ]; then minVer="0"; fi
else # not a mac
  echo "Sorry, not running on a MacOS system, aborting."
  exit 1
fi

# We don't want to run as root
if [ "$EUID" -eq 0 ]; then
  echo "Please don't run this script as root."
  exit 1
fi

# Check to make sure that MacPorts isn't already installed
if command -v port 2>&1 >/dev/null; then
  echo "MacPorts is already installed."
  exit 1
fi

# Internet connection required
connected=1
echo "Checking internet connection..."
curl -s https://www.google.com -o /dev/null
if [ $? -eq 1 ]; then
  echo "Please make sure you are connected to a network that has internet access."
  exit 1
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

# Check the MacPorts releases
downloadUrl="$(curl -s "https://api.github.com/repos/macports/macports-base/releases" | grep '"browser_download_url": "http.*.pkg"' | grep -v "beta\|rc" | grep "$(echo "$macCodename" | tr -d ' ')" | head -1 | cut -d : -f 2,3 | tr -d \" | tr -d ' ')"

# can't download when the link is empty
if [ -z "$downloadUrl" ]; then
  echo "Sorry, but MacOS $macVersion $macCodename is not currently supported."
  exit 1
else
  # grab file name and download to tmp
  downloadFile="/tmp/$(basename -- "$downloadUrl")"
  curl -L "$downloadUrl" -o "$downloadFile"

  # can't install if it failed to download
  if [ $? -ne 0 ]; then
    echo "Couldn't download latest installer from: $downloadUrl"
    exit 1
  else
    echo "Password will be required to install MacPorts, please enter when prompted."
    sudo installer -allowUntrusted -verboseR -pkg "$downloadFile" -target /
    if [ $? -ne 0 ]; then
      echo "Couldn't install MacPorts. (did you enter the right password?)"
      exit 1
    fi
  fi
fi

