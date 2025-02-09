#!/bin/sh

# Copyright (C) 2024  Andrew Larson (github@drewj.la)
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

APP_TITLE="Change Lockscreen"
DESKTOP_PICTURES="/Library/Caches/Desktop Pictures"
USER_UUID="$(dscl . -list /Users GeneratedUID | grep "$USER" | awk '{print $2}')"
USER_DP="${DESKTOP_PICTURES}/${USER_UUID}"

# go to the user specific desktop pictures folder if we can
cd "${USER_DP}" || (
osascript <<EOF
try
  tell app "Finder"
    activate
    display dialog "Error: couldn't access user specific desktop pictures folder." with title "${APP_TITLE}"
  end tell
end try
EOF
)

# in case some how we don't receive any arguments, we have a fallback
if [ -n "$1" ]; then
  # only set lockscreen if image is of correct mimetype
  mimetype=$(file -b --mime-type "$1")
  type=$(echo "$mimetype" | cut -d "/" -f1)
  subtype=$(echo "$mimetype" | cut -d "/" -f2)
  validImage=1 # default is false
  if [ "$type" = "image" ]; then
    if [ "$subtype" = "png" ] || [ "$subtype" = "jpeg" ] || [ "$subtype" = "tiff" ] || [ "$subtype" = "x-pict" ]; then
      validImage=0 # sets it to true
    fi
  fi

  # is the file is a valid image set lockscreen image
  if [ $validImage -eq 0 ]; then
    filename="$(basename -- "$1")"
    ext="${filename##*.}"
    rm -rf lockscreen.*
    cp "$1" "${USER_DP}/lockscreen.$ext"
    osascript <<EOF
try
  tell app "Finder"
    activate
    display dialog "Lockscreen successfully set to: \"$filename\"\n\nPlease make sure to logout first for the new lockscreen to take effect." with title "${APP_TITLE}"
  end tell
end try
EOF
  else
    osascript <<EOF
try
  tell app "Finder"
    activate
    display dialog "Invalid file selected, please make sure you are selecting an image of type: png, jpeg, tiff, or pict." with title "${APP_TITLE}"
  end tell
end try
EOF
  fi
else
  osascript <<EOF
try
  tell app "Finder"
    activate
    display dialog "Error: no arguements given." with title "${APP_TITLE}"
  end tell
end try
EOF
fi
