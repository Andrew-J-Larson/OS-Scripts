#!/bin/sh
# When a USB Mass Storage Device is ejected from the system, it no longer shows up in:
# - `diskutil list`
# - `system_profiler SPUSBDataType`
# However, it still shows up in `ioreg`, so using some filtering, we can grab the list of
# the connected USB Mass Storage Devices.
# Note: Some devices, such as external SD Card readers with more than one slot, will only
#       show one device (the reader) in the list.

command="ioreg -p IOUSB -c AppleUSBDevice -k uid -w0 -r"

if [ "$1" = "-h" ]; then
  echo "Shows a list of connected USB Mass Storage Devices"
  echo
  echo "Command being ran is: \`$command\`"
  echo "Use \`$(echo "$command" | cut -d ' ' -f1) -h\` for more informaton."
else
  $command
fi
