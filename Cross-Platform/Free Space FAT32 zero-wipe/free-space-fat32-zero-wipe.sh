#!/bin/bash
PROMPT_COMMAND='echo -en "\033]0;Free Space FAT32 Drive Wipe\a"'
if [[ -v WSLENV ]]; then is_wsl=false; else is_wsl=true; fi

# Root needed
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root." && exit 1
fi

# certain coreutils commands are required
truncate --version >/dev/null 2>&1 || { echo >&2 "This script requires the 'truncate' command from the 'coreutils' package."; exit 1; }
shred --version >/dev/null 2>&1 || { echo >&2 "This script requires the 'shred' command from the 'coreutils' package."; exit 1; }

# Start
echo -e "\n > > > FAT32 Free-Space Drive Wiper Script < < <\n"
drive_type="vfat" && if [ "$is_wsl" = true ]; then drive_type="drvfs"; fi

# Update for stability
echo "Loading..."
echo
apt-get -qqy update || echo "Running this script without internet access might fail..."

# Show disks
drive_block="-" # place holder value
default_path="/tmp/temp_drive"
mount_path=$default_path
example_drive="/dev/sdb1"
if [ "$is_wsl" = true ]; then example_drive="F"; fi
until ! [ "$drive_block" = "-" ]; do
   bad_path=false
   # Get user input on which to pick
   echo -e "> Available Drives <"
   echo -e "Dir\tSize\n---\t----"
   if [ "$is_wsl" = false ]; then
      fdisk -l | awk '$9 == "FAT32"' | awk '{print $1 "\t" $6}'
   else
      /mnt/c/Windows/System32/cmd.exe /C 'wmic logicaldisk get caption,filesystem,size' | grep -E "[D-Z,]+:       FAT32" | awk '{printf "%s\t%.0fG\n", $1, $3/1073741824}'
   fi
   printf "\nType the directory to your FAT32 drive (e.g. '$example_drive' without quotes): "
   read temp_path

   # Confirm with user
   if [ "$is_wsl" = false ]; then
      if [ $temp_path = $(df -aT | awk '$7 == "/"' | awk '{print $1}') ] || [ fdisk -l | grep -q "$temp_path" | awk '$9 != FAT32' ] || [ fdisk -l "$temp_path" | grep -q "cannot open" ]; then bad_path=true; fi
   else
      if [ -z "$(/mnt/c/Windows/System32/cmd.exe /C 'wmic logicaldisk get caption,filesystem' | grep -E "[D-Z,]+:       FAT32" | grep $temp_path:)" ]; then bad_path=true; fi
	  echo
   fi
   if [ "$bad_path" = true ]; then
      echo -e "Sorry but \"$temp_path\" is not a vaild path!\n"
   else
      if [ "$is_wsl" = false ]; then
	     echo "> Contents of \"$temp_path\" <"
	     fdisk -l $temp_path
      else
	     echo "> Contents of \"$temp_path:\" <"
	     if [ ! -z "$(df -t drvfs --output=source,target | awk -v mount="${temp_path}:" '$1 == mount {print}')" ]; then
		    mount_path="$(df -t drvfs --output=source,target | awk -v mount="${temp_path}:" '$1 == mount {print $2}')"
			if [[ $(ls -A "${mount_path}") ]]; then ls -A "${mount_path}"; else echo [this drive is empty]; fi
		 else
		    if [ -d /tmp/check_temp ]; then rm -r /tmp/check_temp; fi
		    mkdir /tmp/check_temp
			mount -t $drive_type "$temp_path:" /tmp/check_temp
		    if [[ $(ls -A /tmp/check_temp) ]]; then ls -A /tmp/check_temp; else echo [this drive is empty]; fi
		    umount /tmp/check_temp && rm -r /tmp/check_temp
		 fi
	  fi
	  REPLY=X # place holder value
	  continue=false
	  while [ $continue = false ]; do
	     echo && read -n 1 -r -p "Does this look like your drive? (Y/N): "
         if [[ $REPLY =~ ^[Yy]$ ]]; then drive_block=$temp_path; fi
		 if [[ $REPLY =~ ^[Yy]$ ]] || [[ $REPLY =~ ^[Nn]$ ]]; then continue=true; fi
      done
      echo && echo
   fi
done

# Mount the drive if not already mounted
dummydir="$mount_path/DO_NOT_DELETE"
if [ -z "$(df -t drvfs --output=source,target | awk -v mount="${drive_block}:" '$1 == mount {print}')" ]; then
   if [ -d $mount_path ]; then rm -r "$mount_path"; fi
   mkdir "$mount_path"
   mount -t $drive_type "$drive_block:" "$mount_path"
fi
if [ -d $dummydir ]; then
	echo -e "Cleaning up previous files...\n"
	rm -r "$dummydir"
fi
mkdir "$dummydir"
cd "$dummydir"

# Create dummy files
MAX_BYTES=4294901760 # 4294967296 B (4 GiB) - 65536‬ B ... can't handle a full 4 GiB since it needs space to journal the name and location
free_bytes_origin=$(df -B1 | tr -s ' ' $'\t' | grep $drive_block: | cut -f4)
previous_free=false # place holder value
previous_progress="Progress 0.00%" # place holder value
j=1
echo "Starting dummy file creation..."
echo -ne "\n$previous_progress"
until [ "$previous_free" = 0 ]; do
   free_bytes=$(df -B1 | tr -s ' ' $'\t' | grep $drive_block: | cut -f4)
   current_free=$(( $free_bytes_origin - $free_bytes ))
   current_free=$(echo "scale=13; $current_free / $free_bytes_origin * 100" | bc)
   if (("$free_bytes" >= "$MAX_BYTES")); then
      truncate -s $MAX_BYTES $j
	  previous_free=$free_bytes
   else
      truncate -s $free_bytes $j
	  previous_free=0
   fi
   current_progress=$(printf "Progress %.2f%%" "$(bc -l <<< ${current_free})")
   if ! [ "$previous_progress" = "$current_progress" ]; then
      echo -ne "\n$current_progress"
	  previous_progress=$current_progress
   fi
   j=$(($j+1))
done
echo -e "\nProgress 100.00%"

# Wipe the folder (writing zeros to the space)
echo "Wiping files..."
cd "$mount_path"
find "$dummydir/" -exec shred -vzun 0 {} \;
rm -r "$dummydir"

# Remove mount if disk was not previously mounted
if [ "$mount_path" = "$default_path" ]; then
   umount "$mount_path"
   if [ $? -eq 0 ]; then rmdir "$mount_path"
   else
      echo -e "\nATTENTION: The drive was unable to unmount. Please do this manually with \"sudo umount $mount_path\"."
	  if [ "$is_wsl" = true ]; then echo -e "\nSince you are a WSL user, you may need to exit out of all instances of the terminal, before unmounting the drive and removing the folder."; fi
   fi
fi
