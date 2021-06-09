#!/bin/sh

GITHUB_RELEASES="https://api.github.com/repos/ventoy/Ventoy/releases"
OLDDIR="$(cd "$(dirname "$0")" >/dev/null 2>&1 && pwd)"
SCRIPT="$(basename "$0")"
PID="$$"

if [ -f ./ventoy/version ]; then
    curver="$(cat ./ventoy/version)"
fi

if command -v curl >/dev/null 2>&1; then
    dltool=curl
    CHECK_CONNECTION="curl -s https://github.com -o /dev/null"
    GET_RELEASES="curl -s \"$GITHUB_RELEASES\""
elif command -v wget >/dev/null 2>&1; then
    dltool=wget
    CHECK_CONNECTION="wget -q --spider https://github.com"
    GET_RELEASES="wget -q -O - \"$GITHUB_RELEASES\""
fi


echo ''
echo '**********************************************'
echo "      Ventoy: $([ -n "$curver" ] && echo "$curver" || echo "Not Downloaded")"
echo "      longpanda admin@ventoy.net"
echo "      https://www.ventoy.net"
echo '**********************************************'
echo ''


if [ -z "$dltool" ]; then
    echo "A file download tool is not available, please install one of the following tools to continue:"
    echo " * wget"
    echo " * curl"
    exit 1
fi

if ! $CHECK_CONNECTION; then
    echo "Please make sure you are connected to a network that has internet access."
    exit 1
fi

IS_RUNNING="$(ps -A -ww -o pid,ppid,command | grep -v "grep\|$PID" | grep -F "/bin/sh ./$SCRIPT")"
if [ -n "$IS_RUNNING" ]; then
    echo "Please only run one instance of the updater at a time."
    exit 1
fi

SHOW_FILES_IN_DIR="ls -A1 '$OLDDIR' | sed '/^$SCRIPT\$/d' | sed 's/.*/\"&\"/'"
FILES_IN_DIR="$(eval "$SHOW_FILES_IN_DIR")"
FILES_IN_USE="$(echo "$FILES_IN_DIR" | xargs -I {} sh -c 'if lsof "{}" >/dev/null; then echo " > \"{}\""; fi')"
if [ -n "$FILES_IN_USE" ]; then
    echo "Unable to delete old version, the following files are still in use:"
    echo "$FILES_IN_USE"
    exit 1
fi

echo "############ $SCRIPT ############"

echo "Checking for latest version..."
DOWNLOAD_URL="$(eval "$GET_RELEASES" | grep '"browser_download_url".*-linux\.tar\.gz' | awk '{print $2}' | tr -d \" | head -1)"
if [ -z "$DOWNLOAD_URL" ]; then
    echo "Couldn't find latest release, please make sure you have a constant internet connection."
    exit 1
fi
DOWNLOAD_FILE="$(basename -- "$DOWNLOAD_URL")"
newver="$(echo "$DOWNLOAD_FILE" | cut -d - -f2)"
if [ "$curver" = "$newver" ]; then
    echo ''
    echo "Already on latest version of Ventoy: $curver"
    echo ''
    exit
fi

echo "Downloading..."
DL_FILE="/tmp/$DOWNLOAD_FILE"
if [ "$dltool" = "wget" ]; then
    DL_NEW="wget -O \"$DL_FILE\" \"$DOWNLOAD_URL\""
elif [ "$dltool" = "curl" ]; then
    DL_NEW="curl -L -o \"$DL_FILE\" -C - \"$DOWNLOAD_URL\""
fi

if ! eval "$DL_NEW"; then
    echo "Couldn't download latest release, please make sure you have a constant internet connection."
    exit 1
fi

if [ -n "$FILES_IN_DIR" ]; then
    echo ''
    while true; do
        echo "The following files/folders in \"$OLDDIR\" will be removed:"
        echo "$FILES_IN_DIR" | sed 's/^/ > /g'
        echo ''
        printf "%s" "Continue? (Y/N): "
        read yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) echo "Aborted."; exit 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
    echo "Removing older version..."
    RM_OLD_FILES="echo \"$FILES_IN_DIR\" | xargs rm -rf"
    if ! eval "$RM_OLD_FILES"; then
        echo "Unable to delete old version, please make sure you have write permissions in this directory."
        exit 1
    fi
    echo ''
fi

echo "Extracting new version..."
DL_DIR="/tmp/$(echo "$DOWNLOAD_FILE" | cut -d - -f1,2)"
if ! tar -vxf "$DL_FILE" -C "/tmp"; then
    echo "Extraction failed, reason unknown."
    exit 1
fi
if ! eval mv "$DL_DIR/*" "$OLDDIR/"; then
    echo "Unable to move new version, please make sure you have write permissions in this directory."
    exit 1
fi
echo ''
if [ -z "$curver" ]; then
    echo "Successfully downloaded Ventoy: $newver"
else
    echo "Successfully updated Ventoy: $curver -> $newver"
fi
echo ''

printf "Deleting temporary files..."
eval rm -rf "$DL_DIR*"
printf " Done.\n"

