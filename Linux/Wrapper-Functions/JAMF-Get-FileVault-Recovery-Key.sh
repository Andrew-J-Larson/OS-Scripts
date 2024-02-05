#!/bin/bash
# Only tested on Ubuntu
# Requires curl to be installed

# Copyright (C) 2024  Andrew Larson (andrew.j.larson18+github@gmail.com)
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

# Constants
JAMF_URL="https://jamf.example.com:8443" # the JAMF website for your organization
JAMF_INDEX_URL="${JAMF_URL}/index.html" # required for logging in
JAMF_LEGACY_COMPUTERS_URL="${JAMF_URL}/legacy/computers.html" # required to search for machine, and get machine details
JAMF_COMPUTERS_AJAX="${JAMF_URL}/computers.ajax" # the page needed to get recovery information
COOKIES_FILE=/tmp/Cookies.txt
RESULTS_FILE=/tmp/Results.html
DECODED_FILE=/tmp/Decoded.txt

# functions to parse xml documents
xmlgetnext () {
  local IFS='>'
  read -d '<' TAG VALUE
}
parseXML () {
  cat "$1" | while xmlgetnext ; do echo "$TAG" ; done
}
# function to encode data for form submit
rawurlencode() {
  local string="${1}"
  local strlen=${#string}
  local encoded=""
  local pos c o
  for (( pos=0 ; pos<strlen ; pos++ )); do
     c=${string:$pos:1}
     case "$c" in
        [-_.~a-zA-Z0-9] ) o="${c}" ;;
        * )               printf -v o '%%%02x' "'$c"
     esac
     encoded+="${o}"
  done
  echo "${encoded}"
}

# function for getting FileVault recovery keys
# returns nothing if it couldn't find key
getFvdeRecoveryKey () {
  srlnmbr="$1" # this is the serial number
  usr="$2" # this is the username
  psswrd="$3" # this is the password
  # Create credentials encoded to send over
  CredentialsEncoded="username=$(rawurlencode "${usr}")&password=$(rawurlencode "${psswrd}")"
  # Need to search for computer ID first, while also logging in with curl
  ComputerID="$(curl -s -k -u "$usr":"$psswrd" "${JAMF_URL}/JSSResource/computers/serialnumber/${srlnmbr}/subset/general" | grep -oP '(?<=<general><id>).*?(?=</id>)')"
  if [ -n "$ComputerID" ]; then # With the computer ID, we can attempt to get the FileVault personal recovery key
    # Need initial login to get JSESSIONID
    curl -s -k "${JAMF_INDEX_URL}" \
      -c "${COOKIES_FILE}" \
      -H 'Connection: keep-alive' \
      -H 'Cache-Control: max-age=0' \
      -H 'Upgrade-Insecure-Requests: 1' \
      -H "Origin: ${JAMF_URL}" \
      -H 'Content-Type: application/x-www-form-urlencoded' \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
      -H 'Sec-Fetch-Site: same-origin' \
      -H 'Sec-Fetch-Mode: navigate' \
      -H 'Sec-Fetch-User: ?1' \
      -H 'Sec-Fetch-Dest: document' \
      -H "Referer: ${JAMF_INDEX_URL}" \
      -H 'Accept-Language: en-US,en;q=0.9' \
      --data-raw "${CredentialsEncoded}" \
      --compressed
    # gets SessionID from cookies file
    SessionID="$(cat "${COOKIES_FILE}" | tail -1 | awk '{print $7}')"
    # Now we can go to the computer details page
    curl -s -k "${JAMF_LEGACY_COMPUTERS_URL}?id=${ComputerID}&o=r" \
      -o "${RESULTS_FILE}" \
      -H 'Connection: keep-alive' \
      -H 'Upgrade-Insecure-Requests: 1' \
      -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
      -H 'Sec-Fetch-Site: same-origin' \
      -H 'Sec-Fetch-Mode: navigate' \
      -H 'Sec-Fetch-Dest: iframe' \
      -H "Referer: ${JAMF_LEGACY_COMPUTERS_URL}" \
      -H 'Accept-Language: en-US,en;q=0.9' \
      -H "Cookie: JSESSIONID=${SessionID}" \
      --compressed
    # From this page, we need the information required to make the AJAX request
    parseXML "${RESULTS_FILE}" > "${DECODED_FILE}"
    showKeyButtonHTML="$(cat "${DECODED_FILE}" | grep 'FIELD_FILEVAULT2_INDIVIDUAL_KEY_VALUE' -A1 | grep 'SHOW_KEY')"
    # gets the FileVault ID we need to get recovery information
    FileVaultID="$(echo "$showKeyButtonHTML" | grep -oP '(?<=retrieveFV2Key&#x28;).*?(?=,)' )"
    # gets the session token which is required to have a valid AJAX request
    SessionToken="$(cat "${DECODED_FILE}" | grep 'id="session-token"' | grep -oP '(?<=value=").*?(?=")')"
    # Now we can make the AJAX call to get the personal recovery key
    RequestData="fileVaultKeyId=${FileVaultID}&fileVaultKeyType=individualKey&identifier=FIELD_FILEVAULT2_INDIVIDUAL_KEY&ajaxAction=AJAX_ACTION_READ_FILE_VAULT_2_KEY&session-token=${SessionToken}"
    curl -s -k "${JAMF_COMPUTERS_AJAX}?id=${ComputerID}&o=r" \
      -o "${RESULTS_FILE}" \
      -H 'Connection: keep-alive' \
      -H 'Accept: */*' \
      -H 'X-Requested-With: XMLHttpRequest' \
      -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
      -H "Origin: ${JAMF_INDEX_URL}" \
      -H 'Sec-Fetch-Site: same-origin' \
      -H 'Sec-Fetch-Mode: cors' \
      -H 'Sec-Fetch-Dest: empty' \
      -H "Referer: ${JAMF_LEGACY_COMPUTERS_URL}?id=${ComputerID}&o=r" \
      -H 'Accept-Language: en-US,en;q=0.9' \
      -H "Cookie: JSESSIONID=${SessionID}" \
      --data-raw "$RequestData" \
      --compressed
    # Now we just need to grab the FileVaultKey from the data
    FileVaultKey="$(cat "${RESULTS_FILE}" | grep -oP '(?<=<individualKey>).*?(?=</individualKey>)')"
    
    # remove temp files
    rm "${COOKIES_FILE}" "${RESULTS_FILE}" "${DECODED_FILE}"
    # Results
    echo "$FileVaultKey"
  fi
  # clearing stored credentials and password for security reasons
  CredentialsEncoded=""
  psswrd=""
}
