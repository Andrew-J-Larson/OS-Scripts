#!/bin/bash
# Only tested on Ubuntu
# Requires curl to be installed

# Copyright (C) 2023  Andrew Larson (andrew.j.larson18+github@gmail.com)
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
MBAM_URL="https://mbam.example.com" # the MBAM website for your organization
MBAM_Admin_KeyRecoveryURL="${MBAM_URL}/HelpDesk/KeyRecoveryPage.aspx" # the page needed to get recovery information
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

# function for getting BitLocker recovery keys
# returns nothing if it couldn't find key
getBdeRecoveryKey () {
  bdeKeyID="$1" # this is the BDE key identifier
  usr="$2" # this is the username
  psswrd="$3" # this is the password
  # first curl to login, and get: the SessionID (from COOKIE_FILE) and the ViewState/EventValidation (from DECODED_FILE)
  curl --ntlm --user "${usr}:${psswrd}" -c "${COOKIES_FILE}" "${MBAM_Admin_KeyRecoveryURL}" -o "${RESULTS_FILE}" -s
  # capture and encode data to send back in form
  SessionID="$(cat "${COOKIES_FILE}" | tail -1 | awk '{print $7}')"
  parseXML "${RESULTS_FILE}" > "${DECODED_FILE}"
  # form won't be valid unless it has data from webpage also submitted with it
  ViewState="$(rawurlencode $(cat "${DECODED_FILE}" | grep '"__VIEWSTATE"' | grep -oP '(?<=value=").*?(?=")'))"
  EventValidation="$(rawurlencode $(cat "${DECODED_FILE}" | grep '"__EVENTVALIDATION"' | grep -oP '(?<=value=").*?(?=")'))"
  DataRaw="__LASTFOCUS=&__EVENTTARGET=ctl00%24content%24SubmitButton&__EVENTARGUMENT=&__VIEWSTATE=${ViewState}&__VIEWSTATEGENERATOR=C0534C36&__EVENTVALIDATION=${EventValidation}&ctl00%24content%24DomainNameTextBox=&ctl00%24content%24UserNameTextBox=&ctl00%24content%24KeyIdTextBox=${bdeKeyID}&ctl00%24content%24ReasonCodeSelect=Other"
  # second curl to send form, and get data
  curl -L --ntlm --user "${usr}:${psswrd}" "${MBAM_Admin_KeyRecoveryURL}" -o "${RESULTS_FILE}" -s \
    -H 'Connection: keep-alive' \
    -H 'Cache-Control: max-age=0' \
    -H "Origin: ${MBAM_Admin_KeyRecoveryURL}" \
    -H 'Upgrade-Insecure-Requests: 1' \
    -H 'DNT: 1' \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
    -H 'Sec-Fetch-Site: same-origin' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Sec-Fetch-User: ?1' \
    -H 'Sec-Fetch-Dest: document' \
    -H "Referer: ${MBAM_Admin_KeyRecoveryURL}" \
    -H 'Accept-Language: en-US,en;q=0.9' \
    -H "Cookie: ASP.NET_SessionId=${SessionID}" \
    --data-raw "${DataRaw}" \
    --compressed
  # capture and use bitlocker key
  parseXML "${RESULTS_FILE}" > "${DECODED_FILE}"
  BitLockerKey="$(cat "${DECODED_FILE}" | grep '"ctl00$content$KeyReturnField"' | grep -oP '(?<=value=").*?(?=")')"
  
  # remove temp files
  rm "${COOKIES_FILE}" "${RESULTS_FILE}" "${DECODED_FILE}"
  # Results
  echo "$BitLockerKey"
  # clearing stored password for security reasons
  psswrd=""
}
