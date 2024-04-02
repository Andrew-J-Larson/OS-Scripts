<#
  .SYNOPSIS
  Audit Browser Extensions v1.2.0

  .DESCRIPTION
  This script will audit all browser extensions installed from all local drives of the machine, including details such as the user
  (if applicable), and it even supports finding extensions to detached browser data from custom created profiles or portable browsers,
  all the while avoiding extensions built into each browser (e.g. non-removeable extensions) by default. Most Blink (Chromium) and
  Gecko (FireFox)/Goanna (Gecko fork; Palemoon) engine based browsers should be supported. If there's a browser you come across where
  this script isn't working properly, please refer to the unsupported list below before reporting it on the GitHub.

  Browsers installed to different drives should also be detected.

  Unpacked extension detection is limited but should be working.

  If user details can't be found on the local machine, but it's connected to a domain, it will attempt to find the missing
  information for each user account via cached information from the domain.

  Only supports versions of Windows from 7 and newer (only if Windows PowerShell is updated to at least version 5.1).

  The Windows Subsystems for Linux and Android will both not be supported, as those features are turned off by default, and users
  can't turn them on without admin access to begin with.

  Browsers with engines way too out of date won't be supported:
  - Microsoft Edge Legacy (EdgeHTML browser engine)
  - Internet Explorer 11 (Trident browser engine)
  - LunaScape Orion vX.X.X (WebKit/Gecko/Trident browser engine)
  - Maxthon v4.X.X (WebKit/Trident browser engine)
  - Chrome v27.X.X (WebKit browser engine)
  - Opera v12.X.X (Presto browser engine)
  - Safari v5.X.X (WebKit browser engine)
  - Lunascape v4.X.X (Trident browser engine)
  - Firefox v1.0.X (Gecko v1.7.X browser engine)
  - Netscape v7.1.X (Gecko v1.7.X browser engine)

  Browsers too new with lacking extension support won't be supported (last checked, these browsers only enable built-in extensions):
  - Falkon (WebKit browser engine)

  Headless cloud browsers (e.g. Puffin Secure Browser) will never be supported, as their data is completely hosted else where,
  without any direct access to user data (a.k.a. can't ever get extension data).

  .PARAMETER Path
  Changes where the captured browser information is stored. By not providing this value, exporting will default to the directory
  in where the script was launched in (or to the root of the drive if not running directly from a script file).

  .PARAMETER Help
  Brings up this help page, but won't run script.

  .INPUTS
  Path: this is optional, changes location where files will be stored (more about this in the parameter information)

  .OUTPUTS
  Successes, warnings, and errors log to the console.

  Three files with the following captured information:
   - 1 JSON file - Extension info is contained in a structure like the following (in their orignal data type given by each browser):
    - Drives: root of the data (ordered list of drives on the computer)
      |=> Drive (by drive letter)
          |-> DriveType (see https://learn.microsoft.com/en-us/dotnet/api/system.io.drivetype?view=netframework-4.6 )
          |-> DetachedBrowsers (ordered list of browsers where data was not found in any user folder)
              |=> Browser ... (see below for the continued structure...)
          |-> Users (ordered list of users on the drive)
              |=> Username
                  |-> FullName (user's full name, if they have one on their account)
                  |-> DetachedBrowsers (ordered list of browsers where data was not found in standard browser profile paths)
                      |=> Browser ... (see below for the continued structure...)
                  |-> Browsers (ordered list of browsers where existing data was found in the user's folder)
                      |=> Browser (by name, or sometimes path for the detached browsers)
                          |-> Company (by name, but empty if a company name couldn't be found)
                          |-> Engine (by name, the browser engine used for the browser)
                          |-> Profiles (ordered list of profiles in the browser, since there may be more than one profile used)
                              |=> Profile (by path)
                                  |-> Name (or folder name if profile name couldn't be determined)
                                  |-> Account (the main account logged into the profile, if any)
                                      |=> Email       (if there is a logged in account, data here won't be empty)
                                      |=> DisplayName (if there is a logged in account, data here won't be empty)
                                  |-> Extensions (array of extensions)
                                      |=> Extension
                                          |-> (original extension data: will differ based on browser type/version)
   - 2 CSV files - Both files will contain more basic info of the extensions collected, like so:
    - Simplified:
     > DriveLetter,DriveType,Username,ExtensionUnpacked,ExtensionID,ExtensionVersion,ExtensionEnabled,BrowserDataDetached,BrowserEngine,BrowserCompany,BrowserName
      * Note: this is de-duplicated, since any same extension could be installed in different browser profiles of the same user
    - Extensions only:
     > BrowserEngine,ExtensionURLs,ExtensionUnpacked,ExtensionID,ExtensionVendor,ExtensionName,ExtensionDescription
      * Note: if possible, for extensions that came from a webstore/online, additional URLs will be parsed and included
      * Note: this is a de-duplicated list of just all the extensions, with only their information

  .EXAMPLE
  .\Audit-Browser-Extensions.ps1

  .EXAMPLE
  .\Audit-Browser-Extensions.ps1 -Path "C:\Path\To\Where\I\Want\Captured\Data\Stored"

  .EXAMPLE
  .\Audit-Browser-Extensions.ps1 -Help

  .EXAMPLE
  .\Audit-Browser-Extensions.ps1 -h

  .NOTES
  Requires admin! Due to needing access every users AppData folder.

  .LINK
  Script from: https://github.com/Andrew-J-Larson/OS-Scripts/blob/main/Windows/Audit-Browser-Extensions.ps1
#>
#Requires -RunAsAdministrator

<# Copyright (C) 2024  Andrew Larson (github@andrew-larson.dev)

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>. #>

param(
  [Alias("h")]
  [switch]$Help,

  [Parameter(ValueFromRemainingArguments)]
  [ValidateScript({Test-Path -LiteralPath $_})]
  [String]$Path = $(if ($PSScriptRoot) { $PSScriptRoot } elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
  } else { $env:SystemDrive })
)

# check for parameters and execute accordingly
if ($Help.IsPresent) {
  Get-Help $MyInvocation.MyCommand.Path
  exit
}
$Path = $Path.trimend('\')

# Constants

Set-Variable -Name FILENAME_PRE -Option Constant -Value "${env:COMPUTERNAME}_extensions" -ErrorAction SilentlyContinue
Set-Variable -Name FILENAME_POST -Option Constant -Value "$(Get-Date -Format FileDateTimeUniversal)" -ErrorAction SilentlyContinue
Set-Variable -Name REGISTRY_PROFILE_LIST_PATH -Option Constant -Value 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue

Set-Variable -Name KNOWN_SID_RID_TO_SAM -Option Constant -Value ([ordered]@{
  Administrator = 500 # SAM can be altered
  Guest = 501 # SAM can be altered
  KRBTGT = 502 # only available on domain controllers
  DefaultAccount = 503 # first account available on all machines that can't be altered
  WDAGUtilityAccount = 504 # only available on machines with Windows Defender Application Guard installed
}) -ErrorAction SilentlyContinue
Set-Variable -Name MACHINE_SID -Option Constant -Value (
  ((New-Object System.Security.Principal.NTAccount('DefaultAccount')).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value) -replace "(.*)\-$($KNOWN_SID_RID_TO_SAM.'DefaultAccount')(.*)", '$1$2'
) -ErrorAction SilentlyContinue

Set-Variable -Name EXCLUDE_USER_FOLDERS -Option Constant -Value @(
  'Administrator','Guest','KRBTGT','Default','WDAGUtilityAccount','Public'
) -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_TYPES -Option Constant -Value @(
  # https://learn.microsoft.com/en-us/dotnet/api/system.io.drivetype?view=netframework-4.6#fields
  'Unknown',         # = 0
  'NoRootDirectory', # = 1
  'Removable',       # = 2
  'Fixed',           # = 3
  'Network',         # = 4
  'CDRom',           # = 5
  'Ram'              # = 6
 ) -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTERS -Option Constant -Value @(
  if (Get-Volume) {
    (Get-Volume | Where-Object { $_.DriveLetter }).DriveLetter
  } else {
    ( # Get-Volume doesn't work inside of some containers (e.g. Windows Sandbox)
      Get-CimInstance -ClassName Win32_Volume | Sort-Object DriveLetter | Where-Object { $_.DriveLetter }
    ) | ForEach-Object { $_.DriveLetter -replace ':' }
  }
) -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_REGEX_GROUP -Option Constant -Value "DRIVE_LETTER" -ErrorAction SilentlyContinue
Set-Variable -Name USER_IS_DEFAULT_REGEX_GROUP -Option Constant -Value "USER_IS_DEFAULT" -ErrorAction SilentlyContinue
Set-Variable -Name USER_IS_SERVICE_REGEX_GROUP -Option Constant -Value "USER_IS_SERVICE" -ErrorAction SilentlyContinue
Set-Variable -Name USER_IS_SYSTEM_REGEX_GROUP -Option Constant -Value "USER_IS_SYSTEM" -ErrorAction SilentlyContinue
Set-Variable -Name USER_SAM_REGEX_GROUP -Option Constant -Value "USER_SAM" -ErrorAction SilentlyContinue
Set-Variable -Name USER_SID_REGEX_GROUP -Option Constant -Value "USER_SID" -ErrorAction SilentlyContinue
Set-Variable -Name BLINK_PREFERENCES_REGEX_GROUP -Option Constant -Value "BLINK_PREFERENCES" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_EXTENSIONS_REGEX_GROUP -Option Constant -Value "GECKO_EXTENSIONS" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_MSIX_FULLNAME_REGEX_GROUP -Option Constant -Value "BROWSER_MSIX_FULLNAME" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_EXE_FULLNAME_REGEX_GROUP -Option Constant -Value "BROWSER_EXE_FULLNAME" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP -Option Constant -Value "BROWSER_ATYPICAL_FULLNAME" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_PROFILE_NAME_REGEX_GROUP -Option Constant -Value "BROWSER_PROFILE_NAME" -ErrorAction SilentlyContinue
Set-Variable -Name NONSTANDARD_BROWSER_PROFILE_NAME_REGEX_GROUP -Option Constant -Value "NONSTANDARD_BROWSER_PROFILE" -ErrorAction SilentlyContinue
Set-Variable -Name POSSIBLE_BROWSER_PATH_REGEX_GROUP -Option Constant -Value "POSSIBLE_BROWSER_PATH" -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_REGEX -Option Constant -Value @"
[a-zA-Z]\:
"@ -ErrorAction SilentlyContinue

Set-Variable -Name MSIX_HELPER_EXE_REGEX_PART -Option Constant -Value @"
crashpad_handler|plutil
"@ -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_HELPER_EXE_REGEX -Option Constant -Value @"
^(?:.*_proxy|pwahelper|launcher|${MSIX_HELPER_EXE_REGEX_PART})`$
"@ -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_HELPER_EXE_REGEX -Option Constant -Value @"
^(?:crashreporter|default\-browser\-agent|maintenanceservice(?:_installer)?|minidump\-analyzer|pingsender|plugin\-(?:container|hang\-ui)|private_browsing|updater|loader|winEmbed|${MSIX_HELPER_EXE_REGEX_PART})`$
"@ -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_LOADED_RESOURCES_MATCH_REGEX -Option Constant -Value @"
"path"\:"(?<${POSSIBLE_BROWSER_PATH_REGEX_GROUP}>${DRIVE_LETTER_REGEX}(?:\\\\[^"\\]+)+)\\\\[0-9\.]+\\\\resources\\\\[^"\\]+"
"@ -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_LOADED_FEATURES_MATCH_REGEX -Option Constant -Value @"
"rootURI"\:"jar\:file\:///(?<${POSSIBLE_BROWSER_PATH_REGEX_GROUP}>${DRIVE_LETTER_REGEX}(?:/[^"/]+)+)/browser/features/[^"]+"
"@ -ErrorAction SilentlyContinue

# user profiles are created in several possible places
# - [DRIVE]:\Users\[USER_SAM]
#  > the most common place where user profiles are stored
# - [DRIVE]:\Windows\ServiceProfiles\[USER_SAM]
#  > where the SERVICE profiles are stored
# - [DRIVE]:\Windows\System32\Config\systemprofile
#  > where the SYSTEM profile is stored
# - [DRIVE]:\WpSystem\[USER SID]
#  > packaged app data that gets moved to external drive, creates a sid based user "profile" on said drive

Set-Variable -Name BLINK_BROWSER_PREFERENCES_REGEX_PART -Option Constant -Value @"
(?:Secure )?Preferences
"@ -ErrorAction SilentlyContinue

Set-Variable -Name GECKO_BROWSER_PREFERENCES_REGEX_PART -Option Constant -Value @"
extensions\.json
"@ -ErrorAction SilentlyContinue

Set-Variable -Name ALL_BROWSER_PROFILE_DATA_FILE_REGEX_PART -Option Constant -Value @"
(?:${BLINK_BROWSER_PREFERENCES_REGEX_PART}|${GECKO_BROWSER_PREFERENCES_REGEX_PART})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name BROWSER_OPERA_REGEX_PART -Option Constant -Value @"
Opera Software\\Opera(?: [^\\]+)?
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_REGEX_PART -Option Constant -Value @"
[^;=,+[\]\\]{1,20}
"@ -ErrorAction SilentlyContinue

# See the following resources for correct user matching SIDs:
# - Open Specifications (Microsoft Learn)
#  - 2.4.2   SID                                              : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25
#  - 2.4.2.1 SID String Format Syntax                         : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c92a27b1-c772-4fa7-a432-15df5f1b66a1
#  - 2.4.2.2 SID--Packet Representation                       : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
#  - 2.4.2.3 RPC_SID                                          : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/5cb97814-a1c2-4215-b7dc-76d1f4bfad01
#  - 2.4.2.4 Well-Known SID Structures                        : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
#  - [MS-PAC]: Privilege Attribute Certificate Data Structure : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/166d8064-c863-41e1-9c23-edaaa5f36962
#  - 4.1.2.2 SID Filtering and Claims Transformation          : https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/55fc19f2-55ba-4251-8a6a-103dd7c66280
# - Windows App Development - Authorization (Microsoft Learn)
#  - Well-known SIDs                                          : https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
# - Windows Server - Identity and Access (Microsoft Learn)
#  - Service accounts                                         : https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts
#  - Security identifiers                                     : https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
# - Wikipedia
#  - Security Identifier                                      : https://en.wikipedia.org/wiki/Security_Identifier
# SID Format:
# - S-R-X-Y1-Y2-Yn-1-Yn
#   - S                                       = Indicates that the string is a SID
#   - R                                       = Indicates the revision level
#   - X                                       = Indicates the identifier authority value
#   - Y                                       = Represents a series of subauthority values,
#                                               where n is the number of values
#    - Subauthority: Series (Y1-Y2-Yn-1-Yn), Count (n)
#    - First item           (Y1- : Yx, x = 1) = Indicates the first subauthority (dependant on X),
#                                               represented as the first item in the series
#    - Last item            (-Yn : Yx, x = n) = Indicates the relative identifier (RID),
#                                               represented as the last item in the series
#    - All items w/o last   (-Y1-Y2-Yn-1)     = Indicates the machine/domain identifier,
#                                               represented as series excluding the lastitem
# SID Format (Unique; OS service/system accounts):
# - S-1-5-R
#   - 1 (Revision 1)       : There is only one revision.
#   - 5 (NT Authority)     : Is always used for interactive profiles, but not all NT Authority SIDs are for interactive profiles.
#   - R                    = Indicates the unique subauthority value
#    - 17 = IUSR           : An account that's used by the default Internet Information Services (IIS) user.
#    - 18 = LocalSystem    : An account that is used by the operating system.
#    - 19 = LocalService   : A local service account.
#    - 20 = NetworkService : A network service account.
# SID Format (Non-unique; virtual user accounts):
# Note: Since these accounts are non-interactive, it means that no other applications, other than what's authorized to the virtual
#       account, can be used. The only applications that get used for these profiles are servers (e.g. IIS, SQL, etc.). Browsers
#       are not likely to show up here, unless someone was messing around with admin/system access
# - S-1-5-V-R
#   - V                        = Indicates the unique first subauthority value for virtual account classes
#    - 80-111                  : Virtual user account identity classes, but all of these users are non-interactive profiles.
#   - R                        = Many different forms, some unique, some singlets, and some SHA-1 hash based series.
# SID Format (Non-unique; service/normal user accounts):
# - S-1-5-21-X-Y-Z-R
#   - 21 (NT Account Domain)    : The subauthority value associated with NT Authority interactive profiles.
#   - X-Y-Z                     = Indicates the machine/domain identifier, which has three subauthority values
#   - R                         = Indicates the relative identifier (RID), which is the last subauthority value
#    - 500 = Administrator      : A user account for the system administrator. By default, it is the only user account that is given full control over the system.
#    - 501 = Guest              : A user account for people who do not have individual accounts.
#    - 502 = KRBTGT             : A service account that is used by the Key Distribution Center (KDC) service. (domain controllers only)
#    - 503 = DefaultAccount     : A user account managed by the system.
#    - 504 = WDAGUtilityAccount : A user account managed and used by the system for Windows Defender Application Guard scenarios.
#    - 505-511                  : Reserved and undefined, at time of research.
#    - 1000-4294967295          : Valid RID for any new users created.

Set-Variable -Name SID_PREFIX_NT_AUTHORITY_REGEX -Option Constant -Value 'S\-1\-5' -ErrorAction SilentlyContinue

Set-Variable -Name VALID_UNIQUE_SUBAUTHORITY_RANGE_REGEX -Option Constant -Value @"
(?:1[7-9]|20)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_NONUNIQUE_SUBAUTHORITY_REGEX -Option Constant -Value '21' -ErrorAction SilentlyContinue

Set-Variable -Name VALID_VIRTUAL_USERS_SUBAUTHORITY_RANGE_REGEX -Option Constant -Value @"
(?:8\d|9\d|10\d|11[01])
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_GENERIC_SUBAUTHORITY_RANGE_REGEX -Option Constant -Value @"
(?:\d|[1-9]\d{1,8}|[1-3]\d{9}|4[01]\d{8}|42[0-8]\d{7}|429[0-3]\d{6}|4294[0-8]\d{5}|42949[0-5]\d{4}|429496[0-6]\d{3}|4294967[01]\d{2}|42949672[0-8]\d|429496729[0-5])
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_BUILTIN_RID_RANGE_REGEX -Option Constant -Value @"
(?:50\d|51[01])
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_NORMAL_USER_RID_RANGE_REGEX -Option Constant -Value @"
(?:100\d|10[1-9]\d|1[1-9]\d{2}|[2-9]\d{3}|[1-9]\d{4,8}|[1-3]\d{9}|4[01]\d{8}|42[0-8]\d{7}|429[0-3]\d{6}|4294[0-8]\d{5}|42949[0-5]\d{4}|429496[0-6]\d{3}|4294967[01]\d{2}|42949672[0-8]\d|429496729[0-5])
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_MACHINE_OR_DOMAIN_RID_RANGE_REGEX -Option Constant -Value @"
(?:${VALID_BUILTIN_RID_RANGE_REGEX}|${VALID_NORMAL_USER_RID_RANGE_REGEX})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name NORMAL_USER_SID_REGEX_PART -Option Constant -Value @"
${VALID_NONUNIQUE_SUBAUTHORITY_REGEX}(?:\-${VALID_GENERIC_SUBAUTHORITY_RANGE_REGEX}){3}\-${VALID_MACHINE_OR_DOMAIN_RID_RANGE_REGEX}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VIRTUAL_USER_SID_REGEX_PART -Option Constant -Value @"
${VALID_VIRTUAL_USERS_SUBAUTHORITY_RANGE_REGEX}(?:\-${VALID_GENERIC_SUBAUTHORITY_RANGE_REGEX}){2,5}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name VALID_USER_SID_REGEX -Option Constant -Value @"
${SID_PREFIX_NT_AUTHORITY_REGEX}\-(?:${VALID_UNIQUE_SUBAUTHORITY_RANGE_REGEX}|(?:${NORMAL_USER_SID_REGEX_PART}|${VIRTUAL_USER_SID_REGEX_PART}))
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_STANDARD_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
Users(?=\\${USER_SAM_REGEX_PART}\\)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_DEFAULT_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
Users(?=\\Default\\)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SERVICE_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
Windows\\ServiceProfiles(?=\\(?:Local|Network)Service\\)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SYSTEM_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
Windows\\System32\\Config(?=\\systemprofile\\)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
(?:${USER_STANDARD_PROFILE_FOLDER_REGEX_PART}|${USER_SERVICE_PROFILE_FOLDER_REGEX_PART}|${USER_SYSTEM_PROFILE_FOLDER_REGEX_PART})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_STANDARD_OR_DEFAULT_PROFILE_FOLDER_MATCH_REGEX_PART -Option Constant -Value @"
(?(${USER_DEFAULT_PROFILE_FOLDER_REGEX_PART})(?<${USER_IS_DEFAULT_REGEX_GROUP}>Users)|Users)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_SERVICE_OR_SYSTEM_PROFILE_FOLDER_MATCH_REGEX_PART -Option Constant -Value @"
(?:(?<${USER_IS_SERVICE_REGEX_GROUP}>${USER_SERVICE_PROFILE_FOLDER_REGEX_PART})|(?<${USER_IS_SYSTEM_REGEX_GROUP}>${USER_SYSTEM_PROFILE_FOLDER_REGEX_PART}))
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_PROFILE_FOLDER_MATCH_REGEX_PART -Option Constant -Value @"
(?(${USER_STANDARD_PROFILE_FOLDER_REGEX_PART})${USER_SAM_STANDARD_OR_DEFAULT_PROFILE_FOLDER_MATCH_REGEX_PART}|${USER_SAM_SERVICE_OR_SYSTEM_PROFILE_FOLDER_MATCH_REGEX_PART})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SID_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
WpSystem
"@ -ErrorAction SilentlyContinue

Set-Variable -Name STANDARD_BROWSER_PROFILES_FOLDER_REGEX_PART -Option Constant -Value @"
(?:User Data|Profiles)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_PROFILE_FOLDER_REGEX_PART -Option Constant -Value @"
(?:${USER_SAM_PROFILE_FOLDER_REGEX_PART}\\${USER_SAM_REGEX_PART}|${USER_SID_PROFILE_FOLDER_REGEX_PART}\\${VALID_USER_SID_REGEX})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_USER_PROFILE_FOLDER_REGEX -Option Constant -Value @"
${DRIVE_LETTER_REGEX}\\${USER_PROFILE_FOLDER_REGEX_PART}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name APPDATA_FOLDER_REGEX_PART -Option Constant -Value @"
AppData\\(?:Local|Roaming)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name APPDATA_FOLDER_MSIX_REGEX_PART_1 -Option Constant -Value @"
AppData\\Local\\Packages
"@ -ErrorAction SilentlyContinue

Set-Variable -Name APPDATA_FOLDER_MSIX_REGEX_PART_2 -Option Constant -Value @"
LocalCache\\(?:Local|Roaming)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name APPDATA_FOLDER_MSIX_REGEX_PART -Option Constant -Value @"
${APPDATA_FOLDER_MSIX_REGEX_PART_1}\\[^\\]+\\${APPDATA_FOLDER_MSIX_REGEX_PART_2}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name APPDATA_FOLDER_BROWSER_PROFILE_DATA_END_REGEX_PART -Option Constant -Value @"
(?:[^\\]+\\)?[^\\]+\\${STANDARD_BROWSER_PROFILES_FOLDER_REGEX_PART}\\[^\\]+\\${ALL_BROWSER_PROFILE_DATA_FILE_REGEX_PART}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_USER_APPDATA_FOLDER_REGEX -Option Constant -Value @"
${DRIVE_LETTER_USER_PROFILE_FOLDER_REGEX}\\${APPDATA_FOLDER_REGEX_PART}
"@ -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_MATCH_REGEX -Option Constant -Value @"
(?<${DRIVE_LETTER_REGEX_GROUP}>[a-zA-Z])\:
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SAM_FOLDER_MATCH_REGEX_PART -Option Constant -Value @"
${USER_SAM_PROFILE_FOLDER_MATCH_REGEX_PART}\\(?<${USER_SAM_REGEX_GROUP}>${USER_SAM_REGEX_PART})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name USER_SID_FOLDER_MATCH_REGEX_PART -Option Constant -Value @"
${USER_SID_PROFILE_FOLDER_REGEX_PART}\\(?<${USER_SID_REGEX_GROUP}>${VALID_USER_SID_REGEX})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX -Option Constant -Value @"
${DRIVE_LETTER_MATCH_REGEX}\\(?:${USER_SAM_FOLDER_MATCH_REGEX_PART}|${USER_SID_FOLDER_MATCH_REGEX_PART})
"@ -ErrorAction SilentlyContinue

Set-Variable -Name STANDARD_BROWSER_PROFILE_NAME_MATCH_REGEX_PART -Option Constant -Value @"
${STANDARD_BROWSER_PROFILES_FOLDER_REGEX_PART}\\(?<${BROWSER_PROFILE_NAME_REGEX_GROUP}>[^\\]+)
"@ -ErrorAction SilentlyContinue

Set-Variable -Name BROWSER_PREFERENCES_OR_EXTENSIONS_FILE_MATCH_REGEX -Value $(
  '^' + # starts with
  # drive letter will always get a match, but has to be used separately in each match, down to nonstandard matches

  # Conditionals used based on location of user appdata from:
  # - packaged (MSIX)
  # - standard/atypical unpackaged (EXE)
  # - nonstandard (EXE)

  # conditional of packaged (MSIX) appdata is always in a user profile
  "(?(${DRIVE_LETTER_USER_PROFILE_FOLDER_REGEX}\\${APPDATA_FOLDER_MSIX_REGEX_PART}\\" +
   "${APPDATA_FOLDER_BROWSER_PROFILE_DATA_END_REGEX_PART})" +
    # packaged (MSIX) browser appdata
    '(?:' +
      # capture drive, and username or sid (depends on the matched directory)
      "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}\\" +
      # capture browser name (for packaged apps)
      "${APPDATA_FOLDER_MSIX_REGEX_PART_1}\\(?<${BROWSER_MSIX_FULLNAME_REGEX_GROUP}>[^\\]+)\\${APPDATA_FOLDER_MSIX_REGEX_PART_2}\\" +
      # don't need to capture folder directory for name
      '(?:[^\\]+\\)?[^\\]+\\' +
      # capture browser profile name (for packaged apps)
      "${STANDARD_BROWSER_PROFILE_NAME_MATCH_REGEX_PART}\\" +
    ')|' +
    # standard/atypical unpackaged (EXE) browser appdata

    # Opera browsers: all their browser variants have atypical locations for main and side browser profiles,
    #                 while the older versions of same variants have even weirder locations...

    # conditional of atypical older Opera variants browser appdata
    "(?(${DRIVE_LETTER_USER_APPDATA_FOLDER_REGEX}\\${BROWSER_OPERA_REGEX_PART}\\_side_profiles\\[^\\]+\\" +
     "${BLINK_BROWSER_PREFERENCES_REGEX_PART})" +
      # a weird side profiles in a 'side_profiles' folder:
      # - a normal profile created with the '--profile-directory=' command (no menu options)
      '(?:' +
        # capture drive, and username or sid (depends on the matched directory)
        "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}\\${APPDATA_FOLDER_REGEX_PART}\\" +

        # capture the atypical Opera browser name and weird side profile name (for unpackaged apps)
        "(?<${BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP}>${BROWSER_OPERA_REGEX_PART})\\" +
        "_side_profiles\\(?<$BROWSER_PROFILE_NAME_REGEX_GROUP>[^\\]+)\\" +
      ')|' +
      # standard/atypical unpackaged (EXE) browser appdata

      # conditional of atypical older Opera variants browser appdata
      "(?(${DRIVE_LETTER_USER_APPDATA_FOLDER_REGEX}\\${BROWSER_OPERA_REGEX_PART}\\" +
       "${BLINK_BROWSER_PREFERENCES_REGEX_PART})"+
        # a weird main profile that uses the root of the browser appdata folder:
        # - a normal profile created with the '--profile-directory=' command (the 'Default' profile created when browser launched
        #   for the first time)
        '(?:' +
          # capture drive, and username or sid (depends on the matched directory)
          "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}\\${APPDATA_FOLDER_REGEX_PART}\\" +

          # capture the atypical Opera browser name and weird main profile name (for unpackaged apps)
          "(?<${BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP}>Opera Software\\" +
            "(?<$BROWSER_PROFILE_NAME_REGEX_GROUP>Opera(?: [^\\]+)?)" +
          ')\\' +
        ')|' +
        # standard/atypical unpackaged (EXE) browser appdata

        # conditional of atypical standard Opera variants browser appdata
        "(?(${DRIVE_LETTER_USER_APPDATA_FOLDER_REGEX}\\${BROWSER_OPERA_REGEX_PART}\\[^\\]+\\" +
         "${BLINK_BROWSER_PREFERENCES_REGEX_PART})" +
          # profiles that go directly from browser name folder to each profile folder:
          # - a normal profile created with the '--profile-directory=' command (or by menu options in browser if available)
          "(?:" +
            # capture drive, and username or sid (depends on the matched directory)
            "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}\\${APPDATA_FOLDER_REGEX_PART}\\" +

            # capture the atypical Opera browser and profile names (for unpackaged apps)
            "(?<${BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP}>${BROWSER_OPERA_REGEX_PART})\\" +
            "(?<$BROWSER_PROFILE_NAME_REGEX_GROUP>[^\\]+)\\" +
          ')|' +
          # standard unpackaged (EXE) browser appdata

          # Standard browsers: finding browser names and profiles are consistent

          # conditional of standard browser appdata
          "(?(${DRIVE_LETTER_USER_APPDATA_FOLDER_REGEX}\\" +
           # match against all other standard browsers (not in the 'Programs' appdata folder, where local apps are installed)
           '(?!Programs\\)' + # avoided since any detached browser data could end up in here, even if created by another browser
           "${APPDATA_FOLDER_BROWSER_PROFILE_DATA_END_REGEX_PART})" +
            # a standard browser profile doesn't have many quirks to it:
            # - a normal profile created with the '--profile-directory=' command (or by menu options in browser if available)
            "(?:" +
              # capture drive, and username or sid (depends on the matched directory)
              "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}\\" +
              # don't capture AppData, but go into folder (still ignoring the 'Programs' folder)
              "${APPDATA_FOLDER_REGEX_PART}\\(?!Programs\\)" +
              # capture browser and profile name (for unpackaged apps)
              "(?<${BROWSER_EXE_FULLNAME_REGEX_GROUP}>(?:[^\\]+\\)?[^\\]+)\\${STANDARD_BROWSER_PROFILE_NAME_MATCH_REGEX_PART}\\" +
            ')|' +
            # nonstandard unpackaged (EXE) browser appdata

            # Nonstandard browsers: these detached browser profiles are either created with the '--user-data-dir=' command,
            #                       or from portable browsers, which can be located anywhere on the machine

            # capture group of nonstandard browser appdata
            "(?<${NONSTANDARD_BROWSER_PROFILE_NAME_REGEX_GROUP}>" +
              # match depending based on what the starting folder is
              "(?(${DRIVE_LETTER_USER_PROFILE_FOLDER_REGEX})(?:" +
                  # capture drive, and username or sid (depends on the matched directory)
                  "${DRIVE_LETTER_AND_USER_PROFILE_FOLDER_MATCH_REGEX}" +
                ")|(?:" +
                  # otherwise, always capture drive
                  "${DRIVE_LETTER_MATCH_REGEX}" +
                ')' +
              ')' +
              # could go to any depth
              '(?:\\[^\\]+)*' +
            ')\\' + # must leave ending slashes here, to not capture in with the group
          ')' +
        ')' +
      ')' +
    ')' +
  ')' +

  # browser profile data file will always get a match
  '(?:' +
    "(?<${BLINK_PREFERENCES_REGEX_GROUP}>${BLINK_BROWSER_PREFERENCES_REGEX_PART})" +
  '|' +
    "(?<${GECKO_EXTENSIONS_REGEX_GROUP}>${GECKO_BROWSER_PREFERENCES_REGEX_PART})" +
  ')' +

  '$' # ends with
) -ErrorAction SilentlyContinue

Set-Variable -Name GECKO_THUNDERBIRD_ADDON_ID_REGEX_GROUP -Option Constant -Value "ADDON_ID" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_THUNDERBIRD_ADDON_XPI_URL_REGEX -Option Constant -Value "https?\:\/\/addons\.thunderbird\.net\/thunderbird\/downloads\/latest\/[^\/]+\/addon\-(?<${GECKO_THUNDERBIRD_ADDON_ID_REGEX_GROUP}>\d+)\-latest\.xpi.*" -ErrorAction SilentlyContinue

# these constants are values pulled from the source code of each browser engine
Set-Variable -Name BLINK_BROWSER_LOCATION_UNPACKED -Option Constant -Value 4 -ErrorAction SilentlyContinue # special value is given to loaded unpacked extensions
Set-Variable -Name BLINK_BROWSER_LOCATION_COMMAND_LINE -Option Constant -Value 8 -ErrorAction SilentlyContinue # another way unpacked extensions are loaded in

Set-Variable -Name BLINK_BROWSER_LOCATION_COMPONENT -Option Constant -Value 5 -ErrorAction SilentlyContinue # these are system extensions that can't be disabled by user
Set-Variable -Name BLINK_BROWSER_LOCATION_EXTERNAL_COMPONENT -Option Constant -Value 10 -ErrorAction SilentlyContinue # these are system extensions that can be disabled by user
Set-Variable -Name GECKO_BROWSER_SOURCE_TEMPORARY_ADDON -Option Constant -Value "temporary-addon" -ErrorAction SilentlyContinue # special value is given to loaded unpacked extensions
Set-Variable -Name GECKO_BROWSER_SOURCE_FILE_URL -Option Constant -Value "file-url" -ErrorAction SilentlyContinue # can used in combination to check if unpacked extension was loaded
Set-Variable -Name GECKO_BROWSER_SOURCE_ABOUT_ADDONS -Option Constant -Value "about:addons" -ErrorAction SilentlyContinue # can used in combination to check if unpacked extension was loaded
Set-Variable -Name GECKO_BROWSER_LOCATION_APP_SYSTEM_DEFAULTS -Option Constant -Value "app-system-defaults" -ErrorAction SilentlyContinue # these are system addons that can't be disabled by user
Set-Variable -Name GECKO_BROWSER_LOCATION_APP_BUILTINS -Option Constant -Value "app-builtin" -ErrorAction SilentlyContinue # these are system addons that can be disabled by user

Set-Variable -Name BLINK_BROWSER_CHECK_UNPACKED -Option Constant -Value @(
  $BLINK_BROWSER_LOCATION_UNPACKED, $BLINK_BROWSER_LOCATION_COMMAND_LINE
) -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_CHECK_UNPACKED -Option Constant -Value @(
  $GECKO_BROWSER_SOURCE_TEMPORARY_ADDON, $GECKO_BROWSER_SOURCE_FILE_URL, $GECKO_BROWSER_SOURCE_ABOUT_ADDONS
) -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_BROWSER_CHECK_BUILTIN -Option Constant -Value @(
  $BLINK_BROWSER_LOCATION_COMPONENT, $BLINK_BROWSER_LOCATION_EXTERNAL_COMPONENT
) -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_CHECK_BUILTIN -Option Constant -Value @(
  $GECKO_BROWSER_LOCATION_APP_BUILTINS, $GECKO_BROWSER_LOCATION_APP_SYSTEM_DEFAULTS
) -ErrorAction SilentlyContinue

Set-Variable -Name MAXTHON_BROWSER_CHECK_BUILTIN -Option Constant -Value @(
  'hmeocdelkmeefkdcoifldnmnkjebmjek',
  'elinnbcgbnjnlipjgfbhnmnbbdakfhbm',
  'igmjmjglnljahdobnhlmgdamibihhobe',
  'jnehilamlcdoiaifjfpmlkhepdknccjd',
  'apkomdimgoabnaokkggecggjhbbfakmo'
) -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_BROWSER_ENGINE -Option Constant -Value "Blink" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_ENGINE -Option Constant -Value "Gecko" -ErrorAction SilentlyContinue

# data structure of largely unaltered data grabbed from extensions
# (except for removals of redundant locales/languages)
$OriginalExtensionDataJSON = @{
  Drives = @{}
}

# simplify data from extensions, contains headers already
[array]$SimplifiedExtensionDataCSV = ConvertFrom-Csv @'
DriveLetter,DriveType,Username,ExtensionUnpacked,ExtensionID,ExtensionVersion,ExtensionEnabled,BrowserDataDetached,BrowserEngine,BrowserCompany,BrowserName
'@

# only the extensions are in this, contains headers already
[array]$ExtensionsOnlyCSV = ConvertFrom-Csv @'
BrowserEngine,ExtensionURLs,ExtensionUnpacked,ExtensionID,ExtensionVendor,ExtensionName,ExtensionDescription
'@

# Functions

# older versions of Powershell have trouble with newer standards of json
filter Fix-JsonContent {
	($_ -replace $([regex]::Escape('{"":')),'{null:') -replace $([regex]::Escape(',"":')),',null:'
}

# parses useable GitHub URLs, and returns repo URL if valid
function Get-GitHubRepoURL {
  param(
    [Parameter(Mandatory, ValueFromRemainingArguments)]
    [ValidateScript({([System.Uri]::IsWellFormedUriString($_, 'Absolute')) -And (([System.Uri]$_).Scheme -in 'http', 'https')})]
    [String]$GitHubURL
  )

  $RepoGitHubURL = $Null
  $GitHubUrlURI = [System.Uri]$GitHubURL
  if ('github.com','raw.githubusercontent.com' -contains $($GitHubUrlURI.Host)) {
    # there is a reason 'object.githubusercontent.com' is not checked
    $GitHubUrlPath = $GitHubUrlURI.AbsolutePath
    $RepoGitHubPath = (($GitHubUrlPath.split('/') | Select-Object -First 3) | Select-Object -Last 2) -join '/'
    $RepoGitHubURL = "https://github.com/${RepoGitHubPath}"
  }

  return $RepoGitHubURL
}

# removes all browsers that don't have extension data (used for OriginalExtensionDataJSON)
function CleanUp-Browsers ($browsersObject) {
  [array]$browsersObject.Keys | ForEach-Object {
    $selectedBrowserKey = $_
    $selectedBrowserObject = $browsersObject[$selectedBrowserKey]

    $profilesObject = $selectedBrowserObject.Profiles
    [array]$profilesObject.Keys | ForEach-Object {
      $selectedProfileKey = $_
      $selectedProfileObject = $profilesObject[$selectedProfileKey]

      # if we have no extensions in array, delete profile
      if (-Not $selectedProfileObject.Extensions) {
        $profilesObject.Remove($selectedProfileKey)
      }
    }
    # if we have no profiles in dictionary, delete browser
    if (-Not $profilesObject.Count) {
      $browsersObject.Remove($selectedBrowserKey)
    }
  }
}

# MAIN

# Variables

# start with mapping out user SAMs and SIDs
Write-Host "Discovering users, please wait, this may take a while..."

# if connected to a domain, get domain information first
$currentDomain = $Null
$domainSID = $Null
$domainNETBiosName = $Null
try {
  $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
} catch { <# do nothing #> }
# then, if we are connected to a domain, for all unmatched SAM/SID folders, attempt finding users with domain
if ($currentDomain) {
  $domainName = $currentDomain.Name
  $domainDefaultAccountSID = (New-Object System.Security.Principal.NTAccount("${domainName}\DefaultAccount")).Translate(
    [System.Security.Principal.SecurityIdentifier]
  ).Value
  $domainSID = $domainDefaultAccountSID -replace "(.*)\-$($KNOWN_SID_RID_TO_SAM.'DefaultAccount')(.*)", '$1$2'
  $domainNETBiosName = ((New-Object System.Security.Principal.SecurityIdentifier($domainDefaultAccountSID)).Translate(
    [System.Security.Principal.NTAccount]
  ).Value).split('\')[0]
}

# necessary for username checks against SIDs
$ProfileListAllUsernames = [ordered]@{}
# get known builtin user accounts out of the way first
$ProfileListBuiltinUsernames = [ordered]@{}
$KNOWN_SID_RID_TO_SAM.Values | ForEach-Object {
  $rid = $_
  $sid = "${MACHINE_SID}-${rid}"
  try {
    $sidObject = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $userObject = if ($sidObject) { $sidObject.Translate([System.Security.Principal.NTAccount]) }
    $sam = if ($userObject) { ($userObject.Value).split('\')[1] }
    $ProfileListAllUsernames.$sid = $sam
    $ProfileListBuiltinUsernames.$sid = $ProfileListAllUsernames.$sid
  } catch {
    $ProfileListAllUsernames.$sid = $KNOWN_SID_RID_TO_SAM.GetEnumerator().Where({ $_.Value -eq $rid }).Key
    $ProfileListBuiltinUsernames.$sid = $ProfileListAllUsernames.$sid
  }
}
# then get other service/system user or machine/domain users on machine
$ProfileListServiceOrSystemUsernames = [ordered]@{}
$ProfileListMachineUsernames = [ordered]@{}
$ProfileListDomainUsernames = [ordered]@{}
Get-ChildItem -Path $REGISTRY_PROFILE_LIST_PATH | Where-Object {
  $_.PSChildName -notmatch "$("${MACHINE_SID}-".replace('-','\-'))($($KNOWN_SID_RID_TO_SAM.Values -Join '|'))"
} | ForEach-Object {
  $sid = $_.PSChildName
  $sidObject = New-Object System.Security.Principal.SecurityIdentifier($sid)
  $userObject = if ($sidObject) { $sidObject.Translate([System.Security.Principal.NTAccount]) }
  $userNTAccount = if ($userObject) { ($userObject.Value).split('\') }
  $machineOrDomain = if ($userNTAccount) { $userNTAccount[0] }
  $sam = if ($userNTAccount) { $userNTAccount[1] }
  if ($userObject) { $ProfileListAllUsernames.$sid = $sam }
  if ($machineOrDomain) {
    if ($machineOrDomain -eq $env:COMPUTERNAME) {
      $ProfileListMachineUsernames.$sid = $ProfileListAllUsernames.$sid
    } elseif ($domainNETBiosName -And ($machineOrDomain -eq $domainNETBiosName)) {
      $ProfileListDomainUsernames.$sid = $ProfileListAllUsernames.$sid
    } else {
      $ProfileListServiceOrSystemUsernames.$sid = $ProfileListAllUsernames.$sid
    }
  }
}
# if connected to a domain, and we have left over SAMs and SIDs, then attempt to lookup them up in the domain
if ($currentDomain) {
  # get remaining unmatched user SAMs
  $UserFolders = @(
    $DRIVE_LETTERS | ForEach-Object {
      $usersPath = "${_}:\Users"
      if (Test-Path -LiteralPath $usersPath) {
        Get-ChildItem -Path $usersPath -Exclude ($EXCLUDE_USER_FOLDERS) -Attributes !ReparsePoint -Directory -Force | Select -Property Name
      }
    }
  )
  $LeftOverSAM = @(
    $UserFolders | Where-Object {
      $ProfileListLocalOrDomainUsernames.Values -notcontains $_.Name
    }
  )
  $LeftOverSAM = @($LeftOverSAM | Sort-Object -Unique Name | Select-Object -ExpandProperty Name)
  # attempt NTAccount translations to SID
  $LeftOverSAM | ForEach-Object {
    $sam = $_
    $sid = $Null
    try {
      $sid = (New-Object System.Security.Principal.NTAccount("${domainName}\${sam}")).Translate(
        [System.Security.Principal.SecurityIdentifier]
      ).Value
      $ProfileListAllUsernames.$sid = $sam
      $ProfileListLocalOrDomainUsernames.$sid = $ProfileListAllUsernames.$sid
    } catch { <# do nothing #> }
  }

  # get remaining unmatched user SIDs
  $ExcludeSIDs = @($ProfileListAllUsernames.Keys)
  $SidFolders = @(
    $DRIVE_LETTERS | ForEach-Object {
      $sidsPath = "${_}:\WpSystem"
      if (Test-Path -LiteralPath $sidsPath) {
        Get-ChildItem -Path $sidsPath -Exclude ($ExcludeSIDs) -Attributes !ReparsePoint -Directory -Force | Select -Property Name
      }
    }
  )
  $LeftOverSID = @($SidFolders | Sort-Object -Unique Name | Select-Object -ExpandProperty Name)
  # attempt SID translations to NTAccount
  $LeftOverSID | ForEach-Object {
    $sid = $_
    $sam = $Null
    try {
      $sam = ((New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate(
        [System.Security.Principal.NTAccount]
      ).Value).split('\')[1]
      $ProfileListAllUsernames.$sid = $sam
      $ProfileListLocalOrDomainUsernames.$sid = $ProfileListAllUsernames.$sid
    } catch { <# do nothing #> }
  }
}

# Use basic filters first, as it's much faster on file searching, to grab the different browser engine files that have extension data
Write-Host "Searching files, please wait, this may take a while..."
# NOTE: using -Include would make these searches a lot slower
$AllBlinkBrowserPreferencesFiles = @($DRIVE_LETTERS | ForEach-Object {
  Get-ChildItem -Path ${_}:\ -Filter 'Preferences' -Recurse -File -Force -ErrorAction SilentlyContinue
})
$AllBlinkBrowserSecurePreferencesFiles = @($DRIVE_LETTERS | ForEach-Object {
  Get-ChildItem -Path ${_}:\ -Filter 'Secure Preferences' -Recurse -File -Force -ErrorAction SilentlyContinue
})
$AllGeckoBrowserExtensionsFiles = @($DRIVE_LETTERS | ForEach-Object {
  Get-ChildItem -Path ${_}:\ -Filter 'extensions.json' -Recurse -File -Force -ErrorAction SilentlyContinue
})
$AllBrowserPreferencesOrExtensionsFiles = $AllBlinkBrowserPreferencesFiles +
                                          $AllBlinkBrowserSecurePreferencesFiles +
                                          $AllGeckoBrowserExtensionsFiles

# Then, we can use regex to do the matching on these files
$AllBrowserPreferencesOrExtensionsFileMatches = @(
  $AllBrowserPreferencesOrExtensionsFiles |
  Where-Object { $_.FullName -cmatch $BROWSER_PREFERENCES_OR_EXTENSIONS_FILE_MATCH_REGEX} |
  ForEach-Object { [regex]::Matches($_.FullName, $BROWSER_PREFERENCES_OR_EXTENSIONS_FILE_MATCH_REGEX) }
)

# parse all extension data
Write-Host "Parsing data from files..."
for ($i = 0; $i -lt $AllBrowserPreferencesOrExtensionsFileMatches.length; $i++) {
  $browserJsonMatch = $AllBrowserPreferencesOrExtensionsFileMatches[$i]
  $jsonFilePath = $browserJsonMatch.Value
  $jsonContent = Get-Content -LiteralPath $jsonFilePath -Raw -Encoding UTF8 | Fix-JsonContent
  $jsonData = $jsonContent | ConvertFrom-Json

  # differences in determining data based on standard or nonstandard locations of browser appdata
  $nonstandardBrowserProfile = $browserJsonMatch.Groups[$NONSTANDARD_BROWSER_PROFILE_NAME_REGEX_GROUP].length -gt 0

  # Drive
  $driveLetter = $browserJsonMatch.Groups[$DRIVE_LETTER_REGEX_GROUP].Value
  $driveType = "$(
    if (Get-Volume) {
      (Get-Volume -DriveLetter $driveLetter).DriveType
    } else {
      # more complicated to parse things out when Get-Volume isn't available
      $DRIVE_TYPES[(
        Get-CimInstance -ClassName Win32_Volume | Where-Object {
          # this could potentially fail in the future if someone has more than 26 drives mounted
          # (aka all drive letters are used, and system has now resorted to mounting drives to specific folder paths)
          $_.DriveLetter -match "^${driveLetter}\:`$"
        } | Select-Object -First 1 | Select-Object -ExpandProperty DriveType
      )]
    }
  )"
  if (-Not $OriginalExtensionDataJSON.Drives[$driveLetter]) {
    # create drive property with DriveType string and the following objects: Users, DetachedBrowsers
    $OriginalExtensionDataJSON.Drives[$driveLetter] = [ordered]@{
      DriveType = $driveType
      DetachedBrowsers = [ordered]@{}
      Users = [ordered]@{}
    }
  }
  $Drive = $OriginalExtensionDataJSON.Drives[$driveLetter]

  # User (if there is one)
  $username = $Null
  $User = $Null
  $userIsDefault = $browserJsonMatch.Groups[$USER_IS_DEFAULT_REGEX_GROUP].length -gt 0
  $userIsService = $browserJsonMatch.Groups[$USER_IS_SERVICE_REGEX_GROUP].length -gt 0
  $userIsSystem = $browserJsonMatch.Groups[$USER_IS_SYSTEM_REGEX_GROUP].length -gt 0
  $usernameExists = $browserJsonMatch.Groups[$USER_SAM_REGEX_GROUP].length -gt 0
  $userSidExists = $browserJsonMatch.Groups[$USER_SID_REGEX_GROUP].length -gt 0
  if ($usernameExists -Or $userSidExists) {
    # username can be easy or hard to determine sometimes
    if ($userSidExists) {
      # if user SID exists as user, get username, otherwise use the SID as its username
      $userSid = $browserJsonMatch.Groups[$USER_SID_REGEX_GROUP].Value
      $username = if ($ProfileListAllUsernames.$userSid) { $ProfileListAllUsernames.$userSid } else { $userSid }
    } else {
      $username = if ($userIsDefault) {
        'DefaultAccount'
      } elseif ($userIsService -And ($username -eq 'LocalService')) {
        'LOCAL SERVICE'
      } elseif ($userIsService -And ($username -eq 'NetworkService')) {
        'NETWORK SERVICE'
      } elseif ($userIsSystem) {
        'SYSTEM'
      } else { # could be IUSR too, but that user is created under the Users folder like normal
        $browserJsonMatch.Groups[$USER_SAM_REGEX_GROUP].Value
      }
    }

    if (-Not $Drive.Users[$username]) {
      # create user property with FullName string and the following objects: DetachedBrowsers, Browsers
      $Drive.Users[$username] = [ordered]@{
        FullName = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name = '${username}'" -Property FullName | Select-Object -Expand FullName
        DetachedBrowsers = [ordered]@{}
        Browsers = [ordered]@{}
      }
    }
    $User = $Drive.Users[$username]
  }

  # Browser
  $browser = $Null
  $browserName = $Null
  $browserCompany = $Null

  $isBlinkEngine = $False
  $isGeckoEngine = $False
  $browserEngine = if (($browserJsonMatch.Groups[$BLINK_PREFERENCES_REGEX_GROUP].length -gt 0) -And
                       $browserJsonMatch.Groups[$BLINK_PREFERENCES_REGEX_GROUP].Value) {
    $BLINK_BROWSER_ENGINE
    $isBlinkEngine = $True
  } elseif (($browserJsonMatch.Groups[$GECKO_EXTENSIONS_REGEX_GROUP].length -gt 0) -And
            $browserJsonMatch.Groups[$GECKO_EXTENSIONS_REGEX_GROUP].Value) {
    $GECKO_BROWSER_ENGINE
    $isGeckoEngine = $True
  } # else unknown browser engine when all are false
  $supportedBrowserEngine = $isBlinkEngine -Or $isGeckoEngine

  # try to get browser and company names
  $jsonFolderPath = Split-Path -Parent $jsonFilePath
  if (-Not $nonstandardBrowserProfile) {
    # standard browser has consistent names to find
    if ($browserJsonMatch.Groups[$BROWSER_MSIX_FULLNAME_REGEX_GROUP].length -gt 0) {
      # packaged (MSIX) installed browsers have name and company name in single folder format
      $browser = ($browserJsonMatch.Groups[$BROWSER_MSIX_FULLNAME_REGEX_GROUP].Value).split('_')[0]
      $browser = $browser.split('.')
      for ($j = 0; $j -lt $browser.length; $j++) {
        $browser[$j] = $browser[$j] -csplit '(?=[A-Z])' -ne '' -join ' '
      }
    } elseif (($browserJsonMatch.Groups[$BROWSER_EXE_FULLNAME_REGEX_GROUP].length -gt 0) -Or
              ($browserJsonMatch.Groups[$BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP].length -gt 0)) {
      # standard unpackaged (EXE) have very determinable name format
      $browserFullNameGroup = if ($browserJsonMatch.Groups[$BROWSER_EXE_FULLNAME_REGEX_GROUP].length -gt 0) {
        $browserJsonMatch.Groups[$BROWSER_EXE_FULLNAME_REGEX_GROUP]
      } else { # if ($browserJsonMatch.Groups[$BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP].length -gt 0)
        $browserJsonMatch.Groups[$BROWSER_ATYPICAL_FULLNAME_REGEX_GROUP]
      }
      $browser = ($browserFullNameGroup.Value).split('\')
    }
    $browserName = $browser[-1]
    if ($browser[0] -ne $browserName) { $browserCompany = $browser[0] } # browser name can't be company name, finds company name later
  }
  if ($nonstandardBrowserProfile -Or (-Not $browserCompany)) {
    $jsonParentFolderPath = Split-Path -Parent $jsonFolderPath
    $browserFolderPath = $Null
    $browserExeFiles = $()
    $appxManifestXmlFiles = $()
    $geckoApplicationIniFiles = $()

    # detached browsers can't be certain of name, so have to just use the path of the browser by its respective browser engine
    if ($isBlinkEngine) {
      # a 'Last Browser' file may exist, which includes a direct path to the browser EXE file
      $lastBrowserFilePath = $jsonParentFolderPath + '\Last Browser'
      if (Test-Path -LiteralPath $lastBrowserFilePath -PathType Leaf) {
        # encoding needs to be read as unicode, otherwise, spacing gets messed up
        $lastBrowserExePath = Get-Content -LiteralPath $lastBrowserFilePath -Encoding Unicode
        if ($lastBrowserExePath) {
          $browserFolderPath = Split-Path -Parent $lastBrowserExePath
        }
      }
    } elseif ($isGeckoEngine) {
      # a 'compatibility.ini' file may exist, which may include a variable, 'LastPlatformDir', with a direct path to the browser
      # folder, which in turn can be used to check if a 'application.ini' file may exist in the browser folder for browser info
      $compatibilityIniFilePath = $jsonFolderPath + '\compatibility.ini'
      if (Test-Path -LiteralPath $compatibilityIniFilePath -PathType Leaf) {
        $compatibilityIni = Get-Content -LiteralPath $compatibilityIniFilePath -Encoding UTF8
        $lastPlatformDir = if ($compatibilityIni) { $compatibilityIni | Select-String '^LastPlatformDir=' }
        if ($lastPlatformDir) {
          $browserFolderPath = ($lastPlatformDir.Line).split('=')[1]
        }
      }
    }

    # only supported browsers can have additional checks in place for finding browser info from other found files
    if ($supportedBrowserEngine) {
      # search for matching loaded browser resources paths in the json file
      $helperExeRegex = $Null
      $loadedBrowserDataMatches = @()
      if ($isBlinkEngine) {
        $helperExeRegex = $BLINK_HELPER_EXE_REGEX
        $loadedBrowserDataMatches += @([regex]::Matches($jsonContent, $BLINK_LOADED_RESOURCES_MATCH_REGEX))
      } elseif ($isGeckoEngine) {
        $helperExeRegex = $GECKO_HELPER_EXE_REGEX
        $loadedBrowserDataMatches += @([regex]::Matches($jsonContent, $GECKO_LOADED_FEATURES_MATCH_REGEX))
      }

      $loadedBrowserDataPossiblePaths = @()
      if ($browserFolderPath) { $loadedBrowserDataPossiblePaths += @($browserFolderPath) }
      for ($j = 0; $j -lt $loadedBrowserDataMatches.length; $j++) {
        $loadedBrowserDataMatch = $loadedBrowserDataMatches[$j]

        # can't add if there are no matches
        if ($loadedBrowserDataMatch.Groups[$POSSIBLE_BROWSER_PATH_REGEX_GROUP].length -gt 0) {
          # must unescape the json string
          $possiblePathJsonEscaped = $loadedBrowserDataMatch.Groups[$POSSIBLE_BROWSER_PATH_REGEX_GROUP].Value
          $possiblePath = (ConvertFrom-Json ("{`"path`":`"${possiblePathJsonEscaped}`"}")).path
          if ($isGeckoEngine) {
            # additional step needed here to decode URI, and flip the slashes
            $possiblePathUriDecoded = [System.URI]::UnescapeDataString($possiblePath)
            $possiblePath = $possiblePathUriDecoded.replace('/','\')
          }
          $loadedBrowserDataPossiblePaths += @($possiblePath)
        }
      }
      if (-Not $loadedBrowserDataPossiblePaths) {
        # sometimes there's just no better way to find the files we need other than going two directories up
        $loadedBrowserDataPossiblePaths += @(Split-Path -Parent $jsonParentFolderPath)
      }
      if ($loadedBrowserDataPossiblePaths) {
        # first need to shorten list to unique paths only, while retaining original order
        $uniquePossiblePathsOrderedList = [ordered]@{}
        $loadedBrowserDataPossiblePaths | ForEach-Object {
          if (-Not $uniquePossiblePathsOrderedList.$_) {
            $uniquePossiblePathsOrderedList.$_ = $True
          }
        }
        $uniquePossiblePaths = @($uniquePossiblePathsOrderedList.Keys)

        # then loop through all paths, finding browser files of interest that exist
        $firstBrowserExeBrowserFolderPath = $Null
        $firstAppxManifestXmlBrowserFolderPath = $Null
        $firstGeckoApplicationIniBrowserFolderPath = $Null
        $j = 0
        while ($j -lt $uniquePossiblePaths.length) {
          $uniquePossiblePath = $uniquePossiblePaths[$j]

          # find files in the possible browser path
          $moreBrowserExeFiles = @()
          $moreAppxManifestXmlFiles = @()
          $moreGeckoApplicationIniFiles = @()
          if (Test-Path -LiteralPath $uniquePossiblePath) {
            # filter out known helper EXE files
            $moreBrowserExeFiles = @(
              Get-ChildItem -LiteralPath $uniquePossiblePath -Filter '*.exe' -File -Force |
              Where-Object { ($_.BaseName -notmatch $helperExeRegex) -And ($_.VersionInfo -And $_.VersionInfo.ProductName) }
            )
            # find other files that aren't EXEs that can aid in finding information
            $moreAppxManifestXmlFiles = @(Get-ChildItem -LiteralPath $uniquePossiblePath -Filter 'AppxManifest.xml' -File -Force)
            if ($isGeckoEngine) {
              $moreGeckoApplicationIniFiles = @(Get-ChildItem -LiteralPath $uniquePossiblePath -Filter 'application.ini' -File -Force)
            }
          }

          # browser folder path may need to be changed because of the order in which information is checked afterwards
          if ((-Not $firstBrowserExeBrowserFolderPath) -And $moreBrowserExeFiles) {
            $firstBrowserExeBrowserFolderPath = $uniquePossiblePath
          }
          if ((-Not $firstAppxManifestXmlBrowserFolderPath) -And $moreAppxManifestXmlFiles) {
            $firstAppxManifestXmlBrowserFolderPath = $uniquePossiblePath
          }
          if ((-Not $firstGeckoApplicationIniBrowserFolderPath) -And $moreGeckoApplicationIniFiles) {
            $firstGeckoApplicationIniBrowserFolderPath = $uniquePossiblePath
          }

          $browserExeFiles += $moreBrowserExeFiles
          $appxManifestXmlFiles += $moreAppxManifestXmlFiles
          $geckoApplicationIniFiles += $moreGeckoApplicationIniFiles

          $j++
        }
        # browser folder path may need to be changed because of the order in which information is checked afterwards
        if ($firstBrowserExeBrowserFolderPath -Or $firstAppxManifestXmlBrowserFolderPath -Or
            $firstGeckoApplicationIniBrowserFolderPath) {
          # Note: preference order of file info is XML > INI > EXE
          $browserFolderPath = if ($firstAppxManifestXmlBrowserFolderPath) {
            $firstAppxManifestXmlBrowserFolderPath
          } elseif ($firstGeckoApplicationIniBrowserFolderPath) {
            $firstGeckoApplicationIniBrowserFolderPath
          } elseif ($firstBrowserExeBrowserFolderPath) {
            $firstBrowserExeBrowserFolderPath
          }
        }
      }
    }

    # for supported browsers:
    #   if we still don't have browser or company names, either check for info from EXEs or XMLs if they existed,
    #   or (for browser name only) just use folder path, but don't overwrite a browser name if we're just looking for company name
    if ($supportedBrowserEngine -And (-Not ($browserName -Or $browserCompany)) -And
        ($browserFolderPath -Or $browserExeFiles -Or $appxManifestXmlFiles)) {
      # there is a reason some IF statements are NOT put in an ELSEIF format, ORDER MATTERS!!!
      if ($appxManifestXmlFiles) {
        # get details of browser from the first AppxManifest.xml in packaged apps
        [xml]$appxManifestXml = $appxManifestXmlFiles[0] | Get-Content -Encoding UTF8
        $appxPackageIdentityNameArray = ($appxManifestXml.Package.Identity.Name).split('.')
        for ($j = 0; $j -lt $browser.length; $j++) {
          $browser[$j] = $browser[$j] -csplit '(?=[A-Z])' -ne '' -join ' '
        }
        if (-Not $browser) { $browser = $appxPackageIdentityNameArray }
        if (-Not $browserName) { $browserName = $appxPackageIdentityNameArray[-1] }
        if (-Not $browserCompany) {
          $browserCompany = $appxPackageIdentityNameArray[0]
          $browser[0] = $browserCompany
        }
      }
      if ($geckoApplicationIniFiles -And (-Not ($browserName -Or $browserCompany))) {
        # get details of browser from the first application.ini in Gecko based browsers
        $geckoApplicationIni = $geckoApplicationIniFiles[0] | Get-Content -Encoding UTF8

        $appVendor = (($geckoApplicationIni | Select-String '^Vendor=').Line).split('=')[1]
        $appName = (($geckoApplicationIni | Select-String '^Name=').Line).split('=')[1]
        if (($appName -eq 'Firefox') -And ($appVendor -ne 'Mozilla')) {
          # remoting name is sometimes needed instead for the instances where Name was never changed for a Gecko based browser
          $appRemotingName = (($geckoApplicationIni | Select-String '^RemotingName=').Line).split('=')[1]
          $appName = $appRemotingName
        }
        if (-Not $browser) { $browser = @($appVendor, $appName) }
        if (-Not $browserName) { $browserName = $appName }
        if (-Not $browserCompany) {
          $browserCompany = $appVendor
          $browser[0] = $browserCompany
        }
      }
      if ($browserExeFiles -And (-Not ($browserName -Or $browserCompany))) {
        # prefer to use the first EXE with a CompanyName (company name), if available
        $browserExeFilesWithCompanyName = $browserExeFiles | Where-Object { $_.VersionInfo.CompanyName }
        if ($browserExeFilesWithCompanyName) { $browserExeFiles = $browserExeFilesWithCompanyName }

        # get details of browser from the first EXE with file version information (always has ProductName used for browser name)
        $browserExe = $browserExeFiles[0]
        $browserVersionInfo = $browserExe.VersionInfo
        if (-Not $browser) { $browser = @($browserVersionInfo.CompanyName, $browserVersionInfo.ProductName) }
        if (-Not $browserName) { $browserName = $browserVersionInfo.ProductName }
        if (-Not $browserCompany) {
          $browserCompany = $browserVersionInfo.CompanyName
          $browser[0] = $browserCompany
        }
      }
    }

    # determine which path to use as browser name, based on if browser was a supported engine
    if (-Not $browserName) {
      $browserName = if ($supportedBrowserEngine -And $browserFolderPath) {
        # use the browser folder path as the browser name
        $browserFolderPath
      } else {
        # use path as name for browsers where the engine type is unknown
        $jsonParentFolderPath
      }
    }
  }

  $browserJsonMatch.Engine
  # $browser = $browser -Join ' '
  $browserEntrypoint = $Null
  if ($nonstandardBrowserProfile) {
    if ($User) {
      # detached browser at the user level
      if (-Not $User.DetachedBrowsers) { $User.DetachedBrowsers = [ordered]@{} }
      $browserEntrypoint = $User.DetachedBrowsers
    } else {
      # detached browser at the drive level
      if (-Not $Drive.DetachedBrowsers) { $Drive.DetachedBrowsers = [ordered]@{} }
      $browserEntrypoint = $Drive.DetachedBrowsers
    }
  } else {
    # normal browser
    if (-Not $User.Browsers) { $User.Browsers = [ordered]@{} }
    $browserEntrypoint = $User.Browsers
  }
  if (-Not $browserEntrypoint[$browserName]) {
    # create browser property with Profiles object and the following strings: Company, Engine
    $browserEntrypoint[$browserName] = [ordered]@{
      Company = $browserCompany
      Engine = $browserEngine
      Profiles = [ordered]@{}
    }
  }
  $FoundBrowser = $browserEntrypoint[$browserName]

  # Browser profile
  $profileFolderName = if ($browserJsonMatch.Groups[$BROWSER_PROFILE_NAME_REGEX_GROUP].length -gt 0) {
    $browserJsonMatch.Groups[$BROWSER_PROFILE_NAME_REGEX_GROUP].Value
  } else {
    ($jsonFolderPath | Get-Item).BaseName
  }
  $profileName = $profileFolderName
  $profileAccount = [ordered]@{
    Email = $Null
    DisplayName = $Null
  }
  if (-Not $FoundBrowser.Profiles[$jsonFolderPath]) {
    # profile name and account details is a bit tricker to get
    if ($isBlinkEngine) {
      # profile name/account details is only stored in the Preferences file
      $profileJsonData = $jsonData
      if ($jsonFilePath.EndsWith('Secure Preferences')) {
        $profileJsonFilePath = $jsonFolderPath + '\Preferences'
        $profileJsonData = if (Test-Path -LiteralPath $profileJsonFilePath -PathType leaf) {
          Get-Content -LiteralPath $profileJsonFilePath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
        } else { $Null }
      }
      if ($profileJsonData) {
        # profile name
        if ($profileJsonData.profile -And $profileJsonData.profile.name) {
          $profileName = $profileJsonData.profile.name
        }
        # account details (from the main account)
        if ($profileJsonData.account_info) {
          if ($profileJsonData.account_info[0].email) {
            $profileAccount.Email = $profileJsonData.account_info[0].email
          }
          if ($profileJsonData.account_info[0].given_name) {
            $profileAccount.DisplayName = $profileJsonData.account_info[0].given_name
          } elseif ($profileJsonData.account_info[0].full_name) {
            $profileAccount.DisplayName = $profileJsonData.account_info[0].full_name
          }
        }
      }
    } elseif ($isGeckoEngine) {
      # profile name is pulled from the folder name
      $indexFirstPeriod = $profileFolderName.IndexOf('.')
      if ($indexFirstPeriod -gt -1) {
        $testProfileName = $profileFolderName.substring($indexFirstPeriod + 1)
        if ($testProfileName) { $profileName = $testProfileName }
      }
      # account data is pulled from a different file
      $profileJsonFilePath = $jsonFolderPath + '\signedInUser.json'
      $profileJsonData = if (Test-Path -LiteralPath $profileJsonFilePath -PathType leaf) {
        Get-Content -LiteralPath $profileJsonFilePath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
      } else { $Null }
      if ($profileJsonData -And $profileJsonData.accountData) {
        if ($profileJsonData.accountData -And $profileJsonData.accountData.email) {
          $profileAccount.Email = $profileJsonData.accountData.email
        }
        if ($profileJsonData.accountData -And $profileJsonData.accountData.displayName -And
            $profileJsonData.accountData.profileCache -And $profileJsonData.accountData.profileCache.profile -And
            $profileJsonData.accountData.profileCache.profile.displayName) {
          $profileAccount.DisplayName = $profileJsonData.accountData.profileCache.profile.displayName
        }
      }
    }
    # create profile property with an Extensions array
    $FoundBrowser.Profiles[$jsonFolderPath] = [ordered]@{
      Name = $profileName # will be the profile folder name if profile name wasn't obtainable
      Account = $profileAccount # may or may not include online account info if user is logged into browser profile
      Extensions = @()
    }
  }
  $FoundBrowserProfile = $FoundBrowser.Profiles[$jsonFolderPath]

  # get extension list based on browser engine
  $extensionsList = $Null
  if ($isBlinkEngine) {
    # items must exist in $jsonData.extensions.settings, because extension data only comes from one of the "Preferences" files
    $extensionsList = if ($jsonData.extensions) {
      # some browsers like to rename the settings property
      ($jsonData.extensions.PSObject.Properties |
       Where-Object { $_.Name -like "*settings" }).Value.PSObject.Properties
    }
  } elseif ($isGeckoEngine) {
    $addons = $jsonData.addons
    $extensionsList = $addons
  }

  # iterate over extension lists to determine installed extensions, empty lists don't do anything
  $extensionsList | ForEach-Object {
    $extensionID = $Null ; $extensionVersion = $Null ; $extensionVendor = $Null
    $extensionName = $Null ; $extensionDescription = $Null ; $extensionURLs = $null
    $extensionEnabled = $True ; $extensionUnpacked = $False

    # only continue parsing/adding extension data if:
    # - the data is actually an extension
    # - and the extension isn't built into the browser
    if ($isBlinkEngine) {
      $extension = $_.Value

      # Unpacked extension detection
      $extensionUnpacked = $BLINK_BROWSER_CHECK_UNPACKED -contains $extension.location
      # Sometimes manifest data needs to be loaded in manually (usually the case for unpacked extensions)
      $checkExtensionManifestPath = "$($extension.Path)\manifest.json"
      if ((-Not $extension.manifest) -And (Test-Path -LiteralPath $checkExtensionManifestPath -PathType Leaf)) {
        $extensionManifestData = Get-Content -LiteralPath $checkExtensionManifestPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
        $extension | Add-Member -Name "manifest" -Value $extensionManifestData -MemberType NoteProperty
      }
      # Opera browsers may have one or more special builtin app(s) that don't have proper usage of the location properties
      $specialOperaBuiltinCheck = ($extension.manifest.author -eq "Opera Norway AS") -And
                                  ($extension.manifest.update_url) -And
                                  (([System.Uri]$extension.manifest.update_url).Host.EndsWith('operacdn.com'))
      # Maxthon browsers may at least 5 special builtin app(s) that don't have proper usage of the location properties
      $specialMaxthonBuiltinCheck = ($browserName -eq 'Maxthon') -And (
        ($MAXTHON_BROWSER_CHECK_BUILTIN -contains $extension.id) -Or
        ($MAXTHON_BROWSER_CHECK_BUILTIN -contains $_.Name)
      )

      if ($extension.manifest -And (-Not $extension.manifest.theme) -And
          ($BLINK_BROWSER_CHECK_BUILTIN -notcontains $extension.location) -And
          (-Not ($specialOperaBuiltinCheck -Or $specialMaxthonBuiltinCheck))) {
        # remove the `default_locale` property as it's unnecessary extra data
        $extension.manifest.PSObject.Properties.Remove('default_locale')

        # grab simplified data
        $extensionID = if ($extension.id) { $extension.id } else { $_.Name }
        $extensionVersion = $extension.manifest.version
        $extensionVendor = $extension.manifest.author
        $extensionName = $extension.manifest.name
        $extensionDescription = $extension.manifest.description
        $extensionEnabled = $extension.state -And $extension.state -eq 1

        # get all possible URLs
        $extensionHomepageURL = $extension.manifest.homepage_url
        $extensionUpdateURL = $extension.manifest.update_url
        $extensionURLs = @()
        if ($extensionUpdateURL) {
          $urlEncodedExtensionID = [Uri]::EscapeDataString($extensionID)
          $extensionUpdateUrlURI = [System.Uri]$extensionUpdateURL
          $extensionUpdateHost = $extensionUpdateUrlURI.Host
          switch ($extensionUpdateHost) {
            'clients2.google.com' { $extensionURLs += @("https://chromewebstore.google.com/webstore/detail/${urlEncodedExtensionID}") }
            'edge.microsoft.com' { $extensionURLs += @("https://microsoftedge.microsoft.com/addons/detail/${urlEncodedExtensionID}") }
            'extension-updates.opera.com' { $extensionURLs += @("https://addons.opera.com/extensions/details/app_id/${urlEncodedExtensionID}") }
            {($_ -match '(github|raw\.githubusercontent)\.com')} {
              # special case for GitHub
              $extensionGitHub = Get-GitHubRepoURL $extensionUpdateURL
              # we don't want to include this url, if it's the start of the homepage URL
              if ($extensionGitHub -And (-Not $extensionHomepageURL.StartsWith($extensionGitHub))) {
                $extensionURLs += @($extensionGitHub)
              }
            }
            # default: do nothing
          }
        }
        # always include the homepage URL if there is one
        if ($extensionHomepageURL) { $extensionURLs += @($extensionHomepageURL) }
        # only need to add update URL for unknown webstores
        if (($extensionURLs.length -eq 0) -And $extensionUpdateURL) { $extensionURLs += @($extensionUpdateURL) }
        # deduplicate URLs
        $extensionURLs = $extensionURLs | Select-Object -Unique
        # convert to string
        $extensionURLs = "[$(@($extensionURLs | ForEach-Object { " $_ " }) -join ',')]"

        # some browsers remove the extension ID from here
        if (-Not $extension.id) {
          $extension | Add-Member -Name "id" -Value $extensionID -MemberType NoteProperty
        }

        # add extension to the array
        $FoundBrowserProfile.Extensions += @($extension)
      }
    } else { # elseif ($isGeckoEngine)
      $addon = $_

      # Unpacked extension detection
      $extensionUnpacked = (( # only extension type of WebExtension API
        # Gecko versions < 62: https://blog.mozilla.org/addons/2018/02/22/removing-support-unpacked-extensions/
        # and >= 48: (see below)
        $addon.installTelemetryInfo -And $addon.installTelemetryInfo.source -And (
          ($GECKO_BROWSER_CHECK_UNPACKED -contains $addon.installTelemetryInfo.source) -And
            (-Not $addon.installTelemetryInfo.sourceURL) # unsure if this needs to be here, but doesn't hurt to check
        )
      ) -Or ( # old extension type of different APIs included
        # Gecko versions < 57: https://en.wikipedia.org/wiki/Features_of_Firefox#Electrolysis_and_WebExtensions
        $addon.sourceURI -And ($addon.sourceURI).StartsWith('file:///')
      )) -And (
        # see https://github.com/mozilla/gecko-dev/blob/master/toolkit/mozapps/extensions/AddonManager.sys.mjs
        #   SIGNEDSTATE_NOT_REQUIRED = null ... `xpinstall.signatures.required` == false, in "about:config": https://wiki.mozilla.org/Add-ons/Extension_Signing#FAQ
        #   SIGNEDSTATE_MISSING      = 0 ...... unsigned
        # (-Not $addon.signedState) == true, when signedState is null or 0
        (-Not $addon.signedState) -Or ( # when signing extensions was required
          # SIGNEDSTATE_UNKNOWN      = -1 ..... packed with web-ext only for ease of testing, but otherwise still basically unpacked
          # Gecko versions >= 40: https://en.wikipedia.org/wiki/Add-on_(Mozilla)#Restrictions
          $addon.signedState -eq -1
        )
      )

      # NOTE: Unpacked extensions are not supported in the latest versions of Gecko...
      #       - https://blog.mozilla.org/addons/2018/02/22/removing-support-unpacked-extensions/
      #       ... but should still be checked for, due to older versions being used for Gecko forks, e.g. Goanna
      # In modern Gecko versions, unpacked extensions can be temporarily loaded in via `about:debugging`, but detecting what has
      # been loaded would be very complicated, and it would have incomplete data necessary to be viable information...
      # - 3 files, in a browser profile, contain pieces of information
      #   - '.\datareporting\glean\events\events'
      #     - each event... only captures later addon reloads or unloads (unreliable, since ther first load of an unpacked
      #       extension isn't logged)
      #       - `extra.source` = "temporary-addon", for unpacked extensions (un)loaded in
      #       - `extra.addon_id` = (if id exists in manifest of extension) ? true addon id : temporary addon id
      #   - '.\weave\addonsreconciler.json' (indexA has no correlation with indexB)
      #     - each addon in `addons`
      #       - `addons[indexA].scope` = 16, denotes if a temporary addon
      #       - `addons[indexA].id` = (if id exists in manifest of extension) ? true addon id : temporary addon id
      #       - `addons[indexA].guid` = (exists)
      #     - each change in `changes` (could be used to triangulate active unpacked addons against a start time from "prefs.js"...)
      #       - `changes[indexB][0]` = time int (when change occured)
      #       - `changes[indexB][1]` = int, where addon: 1 = loaded, 2 = unloaded
      #       - `changes[indexB][2]` = (if id exists in manifest of extension) ? true addon id : temporary addon id
      #   - '.\prefs.js'
      #     - will only ever show the most recently loaded unpacked extension path (can be found by finding
      #       "devtools.aboutdebugging.tmpExtDirPath"), which means, previously loaded extensions will not have a path to capture...
      #     - "extensions.webextensions.uuids" always load a temporary addon id (never the true addon id) for the unpacked
      #       extensions, but is paired with a guid
      # - temporary addon id's start with uuid and end with '@temporary-addon'
      # - due to bugs, "prefs.js" and "addonsreconciler.json" do not remove temporary addon entries that have been unloaded from
      #   browser restarts/terminations, unless manually unloaded beforehand (unreliable detection of currently loaded unpacked
      #   extensions)

      if ($addon.defaultLocale -And ($addon.type -match "(web)?extension") -And
          ($GECKO_BROWSER_CHECK_BUILTIN -notcontains $addon.location)) {

        # remove the `locales` property as it's unnecessary extra data
        $addon.PSObject.Properties.Remove('locales')

        # grab simplified data
        $extensionID = $addon.id
        $extensionVersion = $addon.version
        $extensionVendor = $addon.defaultLocale.creator
        $extensionName = $addon.defaultLocale.name
        $extensionDescription = $addon.defaultLocale.description
        $extensionEnabled = $addon.active

        # get all possible URLs
        $extensionUpdateURL = $addon.updateURL
        $extensionHomepageURL = $addon.defaultLocale.homepageURL
        $extensionSourceURI = $addon.sourceURI
        $extensionSourceURL = if ($addon.installTelemetryInfo -And $addon.installTelemetryInfo.sourceURL) {
                                $addon.installTelemetryInfo.sourceURL # only modern Gecko versions (w/ install telemetry)
                              }
        $extensionOnlineURL = if ($extensionUpdateURL) {
          $extensionUpdateURL
        } elseif ($extensionSourceURI) {
          $extensionSourceURI
        } else {
          $extensionSourceURL
        }
        # sometimes, Firefox addons are preinstalled, but not from the online store, so signature needs to be checked
        # and if valididated, crafted after the fact
        $craftFirefoxExtension = if ((-Not $extensionOnlineURL) -And $addon.targetApplications) {
          $addon.targetApplications | Where-Object { $_.id -eq 'toolkit@mozilla.org' } | Select-Object -First 1
        }
        $extensionURLs = @()
        if ($extensionOnlineURL -Or $craftFirefoxExtension) {
          $urlEncodedExtensionID = [Uri]::EscapeDataString($extensionID.trimstart('@')) # beginning @'s are removed in webstore URLs
          $extensionSourceUriURI = if (-Not $craftFirefoxExtension) { [System.Uri]$extensionSourceURI }
          $extensionUpdateHost = if ($craftFirefoxExtension) { 'addons.mozilla.org' } else { $extensionSourceUriURI.Host }
          switch ($extensionUpdateHost) {
            'addons.mozilla.org' { $extensionURLs += @("https://${extensionUpdateHost}/addon/${urlEncodedExtensionID}") }
            'addons.thunderbird.net' {
              # special case for Thunderbird
              $AllGeckoThunderbirdAddonXpiUrlMatches = [regex]::Matches($extensionOnlineURL, $GECKO_THUNDERBIRD_ADDON_XPI_URL_REGEX)
              if ($AllGeckoThunderbirdAddonXpiUrlMatches.length -gt 0) {
                $thunderbirdAddonXpiUrlMatch = $AllGeckoThunderbirdAddonXpiUrlMatches[0]
                # has weird ID format on website that doesn't match the installed extension ID
                $thunderbirdAddonID = $thunderbirdAddonXpiUrlMatch.Groups[$GECKO_THUNDERBIRD_ADDON_ID_REGEX_GROUP].Value
                if ($thunderbirdAddonID) { $extensionURLs += @("https://${$extensionUpdateHost}/addon/${thunderbirdAddonID}") }
              }
            }
            <# {($_ -match 'addons(\-dev)?\.(palemoon|basilisk\-browser|epyrus)\.org')} {
              # No clear way to get these browser webstore direct links without first downloading XML data from similar URLs:
              # - https://addons.palemoon.org/?component=integration&type=internal&request=get&addonguid=[ID HERE]
              #   where 'searchresults' needs to have at least 1 result, and the actual store page would be located at
              #   searchresults > addon > learnmore
            } #>
            'realityripple.com' {
              # special case for Reality Ripple
              $extensionRealityRipple = $extensionOnlineURL -replace '/[^/]*$',''
              # we don't want to include this url, if it's the start of the homepage URL
              if ($extensionRealityRipple -And (-Not $extensionHomepageURL.StartsWith($extensionRealityRipple))) {
                $extensionURLs += @($extensionRealityRipple)
              }
            }
            {($_ -match '(github|raw\.githubusercontent)\.com')} {
              # special case for GitHub
              $extensionGitHub = Get-GitHubRepoURL $extensionOnlineURL
              # we don't want to include this url, if it's the start of the homepage URL
              if ($extensionGitHub -And (-Not $extensionHomepageURL.StartsWith($extensionGitHub))) {
                $extensionURLs += @($extensionGitHub)
              }
            }
            # default: do nothing
          }
        }
        # always include the homepage URL if there is one
        if ($extensionHomepageURL) { $extensionURLs += @($extensionHomepageURL) }
        # always include the source URL if there is one (will usually be an alternate to the generated one in the switch statement)
        if ($extensionSourceURL -And ($extensionSourceURL -ne 'https://addons.mozilla.org/en-US/firefox/')) {
          $extensionURLs += @($extensionSourceURL)
        }
        # only need to add update URL for unknown webstores
        if (($extensionURLs.length -eq 0) -And $extensionUpdateURL) { $extensionURLs += @($extensionUpdateURL) }
        # if we still have no URLs, use source URI as a last resort
        if (($extensionURLs.length -eq 0) -And $extensionSourceURI) { $extensionURLs += @($extensionSourceURI) }
        # deduplicate URLs
        $extensionURLs = $extensionURLs | Select-Object -Unique
        # convert to string
        $extensionURLs = "[$(@($extensionURLs | ForEach-Object { " $_ " }) -join ',')]"

        # add extension to the array
        $FoundBrowserProfile.Extensions += @($addon)
      }
    }

    # if valid extension, add data to the other arrays
    if ($extensionID) {
      $SimplifiedExtensionDataCSV += [PSCustomObject]@{
        DriveLetter = $driveLetter
        DriveType = $driveType
        Username = $username
        ExtensionUnpacked = $extensionUnpacked
        ExtensionID = $extensionID
        ExtensionVersion = $extensionVersion
        ExtensionEnabled = $extensionEnabled
        BrowserDataDetached = $nonstandardBrowserProfile
        BrowserEngine = $browserEngine
        BrowserCompany = $browserCompany
        BrowserName = $browserName
      }
      $ExtensionsOnlyCSV += [PSCustomObject]@{
        BrowserEngine = $browserEngine
        ExtensionURLs = $extensionURLs
        ExtensionUnpacked = $extensionUnpacked
        ExtensionID = $extensionID
        ExtensionVendor = $extensionVendor
        ExtensionName = $extensionName
        ExtensionDescription = $extensionDescription
      }
    }
  }
}

# remove entries where data is empty for the JSON
$drivesObject = $OriginalExtensionDataJSON.Drives
[array]$drivesObject.Keys | ForEach-Object {
  $selectedDriveKey = $_
  $selectedDriveObject = $drivesObject[$selectedDriveKey]

  $driveDetachedBrowsersObject = $selectedDriveObject.DetachedBrowsers
  CleanUp-Browsers $driveDetachedBrowsersObject

  $usersObject = $selectedDriveObject.Users
  [array]$usersObject.Keys | ForEach-Object {
    $selectedUserKey = $_
    $selectedUserObject = $usersObject[$selectedUserKey]

    $userDetachedBrowsersObject = $selectedUserObject.DetachedBrowsers
    CleanUp-Browsers $userDetachedBrowsersObject

    $browsersObject = $selectedUserObject.Browsers
    CleanUp-Browsers $browsersObject

    # if we have no browsers (normal and user detached) in dictionary, delete user
    if (-Not ($userDetachedBrowsersObject.Count -Or $browsersObject.Count)) {
      $usersObject.Remove($selectedUserKey)
    }
  }
  # if we have no users and no drive detached browsers, delete drive
  if (-Not ($driveDetachedBrowsersObject.Count -Or $usersObject.Count)) {
    $drivesObject.Remove($selectedDriveKey)
  }
}

# get unique values for the CSVs, while sorting at the same time
$SimplifiedExtensionDataCSV = $SimplifiedExtensionDataCSV | Sort-Object DriveLetter,DriveType,Username,BrowserDataDetached,BrowserEngine,BrowserCompany,BrowserName,ExtensionUnpacked,ExtensionID,ExtensionVersion,ExtensionEnabled -Unique
$ExtensionsOnlyCSV = $ExtensionsOnlyCSV | Sort-Object BrowserEngine,ExtensionURLs,ExtensionUnpacked,ExtensionVendor,ExtensionName,ExtensionID,ExtensionDescription -Unique

# export finialized data
$OriginalExtensionDataJSON | ConvertTo-Json -Compress -Depth 100 | Out-File "${Path}\${FILENAME_PRE}_original_${FILENAME_POST}.json" -Encoding utf8
$SimplifiedExtensionDataCSV | Export-Csv -NoTypeInformation "${Path}\${FILENAME_PRE}_simplified_${FILENAME_POST}.csv" -Encoding utf8
$ExtensionsOnlyCSV | Export-Csv -NoTypeInformation "${Path}\${FILENAME_PRE}_only_${FILENAME_POST}.csv" -Encoding utf8
Write-Output "Data exported to folder: `"${Path}\`""
