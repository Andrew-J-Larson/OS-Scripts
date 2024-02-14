<#
  .SYNOPSIS
  Audit Browser Extensions v1.0.6

  .DESCRIPTION
  This script will get all browser extensions installed from every user profile on the computer (and by default avoiding extensions
  built into each browser, e.g. non-removeable extensions). Most Blink (Chromium) and Gecko (FireFox)/Goanna (Palemoon) engine based
  browsers should be supported, if there's a browser you come across where this script isn't working properly, please report it on
  the GitHub.

  Browsers installed to different drives should also be detected, assuming the data for the browser is still stored on the computer
  in the user's AppData folder.

  Unpacked extension detection is limited but should be working.

  Portable browsers that place their AppData in non-standard directories (e.g. not anywhere within a user's AppData folder) will
  not be supported, and likely won't be in the future, due to most commonly being used on USB drives on the go, and not having
  any permanence on the system.

  Additionally, user profiles that have been moved outside of the Users folder will also likely not be supported, due to an infinite
  number of possiblities of where the user's folder could be stored, but also is generally not supported by Windows anyways.

  The Windows Subsystems for Linux and Android will both not be supported, as those features are turned off by default, and users
  can't turn them on without admin access to begin with.

  Headless cloud browsers (e.g. Puffin Secure Browser) will never be supported, as their data is completely hosted else where, without
  any direct access to user data (a.k.a. can't ever get extension data).

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
    - Root of the data (ordered list of users)
      |=> Username
          |-> User's full name
          |-> Browsers (ordered list of browsers used by the user)
              |=> Browser (by name)
                  |-> Company (by name, but empty if a company name couldn't be found)
                  |-> Engine (by name, the browser engine used for the browser)
                  |-> Profiles (ordered list of profiles in the browser, since there may be more than one profile used)
                      |=> Profile (by name, or folder name if name couldn't be determined)
                          |-> Path (path to the folder the profile is in)
                          |-> Account (the main account logged into the profile, if any)
                              |=> Email       (if there is a logged in account, data here won't be empty)
                              |=> DisplayName (if there is a logged in account, data here won't be empty)
                          |-> Extensions (array of extensions)
                              |=> Extension
                                  |-> (original extension data here will differ based on type of browser and may change over time)
   - 2 CSV files - Both files will contain more basic info of the extensions collected, like so:
    - Simplified:
     > Username,ExtensionUnpacked,ExtensionID,ExtensionVersion,BrowserEngine,BrowserCompany,BrowserName
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

<# Copyright (C) 2024  Andrew Larson (andrew.j.larson18+github@gmail.com)

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
  [ValidateScript({Test-Path -Path $_})]
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

Set-Variable -Name USERS_FOLDER -Option Constant -Value "${env:SystemDrive}\Users" -ErrorAction SilentlyContinue

Set-Variable -Name USERNAME_REGEX_GROUP -Option Constant -Value "USERNAME" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_REGEX_GROUP -Option Constant -Value "BROWSER" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_UWP_REGEX_GROUP -Option Constant -Value "BROWSER_UWP" -ErrorAction SilentlyContinue
Set-Variable -Name PROFILE_REGEX_GROUP -Option Constant -Value "PROFILE" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_REGEX_PRE_PATHING -Option Constant -Value "$(($USERS_FOLDER.replace('\','\\')).replace(':','\:'))\\(?<${USERNAME_REGEX_GROUP}>[^\\]+)\\AppData\\(Local(\\Packages\\(?<${BROWSER_UWP_REGEX_GROUP}>[^\\]+)\\LocalCache\\(Local|Roaming))?|Roaming)" -ErrorAction SilentlyContinue
Set-Variable -Name BROWSER_REGEX_FULL_PATHING -Option Constant -Value "${BROWSER_REGEX_PRE_PATHING}\\(?<${BROWSER_REGEX_GROUP}>([^\\]+\\)?[^\\]+)" -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_BROWSER_PREFERENCES_REGEX -Option Constant -Value "${BROWSER_REGEX_FULL_PATHING}(\\User Data)?\\(?!Opera GX)(?<${PROFILE_REGEX_GROUP}>[^\\]+)\\(Secure )?Preferences" -ErrorAction SilentlyContinue
Set-Variable -Name BLINK_OPERA_GX_MAIN_PREFERENCES_REGEX -Option Constant -Value "${BROWSER_REGEX_PRE_PATHING}\\(?<${BROWSER_REGEX_GROUP}>[^\\]+\\(?<$PROFILE_REGEX_GROUP>[^\\]+))\\(Secure )?Preferences" -ErrorAction SilentlyContinue
Set-Variable -Name BLINK_OPERA_GX_SIDE_PREFERENCES_REGEX -Option Constant -Value "${BROWSER_REGEX_PRE_PATHING}\\(?<${BROWSER_REGEX_GROUP}>[^\\]+\\[^\\]+)\\_side_profiles\\(?<$PROFILE_REGEX_GROUP>[^\\]+)\\(Secure )?Preferences" -ErrorAction SilentlyContinue

Set-Variable -Name GECKO_BROWSER_EXTENSIONS_REGEX -Option Constant -Value "${BROWSER_REGEX_FULL_PATHING}\\Profiles\\(?<${PROFILE_REGEX_GROUP}>[^\\]+)\\extensions\.json" -ErrorAction SilentlyContinue

Set-Variable -Name GECKO_THUNDERBIRD_ADDON_ID_REGEX_GROUP -Option Constant -Value "ADDON_ID" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_THUNDERBIRD_ADDON_XPI_URL_REGEX -Option Constant -Value "https?\:\/\/addons\.thunderbird\.net\/thunderbird\/downloads\/latest\/[^\/]+\/addon\-(?<${GECKO_THUNDERBIRD_ADDON_ID_REGEX_GROUP}>[0-9]+)\-latest\.xpi.*" -ErrorAction SilentlyContinue

# these constants are values pulled from the source code of each browser engine
Set-Variable -Name BLINK_BROWSER_LOCATION_UNPACKED -Option Constant -Value 4 -ErrorAction SilentlyContinue # special value is given to loaded unpacked extensions
Set-Variable -Name BLINK_BROWSER_LOCATION_COMMAND_LINE -Option Constant -Value 8 -ErrorAction SilentlyContinue # another way unpacked extensions are loaded in
Set-Variable -Name BLINK_BROWSER_LOCATION_COMPONENT -Option Constant -Value 5 -ErrorAction SilentlyContinue
Set-Variable -Name BLINK_BROWSER_LOCATION_EXTERNAL_COMPONENT -Option Constant -Value 10 -ErrorAction SilentlyContinue # these are system extensions that can be disabled by user
Set-Variable -Name GECKO_BROWSER_SOURCE_TEMPORARY_ADDON -Option Constant -Value "temporary-addon" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_SOURCE_FILE_URL -Option Constant -Value "file-url" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_SOURCE_ABOUT_ADDONS -Option Constant -Value "about:addons" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_LOCATION_APP_SYSTEM_DEFAULTS -Option Constant -Value "app-system-defaults" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_LOCATION_APP_BUILTINS -Option Constant -Value "app-builtin" -ErrorAction SilentlyContinue # these are system addons that can be disabled by user

Set-Variable -Name BLINK_BROWSER_CHECK_UNPACKED -Option Constant -Value @($BLINK_BROWSER_LOCATION_UNPACKED, $BLINK_BROWSER_LOCATION_COMMAND_LINE) -ErrorAction SilentlyContinue
Set-Variable -Name BLINK_BROWSER_CHECK_BUILTIN -Option Constant -Value @($BLINK_BROWSER_LOCATION_COMPONENT, $BLINK_BROWSER_LOCATION_EXTERNAL_COMPONENT) -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_CHECK_UNPACKED -Option Constant -Value @($GECKO_BROWSER_SOURCE_TEMPORARY_ADDON, $GECKO_BROWSER_SOURCE_FILE_URL, $GECKO_BROWSER_SOURCE_ABOUT_ADDONS) -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_CHECK_BUILTIN -Option Constant -Value @($GECKO_BROWSER_LOCATION_APP_BUILTINS, $GECKO_BROWSER_LOCATION_APP_SYSTEM_DEFAULTS) -ErrorAction SilentlyContinue

Set-Variable -Name BLINK_BROWSER_ENGINE -Option Constant -Value "Blink" -ErrorAction SilentlyContinue
Set-Variable -Name GECKO_BROWSER_ENGINE -Option Constant -Value "Gecko" -ErrorAction SilentlyContinue

# Variables

# largely unaltered data grabbed from extensions
# (removals of redundant locales/languages)
$OriginalExtensionDataJSON = @{
  Users = @{}
}

# simplify data from extensions, contains headers already
[array]$SimplifiedExtensionDataCSV = ConvertFrom-Csv @'
Username,ExtensionUnpacked,ExtensionID,ExtensionVersion,BrowserEngine,BrowserCompany,BrowserName
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

# MAIN

Write-Host "Please wait, this may take a while..."

# use regex to simplify all searching needs, match all extension based json files for the different browser types (based on engine)
$AllBlinkBasedBrowserPreferencesMatches = @(Get-ChildItem -LiteralPath $USERS_FOLDER -Filter "*Preferences" -Recurse -File -Force -ErrorAction SilentlyContinue |
                                            Where-Object { $_.FullName -cmatch $BLINK_BROWSER_PREFERENCES_REGEX } |
                                            ForEach-Object { [regex]::Matches($_.FullName, $BLINK_BROWSER_PREFERENCES_REGEX) }) +
                                          @(Get-ChildItem -LiteralPath $USERS_FOLDER -Filter "*Preferences" -Recurse -File -Force -ErrorAction SilentlyContinue |
                                            Where-Object { $_.FullName -cmatch $BLINK_OPERA_GX_MAIN_PREFERENCES_REGEX } |
                                            ForEach-Object { [regex]::Matches($_.FullName, $BLINK_OPERA_GX_MAIN_PREFERENCES_REGEX) }) +
                                          @(Get-ChildItem -LiteralPath $USERS_FOLDER -Filter "*Preferences" -Recurse -File -Force -ErrorAction SilentlyContinue |
                                            Where-Object { $_.FullName -cmatch $BLINK_OPERA_GX_SIDE_PREFERENCES_REGEX } |
                                            ForEach-Object { [regex]::Matches($_.FullName, $BLINK_OPERA_GX_SIDE_PREFERENCES_REGEX) })
$AllGeckoBasedBrowserExtensionsMatches = @(Get-ChildItem -LiteralPath $USERS_FOLDER -Filter "extensions.json" -Recurse -File -Force -ErrorAction SilentlyContinue |
                                           Where-Object { $_.FullName -cmatch $GECKO_BROWSER_EXTENSIONS_REGEX } |
                                           ForEach-Object { [regex]::Matches($_.FullName, $GECKO_BROWSER_EXTENSIONS_REGEX) })

# with Blink based browsers, extension information is either stored in the "Preferences" or "Secure Preferences" file
$AllBlinkBasedBrowserExtensionsMatches = @()
if ($AllBlinkBasedBrowserPreferencesMatches.length -gt 0) {
  for ($i = 0; $i -lt $AllBlinkBasedBrowserPreferencesMatches.length; $i++) {
    $preferenceMatch = $AllBlinkBasedBrowserPreferencesMatches[$i]
    $jsonPath = $preferenceMatch.Value
    $jsonData = Get-Content $jsonPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json

    # include only each file where extensions.settings exists with items
    if ($jsonData.extensions) {
      # some browsers like to rename the settings property
      $extensionsSettingsCheck = $jsonData.extensions.PSObject.Properties | Where-Object { $_.Name -like "*settings" }
      if ($extensionsSettingsCheck -And $extensionsSettingsCheck.Value -And (@($extensionsSettingsCheck.Value.PSObject.Properties).Count -gt 0)) {
        $AllBlinkBasedBrowserExtensionsMatches += $preferenceMatch
      }
    }
  }
}

# include browser engine info
$AllBlinkBasedBrowserPreferencesMatches | ForEach-Object { $_ | Add-Member -Name Engine -Value $BLINK_BROWSER_ENGINE -MemberType NoteProperty }
$AllGeckoBasedBrowserExtensionsMatches | ForEach-Object { $_ | Add-Member -Name Engine -Value $GECKO_BROWSER_ENGINE -MemberType NoteProperty }

# parse all extension data
$AllBrowserExtensionBasedJsonFileMatches = $AllBlinkBasedBrowserExtensionsMatches + $AllGeckoBasedBrowserExtensionsMatches
for ($i = 0; $i -lt $AllBrowserExtensionBasedJsonFileMatches.length; $i++) {
  $browserJsonMatch = $AllBrowserExtensionBasedJsonFileMatches[$i]
  $jsonPath = $browserJsonMatch.Value
  $jsonData = Get-Content $jsonPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json

  # User
  $username = $browserJsonMatch.Groups[$USERNAME_REGEX_GROUP].Value
  if (-Not $OriginalExtensionDataJSON.Users[$username]) {
    # create user property with FullName string and Browsers object
    $OriginalExtensionDataJSON.Users[$username] = [ordered]@{
      FullName = Get-CimInstance -ClassName Win32_UserAccount -Filter "Name = '${username}'" -Property FullName | Select-Object -Expand FullName
      Browsers = [ordered]@{}
    }
  }
  $User = $OriginalExtensionDataJSON.Users[$username]

  # Browser
  $browser = $Null
  if ($browserJsonMatch.Groups[$BROWSER_UWP_REGEX_GROUP].length -gt 0) {
    # UWP browsers have company name listed elsewhere
    $browser = ($browserJsonMatch.Groups[$BROWSER_UWP_REGEX_GROUP].Value).split('_')[0]
    $browser = $browser.split('.')
    for ($j = 0; $j -lt $browser.length; $j++) {
      $browser[$j] = $browser[$j] -csplit '(?=[A-Z])' -ne '' -join ' '
    }
  } else {
    $browser = ($browserJsonMatch.Groups[$BROWSER_REGEX_GROUP].Value).split('\')
  }
  $browserName = $browser[$browser.length -gt 1]
  $browserCompany = if ($browser[0] -ne $browserName) { $browser[0] } else { $Null } # browser name can't be company name too
  $browserEngine = $browserJsonMatch.Engine
  $browser = $browser -Join ' '
  if (-Not $User.Browsers[$browserName]) {
    # create browser property with Company string and Profiles array
    $User.Browsers[$browserName] = [ordered]@{
      Company = $browserCompany
      Engine = $browserEngine
      Profiles = [ordered]@{}
    }
  }
  $UserBrowser = $User.Browsers[$browserName]
  $isBlinkEngine = $browserEngine -eq $BLINK_BROWSER_ENGINE # ; $isGeckoEngine = $browserEngine -eq $GECKO_BROWSER_ENGINE

  # BrowserProfile
  $profileFolderName = $browserJsonMatch.Groups[$PROFILE_REGEX_GROUP].Value
  $profileName = $profileFolderName
  $profilePath = Split-Path -Parent $jsonPath
  $profileAccount = [ordered]@{
    Email = $Null
    DisplayName = $Null
  }
  if (-Not $UserBrowser.Profiles[$profileName]) {
    # profile name and account details is a bit tricker to get
    if ($isBlinkEngine) {
      # profile name/account details is only stored in the Preferences file
      $profileJsonData = $jsonData
      if ($jsonPath.EndsWith('Secure Preferences')) {
        $profileJsonPath = $profilePath + '\Preferences'
        $profileJsonData = if (Test-Path -Path $profileJsonPath -PathType leaf) {
          Get-Content $profileJsonPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
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
    } else {
      # profile name is pulled from the folder name
      $indexFirstPeriod = $profileFolderName.IndexOf('.')
      if ($indexFirstPeriod -gt -1) {
        $testProfileName = $profileFolderName.substring($indexFirstPeriod + 1)
        if ($testProfileName) { $profileName = $testProfileName }
      }
      # account data is pulled from a different file
      $profileJsonPath = $profilePath + '\signedInUser.json'
      $profileJsonData = if (Test-Path -Path $profileJsonPath -PathType leaf) {
        Get-Content $profileJsonPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
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
    $UserBrowser.Profiles[$profileName] = [ordered]@{
      Path = $profilePath # will be the profile folder name if profile name wasn't obtainable
      Account = $profileAccount # may or may not include online account info if user is logged into browser profile
      Extensions = @()
    }
  }
  $UserBrowserProfile = $UserBrowser.Profiles[$profileName]

  # get extension list based on browser engine
  $extensionsList = $Null
  if ($isBlinkEngine) {
    $extensionsSettings = ($jsonData.extensions.PSObject.Properties | # some browsers like to rename the settings property
                           Where-Object { $_.Name -like "*settings" }).Value.PSObject.Properties
    $extensionsList = $extensionsSettings
  } else { 
    $addons = $jsonData.addons
    $extensionsList = $addons
  }

  # iterate over extension lists to determine installed extensions
  $extensionsList | ForEach-Object {
    $extensionID = $Null ; $extensionVersion = $Null ; $extensionVendor = $Null
    $extensionName = $Null ; $extensionDescription = $Null ; $extensionURLs = $Null
    $extensionUnpacked = $False

    # only continue parsing/adding extension data if:
    # - the data is actually an extension
    # - and the extension isn't built into the browser
    if ($isBlinkEngine) {
      $extension = $_.Value

      # Unpacked extension detection
      $extensionUnpacked = $BLINK_BROWSER_CHECK_UNPACKED -contains $extension.location
      # Sometimes manifest data needs to be loaded in manually (usually the case for unpacked extensions)
      $checkExtensionManifestPath = "$($extension.Path)\manifest.json"
      if ((-Not $extension.manifest) -And (Test-Path -Path $checkExtensionManifestPath -PathType Leaf)) {
        $extensionManifestData = Get-Content $extensionManifestPath -Raw -Encoding UTF8 | Fix-JsonContent | ConvertFrom-Json
        $extension | Add-Member -Name "manifest" -Value $extensionManifestData -MemberType NoteProperty
      }
      # Opera browsers may have one or more special builtin app(s) that they don't have properly using location properties
      $specialOperaBuiltinCheck = ($extension.manifest.author -eq "Opera Norway AS") -And
                                  ($extension.manifest.update_url) -And
                                  (([System.Uri]$extension.manifest.update_url).Host.EndsWith('operacdn.com'))

      if ($extension.manifest -And (-Not $extension.manifest.theme) -And
          ($BLINK_BROWSER_CHECK_BUILTIN -notcontains $extension.location) -And (-Not $specialOperaBuiltinCheck)) {
        # remove the `default_locale` property as it's unnecessary extra data
        $extension.manifest.PSObject.Properties.Remove('default_locale')

        # grab simplified data
        $extensionID = if ($extension.id) { $extension.id } else { $_.Name }
        $extensionVersion = $extension.manifest.version
        $extensionVendor = $extension.manifest.author
        $extensionName = $extension.manifest.name
        $extensionDescription = $extension.manifest.description

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
        $UserBrowserProfile.Extensions += @($extension)
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

        # get all possible URLs
        $extensionUpdateURL = $addon.updateURL
        $extensionHomepageURL = $addon.defaultLocale.homepageURL
        $extensionSourceURI = $addon.sourceURI
        $extensionSourceURL = if ($addon.installTelemetryInfo -And $addon.installTelemetryInfo.sourceURL) {
                                $addon.installTelemetryInfo.sourceURL # only modern Gecko versions (w/ install telemetry)
                              }
        $extensionOnlineURL = if ($extensionUpdateURL) { $extensionUpdateURL } elseif ($extensionSourceURI) {
                                $extensionSourceURI
                              } else { $extensionSourceURL }
        $extensionURLs = @()
        if ($extensionOnlineURL) {
          $urlEncodedExtensionID = [Uri]::EscapeDataString($extensionID.trimstart('@')) # beginning @'s are removed in webstore URLs
          $extensionSourceUriURI = [System.Uri]$extensionSourceURI
          $extensionUpdateHost = $extensionSourceUriURI.Host
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
        if ($extensionSourceURL) { $extensionURLs += @($extensionSourceURL) }
        # only need to add update URL for unknown webstores
        if (($extensionURLs.length -eq 0) -And $extensionUpdateURL) { $extensionURLs += @($extensionUpdateURL) }
        # if we still have no URLs, use source URI as a last resort
        if (($extensionURLs.length -eq 0) -And $extensionSourceURI) { $extensionURLs += @($extensionSourceURI) }
        # deduplicate URLs
        $extensionURLs = $extensionURLs | Select-Object -Unique
        # convert to string
        $extensionURLs = "[$(@($extensionURLs | ForEach-Object { " $_ " }) -join ',')]"

        # add extension to the array
        $UserBrowserProfile.Extensions += @($addon)
      }
    }

    # if valid extension, add data to the other arrays
    if ($extensionID) {
      $SimplifiedExtensionDataCSV += [PSCustomObject]@{
        Username = $username
        ExtensionUnpacked = $extensionUnpacked
        ExtensionID = $extensionID
        ExtensionVersion = $extensionVersion
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
[array]$OriginalExtensionDataJSON.Users.Keys | ForEach-Object {
  $currentUser = $OriginalExtensionDataJSON.Users[$_]
  [array]$currentUser.Browsers.Keys | ForEach-Object {
    $currentUserBrowser = $currentUser.Browsers[$_]
    [array]$currentUserBrowser.Profiles.Keys | ForEach-Object {
      $currentUserBrowserProfile = $currentUserBrowser.Profiles[$_]

      # if we have no extensions in array, delete profile
      if (-Not $currentUserBrowserProfile.Extensions) {
        $currentUserBrowser.Profiles.Remove($_)
      }
    }
    # if we have no profiles in dictionary, delete browser
    if (-Not $currentUserBrowser.Profiles.Count) {
      $currentUser.Browsers.Remove($_)
    }
  }
  # if we have no browsers in dictionary, delete user
  if (-Not $currentUser.Browsers.Count) {
    $OriginalExtensionDataJSON.Users.Remove($_)
  }
}

# get unique values for the CSVs, while sorting at the same time
$SimplifiedExtensionDataCSV = $SimplifiedExtensionDataCSV | Sort-Object Username,BrowserEngine,BrowserCompany,BrowserName,ExtensionUnpacked,ExtensionID,ExtensionVersion -Unique
$ExtensionsOnlyCSV = $ExtensionsOnlyCSV | Sort-Object BrowserEngine,ExtensionURLs,ExtensionUnpacked,ExtensionVendor,ExtensionName,ExtensionID,ExtensionDescription -Unique

# export finialized data
$OriginalExtensionDataJSON | ConvertTo-Json -Compress -Depth 100 | Out-File "${Path}\${FILENAME_PRE}_original_${FILENAME_POST}.json" -Encoding utf8
$SimplifiedExtensionDataCSV | Export-Csv -NoTypeInformation "${Path}\${FILENAME_PRE}_simplified_${FILENAME_POST}.csv" -Encoding utf8
$ExtensionsOnlyCSV | Export-Csv -NoTypeInformation "${Path}\${FILENAME_PRE}_only_${FILENAME_POST}.csv" -Encoding utf8
Write-Output "Data exported to folder: `"${Path}\`""
