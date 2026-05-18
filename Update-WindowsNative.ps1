<#
.SYNOPSIS
    Manages Windows Updates using the Windows Update Agent (WUA) API.

.DESCRIPTION
    This script provides a native PowerShell way to search for, list, and install Windows Updates by interacting directly with the Microsoft.Update.Session COM objects. It handles initiating scans, downloading updates, accepting EULAs, and installing them.

.PARAMETER Action
    Specifies the action to perform. Valid options are:
    - Search: Initiates a new background update detection scan.
    - List: Lists available updates based on the provided Criteria.
    - Install: Searches for, downloads, and installs available updates.

.PARAMETER Criteria
    The raw search criteria string used to filter updates. The default is 'IsInstalled=0 AND IsHidden=0'.

.PARAMETER IsInstalled
    Filters to return only installed updates. If omitted, returns uninstalled updates.

.PARAMETER IsHidden
    Filters to return only hidden updates. If omitted, returns non-hidden updates.

.PARAMETER Categories
    Filters updates by specified category names (e.g., 'Security Updates'). Supports tab completion.

.PARAMETER IsAssigned
    Filters updates to include only those assigned for deployment.

.PARAMETER UpdateId
    Filters updates by their specific unique GUIDs.

.EXAMPLE
    .\Update-WindowsNative.ps1 -Action List
    Lists all available updates that are not installed and not hidden.

.EXAMPLE
    .\Update-WindowsNative.ps1 -Action Install
    Installs all available updates that are not installed and not hidden.

.NOTES
    Author: Chris Stone
    Version: 2.0.7
#>
[CmdletBinding(DefaultParameterSetName = 'CustomCriteria')]
param (
	[Parameter(Mandatory = $false)]
	[ValidateSet('Search', 'List', 'Install')]
	[string] $Action = 'Install',

	[Parameter(ParameterSetName = 'CustomCriteria', Mandatory = $false)]
	[string] $Criteria = 'IsInstalled=0 AND IsHidden=0',

	[Parameter(ParameterSetName = 'BuiltCriteria')]
	[switch] $IsInstalled,

	[Parameter(ParameterSetName = 'BuiltCriteria')]
	[switch] $IsHidden,

	[Parameter(ParameterSetName = 'BuiltCriteria')]
	[ValidateSet(
		'Application',
		'Connectors',
		'Critical Updates',
		'Definition Updates',
		'Developer Kits',
		'Drivers',
		'Feature Packs',
		'Guidance',
		'Security Updates',
		'Service Packs',
		'Tools',
		'Update Rollups',
		'Updates',
		'Upgrades'
	)]
	[string[]] $Categories,

	[Parameter(ParameterSetName = 'BuiltCriteria')]
	[switch] $IsAssigned,

	[Parameter(ParameterSetName = 'BuiltCriteria')]
	[string[]] $UpdateId
)

#region Helper Functions

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,
		[ValidateSet('TRACE', 'INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO',
		[hashtable]$ColorMap = @{
			TRACE = 'DarkGray'
			INFO  = 'Green'
			WARN  = 'Yellow'
			ERROR = 'Red'
		}
	)
	$FormattedMessage = "$(Get-Date -Format 's') [$Level] $Message"
	if ([Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
		Write-Output $FormattedMessage
	} else {
		Write-Host $FormattedMessage -ForegroundColor $ColorMap[$Level]
	}
}

function Get-WuaErrorMessage {
	param(
		[Parameter(Mandatory = $true)]
		[Exception]$Exception
	)

	$WuaMapping = @{
		'0x80240001' = 'WU_E_NO_SERVICE'
		'0x80240002' = 'WU_E_MAX_CAPACITY_REACHED'
		'0x80240003' = 'WU_E_UNKNOWN_ID'
		'0x80240004' = 'WU_E_NOT_INITIALIZED'
		'0x80240005' = 'WU_E_RANGEOVERLAP'
		'0x80240006' = 'WU_E_TOOMANYRANGES'
		'0x80240007' = 'WU_E_INVALIDINDEX'
		'0x80240008' = 'WU_E_ITEMNOTFOUND'
		'0x80240009' = 'WU_E_OPERATIONINPROGRESS'
		'0x8024000A' = 'WU_E_COULDNOTCANCEL'
		'0x8024000B' = 'WU_E_CALL_CANCELLED'
		'0x8024000C' = 'WU_E_NOOP'
		'0x8024000D' = 'WU_E_XML_MISSINGDATA'
		'0x8024000E' = 'WU_E_XML_INVALID'
		'0x8024000F' = 'WU_E_CYCLE_DETECTED'
		'0x80240010' = 'WU_E_TOO_DEEP_RELATION'
		'0x80240011' = 'WU_E_INVALID_RELATIONSHIP'
		'0x80240012' = 'WU_E_REG_VALUE_INVALID'
		'0x80240013' = 'WU_E_DUPLICATE_ITEM'
		'0x80240014' = 'WU_E_INVALID_INSTALL_REQUESTED'
		'0x80240016' = 'WU_E_INSTALL_NOT_ALLOWED'
		'0x80240017' = 'WU_E_NOT_APPLICABLE'
		'0x80240018' = 'WU_E_NO_USERTOKEN'
		'0x80240019' = 'WU_E_EXCLUSIVE_INSTALL_CONFLICT'
		'0x8024001A' = 'WU_E_POLICY_NOT_SET'
		'0x8024001B' = 'WU_E_SELFUPDATE_IN_PROGRESS'
		'0x8024001D' = 'WU_E_INVALID_UPDATE'
		'0x8024001E' = 'WU_E_SERVICE_STOP'
		'0x8024001F' = 'WU_E_NO_CONNECTION'
		'0x80240020' = 'WU_E_NO_INTERACTIVE_USER'
		'0x80240021' = 'WU_E_TIME_OUT'
		'0x80240022' = 'WU_E_ALL_UPDATES_FAILED'
		'0x80240023' = 'WU_E_EULAS_DECLINED'
		'0x80240024' = 'WU_E_NO_UPDATE'
		'0x80240025' = 'WU_E_USER_ACCESS_DISABLED'
		'0x80240026' = 'WU_E_INVALID_UPDATE_TYPE'
		'0x80240027' = 'WU_E_URL_TOO_LONG'
		'0x80240028' = 'WU_E_UNINSTALL_NOT_ALLOWED'
		'0x80240029' = 'WU_E_INVALID_PRODUCT_LICENSE'
		'0x8024002A' = 'WU_E_MISSING_HANDLER'
		'0x8024002B' = 'WU_E_LEGACYSERVER'
		'0x8024002C' = 'WU_E_BIN_SOURCE_ABSENT'
		'0x8024002D' = 'WU_E_SOURCE_ABSENT'
		'0x8024002E' = 'WU_E_WU_DISABLED'
		'0x8024002F' = 'WU_E_NETWORK_COST_EXCEEDS_POLICY'
		'0x80240030' = 'WU_E_ENDPOINT_DISCONNECTED'
		'0x80240031' = 'WU_E_INVALID_FORMAT'
		'0x80240032' = 'WU_E_INVALID_CRITERIA'
		'0x80240033' = 'WU_E_EULA_UNAVAILABLE'
		'0x80240034' = 'WU_E_DOWNLOAD_FAILED'
		'0x80240035' = 'WU_E_UPDATE_NOT_PROCESSED'
		'0x80240036' = 'WU_E_INVALID_OPERATION'
		'0x80240037' = 'WU_E_NOT_SUPPORTED'
		'0x80240038' = 'WU_E_WINHTTP_INVALID_FILE'
		'0x80240039' = 'WU_E_TOO_MANY_RESYNC'
		'0x80240040' = 'WU_E_NO_SERVER_CORE_SUPPORT'
		'0x80240041' = 'WU_E_SYSPREP_IN_PROGRESS'
		'0x80240042' = 'WU_E_UNKNOWN_SERVICE'
		'0x80244017' = 'WU_E_PT_HTTP_STATUS_DENIED'
		'0x80244018' = 'WU_E_PT_HTTP_STATUS_FORBIDDEN'
		'0x80244019' = 'WU_E_PT_HTTP_STATUS_NOT_FOUND'
		'0x8024402B' = 'WU_E_PT_HTTP_STATUS_NOT_MAPPED'
		'0x8024402C' = 'WU_E_PT_WINHTTP_NAME_NOT_RESOLVED'
		'0x8024402F' = 'WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS'
		'0x8024500B' = 'WU_E_REDIRECTOR_ID_SMALLER'
		'0x80246008' = 'WU_E_DM_FAILTOCONNECTTOBITS'
		'0x80072EE2' = 'ERROR_INTERNET_TIMEOUT'
		'0x80070005' = 'E_ACCESSDENIED'
		'0x80072EFD' = 'ERROR_INTERNET_CANNOT_CONNECT'
	}

	$HResult = $null
	if ($Exception.InnerException -and $Exception.InnerException.HResult -ne 0) {
		$HResult = $Exception.InnerException.HResult
	} elseif ($Exception.HResult -ne 0) {
		$HResult = $Exception.HResult
	}

	if ($null -ne $HResult) {
		$HResultHex = '0x{0:X8}' -f [int]$HResult
		$MappedMessage = $WuaMapping[$HResultHex]

		if ($MappedMessage) {
			return "{0} ({1}) - {2}" -f $MappedMessage, $HResultHex, $Exception.Message
		} else {
			return "Code {0} - {1}" -f $HResultHex, $Exception.Message
		}
	}

	return $Exception.Message
}

function Invoke-UpdateDetection {
	Write-Log -Message 'Initiating new update search (DetectNow)...' -Level 'INFO'
	try {
		$AutoUpdate = New-Object -ComObject 'Microsoft.Update.AutoUpdate' -ErrorAction Stop
		$AutoUpdate.DetectNow()
		Write-Log -Message 'Update search initiated successfully.' -Level 'INFO'
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to initiate update search. Error: $ErrorMessage") -Level 'ERROR'
	}
}

function Find-AvailableUpdate {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Criteria
	)
	try {
		Write-Log -Message 'Searching for available updates...' -Level 'TRACE'
		$MSUpdateSearcher = New-Object -ComObject 'Microsoft.Update.Searcher' -ErrorAction Stop
		$MSUpdateSearcher.Online = $true
		return , $MSUpdateSearcher.Search($Criteria).Updates
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to search for updates. Error: $ErrorMessage") -Level 'ERROR'
		return $null
	}
}

function New-UpdateCollection {
	param (
		[Parameter(Mandatory = $true)]
		$Updates
	)
	try {
		$MSUpdateCollection = New-Object -ComObject 'Microsoft.Update.UpdateColl' -ErrorAction Stop
		foreach ($Update in $Updates) {
			$MSUpdateCollection.Add($Update) | Out-Null
		}
		return , $MSUpdateCollection
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to create update collection. Error: $ErrorMessage") -Level 'ERROR'
		return $null
	}
}

function Accept-UpdateEula {
	param (
		[Parameter(Mandatory = $true)]
		$UpdateCollection
	)
	try {
		Write-Log -Message 'Accepting EULAs, if necessary...' -Level 'TRACE'
		foreach ($Update in $UpdateCollection) {
			if (-not $Update.EulaAccepted) {
				$Update.AcceptEula()
			}
		}
		return $true
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to accept EULA for an update. Error: $ErrorMessage") -Level 'ERROR'
		return $false
	}
}

function Receive-UpdateDownload {
	param (
		[Parameter(Mandatory = $true)]
		$UpdateCollection
	)
	try {
		Write-Log -Message 'Downloading selected updates...' -Level 'INFO'
		$MSUpdateSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
		$MSUpdateDownloader = $MSUpdateSession.CreateUpdateDownloader()
		$MSUpdateDownloader.Updates = $UpdateCollection
		$DownloadResult = $MSUpdateDownloader.Download()
		Write-Log -Message ('Download result code: {0}' -f $DownloadResult.ResultCode) -Level 'TRACE'
		return $DownloadResult
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to download updates. Error: $ErrorMessage") -Level 'ERROR'
		return $null
	}
}

function Install-UpdateCollection {
	param (
		[Parameter(Mandatory = $true)]
		$UpdateCollection
	)
	try {
		Write-Log -Message 'Installing downloaded updates...' -Level 'INFO'
		$MSUpdateInstaller = New-Object -ComObject 'Microsoft.Update.Installer' -ErrorAction Stop
		$MSUpdateInstaller.Updates = $UpdateCollection
		return $MSUpdateInstaller.Install()
	} catch {
		$ErrorMessage = Get-WuaErrorMessage -Exception $_.Exception
		Write-Log -Message ("Failed to install updates. Error: $ErrorMessage") -Level 'ERROR'
		return $null
	}
}

#endregion
##################################### MAIN SCRIPT ##############################

Write-Log -Message ('Script Started ').PadRight(80, '-') -Level 'INFO'
$RebootRequired = $false

# Check for Administrative Rights
if (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Log -Message 'Script must be run as Administrator' -Level 'ERROR'
	return
}

# Check for PowerShell Version 3.0+
if ($PSVersionTable.PSVersion.Major -lt 3) {
	Write-Log -Message 'Script requires PowerShell v3.0 or Higher' -Level 'ERROR'
	return
}

if ($PSCmdlet.ParameterSetName -eq 'BuiltCriteria') {
	$BaseCriteriaList = @()
	$BaseCriteriaList += "IsInstalled=$([int]$IsInstalled.IsPresent)"
	$BaseCriteriaList += "IsHidden=$([int]$IsHidden.IsPresent)"

	if ($PSBoundParameters.ContainsKey('IsAssigned')) {
		$BaseCriteriaList += "IsAssigned=$([int]$IsAssigned.IsPresent)"
	}

	$BaseCriteriaString = $BaseCriteriaList -join ' AND '

	$CategoryCriteria = @()
	if ($Categories) {
		$CategoryMap = @{
			'Application'        = '5c9376ab-8ce6-464a-b136-22113dd69801'
			'Connectors'         = '434de588-ed14-48f5-8eec-b151cb56120b'
			'Critical Updates'   = 'e6cf1350-c01b-414d-a61f-263d14d133b4'
			'Definition Updates' = 'e0789628-ce08-4437-be74-2495b842f43b'
			'Developer Kits'     = 'e140075d-8433-45c3-ad87-e72345b36078'
			'Drivers'            = 'ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0'
			'Feature Packs'      = 'b54e7d24-7114-41d5-a92c-613a53ca9e66'
			'Guidance'           = '9511d615-35b2-47bb-927f-f73d8e9260bb'
			'Security Updates'   = '0fa1201d-4330-4fa8-8ae9-ce148a2136e0'
			'Service Packs'      = '68c5b0a3-d1a6-4553-ae49-01d3a7827828'
			'Tools'              = 'b4832bd8-e735-4761-8daf-37f882276ce3'
			'Update Rollups'     = '28bc880e-0592-4cbf-8f95-c79b17911d5f'
			'Updates'            = 'cd5ffd1e-e932-4e3a-bf74-18bf0b1bbd83'
			'Upgrades'           = '3689bdc8-b205-4af4-8d4a-a63924c5e9d5'
		}

		foreach ($Category in $Categories) {
			$MappedId = $CategoryMap[$Category]
			if ($null -ne $MappedId) {
				$CategoryCriteria += "CategoryIDs contains '$MappedId'"
			} else {
				Write-Log -Message "Unknown Category: $Category" -Level 'WARN'
			}
		}
	}

	$UpdateIdCriteria = @()
	if ($UpdateId) {
		foreach ($Id in $UpdateId) {
			$UpdateIdCriteria += "UpdateID='$Id'"
		}
	}

	$OrGroups = @()
	if ($CategoryCriteria.Count -gt 0 -and $UpdateIdCriteria.Count -gt 0) {
		foreach ($Cat in $CategoryCriteria) {
			foreach ($Id in $UpdateIdCriteria) {
				$OrGroups += '{0} AND {1} AND {2}' -f $BaseCriteriaString, $Cat, $Id
			}
		}
	} elseif ($CategoryCriteria.Count -gt 0) {
		foreach ($Cat in $CategoryCriteria) {
			$OrGroups += '{0} AND {1}' -f $BaseCriteriaString, $Cat
		}
	} elseif ($UpdateIdCriteria.Count -gt 0) {
		foreach ($Id in $UpdateIdCriteria) {
			$OrGroups += '{0} AND {1}' -f $BaseCriteriaString, $Id
		}
	} else {
		$OrGroups += $BaseCriteriaString
	}

	if ($OrGroups.Count -gt 1) {
		$Criteria = '({0})' -f ($OrGroups -join ') OR (')
	} else {
		$Criteria = $OrGroups[0]
	}

	Write-Log -Message "Built Search Criteria: $Criteria" -Level 'TRACE'
} else {
	Write-Log -Message "Using Parameter Criteria: $Criteria" -Level 'TRACE'
}

switch ($Action) {
	'Search' {
		Invoke-UpdateDetection
	}

	'List' {
		Write-Log -Message 'Listing available updates...' -Level 'INFO'
		$Updates = Find-AvailableUpdate -Criteria $Criteria

		if ($null -eq $Updates) { return }

		if ($Updates.Count -eq 0) {
			Write-Log -Message 'No available updates found.' -Level 'INFO'
		} else {
			Write-Log -Message ('Found {0} available updates:' -f $Updates.Count) -Level 'INFO'
			foreach ($Update in $Updates) {
				Write-Log -Message ('  - {0}' -f $Update.Title) -Level 'TRACE'
			}
		}
	}

	'Install' {
		Write-Log -Message 'Starting update search and installation...' -Level 'INFO'

		# 1. Search for Updates
		$Updates = Find-AvailableUpdate -Criteria $Criteria
		if ($null -eq $Updates) { return }

		if ($Updates.Count -eq 0) {
			Write-Log -Message 'System is already up-to-date.' -Level 'INFO'
			return
		}

		Write-Log -Message ('Found {0} updates to install.' -f $Updates.Count) -Level 'INFO'

		# 2. Create Update Collection
		$MSUpdateCollection = New-UpdateCollection -Updates $Updates
		if ($null -eq $MSUpdateCollection) { return }

		# 3. Accept EULAs
		if (-not (Accept-UpdateEula -UpdateCollection $MSUpdateCollection)) { return }

		# 4. Download Updates
		$DownloadResult = Receive-UpdateDownload -UpdateCollection $MSUpdateCollection
		if ($null -eq $DownloadResult) { return }

		# 5. Install Updates
		$InstallResult = Install-UpdateCollection -UpdateCollection $MSUpdateCollection
		if ($null -eq $InstallResult) { return }

		# 6. Log Results
		Write-Log -Message ('Installation complete. Result Code: {0}' -f $InstallResult.ResultCode) -Level 'INFO'
		try {
			for ($i = 0; $i -lt $MSUpdateCollection.Count; $i++) {
				$Update = $MSUpdateCollection.Item($i)
				$Result = $InstallResult.GetUpdateResult($i)
				$ResultCodeMap = @{ 0 = 'Not Started'; 1 = 'In Progress'; 2 = 'Succeeded'; 3 = 'Succeeded with Errors'; 4 = 'Failed'; 5 = 'Aborted' }
				Write-Log -Message ('  - {0}: Installation Status: {1}' -f $Update.Title, $ResultCodeMap[$Result.ResultCode]) -Level 'TRACE'
				if ($Result.ResultCode -eq 4) {
					Write-Log -Message ('  - {0}: Installation Failed. Error: {1}' -f $Update.Title, $Result.HResult) -Level 'ERROR'
				}
			}
		} catch {
			Write-Log -Message 'Could not retrieve per-update results.' -Level 'WARN'
		}

		# 7. Check for Reboot
		if ($InstallResult.RebootRequired) {
			Write-Log -Message 'A reboot is required to complete the installation.' -Level 'WARN'
			# Restart-Computer -Force
			$RebootRequired = $true
		}
	}
}

if ($RebootRequired) { Write-Log -Message 'Reboot Needed!' -Level 'WARN' }
Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
