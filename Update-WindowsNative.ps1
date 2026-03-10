<#
.NOTES
	Author:			Chris Stone
	Date-Modified:	2025-11-18 15:29:51
.VERSION
    2.0.7
#>
[CmdletBinding()]
param (
	[Parameter(Mandatory = $false)]
	[ValidateSet('Search', 'List', 'Install')]
	[string] $Action = 'Install'
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

#endregion

#region Main Script: 1. Prerequisites

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

#endregion

#region Main Script: 2. Preparation (Native)

Write-Log -Message ('Running in Native Mode with Action: {0}' -f $Action) -Level 'INFO'

#endregion

#region Main Script: 3. Execution (Native)

switch ($Action) {
	'Search' {
		Write-Log -Message 'Initiating new update search (DetectNow)...' -Level 'INFO'
		try {
			$AutoUpdate = New-Object -ComObject 'Microsoft.Update.AutoUpdate' -ErrorAction Stop
			$AutoUpdate.DetectNow()
			Write-Log -Message 'Update search initiated successfully.' -Level 'INFO'
		} catch {
			Write-Log -Message ('Failed to initiate update search. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
		}
	}

	'List' {
		Write-Log -Message 'Listing available updates...' -Level 'INFO'
		$Updates = $null
		try {
			$MSUpdateSearcher = New-Object -ComObject 'Microsoft.Update.Searcher' -ErrorAction Stop
			$MSUpdateSearcher.Online = $true
			$Updates = $MSUpdateSearcher.Search('IsInstalled=0 AND IsHidden=0').Updates
		} catch {
			Write-Log -Message ('Failed to search for updates. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

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
		$Updates = $null
		try {
			$MSUpdateSearcher = New-Object -ComObject 'Microsoft.Update.Searcher' -ErrorAction Stop
			$MSUpdateSearcher.Online = $true
			Write-Log -Message 'Searching for available updates...' -Level 'TRACE'
			$Updates = $MSUpdateSearcher.Search('IsInstalled=0 AND IsHidden=0').Updates
		} catch {
			Write-Log -Message ('Failed to search for updates. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

		if ($Updates.Count -eq 0) {
			Write-Log -Message 'System is already up-to-date.' -Level 'INFO'
			return
		}

		Write-Log -Message ('Found {0} updates to install.' -f $Updates.Count) -Level 'INFO'

		# 2. Create Update Collection
		$MSUpdateCollection = $null
		try {
			$MSUpdateCollection = New-Object -ComObject 'Microsoft.Update.UpdateColl' -ErrorAction Stop
			foreach ($Update in $Updates) {
				$MSUpdateCollection.Add($Update) | Out-Null
			}
		} catch {
			Write-Log -Message ('Failed to create update collection. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

		# 3. Accept EULAs
		try {
			Write-Log -Message 'Accepting EULAs, if necessary...' -Level 'TRACE'
			foreach ($Update in $MSUpdateCollection) {
				if (-not $Update.EulaAccepted) {
					$Update.AcceptEula()
				}
			}
		} catch {
			Write-Log -Message ('Failed to accept EULA for an update. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

		# 4. Download Updates
		$DownloadResult = $null
		try {
			Write-Log -Message 'Downloading selected updates...' -Level 'INFO'
			$MSUpdateSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
			$MSUpdateDownloader = $MSUpdateSession.CreateUpdateDownloader()
			$MSUpdateDownloader.Updates = $MSUpdateCollection
			$DownloadResult = $MSUpdateDownloader.Download()
			Write-Log -Message ('Download result code: {0}' -f $DownloadResult.ResultCode) -Level 'TRACE'
		} catch {
			Write-Log -Message ('Failed to download updates. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

		# 5. Install Updates
		$InstallResult = $null
		try {
			Write-Log -Message 'Installing downloaded updates...' -Level 'INFO'
			$MSUpdateInstaller = New-Object -ComObject 'Microsoft.Update.Installer' -ErrorAction Stop
			$MSUpdateInstaller.Updates = $MSUpdateCollection
			$InstallResult = $MSUpdateInstaller.Install()
		} catch {
			Write-Log -Message ('Failed to install updates. Error: {0}' -f $_.Exception.Message) -Level 'ERROR'
			return
		}

		# 6. Log Results
		Write-Log -Message ('Installation complete. Result Code: {0}' -f $InstallResult.ResultCode) -Level 'INFO'
		try {
			for ($i = 0; $i -lt $MSUpdateCollection.Count; $i++) {
				$Update = $MSUpdateCollection.Item($i)
				$Result = $InstallResult.GetUpdateResult($i)
				$ResultCodeMap = @{ 0 = 'Not Started'; 1 = 'In Progress'; 2 = 'Succeeded'; 3 = 'Succeeded with Errors'; 4 = 'Failed'; 5 = 'Aborted' }
				Write-Log -Message ('  - {0}: {1}' -f $Update.Title, $ResultCodeMap[$Result.ResultCode]) -Level 'TRACE'
			}
		} catch {
			Write-Log -Message 'Could not retrieve per-update results.' -Level 'WARN'
		}

		# 6. Check for Reboot
		if ($InstallResult.RebootRequired) {
			Write-Log -Message 'A reboot is required to complete the installation.' -Level 'WARN'
			# Restart-Computer -Force
			$RebootRequired = $true
		}
	}
}

#endregion

if ($RebootRequired) { Write-Log -Message 'Reboot Needed!' -Level 'WARN' }
Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
