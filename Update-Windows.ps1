<#
.NOTES
	Author:			Chris Stone
	Date-Modified:	2025-11-11 10:22:24
.VERSION
    2.0.3
#>
[CmdletBinding(DefaultParameterSetName = 'Policy')]
param (
	[Parameter(Mandatory = $true, ParameterSetName = 'Policy')]
	[string] $PolicyUri = 'https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json',

	[Parameter(Mandatory = $true, ParameterSetName = 'Native')]
	[Parameter(ParameterSetName = 'Policy')]
	[ValidateSet('Policy', 'Native')]
	[string] $Mode = 'Policy',

	[Parameter(ParameterSetName = 'Native')]
	[ValidateSet('Search', 'List', 'Install')]
	[string] $Action = 'Install'
)

#region Helper Functions

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,
		[ValidateSet('TRACE', 'INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO'
	)
	$FormattedMessage = "$(Get-Date -Format 's') [$Level] $Message"
	if ([Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
		Write-Output $FormattedMessage
	} else {
		$ColorMap = @{
			TRACE = 'DarkGray'
			INFO  = 'Green'
			WARN  = 'Yellow'
			ERROR = 'Red'
		}
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

if ($Mode -eq 'Policy') {
	#region Main Script: 2. Preparation (Policy)

	Write-Log -Message 'Running in Policy Mode' -Level 'INFO'
	$HttpClient = $null
	$Conf = $null

	try {
		$HttpClient = New-Object System.Net.Http.HttpClient
		Write-Log -Message 'Script Configuration' -Level 'INFO'
		Write-Log -Message 'Loading configuration' -Level 'TRACE'
		try {
			$JsonData = $HttpClient.GetStringAsync($PolicyUri).GetAwaiter().GetResult()
			$Conf = $JsonData | ConvertFrom-Json
		} catch {
			Write-Log -Message ('Failed to download or parse configuration from {0}. Error: {1}' -f $PolicyUri, $_.Exception.Message) -Level 'ERROR'
			return
		}

		if ($null -ne $Conf._meta.Date_Modified) {
			Write-Log -Message 'Verifying configuration' -Level 'TRACE'
			$PatchTuesday = (1..7 | ForEach-Object { $(Get-Date -Day 7).AddDays($_) } | Where-Object { $_.DayOfWeek -like 'Tue*' })
			if (((Get-Date) -gt $PatchTuesday) -and ((Get-Date -Date $Conf._meta.Date_Modified) -lt $PatchTuesday)) {
				Write-Log -Message ('Patch policy data may be Outdated! {0}' -f $Conf._meta.Date_Modified) -Level 'WARN'
			}
		}

		Write-Log -Message 'Collecting current computer configuration' -Level 'INFO'
		$ThisOS = Get-CimInstance -ClassName Win32_OperatingSystem
		$ThisHF = Get-HotFix
		Write-Log -Message ('OS: {0} {1} <{2}>' -f $ThisOS.Caption, $ThisOS.Version, $ThisOS.ProductType) -Level 'TRACE'
		Write-Log -Message ('HF: {0} Installed, Most recent {1}' -f $ThisHF.Count, ($ThisHF.InstalledOn | Measure-Object -Maximum).Maximum) -Level 'TRACE'

		if ($Conf.WindowsEoL) {
			$Conf.WindowsEoL | Where-Object { $ThisOS.Version -match $_.latest } | ForEach-Object {
				if ($_.eol -lt (Get-Date)) {
					Write-Log -Message 'This Operating System is End of Life and may be insecure.' -Level 'WARN'
				} else {
					Write-Log -Message ('Operating System Supported until {0}' -f $_.eol) -Level 'TRACE'
				}
			}
		}

		#endregion

		#region Main Script: 3. Execution (Policy)

		:lCollection foreach ($UpdateCollection in $Conf.WindowsUpdate) {

			# Check each qualifier from the config
			foreach ($Qualifier in $UpdateCollection.OS.PSObject.Properties.Name) {
				if ($ThisOS.$Qualifier -inotmatch $UpdateCollection.OS.$Qualifier) {
					continue lCollection
				}
			}

			if ($UpdateCollection.Updates.Count -lt 1) {
				Write-Log -Message ('No update policy available for {0}, your version of Windows may be unsupported' -f $UpdateCollection.OS.Caption) -Level 'WARN'
				continue lCollection
			}

			Write-Log -Message ('Found Update Policy for {0}' -f $UpdateCollection.OS.Caption) -Level 'INFO'

			foreach ($Update in $UpdateCollection.Updates) {
				Write-Log -Message ('Searching for {0}' -f $Update.Title) -Level 'INFO'
				if (($null -ne $ThisHF.HotFixID) -and ($ThisHF.HotFixID -contains $Update.KBArticleID)) {
					Write-Log -Message 'Found' -Level 'TRACE'
				} else {
					Write-Log -Message 'Not Installed' -Level 'TRACE'

					$Source = $Update.Source
					if ($null -eq $Source) {
						Write-Log -Message 'Source not found - Possibly Unsupported' -Level 'WARN'
						continue
					}

					# Download
					$f = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
					$Stream = $null
					$FileStream = $null
					try {
						Write-Log -Message 'Downloading' -Level 'TRACE'
						$Stream = $HttpClient.GetStreamAsync($Source).GetAwaiter().GetResult()
						$FileStream = [System.IO.File]::Create($f)
						$Stream.CopyTo($FileStream)
					} catch {
						Write-Log -Message ('Failed to download update {0} from {1}. Error: {2}' -f $Update.KBArticleID, $Source, $_.Exception.Message) -Level 'ERROR'
						continue # Skip this update
					} finally {
						if ($FileStream) { $FileStream.Dispose() }
						if ($Stream) { $Stream.Dispose() }
					}

					# Install
					$r = $null
					try {
						Write-Log -Message 'Installing' -Level 'TRACE'
						$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList $f, '/quiet', '/norestart' -Wait -PassThru -ErrorAction Stop
					} catch {
						Write-Log -Message ('Failed to start installer (wusa.exe) for {0}. Error: {1}' -f $Update.KBArticleID, $_.Exception.Message) -Level 'ERROR'
						Remove-Item -Path $f -ErrorAction SilentlyContinue
						continue # Skip this update
					}

					switch ($r.ExitCode) {
						0x0 { Write-Log -Message 'Installed successfully' -Level 'TRACE'; break }
						0x00240006	{ Write-Log -Message 'Update already installed' -Level 'TRACE'; break }
						0x00240005	{ Write-Log -Message 'Installed, Pending reboot' -Level 'TRACE'; $RebootRequired = $true; break }
						0x0BC2 { Write-Log -Message 'Installed, Pending reboot' -Level 'TRACE'; $RebootRequired = $true; break }
						{ $_ -gt 0 } {
							Write-Log -Message ('Installation returned {0} (0x{1:X8})' -f $r.ExitCode, $r.ExitCode) -Level 'ERROR'
							continue # Don't throw, just log and continue to the next update
						}
					}

					Remove-Item -Path $f -ErrorAction SilentlyContinue
				}
			}
			break;
		}

		#endregion

	} finally {
		if ($HttpClient) { $HttpClient.Dispose() }
	}

} else {
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
}

if ($RebootRequired) { Write-Log -Message 'Reboot Needed!' -Level 'WARN' }
Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'