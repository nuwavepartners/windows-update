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
	[string] $PolicyUri = 'https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json'
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

#region Main Script: 2. Preparation (Policy)

Write-Log -Message 'Running in Policy Mode' -Level 'INFO'
$HttpClient = $null
$Conf = $null

if (-not ("System.Net.Http.HttpClient" -as [Type])) {
	Add-Type -AssemblyName System.Net.Http
}
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
	$PatchTuesday = (1..7 | ForEach-Object { $(Get-Date -Day 7 -Hour 0 -Minute 0 -Second 0).AddDays($_) } | Where-Object { $_.DayOfWeek -like 'Tue*' })
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

if ($RebootRequired) { Write-Log -Message 'Reboot Needed!' -Level 'WARN' }
Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
