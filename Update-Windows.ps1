<#
.NOTES
	Author:			Chris Stone
	Date-Modified:	2026-09-08 11:22:00
.VERSION
    2.1.1
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
	[Parameter(Mandatory = $false)]
	[ValidateSet('List', 'Install')]
	[string] $Action = 'Install',

	[Parameter(Mandatory = $false)]
	[string] $PolicyUri = 'https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json',

	[Parameter(Mandatory = $false)]
	[int] $SkipRecentlyUpdated = 0
)

function Write-Log {
	param(
		[Parameter(Mandatory = $true)]
		[string]$Message,
		[ValidateSet('VERBOSE', 'INFO', 'WARN', 'ERROR')]
		[string]$Level = 'INFO',
		[hashtable]$ColorMap = @{
			VERBOSE = 'DarkGray'
			INFO    = 'Green'
			WARN    = 'Yellow'
			ERROR   = 'Red'
		}
	)
	$FormattedMessage = "$(Get-Date -Format 's') [$Level] $Message"
	if ([Environment]::GetCommandLineArgs().Contains('-NonInteractive')) {
		[Console]::WriteLine($FormattedMessage)
	} else {
		Write-Host $FormattedMessage -ForegroundColor $ColorMap[$Level]
	}
}

# 1. Prerequisites

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

# 2. Preparation (Policy)

Write-Log -Message 'Running in Policy Mode' -Level 'INFO'
$Conf = $null

Write-Log -Message 'Script Configuration' -Level 'INFO'
Write-Log -Message 'Loading configuration' -Level 'VERBOSE'
try {
	$JsonData = Invoke-WebRequest -Uri $PolicyUri -UseBasicParsing -ErrorAction Stop
	$Conf = $JsonData.Content | ConvertFrom-Json
} catch {
	Write-Log -Message ('Failed to download or parse configuration from {0}. Error: {1}' -f $PolicyUri, $_.Exception.Message) -Level 'ERROR'
	return
}

if ($null -ne $Conf._meta.Date_Modified) {
	Write-Log -Message 'Verifying configuration' -Level 'VERBOSE'
	$PatchTuesday = (1..7 | ForEach-Object { $(Get-Date -Day 7 -Hour 0 -Minute 0 -Second 0).AddDays($_) } | Where-Object { $_.DayOfWeek -like 'Tue*' })
	if (((Get-Date) -ge $PatchTuesday.AddDays(1)) -and ((Get-Date -Date $Conf._meta.Date_Modified) -lt $PatchTuesday)) {
		Write-Log -Message ('Patch policy data may be Outdated! {0}' -f $Conf._meta.Date_Modified) -Level 'WARN'
	}
}

Write-Log -Message 'Collecting current computer configuration' -Level 'INFO'
$ThisOS = Get-CimInstance -ClassName Win32_OperatingSystem
$ThisCBS = @(Get-HotFix -ErrorAction SilentlyContinue)
$ThisWUS = @()
try {
	$WUSession = New-Object -ComObject "Microsoft.Update.Session"
	$WUSearcher = $WUSession.CreateUpdateSearcher()
	$historyCount = $WUSearcher.GetTotalHistoryCount()
	if ($historyCount -gt 0) {
		$ThisWUS = @($WUSearcher.QueryHistory(0, $historyCount))
	}
} catch {
	Write-Log -Message ('Unable to query Windows Update history: {0}' -f $_.Exception.Message) -Level 'VERBOSE'
}
Write-Log -Message ('OS: {0} {1} <{2}>' -f $ThisOS.Caption, $ThisOS.Version, $ThisOS.ProductType) -Level 'VERBOSE'
Write-Log -Message ('CBS: {0} Installed, Most recent {1}' -f $ThisCBS.Count, ($ThisCBS.InstalledOn | Measure-Object -Maximum).Maximum) -Level 'VERBOSE'
Write-Log -Message ('WUS: {0} updates installed, Most recent {1}' -f $ThisWUS.Count, ($ThisWUS.Date | Measure-Object -Maximum).Maximum) -Level 'VERBOSE'

if ($Conf.WindowsEoL) {
	$Conf.WindowsEoL | Where-Object { $ThisOS.Version -match $_.latest } | ForEach-Object {
		if ($_.eol -lt (Get-Date)) {
			Write-Log -Message 'This Operating System is End of Life and may be insecure.' -Level 'WARN'
		} else {
			Write-Log -Message ('Operating System Supported until {0}' -f $_.eol) -Level 'VERBOSE'
		}
	}
}

if ($SkipRecentlyUpdated -gt 0) {
	$MostRecentCBS = ($ThisCBS.InstalledOn | Measure-Object -Maximum).Maximum
	if ($null -ne $MostRecentCBS) {
		$DaysSinceLastUpdate = ((Get-Date) - [datetime]$MostRecentCBS).TotalDays
		if ($DaysSinceLastUpdate -lt $SkipRecentlyUpdated) {
			Write-Log -Message ('Skipped: Most recently installed update was {0:N1} days ago (Threshold: {1} days)' -f $DaysSinceLastUpdate, $SkipRecentlyUpdated) -Level 'INFO'
			return
		}
	}
}

# 3. Execution (Policy)

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
		$KBId = if ($Update.KBArticleID -notmatch '^KB') { "KB$($Update.KBArticleID)" } else { $Update.KBArticleID }
		if ((($null -ne $ThisCBS.HotFixID) -and ($ThisCBS.HotFixID -contains $KBId)) -or (($null -ne $ThisWUS.Title) -and ($ThisWUS.Title -match $KBId))) {
			Write-Log -Message 'Found' -Level 'VERBOSE'
		} else {
			Write-Log -Message 'Not Installed' -Level 'VERBOSE'

			if (($Action -eq 'Install') -and $PSCmdlet.ShouldProcess($Update.KBArticleID, 'Download and install update')) {
				$Source = $Update.Source
				if ($null -eq $Source) {
					Write-Log -Message 'Source not found - Possibly Unsupported' -Level 'WARN'
					continue
				}

				# Download
				$f = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
				try {
					Write-Log -Message 'Downloading' -Level 'VERBOSE'
					Invoke-WebRequest -Uri $Source -OutFile $f -UseBasicParsing -ErrorAction Stop
				} catch {
					Write-Log -Message ('Failed to download update {0} from {1}. Error: {2}' -f $Update.KBArticleID, $Source, $_.Exception.Message) -Level 'ERROR'
					Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
					continue # Skip this update
				}

				# Verify the package is genuinely signed by Microsoft before installing it
				$Sig = Get-AuthenticodeSignature -FilePath $f
				if (($Sig.Status -ne 'Valid') -or ($Sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation')) {
					Write-Log -Message ('Authenticode signature check failed for {0} ({1}). Refusing to install.' -f $Update.KBArticleID, $Sig.Status) -Level 'ERROR'
					Remove-Item -Path $f -Force -ErrorAction SilentlyContinue
					continue # Skip this update
				}

				# Install
				$r = $null
				try {
					Write-Log -Message 'Installing' -Level 'VERBOSE'
					$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList "`"$f`"", '/quiet', '/norestart' -Wait -PassThru -ErrorAction Stop
				} catch {
					Write-Log -Message ('Failed to start installer (wusa.exe) for {0}. Error: {1}' -f $Update.KBArticleID, $_.Exception.Message) -Level 'ERROR'
					Remove-Item -Path $f -ErrorAction SilentlyContinue
					continue # Skip this update
				}

				try {
					switch -Exact ($r.ExitCode) {
						0x0 { Write-Log -Message 'Installed successfully' -Level 'VERBOSE'; break }
						0x00240006	{ Write-Log -Message 'Update already installed' -Level 'VERBOSE'; break }
						0x00240005	{ Write-Log -Message 'Installed, Pending reboot' -Level 'VERBOSE'; $RebootRequired = $true; break }
						0x0BC2 { Write-Log -Message 'Installed, Pending reboot' -Level 'VERBOSE'; $RebootRequired = $true; break }
						default {
							Write-Log -Message ('Installation returned {0} (0x{1:X8})' -f $r.ExitCode, $r.ExitCode) -Level 'ERROR'
							continue # Don't throw, just log and continue to the next update
						}
					}
				} finally {
					Remove-Item -Path $f -ErrorAction SilentlyContinue
				}
			}
		}
	}
	break;
}

if ($RebootRequired) { Write-Log -Message 'Reboot Needed!' -Level 'WARN' }
Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
