<#
.SYNOPSIS
    Manages user access to Windows Update UX, hides the System Tray icon, and suppresses auto-reboots.

.DESCRIPTION
    Designed for RMM execution (SYSTEM context). Iterates through a defined
    list of HKLM registry configurations to manage Windows Update UX and access.

    The script is idempotent; it checks for key existence and applies changes based on parameters.

.PARAMETER UxMode
    Determines if UX restrictions (Settings access, Tray icon, Auto-Reboot) are applied.
    'Disable' (default) prevents access and hides UX.
    'Enable' removes these restrictions.

.PARAMETER WuMode
    Determines if overall Windows Update access is allowed.
    'Disable' creates the 'DisableWindowsUpdateAccess' registry key to prevent access.
    'Enable' (default) removes this registry key if it exists.

.NOTES
    Author:     Chris Stone
    Date:       2026-01-16
    Version:    1.3.1
    Requires:   Administrative privileges (HKLM).
    PSVersion:  5.0+
#>

[CmdletBinding()]
param (
	[switch]$SkipServiceRestart,

	[ValidateSet('Enable', 'Disable')]
	[string]$UxMode = 'Disable',

	[ValidateSet('Enable', 'Disable')]
	[string]$WuMode = 'Enable'
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

$UxModeRegs = @(
	# --- Core "Stop Automatic Updates" Policies ---
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
		Name  = 'NoAutoUpdate'
		Value = 1
		Type  = 'DWord'
	},
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
		Name  = 'AUOptions'
		Value = 2
		Type  = 'DWord'
	},
	# --- UX & Reboot Restrictions ---
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
		Name  = 'SetDisableUXWUAccess'
		Value = 1
		Type  = 'DWord'
	},
	@{
		Path  = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
		Name  = 'TrayIconVisibility'
		Value = 0
		Type  = 'DWord'
	},
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
		Name  = 'NoAutoRebootWithLoggedOnUsers'
		Value = 1
		Type  = 'DWord'
	},
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
		Name  = 'SetUpdateNotificationLevel'
		Value = 0
		Type  = 'DWord'
	},
	@{
		Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
		Name  = 'UpdateNotificationLevel'
		Value = 2
		Type  = 'DWord'
	}
)

$WuModeResg = @{
	Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	Name  = 'DisableWindowsUpdateAccess'
	Value = 1
	Type  = 'DWord'
}

################################## THE SCRIPT ##################################
Write-Log -Message ('Script Started ').PadRight(80, '-') -Level 'INFO'
$Changed = 0

if ($UxMode -eq 'Disable') {
	Write-Log -Message 'UxMode Disable' -Level 'INFO'
	foreach ($Config in $UxModeRegs) {
		# Ensure the Registry Key exists before attempting to set the property
		if (-not (Test-Path -Path $Config.Path)) {
			Write-Log -Message "Key not found. Creating: $($Config.Path)" -Level 'TRACE'
			New-Item -Path $Config.Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
		}
		$ExistingValue = Get-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction SilentlyContinue
		if ($ExistingValue.($Config.Name) -eq $Config.Value) {
			Write-Log -Message "Property $($Config.Name) already set to $($Config.Value)" -Level 'TRACE'
		} else {
			Write-Log -Message "Setting $($Config.Name) from $($ExistingValue.($Config.Name)) to $($Config.Value)" -Level 'TRACE'
			Set-ItemProperty @Config -ErrorAction Stop
			$Changed++
		}
	}
} else {
	Write-Log -Message 'UxMode Enable' -Level 'INFO'
	foreach ($Config in $UxModeRegs) {
		if (Test-Path -Path $Config.Path) {
			$ExistingValue = Get-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction SilentlyContinue
			if ($null -ne $ExistingValue) {
				Write-Log -Message "Removing $($Config.Name)" -Level 'TRACE'
				Remove-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction Stop
				$Changed++
			} else {
				Write-Log -Message "Property $($Config.Name) not found." -Level 'TRACE'
			}
		}
	}
}

if ($WuMode -eq 'Disable') {
	Write-Log -Message 'WuMode Disable' -Level 'INFO'

	if (-not (Test-Path -Path $WuModeResg.Path)) {
		Write-Log -Message "Key not found. Creating: $($WuModeResg.Path)" -Level 'TRACE'
		New-Item -Path $WuModeResg.Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
	}

	$ExistingValue = Get-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction SilentlyContinue
	if ($ExistingValue.($WuModeResg.Name) -eq $WuModeResg.Value) {
		Write-Log -Message "Property $($WuModeResg.Name) already set to $($WuModeResg.Value)" -Level 'TRACE'
	} else {
		Write-Log -Message "Setting $($WuModeResg.Name) from $($ExistingValue.($WuModeResg.Name)) to $($WuModeResg.Value)" -Level 'TRACE'
		Set-ItemProperty @WuModeResg -ErrorAction Stop
		$Changed++
	}
} else {
	Write-Log -Message 'WuMode Enable' -Level 'INFO'
	if (Test-Path -Path $WuModeResg.Path) {
		$ExistingValue = Get-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction SilentlyContinue
		if ($null -ne $ExistingValue) {
			Write-Log -Message "Removing $($WuModeResg.Name)" -Level 'TRACE'
			Remove-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction Stop
			$Changed++
		} else {
			Write-Log -Message "Property $($WuModeResg.Name) not found." -Level 'TRACE'
		}
	}
}

if ((-not $SkipServiceRestart) -and ($Changed -gt 0)) {
	Write-Log -Message 'Restarting Windows Update Service' -Level 'INFO'
	Restart-Service -Name wuauserv -Force -ErrorAction Stop
}

Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
