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
    Version:    1.4.2
    Requires:   Administrative privileges (HKLM).
    PSVersion:  5.0+
#>

[CmdletBinding(SupportsShouldProcess = $true)]
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

$WuModeReg = @{
	Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	Name  = 'DisableWindowsUpdateAccess'
	Value = 1
	Type  = 'DWord'
}

################################## THE SCRIPT ##################################
Write-Log -Message ('Script Started ').PadRight(80, '-') -Level 'INFO'

# Check for Administrative Rights
if (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Log -Message 'Script must be run as Administrator' -Level 'ERROR'
	return
}

$Changed = 0

if ($UxMode -eq 'Disable') {
	Write-Log -Message 'UxMode Disable' -Level 'INFO'
	foreach ($Config in $UxModeRegs) {
		# Ensure the Registry Key exists before attempting to set the property
		if (-not (Test-Path -Path $Config.Path)) {
			if ($PSCmdlet.ShouldProcess($Config.Path, 'Create registry key')) {
				Write-Log -Message "Key not found. Creating: $($Config.Path)" -Level 'VERBOSE'
				New-Item -Path $Config.Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
			}
		}
		$ExistingValue = Get-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction SilentlyContinue
		if (($null -ne $ExistingValue) -and ($ExistingValue.PSObject.Properties.Name -contains $Config.Name) -and ($ExistingValue.($Config.Name) -eq $Config.Value)) {
			Write-Log -Message "Property $($Config.Name) already set to $($Config.Value)" -Level 'VERBOSE'
		} elseif ($PSCmdlet.ShouldProcess($Config.Path, "Set registry property $($Config.Name) to $($Config.Value)")) {
			Write-Log -Message "Setting $($Config.Name) from $($ExistingValue.($Config.Name)) to $($Config.Value)" -Level 'VERBOSE'
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
				if ($PSCmdlet.ShouldProcess($Config.Path, "Remove registry property $($Config.Name)")) {
					Write-Log -Message "Removing $($Config.Name)" -Level 'VERBOSE'
					Remove-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction Stop
					$Changed++
				}
			} else {
				Write-Log -Message "Property $($Config.Name) not found." -Level 'VERBOSE'
			}
		}
	}
}

if ($WuMode -eq 'Disable') {
	Write-Log -Message 'WuMode Disable' -Level 'INFO'

	if (-not (Test-Path -Path $WuModeReg.Path)) {
		if ($PSCmdlet.ShouldProcess($WuModeReg.Path, 'Create registry key')) {
			Write-Log -Message "Key not found. Creating: $($WuModeReg.Path)" -Level 'VERBOSE'
			New-Item -Path $WuModeReg.Path -ItemType Directory -Force -ErrorAction Stop | Out-Null
		}
	}

	$ExistingValue = Get-ItemProperty -Path $WuModeReg.Path -Name $WuModeReg.Name -ErrorAction SilentlyContinue
	if (($null -ne $ExistingValue) -and ($ExistingValue.PSObject.Properties.Name -contains $WuModeReg.Name) -and ($ExistingValue.($WuModeReg.Name) -eq $WuModeReg.Value)) {
		Write-Log -Message "Property $($WuModeReg.Name) already set to $($WuModeReg.Value)" -Level 'VERBOSE'
	} elseif ($PSCmdlet.ShouldProcess($WuModeReg.Path, "Set registry property $($WuModeReg.Name) to $($WuModeReg.Value)")) {
		Write-Log -Message "Setting $($WuModeReg.Name) from $($ExistingValue.($WuModeReg.Name)) to $($WuModeReg.Value)" -Level 'VERBOSE'
		Set-ItemProperty @WuModeReg -ErrorAction Stop
		$Changed++
	}
} else {
	Write-Log -Message 'WuMode Enable' -Level 'INFO'
	if (Test-Path -Path $WuModeReg.Path) {
		$ExistingValue = Get-ItemProperty -Path $WuModeReg.Path -Name $WuModeReg.Name -ErrorAction SilentlyContinue
		if ($null -ne $ExistingValue) {
			if ($PSCmdlet.ShouldProcess($WuModeReg.Path, "Remove registry property $($WuModeReg.Name)")) {
				Write-Log -Message "Removing $($WuModeReg.Name)" -Level 'VERBOSE'
				Remove-ItemProperty -Path $WuModeReg.Path -Name $WuModeReg.Name -ErrorAction Stop
				$Changed++
			}
		} else {
			Write-Log -Message "Property $($WuModeReg.Name) not found." -Level 'VERBOSE'
		}
	}
}

if ((-not $SkipServiceRestart) -and ($Changed -gt 0) -and $PSCmdlet.ShouldProcess('wuauserv', 'Restart service')) {
	Write-Log -Message 'Restarting Windows Update Service' -Level 'INFO'
	try {
		Restart-Service -Name wuauserv -Force -ErrorAction Stop
	} catch {
		Write-Log -Message ('Failed to restart Windows Update service: {0}' -f $_.Exception.Message) -Level 'WARN'
	}
}

Write-Log -Message ('Script Finished ').PadRight(80, '-') -Level 'INFO'
