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
	[ValidateSet('Enable', 'Disable')]
	[string]$UxMode = 'Disable',

	[ValidateSet('Enable', 'Disable')]
	[string]$WuMode = 'Enable'
)

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

if ($UxMode -eq 'Disable') {
	foreach ($Config in $UxModeRegs) {
		# Ensure the Registry Key exists before attempting to set the property
		if (-not (Test-Path -Path $Config.Path)) {
			Write-Verbose "Key not found. Creating: $($Config.Path)"
			$null = New-Item -Path $Config.Path -ItemType Directory -Force -ErrorAction Stop
		}

		# Apply the registry value using splatting
		Set-ItemProperty @Config -ErrorAction Stop

		# Verify the change
		$Readback = (Get-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction Stop).($Config.Name)
		Write-Output ('[{0}] "{1}" is now: {2}' -f $Config.Path, $Config.Name, $Readback)
	}
} else {
	foreach ($Config in $UxModeRegs) {
		if (Test-Path -Path $Config.Path) {
			$prop = Get-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction SilentlyContinue
			if ($null -ne $prop) {
				Remove-ItemProperty -Path $Config.Path -Name $Config.Name -ErrorAction Stop
				Write-Output ('Removed "{0}" from [{1}]' -f $Config.Name, $Config.Path)
			}
		}
	}
}

$WuModeResg = @{
	Path  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
	Name  = 'DisableWindowsUpdateAccess'
	Value = 1
	Type  = 'DWord'
}

if ($WuMode -eq 'Disable') {
	if (-not (Test-Path -Path $WuModeResg.Path)) {
		Write-Verbose "Key not found. Creating: $($WuModeResg.Path)"
		$null = New-Item -Path $WuModeResg.Path -ItemType Directory -Force -ErrorAction Stop
	}

	Set-ItemProperty @WuModeResg -ErrorAction Stop
	$Readback = (Get-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction Stop).($WuModeResg.Name)
	Write-Output ('[{0}] "{1}" is now: {2}' -f $WuModeResg.Path, $WuModeResg.Name, $Readback)
} else {
	if (Test-Path -Path $WuModeResg.Path) {
		$prop = Get-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction SilentlyContinue
		if ($null -ne $prop) {
			Remove-ItemProperty -Path $WuModeResg.Path -Name $WuModeResg.Name -ErrorAction Stop
			Write-Output ('Removed "{0}" from [{1}]' -f $WuModeResg.Name, $WuModeResg.Path)
		}
	}
}
