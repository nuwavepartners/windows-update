<#
.NOTES
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2024-02-05 13:22:18
#>
[CmdletBinding()]
Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Windows-UpdatePolicy.json'
)

# Check for Administrative Rights
If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Throw "Script must be run as Administrator"
}

# Check for PowerShell Version 3.0+
If ($PSVersionTable.PSVersion.Major -lt 3) {
	Throw "Script requires PowerShell v3.0 or Higher"
}

################################## THE SCRIPT ##################################

Write-Output ('Script Started ').PadRight(80,'-')
$RebootRequired = $false

# Load Configuration(s)
Write-Output "Script Configuration"
Write-Output ("`tLoading")
$Conf = (Invoke-WebRequest -Uri $Configs).Content | ConvertFrom-Json

Write-Output "`tVerifying"
$PatchTuesday = (1..7 | ForEach-Object { $(Get-Date -Day 7).AddDays($_) } | Where-Object { $_.DayOfWeek -like "Tue*" })
If (((Get-Date) -gt $PatchTuesday) -and ((Get-Date -Date $Conf.WindowsUpdate._meta.Date_Modified) -lt $PatchTuesday)) {
	Write-Warning ("Patch policy data may be Outdated! {0}" -f $Conf.WindowsUpdate._meta.Date_Modified)
}

Write-Output 'Collecting current computer configuration'
$ThisOS = Get-CimInstance -ClassName Win32_OperatingSystem
$ThisHF = Get-HotFix
Write-Output ("`tOS: {0} {1} <{2}>" -f $ThisOS.Caption, $ThisOS.Version, $ThisOS.ProductType)
Write-Output ("`tHF: {0} Installed, Most recent {1}" -f $ThisHF.Count, ($ThisHF.InstalledOn | Measure-Object -Maximum).Maximum)

:lCollection Foreach ($UpdateCollection in $Conf.WindowsUpdate) {

	# Check each qualifier from the config
	Foreach ($Qualifier in $UpdateCollection.OS.PSObject.Properties.Name) {
		If ($ThisOS.$Qualifier -inotmatch $UpdateCollection.OS.$Qualifier) {
			Continue lCollection
		}
	}

	If ($UpdateCollection.Updates.Count -lt 1) {
		Write-Output ('No updates unavailable for {0}, your version of Windows may be unsupported' -f $UpdateCollection.OS.Caption)
		Continue lCollection
	}

	Write-Output ('Found Updates for ' + $UpdateCollection.OS.Caption)

		Foreach ($Update in $UpdateCollection.Updates) {
		Write-Output "Searching for $($Update.Title)"
		If (($null -ne $ThisHF.HotFixID) -and ((Compare-Object -ReferenceObject ($ThisHF.HotFixID -replace '\D', '') -DifferenceObject $Update.KBArticleID -IncludeEqual).SideIndicator -contains '==')) {
			Write-Output "`tFound"
		} else {
			Write-Output "`tNot Installed"

			$Source = $Update.Source
			If ($null -eq $Source) {
				Write-Output "`tSource not found - Possibly Unsupported"
				Continue
			}

			$f = $null

			# Try Cache Location
			If ($CacheDir.Trim().Length -gt 0) {
				$f = Invoke-CacheGet -CacheDir $CacheDir -FileName $Source.Split('\')[-1] -FileHash $Source.Split('\')[-1].Split('_')[-1].Substring(0,40)
				Write-Verbose ("Invoke-CacheGet Returned: {0}" -f $f)
			}

			# Download from Source
			If ($null -eq $f) {
				Write-Output "`tDownloading"
				$f = Join-Path $env:TEMP ([System.IO.Path]::GetRandomFileName())
				Start-BitsTransfer -Source $Source -Destination $f
			}

			Write-Output "`tInstalling"
			$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList $f,'/quiet','/norestart' -Wait -PassThru
			Switch ($r.ExitCode) {
				0x0			{ Write-Output "`tInstalled successfully"; Break }
				0x00240006	{ Write-Output "`tUpdate already installed"; Break }
				0x00240005	{ Write-Output "`tInstalled, Pending reboot"; $RebootRequired = $true; Break }
				0x0BC2		{ Write-Output "`tInstalled, Pending reboot"; $RebootRequired = $true; Break }
				{$_ -gt 0 }	{
					Write-Output "`t`t`Installation returned $($r.ExitCode) 0x$('{0:X8}' -f $r.ExitCode)"
					Throw "Installation Failed."
				}
			}

			Remove-Item -Path $f -ErrorAction SilentlyContinue
		}
	}
	Break;
}

If ($RebootRequired) { Write-Output "Reboot Needed!" }
Write-Output ('Script Finished ').PadRight(80,'-')
