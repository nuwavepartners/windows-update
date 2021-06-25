<# 
.NOTES 
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2021-04-16 12:16:44
#>
[CmdletBinding()]
Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Windows-UpdatePolicy.json',
	$CacheDir = ''
)

# Check for PowerShell Version 3.0+
If ($PSVersionTable.PSVersion.Major -lt 3) {
	Throw "Script requires PowerShell v3.0 or Higher"
}

################################## FUNCTIONS ##################################

function Invoke-CacheGet {
Param (
	[Parameter(Mandatory=$true)]	[string]	$CacheDir,
	[Parameter(Mandatory=$true)]	[string]	$FileName,
	[Parameter(Mandatory=$false)]	[string]	$FileHash
)
	$CachePath = @($CacheDir, $FileName.ToString().Split('/')[-1]) -join '\'
	$LocalPath = @($Env:TEMP, [System.IO.Path]::GetRandomFileName()) -join '\'
	If (Test-Path -Path $CachePath -PathType Leaf) {
		# Copy to local
		Copy-Item -Path $CachePath -Destination $LocalPath

		# Calculate Hash
		If ($PSBoundParameters.ContainsKey('FileHash')) {
			$stream = New-Object system.IO.FileStream($LocalPath, "Open", "Read", "ReadWrite")
			$csp = New-Object -TypeName System.Security.Cryptography.SHA1Cng
			$hash = [System.BitConverter]::ToString($csp.ComputeHash($stream)).Replace("-", [String]::Empty).ToLower();
			$stream.Dispose(); $stream.Close(); $csp.Dispose()


			If ($hash -ne ($FileHash).ToLower()) {
				Write-Verbose "`tCache Invalid"
				Return $null
			}
		}
		Write-Verbose "`tCache Found"
		Return $LocalPath
		
	} 
	Write-Verbose "`tCache Unpopulated"
	Return $null
}

function Invoke-DownloadJson {
Param (
	[Parameter(Mandatory=$true)]	[uri] $Uri
)
Begin {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
}
Process {
	$R = (New-Object System.Net.WebClient).DownloadString($Uri) | ConvertFrom-Json
	If ($null -ne $R._meta) {
		Add-Member -InputObject $R._meta -MemberType NoteProperty -Name 'Source' -Value $Uri.AbsoluteUri -Force
		Add-Member -InputObject $R._meta -MemberType NoteProperty -Name 'Date_Accessed' -Value $(Get-Date -Format 's') -Force
	}
}
End {
	Return $R
}
}

function Merge-JsonConfig {
Param (
	[Object] $InputObject,
	[Object] $MergeObject
)
	Foreach ($P in ($MergeObject.PSObject.Properties.Name | Where-Object {$_ -notmatch "^_"})) {
		Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $P -Value $MergeObject.$P -Force
		If ($null -ne $MergeObject._meta) {
			Add-Member -InputObject $InputObject.$P -MemberType NoteProperty -Name '_meta' -Value $MergeObject._meta -Force
		}
	}
}

Function Import-JsonConfig {
Param (
	[Uri[]]	$Uri,
	[String[]] $Path,
	[String] $Raw,
	[Object] $InputObject = (New-Object Object)
)
	Process {
		If ($null -ne $Path)	{ Foreach ($P in $Path) { Merge-JsonConfig -InputObject $InputObject -MergeObject (Get-Content -Raw -Path $P | ConvertFrom-Json) } }
		If ($null -ne $Uri)		{ Foreach ($U in $Uri)	{ Merge-JsonConfig -InputObject $InputObject -MergeObject (Invoke-DownloadJson $U) } }
		If ($null -ne $Raw)		{ Merge-JsonConfig -InputObject $InputObject -MergeObject (ConvertFrom-Json -InputObject $Raw) }
	}
	End {
		Return $InputObject
	}
}

################################## THE SCRIPT ##################################

Write-Output ('Script Started ').PadRight(80,'-')
$RebootRequired = $false

# Load Configuration(s)
Write-Output "Configuration"
Write-Output ("`tLoading")
$Conf = Import-JsonConfig -Uri $Configs

Write-Output "`tVerifying"
$PatchTuesday = (0..6 | ForEach-Object { $(Get-Date -Day 7).AddDays($_) } | Where-Object { $_.DayOfWeek -like "Tue*" })
If (((Get-Date) -gt $PatchTuesday) -and ((Get-Date -Date $Conf.WindowsUpdate._meta.Date_Modified) -lt $PatchTuesday)) {
	Write-Warning ("Patch policy data may be Outdated! {0}" -f $Conf.WindowsUpdate._meta.Date_Modified)
}
If ($CacheDir.Trim().Length -gt 0) {
	Write-Output ("`tCache: {0}" -f $CacheDir)
} else {
	Write-Output "`tCache: Unspecified"
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

	Write-Output ('Found Updates for ' + $UpdateCollection.OS.Caption)
		
		$Transfer = @()
		Foreach ($Update in $UpdateCollection.Updates) {
			$Transfer += [PSCustomObject]@{
				Source = $Update.Source;
				Destination = @($CacheDir, $Update.Source.ToString().Split('/')[-1]) -join '\'
			}
		}
		
		Write-Output ('Populating Cache...')
		$Transfer | Start-BitsTransfer
	Break;
}

If ($RebootRequired) { Write-Output "Reboot Needed!" }
Write-Output ('Script Finished ').PadRight(80,'-')
