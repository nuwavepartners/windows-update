<# 
.NOTES 
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2022-05-31 12:33:23
#>
[CmdletBinding()]
Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Windows-UpdatePolicy.json',
	$CacheDir = ''
)

# Check for Administrative Rights
If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Throw "Script must be run as Administrator"
}

# Check for PowerShell Version 3.0+
If ($PSVersionTable.PSVersion.Major -lt 3) {
	Throw "Script requires PowerShell v3.0 or Higher"
}

################################## FUNCTIONS ##################################

function Invoke-DownloadFile {
	Param (
		[Parameter(Mandatory=$true)]				[uri] $Uri,
													[string] $Path = $Env:TEMP,
		[ValidateScript({$_ -match '\w+|.\w{32}'})]	[string] $Hash
	)

	Process {
		# Check Cache for file
		If (!([Environment]::UserInteractive) -and ($null -ne $Hash)) {
						$UriFileName = $Uri.Segments[-1]
			[uri]$CacheDir = ($script:CacheDir, [System.IO.Path]::GetDirectoryName($PSScriptRoot), $Env:TEMP -ne $null)[0]
			#$CachePath = [System.IO.Path]::Combine($CacheDir, $UriFileName)
			$CachePath = [Uri]::New($CacheDir, $UriFileName)
			Write-Verbose ("Checking {0} {1} {2}" -f $UriFileName, $CacheDir, $CachePath)
			If (Test-Path -Path $CachePath) {
				$HashAlg = [System.Security.Cryptography.HashAlgorithm]::Create(($Hash -split '\|')[0])
				$FileStream = [System.IO.FileStream]::New($CachePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
				$CacheHash = [System.BitConverter]::ToString($HashAlg.ComputeHash($FileStream)).Replace('-', [String]::Empty).ToLower()
				$HashAlg.Dispose(); $FileStream.Dispose()
				If($CacheHash -eq ($Hash -split '\|')[-1].ToLower()) {
					Write-Verbose 'Using Cached File, Hash Verified'
					Return $CachePath
				}
				Write-Verbose ('{0} with {1} hash does not match {2}' -f $CachePath, $CacheHash, $Hash)
			}
		}

		# Setup Connections
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
		$WebReq = [System.Net.WebRequest]::Create($Uri)
		$WebReq.Timeout = 5000 # 5 Seconds

		$WebResp = $WebReq.GetResponse()
		If ($WebResp.StatusCode -ne 'OK') {
			throw $WebResp.StatusDescription
		}
		$bLengthTotal = $WebResp.get_ContentLength() # File Size

		# File name and stream
		If (Test-Path -Path $Path -Type Container) {
			If ($WebResp.Headers.Keys -contains 'Content-Disposition') {
				# Server provided file name
				$FileName = $Path + '\' + ($WebResp.GetResponseHeader("Content-Disposition").Split('=')[-1] -replace '"','')
			} else {
				# Server did not provide name, random
				$FileName = $Path + '\' + [System.IO.Path]::GetRandomFileName() + '.' + $Uri.ToString().Split('.')[-1]
			}
		} elseif (Test-Path -Path (Split-Path -Path $Path -Parent) -Type Container) {
			# Function called with destination file name and valid folder
			$FileName = $Path
		} else {
			# Function called with invalid path
			throw "Invalid path provided to $($MyInvocation.MyCommand.Name)"
		}
		$FileStream = New-Object -TypeName System.IO.FileStream -ArgumentList $FileName, Create

		# Setup for download
		$Buf = New-Object byte[] ([Math]::Min([Math]::Max(($bLengthTotal / 100), 2KB), 256KB))
		$bDownloaded = 0; $bRead = 0; $tStart = Get-Date
		$WebStream = $WebResp.GetResponseStream()

		Do {	# Do the download
			$bDownloaded += ($bRead = $WebStream.Read($Buf, 0, $Buf.Length))
			$FileStream.Write($Buf, 0, $bRead)
			# Progress update
			If ($Progress.IsPresent) {
				Write-Progress -Activity "Downloading File" -Status ("{0} of {1}" -f $(Convert-DisplayBytes($bDownloaded)), $(Convert-DisplayBytes($bLengthTotal))) `
					-PercentComplete ($bDownloaded / $bLengthTotal * 100) `
					-SecondsRemaining (($bLengthTotal - $bDownloaded) / $bDownloaded * (New-TimeSpan -Start $tStart).TotalSeconds)
			}
		} While (($bRead -gt 0) -and ($WebStream.CanRead))

		$FileStream.Flush(); $FileStream.Close(); $FileStream.Dispose(); $WebStream.Dispose(); $WebResp.Close()	# Cleanup
		If ($Progress.IsPresent) { Write-Progress -Activity "Downloading File" -Completed }

		return $FileName
	}
}

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
$PatchTuesday = (1..7 | ForEach-Object { $(Get-Date -Day 7).AddDays($_) } | Where-Object { $_.DayOfWeek -like "Tue*" })
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

	If ($UpdateCollection.Updates.Count -lt 1) {
		Write-Output ('Updates unavailable for {0}, this version may be unsupported' -f $UpdateCollection.OS.Caption)
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
				$f = Invoke-DownloadFile -Uri $Source
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
		}
	}
	Break;
}

If ($RebootRequired) { Write-Output "Reboot Needed!" }
Write-Output ('Script Finished ').PadRight(80,'-')
