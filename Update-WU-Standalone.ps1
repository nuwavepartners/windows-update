#### By Chris Stone <chris.stone@nuwavepartners.com> v0.2.154 2020-07-13 13:14:28

Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Windows-UpdatePolicy-SSU.json'
)

# Check for Administrative Rights
If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host -ForegroundColor Red "Script must be run as Administrator"
	Return
}

# Check for PowerShell Version 3.0+
If ($PSVersionTable.PSVersion.Major -lt 3) {
	Write-Host -ForegroundColor Red "Script requires PowerShell v3.0 or Higher"
	Return
}

################################## FUNCTIONS ##################################

function Convert-DisplayBytes($num)
{
	$exp = [Math]::Floor([Math]::Log10($num)/3)
	Return "{0:G3} {1}" -f ($num/[Math]::Pow(1000,$exp)), @("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")[$exp]
}

function Invoke-DownloadFile {
Param (
	[Parameter(Mandatory=$true)]	[uri] $Uri,
									[string] $Path = $Env:TEMP,
									[Switch] $Progress,
	[Parameter(Mandatory=$false)]	[uri] $Proxy,
	[Parameter(Mandatory=$false)]	[System.Net.ICredentials] $ProxyCred,
	[Parameter(Mandatory=$false)]	[Int]	$Retries = 3
)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
	$WebReq = [System.Net.WebRequest]::Create($Uri)
	$WebReq.Timeout = 5000 # 5 Seconds
	If ($Proxy -ne $null) {
		$WebProxy = New-Object System.Net.WebProxy($Proxy)
		If ($ProxyCred -ne $null) { $WebProxy.Credentials = $ProxyCred }
		$WebReq.Proxy = $WebProxy
	}
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
			# Server did not provide name, split or random
			If ($PSVersionTable.PSVersion -ge [version]"3.0") {
				$FileName = $Path + '\' + (Split-Path -Path $Uri -Leaf)
			} else {
				$FileName = $Path + '\' + [System.IO.Path]::GetRandomFileName() + '.' + $Uri.ToString().Split('.')[-1]
			}
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

function Invoke-DownloadJson {
Param (
	[Parameter(Mandatory=$true, ValueFromPipeline=$true)]	[uri] $Uri
)
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
	$R = (New-Object System.Net.WebClient).DownloadString($Uri) | ConvertFrom-Json
	If ($R._meta -ne $null) {
		Add-Member -InputObject $R._meta -MemberType NoteProperty -Name 'Source' -Value $Uri.AbsoluteUri -Force
		Add-Member -InputObject $R._meta -MemberType NoteProperty -Name 'Date_Accessed' -Value $(Get-Date -Format 's') -Force
	}
	return $R
}

function Merge-JsonConfig {
Param (
	[Object] $InputObject,
	[Object] $MergeObject
)
	Foreach ($P in ($MergeObject.PSObject.Properties.Name |? {$_ -notmatch "^_"})) {
		Add-Member -InputObject $InputObject -MemberType NoteProperty -Name $P -Value $MergeObject.$P -Force
		If ($MergeObject._meta -ne $null) {
			Add-Member -InputObject $InputObject.$P -MemberType NoteProperty -Name '_meta' -Value $MergeObject._meta -Force
		}
	}
}

Function Load-JsonConfig {
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

Write-Host ('Script Started ').PadRight(80,'-')
$RebootRequired = $false

# Load Configuration(s)
Write-Host ("Loading configurations")
$Conf = Load-JsonConfig -Uri $Configs

Write-Host "Verifying configurations"
$PatchTuesday = (0..6 | % {$(Get-Date -Day 7).AddDays($_) } |? {$_.DayOfWeek -like "Tue*"})
If (((Get-Date) -gt $PatchTuesday) -and ((Get-Date -Date $Conf.WindowsUpdate._meta.Date_Modified) -lt $PatchTuesday)) {
	Write-Host -ForegroundColor Red "WARNING - Patch policy data may be Outdated - WARNING"
}

Write-Host 'Collecting current computer configuration'
$ThisOS = GWMI Win32_OperatingSystem
$ThisHF = Get-HotFix
Write-Host "This OS: $($ThisOS.Caption) ($($ThisOS.Version)) <$($ThisOS.ProductType)>"

:lCollection Foreach ($UpdateCollection in $Conf.WindowsUpdate) {

	# Check each qualifier from the config
	Foreach ($Qualifier in $UpdateCollection.OS.PSObject.Properties.Name) {
		If ($ThisOS.$Qualifier -inotmatch $UpdateCollection.OS.$Qualifier) {
			Continue lCollection
		}
	}

	Write-Host ('Found Updates for ' + $UpdateCollection.OS.Caption)

	Foreach ($Selector in $UpdateCollection.Selectors.PSobject.Properties) {
		$UpdateCollection.Selectors.$($Selector.Name) = $ExecutionContext.InvokeCommand.ExpandString($Selector.Value)
	}

	Foreach ($Update in $UpdateCollection.Updates) {
		Write-Host "Searching for $($Update.Name)"
		If (($null -ne $ThisHF.HotFixID) -and ((Compare-Object -ReferenceObject $ThisHF.HotFixID -DifferenceObject $Update.HotFixID -IncludeEqual).SideIndicator -contains '==')) {
			Write-Host "`tFound" -ForegroundColor Green
		} else {
			Write-Host "`tNot Installed" -ForegroundColor Yellow
			Write-Host "`tDownloading"
			If ($null -eq $UpdateCollection.Selectors.Source) {
				$Source = $Update.Source
			} else {
				$Source = $Update.Source.$($ExecutionContext.InvokeCommand.ExpandString("$($UpdateCollection.Selectors.Source)"))
			}
			If ($null -eq $Source) {
				Write-Host "`tSource not found - Unsupported?" -ForegroundColor Red
				Continue
			}
			$f = Invoke-DownloadFile -Uri $Source
			Write-Host "`tInstalling"
			$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList $f,'/quiet','/norestart' -Wait -PassThru
			Switch ($r.ExitCode) {
				0x0			{ Write-Host "`tInstalled successfully"; Break }
				0x00240006	{ Write-Host "`tUpdate already installed"; Break }
				0x00240005	{ Write-Host "`tInstalled, Pending reboot"; $RebootRequired = $true; Break }
				0x0BC2		{ Write-Host "`tInstalled, Pending reboot"; $RebootRequired = $true; Break }
				{$_ -gt 0 }	{
					Write-Host "`t`t`Installation returned $($r.ExitCode) 0x$('{0:X8}' -f $r.ExitCode)" -ForegroundColor Yellow
					Throw "Installation Failed."
				}
			}
		}
	}
	Break;
}

If ($RebootRequired) { Write-Host "Reboot Needed!" }
Write-Host ('Script Finished ').PadRight(80,'-')
