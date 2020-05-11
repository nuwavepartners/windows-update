#### By Chris Stone <chris.stone@nuwavepartners.com> v0.2.136 2020-05-06T13:57:18.486Z

Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Windows-UpdatePolicy.json'
)

If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host -ForegroundColor Red "Script must be run as Administrator"
	Return
}

################################## FUNCTIONS ##################################

function Convert-DisplayBytes($num)
{
    [System.Collections.ArrayList]$unit = @("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    while ($num -gt 1kb) {
        $num = $num / 1kb
        $unit.Remove($unit[0])
    }
    Return "{0:N1} {1}" -f $num, $unit[0]
}

function Invoke-DownloadFile {
Param (
	[Parameter(Mandatory=$true)]	[uri] $Uri,
									[string] $Path = $Env:TEMP,
									[Switch] $Progress,
	[Parameter(Mandatory=$false)]	[uri] $Proxy,
	[Parameter(Mandatory=$false)]	[System.Net.ICredentials] $ProxyCred
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
		# Assert
		If ($bDownloaded -gt ($bLengthTotal * 2)) { Throw "Downloaded file significantly bigger than expected" }
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

Function Load-JsonConfig {
Param (
	[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
	[Uri[]]	$Uri
)
	Begin {
		$Ret = New-Object PSCustomObject
	}
	Process {
		Foreach ($u in $Uri) {
			# Get the JSON
			Switch -Regex ($u.Scheme) {
				'http|https' 	{	$t = Invoke-DownloadJson $u; Break }
				'file'			{	$t = $(Get-Content -Raw -Path $u.OriginalString | ConvertFrom-Json); Break }
				Default			{	Throw "Unsupport Uri Scheme $_" }
			}
			# Add to the Return Object
			Foreach ($P in ($t.PSObject.Properties.Name -notmatch "^_")) {
				Add-Member -InputObject $Ret -MemberType NoteProperty -Name $P -Value $t.$P -Force
				If ($t._meta -ne $null) {
					Add-Member -InputObject $Ret.$P -MemberType NoteProperty -Name '_meta' -Value $t._meta -Force
				}
			}
		}
	}
	End {
		Return $Ret
	}
}

function Get-CustomerSiteProperty {
Param (
	[Object[]]			$Sites,
	[string]			$Property
)
Begin {
	$LocalIPs = Get-WmiObject Win32_NetworkAdapterConfiguration |?{$_.IPAddress} | Select -Expand IPAddress |? {$_ -match '(\d+\.){3}\d+'}
}
Process {
	Foreach ($Site in ($Sites |? {($_.Subnet -match '(\d+\.){3}\d+/\d+') -and ($_.$Property -ne $null)})) {
		#Site Info
		$SubnetMask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - ($Site.Subnet.Split('/')[1] -as [int])))
		$SiteIPAddr = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($Site.Subnet.Split('/')[0])).GetAddressBytes()), 0)

		# Check each Local IP against the Site
		Foreach ($LocalIP in $LocalIPs) {
			$LocalIPAddr = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($LocalIP).GetAddressBytes()), 0)

			If (($SiteIPAddr -band $SubnetMask) -eq ($LocalIPAddr -band $SubnetMask)) {
				$Ret = $Site.$Property
			}
		}
	}
}
End {
	If ($Ret -eq $null) {
		$Ret = ($Sites |? {$_.Default -eq $true}).$Property
	}
	Return $Ret
}
}

function Test-SoftwareVerify {
Param (
	[object] $SoftwareSpec
)
	If ($SoftwareSpec.Verify -eq $null) { Return 0 }
	$self = $SoftwareSpec #For reflection in Json
	Foreach ($SoftVerf in $SoftwareSpec.Verify.PSObject.Properties) {
		Switch -regex ($SoftVerf.Name) {
			'^Service$'	{
				#Check if service exists...
				$Service = Get-Service -Name $SoftVerf.Value -ErrorAction SilentlyContinue
				If ($Service -ne $null) {
					If ($Service.Status -eq 'Running') {
						Continue
					} else {
						If ((Start-Service $Service -ErrorAction SilentlyContinue -PassThru).Status -ne 'Running') {
							Return -1
						} else {
							Continue
						}
					}
				} else {
					Return -1
				}
			}
			'GPV' {
				#Get Item Property Value...
				$SoftVerf.Value.PSObject.Properties |% {
					# TODO Fix string expansion?
					$SoftVerf.Value.$($_.Name) = $ExecutionContext.InvokeCommand.ExpandString($_.Value)
				}

				# TODO Implement support for multiple dereferencing
				$PropSpec = ($SoftVerf.Value.Property -split '\.')
				If ($PropSpec.Count -le 1) {
					$Prop = (Get-ItemProperty -Path $SoftVerf.Value.Path).$($PropSpec[0])
				} else {
					$Prop = (Get-ItemProperty -Path $SoftVerf.Value.Path).$($PropSpec[0]) | Select -Expand $PropSpec[1]
				}

				# TODO Implement better Datatyping
				If ($null -ne $SoftVerf.Value.Datatype) {
					iex ('$r = $Prop ' + $SoftVerf.Value.Operator + ' ' + $SoftVerf.Value.Value)
				} else {
					iex ('$r = $Prop ' + ' -as [' + $SoftVerf.Value.Datatype + '] ' + $SoftVerf.Value.Operator + ' ' + $SoftVerf.Value.Value)
				}

				If ($r) {
					Continue
				} else {
					Return -1
				}

			}
			Default {
				throw "Unsupported or Malformed Software Verification Method: $($SoftVerf.Name)"
			}
		}
	}
	Return 0
}

function Install-Software {
Param (
	[object]	$SoftwareSpec,
	[switch]	$Progress
)

	$TempFile = Invoke-DownloadFile $SoftwareSpec.Installer.Source -Progress:$Progress.IsPresent

	Switch ( $SoftwareSpec.Installer.Type ) {
		"MSI" {
			$R = Install-MSIProduct -PassThru -Path $TempFile -Properties $SoftwareSpec.Installer.Arguments
		}
		"EXE" {
			$R = Start-Process -PassThru -Wait -FilePath $TempFile -ArgumentList $SoftwareSpec.Installer.Arguments
		}
		"MSU" {
			if (!(Test-Path $env:systemroot\SysWOW64\wusa.exe)) {
			  $pWusa = "$env:systemroot\System32\wusa.exe"
			} else {
			  $pWusa = "$env:systemroot\SysWOW64\wusa.exe"
			}
			$R = Start-Process -FilePath $pWusa -ArgumentList ($TempFile, '/quiet', '/norestart', $SoftwareSpec.Installer.Arguments) -Wait
		}
		default {
			throw "Unsupported Installer"
		}
	}

	return $R
}

################################## THE SCRIPT ##################################

Write-Host ('Script Started ').PadRight(80,'-')
$RebootRequired = $false

# Load Configuration(s)
Write-Host ("Loading configurations")
$Conf = Load-JsonConfig -Uri $Configs

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
		If ((Compare-Object -ReferenceObject $ThisHF.HotFixID -DifferenceObject $Update.HotFixID -IncludeEqual).SideIndicator -contains '==') {
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
