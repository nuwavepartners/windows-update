#### By Chris Stone <chris.stone@nuwavepartners.com> v0.2.79 2020-03-17T18:41:52.015Z

Param (
	$Configs = 'https://vcs.nuwave.link/git/windows/update/blob_plain/HEAD:/wu.json'
)

If (!(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-Host -ForegroundColor Red "Script must be run as Administrator"
	Return
}

If (((Get-Module -ListAvailable NuWave-Common) |? {$_.Version -ge [version]"0.3.3"}).Count -lt 1) {
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls11;
	iex ((New-Object System.Net.WebClient).DownloadString('https://vcs.nuwave.link/git/powershell/nuwave-common/blob_plain/master:/install.ps1'))
	If (!(Import-Module -PassThru -Name NuWave-Common)) {
		Throw "Could not load or install NuWave-Common Module"
	}
}

################################## FUNCTIONS ###################################

Function Load-JsonConfig {
Param (
	[Parameter(Mandatory=$true)]
	[Uri]	$Uri
)
	$t = $Uri -as [System.URI]
	If (($t.AbsoluteURI-ne $null) -and ($t.Scheme -match '[http|https]')) {
		Return Invoke-DownloadJson $Uri
	} else {
		Return $(Get-Content $Uri.OriginalString -Raw | ConvertFrom-Json)
	}
}

################################## THE SCRIPT ##################################

Set-DebugFile 'C:\NuWave.log'
Out-Debug (__FILE__ + ' Script Started ' + '-' * 60)
$RebootRequired = $false

# Load Configuration(s)
Out-Debug ("Retrieving configurations")
$Conf = New-Object PSCustomObject
Foreach ($Config in $Configs) {
	Foreach ($P in (($t = Load-JsonConfig $Config).PSObject.Properties.Name -notmatch "^_")) {
		Add-Member -InputObject $Conf -MemberType NoteProperty -Name $P -Value $t.$P -Force
	}
}

Out-Debug 'Collecting current computer configuration'
$ThisOS = GWMI Win32_OperatingSystem
$ThisHF = Get-HotFix

:lCollection Foreach ($UpdateCollection in $Conf.WindowsUpdate) {

	# Check each qualifier from the config
	Foreach ($Qualifier in $UpdateCollection.OS.PSObject.Properties.Name) {
		If ($ThisOS.$Qualifier -inotmatch $UpdateCollection.OS.$Qualifier) {
			Continue lCollection
		}
	}

	Out-Debug ('Found Updates for ' + $UpdateCollection.OS.Caption)

	$UpdateCollection.Selectors.PSobject.Properties |% {
		$UpdateCollection.Selectors.$($_.Name) = $ExecutionContext.InvokeCommand.ExpandString($_.Value)
	}

	Foreach ($Update in $UpdateCollection.Updates) {
		Out-Debug "Searching for $($Update.HotFixID)"
		If (($ThisHF | Select -ExpandProperty HotFixID) -contains $Update.HotFixID) {
			Out-Debug "    Found $($Update.HotFixID) Installed"
		} else {
			Out-Debug "    Downloading $($Update.HotFixID)"
			If ($UpdateCollection.Selectors.Source -ne $null) {
				$f = Invoke-DownloadFile -Uri $Update.Source -Progress
			} else {
				$f = Invoke-DownloadFile -Uri $Update.$($UpdateCollection.Selectors.Source) -Progress
			}
			Out-Debug "    Installing $($Update.HotFixID)"
			$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList $f,'/quiet','/norestart' -Wait -PassThru
			Switch ($r.ExitCode) {
				0x00240006	{ Out-Debug "    Update already installed" }
				0x00240005	{ Out-Debug "    Installed, Pending reboot"; $RebootRequired = $true }
				default		{
					Out-Debug "    Installation returned $($r.ExitCode) 0x$('{0:X8}' -f $r.ExitCode)"
					Throw "Installation Failed."
				}
			}
		}
	}
}

If ($RebootRequired) { Write-Host "Reboot Needed!" }
Out-Debug (__FILE__ + ' Script Finished ' + '-' * 60)
