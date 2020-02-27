#### By Chris Stone <chris.stone@nuwavepartners.com> v0.2.59 2020-02-27T17:15:36.305Z

$UpdateConfigUri = 'https://vcs.nuwave.link/git/windows/update/blob_plain/devel:/wu.json'

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

Set-DebugFile 'C:\NuWave.log'
Out-Debug ('' + __FILE__ + ' Script Started ' + '-' * 60)
$RebootRequired = $false

Out-Debug 'Downloading Windows Update Configuration'
$UpdateConfig = Invoke-DownloadJSON $UpdateConfigUri


Out-Debug 'Collecting current computer configuration'
$ThisOS = GWMI Win32_OperatingSystem
$ThisHF = Get-HotFix

:lCollection Foreach ($UpdateCollection in $UpdateConfig.WindowsUpdate) {

	# Check each qualifier from the config
	Foreach ($Qualifier in $UpdateCollection.OS.PSObject.Properties.Name) {
		If ($ThisOS.$Qualifier -inotmatch $UpdateCollection.OS.$Qualifier) {
			Continue lCollection
		}
	}

	Out-Debug ('Found Updates for ' + $UpdateCollection.OS.Caption)

	Foreach ($Update in $UpdateCollection.Updates) {
		Out-Debug "Searching for $($Update.HotFixID)"
		If (($ThisHF | Select -ExpandProperty HotFixID) -contains $Update.HotFixID) {
			Out-Debug "    Found $($Update.HotFixID) Installed"
		} else {
			Out-Debug "    Downloading $($Update.HotFixID)"
			$f = Invoke-DownloadFile -Uri $Update.Source -Progress
			Out-Debug "    Installing $($Update.HotFixID)"
			$r = Start-Process -FilePath 'C:\Windows\System32\wusa.exe' -ArgumentList $f,'/quiet','/norestart' -Wait -PassThru
			Switch ($r.ExitCode) {
				0x00240006	{ Out-Debug "    Update already installed" }
				0x00240005	{ Out-Debug "    Installed, Pending reboot"; $RebootRequired = $true }
				default		{ Out-Debug "    Installation returned $($r.ExitCode)" }
			}
		}
	}
}

If ($RebootRequired) { Restart-Computer }
Out-Debug ('' + __FILE__ + ' Script Finished ' + '-' * 60)
