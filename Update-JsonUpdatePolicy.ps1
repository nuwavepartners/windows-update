<#
.NOTES
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2025-06-11 11:44:08
#>
#Requires -Version 7

################################## FUNCTIONS ##################################

function Get-WUCSearch {
	Param (
		[string]	$Query,
		[Uri]		$Uri = 'https://www.catalog.update.microsoft.com/Search.aspx'
	)
	$SearchResults = (Invoke-WebRequest -Uri $Uri -Method Post -Body ('q={0}' -f $Query)).Links | Where-Object id -Like '*_link'

	If (!$SearchResults.Count) { return $null }

	return $SearchResults | ForEach-Object {
		$UpdateID = $_.id -replace '_link', ''
		$Title = ($_.outerHTML -replace '<.+>', '').Trim()
		$KBN = [Regex]::Matches($Title, 'KB\d+')[0].Value
		$Source = Get-WUCDownload $UpdateID
		return @{
			UpdateID    = $UpdateID
			Title       = $Title
			KBArticleID = $KBN
			Source      = $Source
		} } | Sort-Object -Property 'KBArticleID' -Descending
}

function Get-WUCDownload {
	Param (
		[string]	$updateId,
		[Uri]		$Uri = 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx'
	)
	$DownloadResults = Invoke-WebRequest -Uri $Uri -Method "POST" -Body ('updateIDs=[{"updateID":"#"}]' -replace '#', $updateId)
	Return (($DownloadResults.Content -split '\r?\n').Trim() -match '^downloadInformation\[0\].files\[0\].url' -split ' ')[-1].Replace("'", "").Replace(";", "")
}

################################## THE SCRIPT ##################################

Write-Output ('Script Started ').PadRight(80, '-')

$WUs = @()

# Windows 10.x
$ModernOSs = @(
	@{WUName = "Windows 10 Version 1507"; Caption = "Microsoft Windows 10"; Version = "10.0.10240" },
	@{WUName = "Windows 10 Version 1511"; Caption = "Microsoft Windows 10"; Version = "10.0.10586" },
	@{WUName = "Windows 10 Version 1607"; Caption = "Microsoft Windows 10"; Version = "10.0.14393" },
	@{WUName = "Windows 10 Version 1703"; Caption = "Microsoft Windows 10"; Version = "10.0.15063" },
	@{WUName = "Windows 10 Version 1709"; Caption = "Microsoft Windows 10"; Version = "10.0.16299" },
	@{WUName = "Windows 10 Version 1803"; Caption = "Microsoft Windows 10"; Version = "10.0.17134" },
	@{WUName = "Windows 10 Version 1809"; Caption = "Microsoft Windows 10"; Version = "10.0.17763" },
	@{WUName = "Windows 10 Version 1903"; Caption = "Microsoft Windows 10"; Version = "10.0.18362" },
	@{WUName = "Windows 10 Version 1909"; Caption = "Microsoft Windows 10"; Version = "10.0.18363" },
	@{WUName = "Windows 10 Version 20H1"; Caption = "Microsoft Windows 10"; Version = "10.0.19041" },
	@{WUName = "Windows 10 Version 20H2"; Caption = "Microsoft Windows 10"; Version = "10.0.19042" },
	@{WUName = "Windows 10 Version 21H1"; Caption = "Microsoft Windows 10"; Version = "10.0.19043" },
	@{WUName = "Windows 10 Version 21H2"; Caption = "Microsoft Windows 10"; Version = "10.0.19044" },
	@{WUName = "Windows 10 Version 22H2"; Caption = "Microsoft Windows 10"; Version = "10.0.19045" },
	@{WUName = "Windows 11"; Caption = "Microsoft Windows 11"; Version = "10.0.22000" },
	@{WUName = "Windows 11 Version 22H2"; Caption = "Microsoft Windows 11"; Version = "10.0.22621" },
	@{WUName = "Windows 11 Version 23H2"; Caption = "Microsoft Windows 11"; Version = "10.0.22631" },
	@{WUName = "Windows 11 Version 24H2"; Caption = "Microsoft Windows 11"; Version = "10.0.26100" },
	@{WUName = "Windows Server 2016"; Caption = "Microsoft Windows Server 2016"; Version = "10.0.14393" },
	@{WUName = "Windows Server 2019"; Caption = "Microsoft Windows Server 2019"; Version = "10.0.17763" },
	@{WUName = "Microsoft server operating system version 21H2"; Caption = "Microsoft Windows Server 2022"; Version = "10.0.20348" }
	#	@{WUName = "Microsoft server operating system, version 22H2"; Caption = "Microsoft Windows Server 2022"; Version = "10.0.20348" }
	@{WUName = "Microsoft server operating system version 23H2"; Caption = "Microsoft Windows Server 2022"; Version = "10.0.25398" }
	@{WUName = "Microsoft server operating system version 24H2"; Caption = "Microsoft Windows Server 2025"; Version = "10.0.26100"}
)

Foreach ($OS in $ModernOSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	[System.Collections.Generic.List[Hashtable]]$SearchUpdates = @(
			(Get-WUCSearch ('"Servicing Stack Update for {0} for x64-based Systems" -Preview' -f $OS.WUName) | Select-Object -First 1),
			(Get-WUCSearch ('"Cumulative Update for {0} for x64-based Systems" -Dynamic' -f $OS.WUName) | Select-Object -First 1),
			(Get-WUCSearch ('"Microsoft .NET Framework" 4.8 for "{0}"' -f $OS.WUName) | Select-Object -First 1),
			(Get-WUCSearch ('"Cumulative Update for .NET Framework {0} for x64"' -f $OS.WUName) | Select-Object -First 1)
	)
	$SearchUpdates.RemoveAll({ $args[0] -eq $null }) | Out-Null
	$WUs += @{
		OS      = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = $SearchUpdates.ToArray()
	}
}

# Windows 6.x
$Win63OSs = @(
	@{WUName = "Windows Server 2012 R2"; Caption = "Microsoft Windows Server 2012 R2"; Version = "6.3.9600" },
	@{WUName = "Windows 8.1"; Caption = "Microsoft Windows 8.1"; Version = "6.3.9600" },
	@{WUName = "Windows Server 2012"; Caption = "Microsoft Windows Server 2012"; Version = "6.2.9200" },
	@{WUName = "Windows 8"; Caption = "Microsoft Windows 8"; Version = "6.2.9200" },
	@{WUName = "Windows Server 2008 R2"; Caption = "Microsoft Windows Server 2008 R2"; Version = "6.1.7601" },
	@{WUName = "Windows 7"; Caption = "Microsoft Windows 7"; Version = "6.1.7601" }
)

Foreach ($OS in $Win63OSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	[System.Collections.Generic.List[Hashtable]]$SearchUpdates = @(
		(Get-WUCSearch ('"Servicing Stack Update for {0} for x64-based Systems" -Preview' -f $OS.WUName) | Select-Object -First 1),
		(Get-WUCSearch ('"Security Monthly Quality Rollup for {0} for x64-based Systems" -Dynamic' -f $OS.WUName) | Select-Object -First 1),
		(Get-WUCSearch ('"Microsoft .NET Framework" 4.8 for "{0}"' -f $OS.WUName) | Select-Object -First 1),
		(Get-WUCSearch ('"Cumulative Update for .NET Framework {0} for x64"' -f $OS.WUName) | Select-Object -First 1)
		(Get-WUCSearch ('{0} "KB3191564"' -f $OS.WUName) | Select-Object -First 1)
		(Get-WUCSearch ('{0} "KB3191565"' -f $OS.WUName) | Select-Object -First 1)
	)
	$SearchUpdates.RemoveAll({ $args[0] -eq $null }) | Out-Null
	$WUs += @{
		OS      = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = $SearchUpdates.ToArray()
	}
}

# EoL Information

$EoLURI = 'https://endoflife.date/api/windows.json'
$EoL = (New-Object System.Net.WebClient).DownloadString($EoLURI) | ConvertFrom-Json

# Generate

$Out = @{
	_meta         = @{
		Date_Modified = (((Get-Date).ToUniversalTime() | Get-Date -f 's') + 'Z')
	};
	WindowsUpdate = $WUs;
	WindowsEoL    = $EoL
}

$Out | ConvertTo-Json -Depth 9 -AsArray | Out-File -FilePath ".\Windows-UpdatePolicy.json"

$M