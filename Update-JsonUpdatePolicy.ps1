<#
.NOTES
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2024-02-02 14:12:02
#>
[CmdletBinding()]
Param (
)

################################## FUNCTIONS ##################################

Function Get-UpdateInfo {
Param (
	[string] $QV
)
	$Query = "
	SELECT TOP (1) u.UpdateID, lp.Title,
		(SELECT TOP (1) KBArticleID
			FROM dbo.tbKBArticleForRevision
			WHERE RevisionID = r.RevisionID
			ORDER BY KBArticleID DESC) AS KBArticleID
	FROM tbLocalizedProperty AS lp
	LEFT JOIN tbLocalizedPropertyForRevision AS lpfr ON lpfr.LocalizedPropertyID = lp.LocalizedPropertyID
	LEFT JOIN tbRevision AS r ON r.RevisionID = lpfr.RevisionID
	LEFT JOIN tbUpdate AS u ON u.LocalUpdateID = r.LocalUpdateID
	LEFT JOIN tbKBArticleForRevision AS kbafr ON kbafr.RevisionID = lpfr.RevisionID
	WHERE lp.Title like '#' AND lpfr.LanguageID = 1033
	ORDER BY KBArticleID DESC"
	$R = Invoke-Sqlcmd -Query $Query.Replace('#', $QV) -ServerInstance "localhost\SQLEXPRESS" -Database "SUSDB" -OutputAs DataRows | Select-Object * -ExcludeProperty ItemArray, Table, RowError, RowState, HasErrors
	If ($null -ne $R) {
		$URL = (((Invoke-WebRequest -Uri "https://www.catalog.update.microsoft.com/DownloadDialog.aspx" -Method "POST" -Body ('updateIDs=[{"updateID":"'+ $R.UpdateID + '"}]')).Content -split '\r?\n').Trim() -match '^downloadInformation\[0\].files\[0\].url' -split ' ')[-1].Replace("'","").Replace(";","")
		Add-Member -InputObject $R -MemberType NoteProperty -Name Source -Value $URL
	}
	Return $R
}

################################## THE SCRIPT ##################################

Write-Output ('Script Started ').PadRight(80,'-')

Write-Output ('Checking WSUS')
$WsusServer = Get-WsusServer
Write-Output ('Server: {0}' -f $WsusServer.Name)
$LastSync = $WsusServer.GetSubscription().GetLastSynchronizationInfo()
Write-Output ('Last Sync: {0} {1}' -f $LastSync.EndTime, $LastSync.Result)
if ($LastSync.EndTime -lt (Get-Date).AddDays(-3)) {
	Throw 'Outdated WSUS Synchronization'
}
if ($lastSync.Result -ne 'Succeeded') {
	Throw 'Last WSUS Synchronization not Succeeded'
}

$WUs = @()

# Windows 10, Server 2016/2019
$ModernOSs = @(
	@{WUName="Windows 10 Version 1507"; Caption="Microsoft Windows 10"; Version="10.0.10240"},
	@{WUName="Windows 10 Version 1511"; Caption="Microsoft Windows 10"; Version="10.0.10586"},
	@{WUName="Windows 10 Version 1607"; Caption="Microsoft Windows 10"; Version="10.0.14393"},
	@{WUName="Windows 10 Version 1703"; Caption="Microsoft Windows 10"; Version="10.0.15063"},
	@{WUName="Windows 10 Version 1709"; Caption="Microsoft Windows 10"; Version="10.0.16299"},
	@{WUName="Windows 10 Version 1803"; Caption="Microsoft Windows 10"; Version="10.0.17134"},
	@{WUName="Windows 10 Version 1809"; Caption="Microsoft Windows 10"; Version="10.0.17763"},
	@{WUName="Windows 10 Version 1903"; Caption="Microsoft Windows 10"; Version="10.0.18362"},
	@{WUName="Windows 10 Version 1909"; Caption="Microsoft Windows 10"; Version="10.0.18363"},
	@{WUName="Windows 10 Version 20H1"; Caption="Microsoft Windows 10"; Version="10.0.19041"},
	@{WUName="Windows 10 Version 20H2"; Caption="Microsoft Windows 10"; Version="10.0.19042"},
	@{WUName="Windows 10 Version 21H1"; Caption="Microsoft Windows 10"; Version="10.0.19043"},
	@{WUName="Windows 10 Version 21H2"; Caption="Microsoft Windows 10"; Version="10.0.19044"},
	@{WUName="Windows 10 Version 22H2"; Caption="Microsoft Windows 10"; Version="10.0.19045"},
	@{WUName="Windows 11";				Caption="Microsoft Windows 11"; Version="10.0.22000"},
	@{WUName="Windows 11 Version 22H2"; Caption="Microsoft Windows 11"; Version="10.0.22621"},
	@{WUName="Windows 11 Version 23H2"; Caption="Microsoft Windows 11"; Version="10.0.22631"},
	@{WUName="Windows Server 2016"; Caption="Microsoft Windows Server 2016"; Version="10.0.14393"},
	@{WUName="Windows Server 2019"; Caption="Microsoft Windows Server 2019"; Version="10.0.17763"},
	@{WUName="Microsoft server operating system version 21H2"; Caption="Microsoft Windows Server 2022"; Version="10.0.20348"}
#	@{WUName="Microsoft server operating system, version 22H2"; Caption="Microsoft Windows Server 2022"; Version="10.0.20348"}
	@{WUName="Microsoft server operating system version 23H2"; Caption="Microsoft Windows Server 2022"; Version="10.0.20348"}
)

Foreach ($OS in $ModernOSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	$WUs += @{
		OS = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = @(
			(Get-UpdateInfo -QV ("%Servicing Stack Update for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("%[0-9] Cumulative Update for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("Microsoft .NET Framework 4.8 for%" + $OS.WUName + "%")),
			(Get-UpdateInfo -QV ("%Cumulative Update for .NET Framework%" + $OS.WUName + " for x64%"))
		) | Where-Object { $_ }
	}
}

# Server 2012 R2 / 8.1
$Win63OSs = @(
	@{WUName="Windows Server 2012 R2"; Caption="Microsoft Windows Server 2012 R2"; Version="6.3.9600"},
	@{WUName="Windows 8.1"; Caption="Microsoft Windows 8.1"; Version="6.3.9600"}
)

Foreach ($OS in $Win63OSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	$WUs += @{
		OS = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = @(
			(Get-UpdateInfo -QV ("%Servicing Stack Update for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("%Security Monthly Quality Rollup for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("Microsoft .NET Framework 4.8 for%" + $OS.WUName + "%")),
			(Get-UpdateInfo -QV ("%Cumulative Update for .NET Framework%" + $OS.WUName + " for x64%")),
			(Get-UpdateInfo -QV ("%" + $OS.WUName + "%KB3191564%"))		# WMF5.1
		) | Where-Object { $_ }
	}
}

# Server 2012 / 8
$Win62OSs = @(
	@{WUName="Windows Server 2012"; Caption="Microsoft Windows Server 2012"; Version="6.2.9200"},
	@{WUName="Windows 8"; Caption="Microsoft Windows 8"; Version="6.2.9200"}
)

Foreach ($OS in $Win62OSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	$WUs += @{
		OS = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = @(
			(Get-UpdateInfo -QV ("%Servicing Stack Update for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("%Security Monthly Quality Rollup for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("Microsoft .NET Framework 4.8 for%" + $OS.WUName + "%")),
			(Get-UpdateInfo -QV ("%Cumulative Update for .NET Framework%" + $OS.WUName + " for x64%")),
			(Get-UpdateInfo -QV ("%" + $OS.WUName + "%KB3191565%"))		# WMF5.1
		) | Where-Object { $_ }
	}
}

# Server 2008 R2 / 7 (w/SP Only)
$Win6OSs = @(
	@{WUName="Windows Server 2008 R2"; Caption="Microsoft Windows Server 2008 R2"; Version="6.1.7601"},
	@{WUName="Windows 7"; Caption="Microsoft Windows 7"; Version="6.1.7601"}
)

Foreach ($OS in $Win62OSs) {
	Write-Output ("Finding updates for {0}" -f $OS.WUName)
	$WUs += @{
		OS = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = @(
			(Get-UpdateInfo -QV ("%Servicing Stack Update for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("%Security Monthly Quality Rollup for " + $OS.WUName + " for x64-based Systems%")),
			(Get-UpdateInfo -QV ("Microsoft .NET Framework 4.8 for%" + $OS.WUName + "%")),
			(Get-UpdateInfo -QV ("%Cumulative Update for .NET Framework%" + $OS.WUName + " for x64%")),
			(Get-UpdateInfo -QV ("%" + $OS.WUName + "%KB3191565%"))		# WMF5.1
		) | Where-Object { $_ }
	}
}

# Generate

$Out = @{
	_meta= @{
		Date_Modified=(((Get-Date).ToUniversalTime() | Get-Date -f 's') + 'Z')
	};
	WindowsUpdate= $WUs
}

$Out | ConvertTo-Json -Depth 99 | Out-File -FilePath ".\Windows-UpdatePolicy.json"

