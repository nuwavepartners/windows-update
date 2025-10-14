<#
.NOTES
	Author:			Chris Stone <chris.stone@nuwavepartners.com>
	Date-Modified:	2025-10-10 13:07:24
#>
#Requires -Version 7

################################## FUNCTIONS ###################################

function Get-WUCSearch {
	Param (
		[string]	$Query,
		[int]		$Limit = 1,
		[Uri]		$Uri = 'https://www.catalog.update.microsoft.com/Search.aspx'
	)
	$SearchResults = (Invoke-WebRequest -Uri $Uri -Method Post -Body ('q={0}' -f $Query)).Links | Where-Object id -Like '*_link' | Select-Object -First $Limit

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

# Load existing policy file if it exists
$ExistingPolicy = $null
If (Test-Path -Path ".\Windows-UpdatePolicy.json") {
    Write-Output "Loading existing policy file"
    $ExistingPolicy = Get-Content -Path ".\Windows-UpdatePolicy.json" | ConvertFrom-Json
}

# Load OS Mapping Data from external JSON file
$OSs = Get-Content -Path ".\Windows-Mapping.json" | ConvertFrom-Json

# EoL Information
$EoLURI = 'https://endoflife.date/api/windows.json'
$EoL = (New-Object System.Net.WebClient).DownloadString($EoLURI) | ConvertFrom-Json

# Define Update Search Specifications using embedded JSON
$WUSpec = @'
[
    {
        "VersionSpec": ">=10.0.0",
        "QueryString": "'\"Cumulative Update for {0} for x64-based Systems\" -Dynamic'"
    },
    {
        "VersionSpec": "<10.0.0",
        "QueryString": "'\"Security Monthly Quality Rollup for {0} for x64-based Systems\" -Dynamic'"
    },
    {
        "VersionSpec": "*",
        "QueryString": "'\"Microsoft .NET Framework\" 4.8 for \"{0}\"'"
    },
    {
        "VersionSpec": "*",
        "QueryString": "'\"Cumulative Update for .NET Framework {0} for x64\"'"
    },
    {
        "VersionSpec": "<=6.3.9600",
        "QueryString": "'{0} \"KB3191564\"'"
    },
    {
        "VersionSpec": "==6.2.9200",
        "QueryString": "'{0} \"KB3191565\"'"
    }
]
'@ | ConvertFrom-Json

$WUs = @()

# Single loop to process all operating systems
Foreach ($OS in $OSs) {

	# Check End of Life status before searching for updates
	$EoLInfo = $EoL | Where-Object { $_.latest -eq $OS.Version } | Sort-Object { [datetime]$_.eol } -Descending | Select-Object -First 1
	If (($null -ne $EoLInfo) -and ([datetime]$EoLInfo.eol -lt (Get-Date).AddDays(-30))) {
		Write-Output ("`t{0} past End of Life ({1}). Copying from existing policy." -f $OS.WUName, ([datetime]$EoLInfo.eol).ToString('yyyy-MM-dd'))

        $ExistingOSUpdates = $null
        if ($null -ne $ExistingPolicy) {
            $ExistingOSUpdates = ($ExistingPolicy.WindowsUpdate | Where-Object { $_.OS.Version -eq $OS.Version }).Updates
        }

		$WUs += @{
			OS      = @{
				Caption = $OS.Caption;
				Version = $OS.Version
			}
			Updates = if ($null -ne $ExistingOSUpdates) { $ExistingOSUpdates } else { @() }
		}
		Continue
	}

	Write-Output ("Finding updates for {0}" -f $OS.WUName)

	[System.Collections.Generic.List[Hashtable]]$SearchUpdates = @()
	$OSVersion = [version]$OS.Version

	# Find applicable updates based on version specification
	Foreach ($Spec in $WUSpec) {
		$VersionCheck = switch -Regex ($Spec.VersionSpec) {
			'^\*'          { $true }
			'^>=([0-9.]+)' { $OSVersion -ge [version]$Matches[1] }
			'^>([0-9.]+)'  { $OSVersion -gt [version]$Matches[1] }
			'^<=([0-9.]+)' { $OSVersion -le [version]$Matches[1] }
			'^<([0-9.]+)'  { $OSVersion -lt [version]$Matches[1] }
			'^==([0-9.]+)' { $OSVersion -eq [version]$Matches[1] }
			default        { $false }
		}

		If ($VersionCheck) {
			$Query = $Spec.QueryString -f $OS.WUName
			$SearchUpdates.Add((Get-WUCSearch -Query $Query))
		}
	}

	$SearchUpdates.RemoveAll({ $args[0] -eq $null }) | Out-Null
	$WUs += @{
		OS      = @{
			Caption = $OS.Caption;
			Version = $OS.Version
		}
		Updates = $SearchUpdates.ToArray()
	}
}

# Generate the final policy file
$Out = @{
	_meta         = @{
		Date_Modified = (((Get-Date).ToUniversalTime() | Get-Date -f 's') + 'Z')
	};
	WindowsUpdate = $WUs;
	WindowsEoL    = $EoL
}

$Out | ConvertTo-Json -Depth 9 -AsArray | Out-File -FilePath ".\Windows-UpdatePolicy.json"

Write-Output ('Script Finished ').PadRight(80, '-')
