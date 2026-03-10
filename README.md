# NuWave Windows Update Scripts

A collection of scripts to make updating a computer more convenient.

## Scripts Overview

*   `Update-Windows.ps1`: Updates a computer based on a customized update configuration policy. Takes an optional `-PolicyUri` parameter.
*   `Update-WindowsNative.ps1`: Uses the native Windows Update API to Search, List, or Install updates. Takes an optional `-Action` parameter ('Search', 'List', or 'Install').
*   `Update-WindowsUpdatePolicy.ps1`: Generates the `Windows-UpdatePolicy.json` configuration file based on Microsoft Update Catalog data. Takes an optional `-SkipEoL` switch (defaults to `$true`) to bypass searching for updates for operating systems past their End of Life. Run with `-SkipEoL:$false` to force a search for all OS versions.

## Install Updates via Policy

Open a Windows PowerShell prompt as Administrator, paste this:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1')))
```

## Install Updates Natively

Open a Windows PowerShell prompt as Administrator, paste this:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-WindowsNative.ps1')))
```
