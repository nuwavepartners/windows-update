# Update-WindowsUpdatePolicy.ps1

This file is for Internal Use only. It is used to generate the `Windows-UpdatePolicy.json` file, which is consumed by the `Update-WindowsByPolicy.ps1` script.

## PARAMETERS

### `-SkipEoL <switch>`
* Controls whether operating systems that have passed their End-of-Life date should have their updates dynamically retrieved from Microsoft Update Catalog.
* By default (`$true`), the script skips End-of-Life checks on older systems and directly copies their previous known configuration from an existing `Windows-UpdatePolicy.json`.
* Running with `-SkipEoL:$false` will force the script to search the Microsoft Update Catalog for updates for ALL operating systems, ignoring their support lifecycle.

## Policy Update Usage

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-WindowsUpdatePolicy.ps1')))
```
