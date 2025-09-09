# Update-JsonUpdatePolicy.ps1

This file is for Internal Use only, do not run this on end user systems.
Used to generate the Windows-UpdatePolicy.json file used by the Update-Windows.ps1 script.

## Policy Update

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-JsonUpdatePolicy.ps1')))
```