# NuWave Windows Update Scripts

A collection of scripts to make updating a computer more convenient.

## Install Updates on a Client

Open a Windows PowerShell prompt as Administrator, paste this:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1')))
```

