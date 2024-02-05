# NuWave Windows Update Scripts

A collection of scripts to make updating a computer more convenient.

## Client Quick Start

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://vcs.nuwave.link/git/windows/update/blob_plain/master:/Update-Windows.ps1')))
```

## Client Upgrade

TBA
