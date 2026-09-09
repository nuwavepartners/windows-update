# NuWave Windows Update Scripts

A collection of scripts to make updating a computer more convenient.

[![Update Windows Update Policy](https://github.com/nuwavepartners/windows-update/actions/workflows/update-policy.yml/badge.svg)](https://github.com/nuwavepartners/windows-update/actions/workflows/update-policy.yml)

## Scripts Overview

*   `Update-Windows.ps1`: Updates a computer based on a customized update configuration policy. Takes an optional `-PolicyUri` parameter.
*   `Update-WindowsNative.ps1`: Uses the native Windows Update API to Search, List, or Install updates. Takes an optional `-Action` parameter ('Search', 'List', or 'Install') and an optional `-Criteria` parameter.
*   `Update-WindowsUpdatePolicy.ps1`: Generates the `Windows-UpdatePolicy.json` configuration file based on Microsoft Update Catalog data. Takes an optional `-SkipEoL` switch (defaults to `$true`) to bypass searching for updates for operating systems past their End of Life. Run with `-SkipEoL:$false` to force a search for all OS versions.
*   `Upgrade-Windows11.ps1`: Downloads and executes the Windows 11 Upgrade Assistant. Optionally takes `-UpgradeNow` to execute the installer immediately, otherwise it places a shortcut on the desktop. It also accepts `-SkipReadinessCheck`, `-SkipSKUCheck`, and `-SkipESUCheck` switches to override upgrade blockers.

## Typical Usage

### Install Updates via Policy

Open a Windows PowerShell prompt as Administrator, paste this:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1')))
```

### Install Updates Natively

Open a Windows PowerShell prompt as Administrator, paste this:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-WindowsNative.ps1'))) -Action Install
```

## Compatibility

This project is intended to work on all Windows 6.0+ (Vista/Server 2008)  Operating Systems with PowerShell 3.0+; the oldest OSes may need Windows Management Framework and/or .NET Framework updates before the scripts function correctly.

## AI Usage Disclosure

This project utilizes AI coding assistants for code generation and debugging. All AI-generated code has been reviewed, tested, and validated by human maintainers.

## License

MIT License. Copyright (c) 2026. See [LICENSE](LICENSE) for details.
