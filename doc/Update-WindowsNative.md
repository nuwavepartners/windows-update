# Update-WindowsNative.md Help

This document provides help for the Windows update PowerShell script: `Update-WindowsNative.ps1`.

## SYNOPSIS

This script automates the process of querying, downloading, and installing Windows updates natively using the Windows Update Agent COM objects.

## DESCRIPTION

This script leverages the native Windows Update API (`Microsoft.Update.Session`) to search for and install updates. It performs the following actions based on the provided `-Action` parameter:

*   **Checks Prerequisites**: Verifies administrator privileges and PowerShell version.
*   **Search**: Initiates a background scan using the Windows Update Agent (`DetectNow`).
*   **List**: Queries the Windows Update API constraints for missing updates and lists what is available.
*   **Install**: Sequences a full scan, download, and installation of all applicable updates natively, tracking reboot requirements.

## PARAMETERS

*   **`-Action <string>`**: Modifies the behavior of the native Windows Update call.
    *   **Valid Values**: `Search`, `List`, `Install`
    *   **Required**: False
    *   **Default**: `Install`
*   **`-Criteria <string>`**: The query string used to search for updates.
    *   **Required**: False
    *   **Default**: `IsInstalled=0 AND IsHidden=0`

## EXAMPLES

### Example 1: Installing Updates via Native API (Default)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-WindowsNative.ps1')))
```

### Example 2: Finding Available Updates via Native API

```powershell
.\Update-WindowsNative.ps1 -Action List
```

## NOTES

*   **Administrator Privileges**: This script must be run in a PowerShell session with elevated (Administrator) privileges.
*   **PowerShell Version**: Requires PowerShell version 3.0 or higher.
*   **Internet Connection**: An active internet connection is necessary to download the Windows updates.
