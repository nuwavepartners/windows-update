# Update-Windows.md Help

This document provides help for the Windows update PowerShell script: `Update-Windows.ps1`.

## SYNOPSIS

This script automates the process of querying, downloading, and installing Windows updates.

## DESCRIPTION

This script is designed to simplify the process of keeping a Windows machine up-to-date by using a predefined JSON configuration file to determine which updates are applicable. It performs the following actions:

* **Checks Prerequisites**: Verifies that the script is run with administrator privileges and that the PowerShell version is 3.0 or higher.
* **Loads Configuration**: Downloads a JSON file containing the update policies. By default, it uses the configuration from the NuWave Partners GitHub repository.
* **System Analysis**: Gathers information about the local operating system, including the caption, version, and a list of installed hotfixes.
* **End-of-Life Check**: Cross-references the OS version with a list of end-of-life dates to warn if the operating system is no longer supported.
* **Early Exit Check**: If the `-SkipRecentlyUpdated` parameter is provided, checks the date of the most recently installed update and exits early if it was installed within the specified number of days.
* **Update Discovery**: Matches the system's OS details with the update policies in the configuration file to find relevant updates.
* **Installation**: Depending on the `-Action` parameter, it will either list the applicable updates or download and install them using `wusa.exe`. The script will notify you if a reboot is required after an installation.

## PARAMETERS

*   **`-Action <string>`**: Modifies the behavior of the update policy application.
    *   **Valid Values**: `List`, `Install`
    *   **Required**: False
    *   **Default**: `Install`
*   **`-PolicyUri <string>`**: Specifies the URL of the JSON configuration file that contains the update policies.
    *   **Required**: False
    *   **Default**: `https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json`
*   **`-SkipRecentlyUpdated <int>`**: Skips the update execution process if the most recently installed update occurred within the specified number of days.
    *   **Required**: False
    *   **Default**: `0` (Disabled)

## EXAMPLES

### Example 1: Installing Updates via Policy (Default)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1')))
```

### Example 2: Finding Available Updates via Policy

```powershell
.\Update-Windows.ps1 -Action List
```

### Example 3: Skip Updates if Recently Installed

```powershell
.\Update-Windows.ps1 -SkipRecentlyUpdated 90
```

Convenient for running the script on a regular schedule, and catching up a server that has fallen behind on updates.

## NOTES

* **Administrator Privileges**: These scripts must be run in a PowerShell session with elevated (Administrator) privileges.
* **PowerShell Version**: Requires PowerShell version 3.0 or higher.
* **Internet Connection**: An active internet connection is necessary to download the configuration file and the Windows updates.
* **Exit Codes**: The script uses `wusa.exe` to install updates. Common exit codes for this process include:
  * `0x0`: The update installed successfully.
  * `0x00240006`: The update is already installed.
  * `0x00240005` or `0x0BC2`: The update was installed and a reboot is required.