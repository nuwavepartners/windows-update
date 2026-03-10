# Update-Windows Scripts Help

This document provides help for the Windows update PowerShell scripts: `Update-Windows.ps1` and `Update-WindowsNative.ps1`.

## SYNOPSIS

These scripts automate the process of querying, downloading, and installing Windows updates.

## DESCRIPTION

There are two primary scripts for applying updates, depending on the required approach:

### 1. Update-Windows.ps1

This script is designed to simplify the process of keeping a Windows machine up-to-date by using a predefined JSON configuration file to determine which updates are applicable. It performs the following actions:

* **Checks Prerequisites**: Verifies that the script is run with administrator privileges and that the PowerShell version is 3.0 or higher.
* **Loads Configuration**: Downloads a JSON file containing the update policies. By default, it uses the configuration from the NuWave Partners GitHub repository.
* **System Analysis**: Gathers information about the local operating system, including the caption, version, and a list of installed hotfixes.
* **End-of-Life Check**: Cross-references the OS version with a list of end-of-life dates to warn if the operating system is no longer supported.
* **Update Discovery**: Matches the system's OS details with the update policies in the configuration file to find relevant updates.
* **Installation**: Downloads and installs any missing updates using `wusa.exe`. The script will notify you if a reboot is required.

### 2. Update-WindowsNative.ps1

This script leverages the native Windows Update API (`Microsoft.Update.Session`) to search for and install updates. It performs the following actions based on the provided `-Action` parameter:

* **Checks Prerequisites**: Verifies administrator privileges and PowerShell version.
* **Search**: Initiates a background scan using the Windows Update Agent (`DetectNow`).
* **List**: Queries the Windows Update API constraints for missing updates and lists what is available.
* **Install**: Sequences a full scan, download, and installation of all applicable updates natively, tracking reboot requirements.

## PARAMETERS

### Update-Windows.ps1
* **`-PolicyUri <string>`**: Specifies the URL of the JSON configuration file that contains the update policies.
  * **Required**: False
  * **Default**: `https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json`

### Update-WindowsNative.ps1
* **`-Action <string>`**: Modifies the behavior of the native Windows Update call.
  * **Valid Values**: `Search`, `List`, `Install`
  * **Required**: False
  * **Default**: `Install`

## EXAMPLES

### Example 1: Installing Updates via Policy (Default)

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1')))
```

### Example 2: Installing Updates via Native API

```powershell
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-WindowsNative.ps1')))
```

### Example 3: Finding Available Updates via Native API

```powershell
.\Update-WindowsNative.ps1 -Action List
```

## NOTES

* **Administrator Privileges**: These scripts must be run in a PowerShell session with elevated (Administrator) privileges.
* **PowerShell Version**: Requires PowerShell version 3.0 or higher.
* **Internet Connection**: An active internet connection is necessary to download the configuration file and the Windows updates.
* **Exit Codes (Policy mode)**: The script uses `wusa.exe` to install updates natively.
  * `0x0`: The update installed successfully.
  * `0x00240006`: The update is already installed.
  * `0x00240005` or `0x0BC2`: The update was installed and a reboot is required.