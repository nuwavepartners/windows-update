# Update-Windows.ps1 Help

This document provides help for the `Update-Windows.ps1` PowerShell script.

## SYNOPSIS

The `Update-Windows.ps1` script automates the process of downloading and installing Windows updates.

## DESCRIPTION

This script is designed to simplify the process of keeping a Windows machine up-to-date. It uses a predefined JSON configuration file to determine which updates are applicable to the system. The script performs the following actions:

* **Checks Prerequisites**: Verifies that the script is run with administrator privileges and that the PowerShell version is 3.0 or higher.

* **Loads Configuration**: Downloads a JSON file containing the update policies. By default, it uses the configuration from the NuWave Partners GitHub repository.

* **System Analysis**: Gathers information about the local operating system, including the caption, version, and a list of installed hotfixes.

* **End-of-Life Check**: Cross-references the OS version with a list of end-of-life dates to warn if the operating system is no longer supported.

* **Update Discovery**: Matches the system's OS details with the update policies in the configuration file to find relevant updates.

* **Installation**: Downloads and installs any missing updates. The script will notify you if a reboot is required to complete the installation.

## SYNTAX

```
.\Update-Windows.ps1 [-Configs <string>]

```

## PARAMETERS

### -Configs `<string>`

Specifies the URL of the JSON configuration file that contains the update policies.

* **Required**: False

* **Default Value**: `https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Windows-UpdatePolicy.json`

## EXAMPLES

### Example 1: Basic Usage

This example shows how to run the script with the default configuration. This is the most common use case.

```
[Net.ServicePointManager]::SecurityProtocol = [System.Enum]::GetValues([System.Net.SecurityProtocolType]) | Where-Object { $_ -match 'Tls' };
& ([scriptblock]::Create((New-Object System.Net.WebClient).DownloadString('[https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1](https://raw.githubusercontent.com/nuwavepartners/windows-update/main/Update-Windows.ps1)')))

```

### Example 2: Using a Custom Configuration File

This example demonstrates how to run the script with a custom configuration file hosted at a different URL.

```
.\Update-Windows.ps1 -Configs '[https://your-server.com/path/to/your/Custom-UpdatePolicy.json](https://your-server.com/path/to/your/Custom-UpdatePolicy.json)'

```

## NOTES

* **Administrator Privileges**: This script must be run in a PowerShell session with elevated (Administrator) privileges.

* **PowerShell Version**: Requires PowerShell version 3.0 or higher.

* **Internet Connection**: An active internet connection is necessary to download the configuration file and the Windows updates.

* **Exit Codes**: The script uses `wusa.exe` to install updates. The exit codes are interpreted as follows:

  * `0x0`: The update installed successfully.

  * `0x00240006`: The update is already installed.

  * `0x00240005`: The update was installed and a reboot is required.

  * `0x0BC2`: The update was installed and a reboot is required.