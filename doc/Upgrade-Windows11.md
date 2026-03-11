# Upgrade-Windows11.md Help

This document provides help for the Windows 11 upgrade PowerShell script: `Upgrade-Windows11.ps1`.

## SYNOPSIS

Orchestrates the download and execution of the Windows 11 Upgrade Assistant.

## DESCRIPTION

This script performs all steps necessary to prepare for and initiate a Windows 11 upgrade. It is designed to be run as an administrator.

The script will:
1. Check for Administrator privileges.
2. Create a log directory at `C:\Temp\UpgradeLog`.
3. Run a hardware readiness check natively (unless `-SkipReadinessCheck` is used).
4. Check that the Windows Operating System SKU is in the supported range (unless `-SkipSKUCheck` is used).
5. Check if the system has an active Windows 10 Extended Security Updates (ESU) license, which blocks the upgrade natively (unless `-SkipESUCheck` is used).
6. Resolve the download URL and download the Windows 11 Installation Assistant to the temp folder.
7. Either execute the upgrade immediately (if `-UpgradeNow` is specified) or create a public desktop shortcut for a user to run the upgrade manually.

The upgrade is run quietly and will copy its logs to `C:\Temp\UpgradeLog`.

## PARAMETERS

*   **`-UpgradeNow`**: A switch parameter that, if present, causes the script to immediately execute the Windows 11 Installation Assistant in quiet mode.
    *   If omitted, the script will instead create a 'Upgrade Windows' shortcut on the public desktop (`C:\Users\Public\Desktop`).
*   **`-SkipReadinessCheck`**: A switch parameter that, if present, skips the Windows 11 hardware readiness check (which is performed by the `Test-Win11Readiness` function).
*   **`-SkipSKUCheck`**: A switch parameter that, if present, skips verifying the Windows SKU is valid for upgrade.
*   **`-SkipESUCheck`**: A switch parameter that, if present, skips checking for an active ESU license.

## EXAMPLES

### Example 1: Preparation Mode (Default)

```powershell
.\Upgrade-Windows11.ps1
```
**Description:** This is the default mode. The script runs the readiness check, downloads the installer, and creates a shortcut named "Upgrade Windows" on the public desktop. No upgrade is performed at this time.

### Example 2: Immediate Upgrade mode

```powershell
.\Upgrade-Windows11.ps1 -UpgradeNow
```
**Description:** Runs the readiness check, downloads the installer, and immediately begins the Windows 11 upgrade in quiet mode.

### Example 3: Immediate Upgrade mode without Readiness Check

```powershell
.\Upgrade-Windows11.ps1 -UpgradeNow -SkipReadinessCheck
```
**Description:** Skips the hardware readiness check, downloads the installer, and immediately begins the Windows 11 upgrade in quiet mode. This is useful for testing or on machines that are known to be compatible.

## NOTES

*   **Administrator Privileges**: This script requires elevated (Administrator) privileges to execute properly.
*   **Internet Connection**: An active internet connection is necessary to download the Windows 11 Installation Assistant.
*   **Hardware Readiness**: The script uses a native readiness function, largely based on Microsoft's `HardwareReadiness.ps1` script.
