# Set-WindowsUpdateUx.ps1

## Synopsis
Manages user access to Windows Update UX, hides the System Tray icon, and suppresses auto-reboots.

## Description
Designed for RMM execution in the SYSTEM context. This script configures a variety of registry keys in `HKLM` to either lock down or open up access to Windows Update settings and visibility. It evaluates two primary modes:

*   **UxMode**: Manages visual and interactive elements (e.g., the Settings menu, System Tray icons, and reboot notifications).
*   **WuMode**: Manages the core administrative lock that prevents any access to Windows Update.

The script checks for the existence of required registry paths and handles creation if missing. It provides verbose output of applied changes.

## Parameters

### `-SkipServiceRestart`
If specified, skips restarting the Windows Update (`wuauserv`) service after registry changes are applied. By default, the service is restarted to immediately apply any effective modifications.

### `-UxMode`
Determines if UX restrictions (Settings access, Tray icon, Auto-Reboot) are applied.
*   **Disable** (Default): Updates the registry to hide the System Tray icon, suppress reboot notifications, and prevent access to Windows Update settings.
*   **Enable**: Removes the UX restriction registry keys, restoring normal visibility and settings access.

### `-WuMode`
Determines if overall Windows Update access is allowed.
*   **Enable** (Default): Removes the `DisableWindowsUpdateAccess` registry key, granting the user access to Windows Update.
*   **Disable**: Sets `DisableWindowsUpdateAccess` to `1`, locking out user access to Windows Update features.

## Examples

### Restrict UX but allow general update access (Default behavior)
```powershell
.\Set-WindowsUpdateUx.ps1
```

### Enable UX and Enable Windows Update access (Revert to standard behavior)
```powershell
.\Set-WindowsUpdateUx.ps1 -UxMode Enable -WuMode Enable
```

### Completely disable UX and lock out Windows Update entirely
```powershell
.\Set-WindowsUpdateUx.ps1 -UxMode Disable -WuMode Disable
```

## Additional Information
*   **Author**: Chris Stone
*   **Version**: 1.4.2
*   **Requirements**: Administrative privileges (HKLM access needed).
