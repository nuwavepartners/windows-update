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
*   **Disable** (Default): Updates the registry to hide the System Tray icon, suppress reboot notifications, prevent access to Windows Update settings, and hide the Windows Update page (plus its sub-pages: action, history, restart options) from the Settings app entirely via `SettingsPageVisibility`.
*   **Enable**: Removes the UX restriction registry keys, restoring normal visibility and settings access, including un-hiding the Windows Update Settings page.

The Settings-page hide exists because on machines where the Windows Update Orchestrator is disabled in favor of direct WUA COM automation (see `Update-WindowsNative.ps1`), the Settings app's Windows Update page shows permanently stale "available updates" data from the disabled Orchestrator - it can never refresh, and users file support tickets over it. Hiding the page removes the confusion at the source rather than just restricting interaction with it. The `SettingsPageVisibility` registry value is shared - other tools/policies could also use it to hide unrelated Settings pages - so this script merges its own page identifiers into whatever is already there (and removes only its own identifiers on `-UxMode Enable`) rather than overwriting the whole value. If the existing value is in the `showonly:` (allow-list) format, or an unrecognized format, the script leaves it untouched rather than guess.

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
*   **`-WhatIf` / `-Confirm`**: Supported. Every registry key/property change and the `wuauserv` restart are gated behind `ShouldProcess`, so `-WhatIf` previews changes without applying them.
