# PowerShell Code Quality & Security Audit

**Audit Date:** September 8, 2026
**Remediation Date:** September 9, 2026 — 35/36 findings fixed, 1 left open with reasoning (see Remediation Status below)
**Target Repository:** Windows Update Automation Suite
**Scope:**
- `Set-WindowsUpdateUx.ps1`
- `Update-Windows.ps1`
- `Update-WindowsNative.ps1`
- `Update-WindowsUpdatePolicy.ps1`
- `Upgrade-Windows11.ps1`

---

## Executive Summary

This audit evaluates the repository against four core criteria:
1. **Security & Privilege:** Credential management, execution elevation, injection vectors, filesystem ACLs, and integrity validation.
2. **Error Handling & Robustness:** Terminating vs. non-terminating error actions, exception trapping, and resource lifecycle management (COM, Streams, Temp files).
3. **Edge Cases & Portability:** Parameter validation, PowerShell 5.1 vs. 7+ compatibility, type casting, and query limitations.
4. **PowerShell Best Practices & Structure:** Function architecture, pipeline discipline, approved verbs, and state-change safety (`SupportsShouldProcess`).

---

## Remediation Status

All 36 original findings have been triaged. 35 were fixed directly in the scripts (each verified — parsed, and where practical, run against live endpoints/data or isolated function tests, not just read), or otherwise confirmed resolved by the author. 1 remains open as an in-place annotation with reasoning rather than a guessed-at change:

| ID | File | Why it's still open |
| :--- | :--- | :--- |
| [REC-02](#1-set-windowsupdateuxps1) | `Set-WindowsUpdateUx.ps1` | Fixing it project-wide would need a shared-module refactor across all five `Write-Log` copies, and the naive per-file fix changes default-visible output; `Write-Information` also breaks the PS 3.0 compatibility floor these scripts require |

WARN-08 (COM object lifecycle in `Update-WindowsNative.ps1`) and WARN-16 (`WebRequest.CreateHttp`) were both reopened and fully resolved after follow-up input from the author clarified scope/constraints the original annotations were missing — see their entries below. REC-10 (`SoftwareLicensingProduct` WMI query) was confirmed resolved by the author, who considers the existing filter reasonable optimization as-is; benchmarking backed that up.

Several other findings were corrected rather than taken at face value — see the `Resolved, with a correction` / `Annotation` notes throughout for specifics (e.g. REC-06's `Receive-UpdateDownload` wasn't actually a violation, CRIT-07's crash didn't reproduce under testing, WARN-15's claimed speedup didn't hold up under benchmarking).

---

## File-by-File Detailed Findings

---

### 1. `Set-WindowsUpdateUx.ps1`

#### Critical Findings
* *[CRIT-01] Resolved — elevation check added ([Set-WindowsUpdateUx.ps1](../Set-WindowsUpdateUx.ps1)).*

---

#### Warning Findings

* *[WARN-01] Resolved — Restart-Service now wrapped in try/catch.*

* *[WARN-02] Resolved — property-existence check added before comparison.*

* *[WARN-03] Resolved — `$WuModeResg` renamed to `$WuModeReg` throughout.*

---

#### Recommendation Findings

* *[REC-01] Resolved — `SupportsShouldProcess` added; all registry/service mutations gated on `$PSCmdlet.ShouldProcess`.*

##### [REC-02] Direct Console Writing via `Write-Host`
* **Location:** Lines 58–60
  ```powershell
  Write-Host $FormattedMessage -ForegroundColor $ColorMap[$Level]
  ```
* **Criteria:** Output Stream Discipline
* **Failure Mode / Risk:** `Write-Host` bypasses standard PowerShell output streams (Information/Verbose/Warning/Error), preventing downstream automation from capturing or redirecting structured stream data.
* **Mitigation Snippet:** Use `Write-Information`, `Write-Verbose`, and `Write-Warning` with message tags.
* **Annotation (not applied):** This is identical `Write-Log` code shared verbatim across all five scripts — and across other scripts/projects outside this repo, per the author — and the `Write-Host` branch only runs when `[Environment]::GetCommandLineArgs()` does **not** contain `-NonInteractive`; the NonInteractive branch already routes through `[Console]::WriteLine`, which is the actual fix for RMM/automation capture (stdout), and appears to be a deliberate prior fix for exactly this class of problem. Rerouting the interactive branch to standard streams would be a behavior change, not a pure cleanup: those streams are silent by default (`$VerbosePreference`/`$WarningPreference` etc. = `SilentlyContinue`/off) unless the caller opts in, so TRACE/INFO-level lines that are unconditionally visible today would silently disappear for anyone running the script interactively without extra flags.

  The mitigation's `Write-Information` is also off the table on its own: these scripts target PowerShell 3.0 (see the explicit `$PSVersionTable.PSVersion.Major -lt 3` check in `Update-Windows.ps1`), and `Write-Information` wasn't introduced until 5.0 — using it would break that compatibility floor. `Write-Error`, `Write-Warning`, and `Write-Verbose` are all available since 3.0, so they remain viable.

  A better shape than either "replace Write-Host" or "leave it alone" would be to have `Write-Log` emit through the native cmdlet for each level (`Write-Warning` for WARN, `Write-Error` for ERROR, `Write-Verbose` for TRACE) *in addition to* the existing console/`[Console]::WriteLine` output, rather than instead of it — additive, so nothing currently visible stops being visible, but callers that want to capture/redirect a specific stream (e.g. `-ErrorVariable`, `2>`, `-WarningAction`) gain the ability to. Since `Write-Log` is reused across many of the author's other projects, this is a change worth making once, deliberately, in whatever shared source of truth `Write-Log` has — not as a one-off edit to this copy. Left to the user to implement on their own timeline; no fix applied here.

---

### 2. `Update-Windows.ps1`

#### Critical Findings

* *[CRIT-02] Resolved — `switch` now has a `default` arm covering negative HRESULTs, wrapped in `try/finally` for unconditional cleanup. Note: `.NET`'s `X8` format already renders negative Int32 values as correct two's-complement hex, so the `-band 0xFFFFFFFF` in the original mitigation snippet was unnecessary and omitted.*

* *[CRIT-03] Resolved — failed downloads are now removed from `$env:TEMP`. Cleanup runs in `finally` after stream disposal (not directly in `catch`, as the mitigation snippet showed) so the file handle is released before deletion is attempted.*

---

#### Warning Findings

* *[WARN-04] Resolved (confirmed empirically — Start-Process does not auto-quote array elements with spaces, even in PS7, not just 5.1) — `$f` is now quoted in `-ArgumentList`.*

* *[WARN-05] Resolved — `HttpClient`/`GetAwaiter().GetResult()` replaced entirely with `Invoke-WebRequest` (verified against the live `PolicyUri` endpoint). This also closes REC-04, since there's no `HttpClient` instance left to dispose.*

* *[WARN-06] Resolved — Authenticode signature check (signer subject `O=Microsoft Corporation`) added before install; verified against a known-good signed binary.*

* *[WARN-07] Resolved — KB ID normalized to always carry the `KB` prefix before matching.*

---

#### Recommendation Findings

* *[REC-03] Resolved — `return 0` changed to bare `return`.*

* *[REC-04] Resolved together with WARN-05 — see above.*

* *[REC-05] Resolved — `SupportsShouldProcess` added; download+install gated on `$PSCmdlet.ShouldProcess`.*

---

### 3. `Update-WindowsNative.ps1`

#### Critical Findings
* *No Critical findings detected in this file.*

---

#### Warning Findings

* *[WARN-08] Resolved — scope clarified by the author: only COM objects that are created, used, and never themselves returned need releasing; long-lived returned objects (and their onward COM child references) are out of scope. `$AutoUpdate` (`Invoke-UpdateDetection`), `$MSUpdateSession`/`$MSUpdateSearcher`/`$SearchResult` (`Find-AvailableUpdate`), `$MSUpdateSession`/`$MSUpdateDownloader` (`Receive-UpdateDownload`), and `$MSUpdateSession`/`$MSUpdateInstaller` (`Install-UpdateCollection`) are all now released — none of these are themselves a return value. `$MSUpdateCollection` in `New-UpdateCollection` is untouched since it *is* the return value (the original finding's line-244 location was a misfire flagging this one). Verified live: `Find-AvailableUpdate` ran against this machine's real Windows Update Agent (6 updates found), and the returned `IUpdateCollection` stayed fully usable after its parent session/searcher/search-result were released — confirming releasing the parent RCW does not invalidate an already-obtained child COM interface, at least for this call path. `Receive-UpdateDownload`/`Install-UpdateCollection` weren't live-tested (would actually download/install real updates) but follow the identical WUA interface-separation pattern.*

* *[WARN-09] Resolved — replaced with a linear (M+N)-sized grouped-OR expression; verified equivalent output across several category/ID combinations.*

---

#### Recommendation Findings

* *[REC-06] Resolved, with a correction — `Accept-UpdateEula` → `Confirm-UpdateEula`, `Log-AvailableUpdates` → `Write-AvailableUpdateLog`. `Receive-UpdateDownload` was left as-is: `Receive` is already an approved verb (Communications group, e.g. `Receive-Job`), so the original finding was wrong to list it as a violation.*

* *[REC-07] Resolved — `SupportsShouldProcess` added; download+install gated on `$PSCmdlet.ShouldProcess`.*

---

### 4. `Update-WindowsUpdatePolicy.ps1`

#### Critical Findings

* *[CRIT-04] Resolved — regex match guarded with `.Success` instead of indexing `[0]`.*

* *[CRIT-05] Resolved — both catalog functions now catch network failures and return `$null`; verified end-to-end against the live catalog.*

---

#### Warning Findings

* *[WARN-10] Resolved, with a gap the original mitigation missed — the flagged comparison wasn't the first unguarded cast. `Sort-Object { [datetime]$_.eol }` selecting the EoL record ran (and would have thrown) *before* the flagged `if` line, so guarding only the comparison wouldn't have prevented the crash. Both casts now use `TryParse`. Verified against the live `endoflife.date` API across all 25 current Windows entries.*

* *[WARN-11] Resolved — `WebClient` replaced with `Invoke-RestMethod`; verified against the live endoflife.date API.*

* *[WARN-12] Resolved — all four relative paths anchored to `$PSScriptRoot`. GitHub Actions workflow unaffected (already runs from the repo root).*

---

#### Recommendation Findings

* *[REC-08] Resolved, with a correction — the PS 5.1-vs-7 rationale didn't actually apply since this script requires `#Requires -Version 7` (single-runtime, so `Out-File`'s default was already consistent), but explicit encoding is still good practice. Switched to `Set-Content -Encoding utf8`; verified it adds no BOM on this PS7 runtime.*

* *[REC-09] Resolved — result is now validated against `^https?://` before returning; verified against a real Catalog update ID.*

---

### 5. `Upgrade-Windows11.ps1`

#### Critical Findings

* *[CRIT-06] Resolved — all three early-exit paths now populate and return `$outObject`. Verified by extracting and invoking the function in isolation.*

* *[CRIT-07] Resolved, with a correction — the guard was applied, but the claimed crash did not reproduce under direct testing: calling `Add-Type -TypeDefinition $Source` twice with the identical (unchanged) source string in the same PS7.6 session succeeded silently both times rather than throwing `TypeAlreadyExists`, which suggests `Add-Type` caches/reuses the compiled assembly for byte-identical source. The guard is kept anyway as harmless defense-in-depth.*

---

#### Warning Findings

* *[WARN-13] Resolved — `Everyone` narrowed to `Authenticated Users`; verified the account resolves correctly.*

* *[WARN-14] Resolved — falls back to `[System.IO.Path]::GetTempPath()` when the machine `TEMP` value is empty or missing.*

* *[WARN-15] Resolved, with a correction — switched to `-Property`, but benchmarked (3 trials each) and found no measurable speed difference (~2.4-2.7s either way) on this machine. `-Property` appears to filter only the returned object's properties, not the underlying WMI queries the cmdlet issues, so the claimed 5-15s performance benefit did not hold up under measurement. Applied anyway since it's still correct and narrows intent.*

* *[WARN-16] Resolved, superseding the earlier annotation — the original mitigation (`HttpClient`) was rejected for the wrong reason. Checked against Microsoft's own API version metadata: `WebRequest.CreateHttp` (the flagged call) and `System.Net.Http.HttpClient` (the suggested replacement) both require .NET Framework 4.5+ — `CreateHttp`'s documented "Applies to" list starts at `netframework-4.5`, with no 4.0 entry, so switching to `HttpClient` would not have fixed anything for old-OS compatibility. `WebRequest.Create(string)` (no `Http` in the name — a different, older overload) is documented back to `netframework-1.1`, i.e. always available, and PowerShell's dynamic member resolution means no cast is needed: for an `http(s)://` URL it still constructs an actual `HttpWebRequest` at runtime, so `.Method`, `.AllowAutoRedirect`, `.ResponseUri`, and `.Close()` all continue to work. Verified locally, including running the full function end-to-end against the live download URL. Swapped `CreateHttp` → `Create`. This also means the script's prior code was already silently requiring .NET Framework 4.5+ beyond its stated PS 3.0 floor — a latent gap on a true PS3/.NET4.0-only box (e.g. an unpatched Server 2008), independent of and predating this finding's original "deprecated API" framing.*

* *[WARN-17] Resolved — `/copylogs` path is now quoted. Not an active bug today ($UpgradeLogDir is hardcoded to a no-space path), but latent for any future change.*

---

#### Recommendation Findings

* *[REC-10] Resolved — the author confirms the existing `ApplicationId`/`PartialProductKey` filter is the intended, reasonable level of optimization for this query. Benchmarking (no filter at all ≈59s vs. the existing filter ≈2.4-2.8s vs. the further `Name`/`LicenseStatus` narrowing the original mitigation suggested ≈3.8-6.2s) backs this up — the existing filter already captures the ~20x available speedup, and narrowing further measured slower, not faster. No change made.*

* *[REC-11] Resolved — the signature was already invalidated by this cycle's own edits (confirmed `HashMismatch` via `Get-AuthenticodeSignature`) and its certificate had independently expired 2025-11-15, so the stale block was removed and a `.NOTES` line documents the re-signing requirement rather than leaving a CI/CD process undocumented elsewhere.*

* *[REC-12] Resolved — all four dead-code blocks removed (three as part of the CRIT-06 rewrite, the fourth on its own); verified the function still runs end-to-end afterward.*

---

## Remaining Open Items

The one item left open (see the Remediation Status table above) is the only remaining work from this audit:

1. Decide whether project-wide `Write-Log` stream discipline (REC-02) is worth a shared-module refactor — and if so, add native-stream output (`Write-Warning`/`Write-Error`/`Write-Verbose`, all PS 3.0-compatible) alongside the existing console output rather than replacing it, since `Write-Log` is reused across the author's other projects.

