# Fork Notes (`tariqaq/a-better-antivirus`)

This repository tracks [`vulnix0x4/a-better-antivirus`](https://github.com/vulnix0x4/a-better-antivirus) (`upstream/main`, currently synced through `f527464` / `v0.7.1`) and carries additional Windows hardening, reliability fixes, and regression tests built locally from source.

## Patches Carried in This Fork

### 1. NTFS Junction & Symlink (Reparse Point) Hardening
- **Component-by-component no-reparse traversal (`internal/winsec/safepath_windows.go`):** Opens every path segment and leaf with `FILE_OPEN_REPARSE_POINT` via `NtCreateFile`, returning `ErrReparsePoint` on junctions or symlinks and acting directly on the verified handle (`OpenNoReparse`, `OpenFileNoReparse`, `OpenFileNoReparseAsync`, `OpenDirNoReparse`, `MkdirAllNoReparse`, `ReadFileNoReparse`, `ReadFileNoReparseLimit`, `WriteFileNewNoReparse`, `OverwriteFileNoReparse`, `DeleteFileNoReparse`, `RemoveEmptyDirNoReparse`, `StatNoReparse`, `ReadDirNoReparse`).
- **Handle-based SACL security (`internal/winsec/winsec_windows.go`):** `SetBaitAudit`, `ClearAudit`, and `HasBaitAudit` open bait files via `OpenFileNoReparse` with `AccessSystemSecurity | AccessReadControl` and apply SACLs by handle (`SetSecurityInfo` / `GetSecurityInfo`) instead of path-based calls.
- **Safe bait operations & instant-freeze handles (`internal/baits/apply.go`, `internal/baits/blend_windows.go`, `internal/baits/recent.go`, `internal/instant/instant_windows.go`):** Bait creation, aging, ownership, indexing checks, repairs, blending, deletion, Recent-shortcut cleanup, oplock `Arm`, and `Holders` all refuse NTFS junctions/symlinks; `Check` reports `Kind: "reparse"`.
- **Tamper alerting on junction replacement (`internal/service/health.go`):** When a bait fails repair due to `reparse`, `healthCheck` raises a deduplicated critical `KindTamper` alert instead of failing silently.

### 2. Strict Authenticode Signer Verification
- **Valid signature required (`internal/classify/classify.go`):** `SweepExempt`, `TricksAllowed`, `decide`, and `ruleMatches` require `sig.Valid == true` before matching `IgnoreRule.Signer`, preventing untrusted or self-signed binaries with a spoofed certificate CN from matching publisher-pinned trust rules.

### 3. Clipboard Bait Hardening & Anti-Fingerprinting
- **OS & UI-critical process protection (`internal/clipbait/suspects_windows.go`, `internal/clipbait/guard_windows.go`):** Filters named clipboard candidates (`ownerFirst`, `wipedBy`, `ownerAfter`) through `protectedClipPID` / `protectedClipImage` before `pauseTest` so `ProtectedProcess` and Microsoft-signed `uiCritical` processes are never suspended.
- **Pre-allocation size guard & padded-address defense (`internal/clipbait/guard_windows.go`, `internal/clipbait/address.go`, `internal/service/clipboard_windows.go`):**
  - `readFormatLimit` checks `GlobalSize` against the remaining `maxSavedBytes` (8 MiB) budget before locking or copying clipboard memory.
  - `Looks` rejects strings over 256 bytes before trimming whitespace; `Cycle` trims `Finding.Replacement` so padded clipboard swaps cannot exceed `listenClipGuard`'s 1 MiB scanner buffer.
  - `listenClipGuard` logs `sc.Err()` if scanner reading fails.
- **Neutral window class (`internal/clipbait/guard_windows.go`):** Uses `clipWindowClass = "ClipboardSyncHost"` instead of `"ABAClipboardBait"`.

### 4. DoS, Bounds & Service Memory Hardening
- **Bounded `CleanRecent` & `LnkTarget` bounds check (`internal/baits/recent.go`):** Caps `.lnk` reads via `safeReadFileLimit(..., 1<<20)` (1 MiB) and checks `size < 28 || size > len(li)` in `LnkTarget` to prevent out-of-bounds slice panics on malformed shortcuts.
- **Bounded browser metadata reads (`internal/baits/catalog.go`, `internal/baits/blend_*.go`):** `readLocalState` and `firefoxProfiles` use `safeReadFileLimit(..., maxMetadataBytes)` (4 MiB) and reject junctions/symlinks.
- **Bounded in-memory service caches (`internal/service/service.go`, `internal/engine/engine.go`):** Caps `hashCache` at 2048 entries; prunes expired entries from `e.seen` and caps it at 4096 entries.
- **Descendant freeze filtering (`internal/service/service.go`, `internal/engine/engine.go`):** `SuspendMore` checks `!s.eng.ProtectedProcess(img)` alongside self and elevated checks.
- **Strict alert ID loading (`internal/alerts/alerts.go`):** `alerts.Load` rejects empty IDs, slashes, and `..` path traversal sequences.

### 5. Event Log & Discord Delivery Reliability
- **Bounded `wevtapi` wait (`internal/evtlog/evtlog_windows.go`):** Keeps `ResetEvent` after the `EvtNext` drain loop (required by Windows Event Log pull subscriptions) while using a 1-second bounded wait instead of `INFINITE` so any signal race drains within 1 second.
- **Discord embed rune limits (`internal/notify/phone.go`):** Truncates Discord webhook embed titles to 250 runes and descriptions to 4000 runes with `"…"` so large multi-bait alerts stay under Discord's 256/4096 limits.

## Local Build & Update (Windows)

```powershell
go vet ./...
go test ./...
go build -o dist\aba.exe ./cmd/aba
```

Install or update the local service from an Administrator PowerShell prompt while keeping existing settings:

```powershell
& 'c:\Users\trqboi\Documents\a-better-antivirus\dist\aba.exe' install --yes --keep-settings
```

## Upstream Sync Workflow

```powershell
git fetch upstream
git log HEAD..upstream/main --oneline
git merge upstream/main
```
