# LarchScan desktop guide

Run **LarchScan-0.4.0-Setup.exe** to install per-user (Start Menu shortcut, optional Desktop shortcut, optional CLI `PATH` entry, and an Add/Remove Programs uninstaller), or extract the portable ZIP and open **LarchScan.exe**. Because the current release is unsigned, Windows Defender SmartScreen may show *"Windows protected your PC"* on first launch — click **More info → Run anyway** after verifying the SHA-256 checksum.

The app uses standard Windows file and folder pickers and does not require administrator access for scanning files you can already read. Uninstalling LarchScan removes program files and shortcuts while preserving your local reports and quarantine vault under `%LOCALAPPDATA%\LarchScan`.

## Scan options & Startup audit

- **Quick scan** inspects **Downloads** and **Desktop** (including `.zip` archive interiors and PE Authenticode checks).
- **Single file** opens a file picker for targeted inspection.
- **Folder scan** walks the selected directory and its subfolders.
- **System drive** walks the Windows system drive (excluding LarchScan's own storage directory).
- **Startup audit** (**Startup** tab) inspects Registry `Run`/`RunOnce` keys (HKCU & HKLM), User & Common Startup folders, and enabled non-OS Windows Scheduled Tasks. It flags script/LOLBin hosts (`persistence.script-host`), temp/Downloads targets (`persistence.temp-or-downloads`), unsigned user-writable binaries (`persistence.unsigned-user-binary`), missing targets (`persistence.missing-target`), and any file-rule matches on the target binary — without modifying registry keys automatically.

Scans run on background threads with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` so active apps are not disrupted. A global status bar lets you view progress or stop an active scan from any tab.

Command-line launch options:

```powershell
.\LarchScan.exe --scan "C:\Some Folder"
.\LarchScan.exe --background-quick
.\LarchScan.exe --help
.\LarchScan.exe --version
```

## Built-in checks & custom signed rule bundles

- `demo.fixture`: Harmless verification fixture (`examples/demo.txt`).
- `triage.document-named-pe`: Windows PE executables carrying document, image, media, or archive filenames (including space-padded double extensions such as `invoice.pdf .exe`).
- `triage.double-extension-script`: Document or image names paired with Windows script/shortcut extensions (`.lnk`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.js`, `.hta`, `.msi`, etc.).
- `triage.bidi-filename`: Filenames containing Unicode bidirectional override/isolate control characters (such as RTLO `U+202E`).
- `triage.invalid-authenticode`: Embedded Windows Authenticode signature failed `WinVerifyTrust` integrity verification.
- `triage.packed-unsigned-pe`: Unsigned PE with a known packer section (e.g., `UPX0`) or high executable code section Shannon entropy (≥ 7.45).
- `archive.*`: Any of the above or custom rules matched inside a `.zip` file inspected safely in memory (up to 256 files, 8 MiB per entry, 32 MiB total uncompressed).
- Custom SHA-256 arrays or structured `larchscan-rules/1` pattern bundles (`ascii`, `ascii_nocase`, `hex`, `utf16le` strings with extension/PE/entropy filters) plus optional **Ed25519 public key verification** in **Settings** (fail-closed if unsigned or tampered).
- Optional Windows AMSI verdicts (`amsi.detected`, `amsi.policy`; 0-byte files are skipped cleanly).

## Quarantine, restore, and delete

From **Scan results** (or **Startup** when a target file matched a file rule), review the finding reasons, PE signature badge, SHA-256 hash, copy hash or reveal in File Explorer, and choose **Quarantine…** to archive under an exclusive file handle.

- Archives use `larchscan/2` (preserving Windows `Zone.Identifier` Mark-of-the-Web streams up to 16 KiB) while remaining backward-compatible with `larchscan/1`.
- In **Quarantine**, each item shows finding reasons, archive timestamp, `Zone.Identifier` status, and SHA-256. **Restore…** verifies the full archive digest and writes to a new NTFS path without overwriting; **Delete…** permanently removes the `.lsq` file after confirmation.
- Stray or corrupt `.lsq` files show a warning banner without hiding or blocking healthy archives.

## Background Task Scheduler, System Tray & storage

- **Background Windows Task Scheduler (Settings):** Registers a per-user `LarchScan Quick Scan` task that runs `LarchScan.exe --background-quick` headlessly on your chosen interval (even when LarchScan is closed), saving reports to **Scan history** with an exclusive lockfile to prevent overlaps.
- **Keep running in system tray (Settings):** Closing the window hides LarchScan to the Windows notification area (left-click to reopen, right-click for Quick Scan, Startup Audit, or Quit).
- **Local storage:** Defaults to `%LOCALAPPDATA%\LarchScan` (overridable via `LARCHSCAN_DATA_DIR`). Up to 100 recent reports are retained and automatically pruned; individual reports or all history can be deleted in **Scan history**.

LarchScan has no kernel real-time blocking driver, network filter, or commercial threat feed. Keep Windows Defender or another real-time AV active alongside it. [CLI and archive format](cli-guide.md)
