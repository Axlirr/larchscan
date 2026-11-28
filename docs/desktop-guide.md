# LarchScan desktop guide

Extract the Windows release ZIP and open **LarchScan.exe**. The app uses standard Windows file and folder pickers and does not require administrator access for scanning files you can already read.

## Scan

- **Quick scan** inspects the folders Windows identifies as **Downloads** and **Desktop** (deduplicated if they point to the same path).
- **Single file** opens a file picker for a targeted scan.
- **Folder scan** walks the selected directory and its subfolders.
- **System drive** walks the drive where Windows is installed. Inaccessible folders, reparse points, and files over 32 MiB appear as incomplete checks. The desktop app excludes its own storage directory.

Scans run in a background worker thread and open files with read/write/delete sharing so running applications are not disrupted. While a scan is running, a global status bar lets you view progress or stop the scan from any screen to save a partial report.

You can also launch the app directly against a target path from PowerShell:

```powershell
.\LarchScan.exe --scan "C:\Some Folder"
.\LarchScan.exe --help
.\LarchScan.exe --version
```

## Findings, quarantine, restore, and delete

Built-in triage checks include:

- `demo.fixture`: Built-in harmless SHA-256 verification fixture (`examples/demo.txt`).
- `triage.document-named-pe`: Valid Windows PE executables carrying document, image, media, or archive filenames (including space-padded double extensions such as `invoice.pdf .exe`).
- `triage.double-extension-script`: Document or image names paired with Windows script or shortcut launcher extensions (such as `.pdf.lnk` or `.docx .ps1`).
- `triage.bidi-filename`: Filenames containing Unicode bidirectional override or isolate control characters (such as RTLO `U+202E`).
- Custom analyst SHA-256 rules and optional Windows AMSI verdicts (`amsi.detected`, `amsi.policy`).

From **Scan results**, you can filter findings or skipped rows by filename, path, or rule, copy a file's SHA-256 digest, reveal the file in File Explorer, or choose **Quarantine…**. After confirmation, LarchScan verifies the digest and applicable rules again under an exclusive file handle, archives the primary bytes plus any Windows `Zone.Identifier` (Mark-of-the-Web) stream, verifies the written archive by streaming readback, and removes the original.

In **Quarantine**, each entry shows the original path, the finding reasons that triggered archival, the archive timestamp, whether `Zone.Identifier` was preserved, and the SHA-256 digest:

- **Restore…** verifies the archive integrity and writes the bytes to a new NTFS file path without overwriting existing files, reapplying the original `Zone.Identifier` stream (or `ZoneId=3` if none was recorded). The vault copy is retained until you delete it.
- **Delete…** permanently removes the `.lsq` archive after confirmation.

Files with alternate NTFS data streams other than `Zone.Identifier`, multiple hard links, EFS encryption, read-only attributes, or reparse points remain ineligible for quarantine and are left untouched. If a corrupt or stray `.lsq` file exists in the vault folder, LarchScan surfaces a warning without hiding or blocking healthy archives.

## Reports, settings, and storage location

By default, LarchScan saves settings, reports, WebView state, and quarantine archives under `%LOCALAPPDATA%\LarchScan`. You can override this root directory for portable or isolated triage by setting the `LARCHSCAN_DATA_DIR` environment variable before launching `LarchScan.exe`:

```powershell
$env:LARCHSCAN_DATA_DIR = "C:\Cases\Case01\larchscan-data"
.\LarchScan.exe
```

- **Scan history** displays up to 100 recent reports and automatically prunes older report JSON files beyond 100. You can also delete individual reports or clear history from the **Scan history** screen.
- Each saved report keeps full scan counts and up to 300 finding rows and 300 incomplete-check rows, including numeric AMSI results when enabled. Reports contain local file paths; review exports before sharing.
- In **Settings**, you can enable Windows AMSI (empty 0-byte files are skipped cleanly without provider errors), choose a custom JSON SHA-256 rules file, open the local data folder, and configure scheduled quick scans.
- Scheduled quick scans run while LarchScan stays open, display the next scheduled run time, skip an interval if another scan or vault operation is active, run without pulling you off your current tab, and never quarantine automatically.

This release covers on-demand and scheduled file triage and recovery. It has no background protection service, maintained threat feed, rootkit scanning, ransomware rollback, or independently measured detection accuracy. [CLI and archive format](cli-guide.md)
