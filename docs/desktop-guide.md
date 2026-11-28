# LarchScan desktop guide

Extract the Windows release ZIP and open **LarchScan.exe**. The app uses standard Windows file and folder pickers. It does not require administrator access for scanning files you can already read.

## Scan

- **Quick scan** inspects the folders Windows identifies as Downloads and Desktop.
- **Single file** opens a file picker for a targeted scan.
- **Folder scan** walks the selected directory and its subfolders.
- **System drive** walks the drive where Windows is installed. Inaccessible folders, reparse points and files over 32 MiB can appear as incomplete checks. The desktop app excludes its own storage directory.

The scan runs in a worker thread. Stop it to save a partial report. You can also launch the app with a path from PowerShell.

```powershell
.\LarchScan.exe --scan "C:\Some Folder"
```

## Review and recover

Findings include the matching rule, its explanation, and the file's SHA-256 fingerprint. A misleading name alone is a reason to investigate. An empty findings list means the selected checks found no match within their coverage.

Choose **Quarantine** next to a finding and confirm the action. LarchScan checks the fingerprint and applicable rules again, verifies the archive, and removes the original from its directory. To recover a file, open **Quarantine**, select **Restore**, and choose a new path. A restore retains the vault copy, adds a Windows Internet-zone marker, and refuses to overwrite an existing file. Original permissions, timestamps, and extra streams are outside the archive format. Files with extra streams, multiple hard links, EFS encryption, or read-only attributes are ineligible for quarantine.

## Reports and settings

LarchScan saves reports, settings, and quarantine archives under `%LOCALAPPDATA%\LarchScan`. The history screen shows up to 100 recent reports. Each report contains full counts and up to 300 finding rows and 300 incomplete-check rows. Reports contain local paths. Treat an export accordingly when sharing it.

In **Settings**, enable AMSI to send inspected content to the installed Windows antimalware provider. The provider controls any associated network use. You can also select a custom JSON rule file and set the interval for quick scans. Scheduled scans require an open app and skip an interval when another scan or vault operation is active. They do not quarantine automatically.

This release covers file triage and recovery. It has no background protection service, maintained threat feed, rootkit scanning, ransomware rollback, or independently measured detection accuracy. [CLI and archive format](cli-guide.md)
