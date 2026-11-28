<div align="center">

<img src="docs/images/larchscan-icon.png" width="76" height="76" alt="LarchScan tree-ring icon">

# LarchScan

### Inspect files, understand findings, and manage quarantine on Windows.

An open-source desktop scanner with file and folder scans, reviewable findings, and reversible quarantine. Built in Rust.

[![Windows x64](https://img.shields.io/badge/Windows-x64-254c3a?style=flat-square)](https://github.com/Axlirr/larchscan/releases/tag/v0.2.0)
[![Release v0.2.0](https://img.shields.io/badge/Release-v0.2.0-b8d999?style=flat-square)](https://github.com/Axlirr/larchscan/releases/tag/v0.2.0)
[![MIT License](https://img.shields.io/badge/License-MIT-d8a750?style=flat-square)](LICENSE)

**[Download for Windows](https://github.com/Axlirr/larchscan/releases/download/v0.2.0/larchscan-0.2.0-windows-x64.zip)** · [Quick start](#quick-start) · [Screenshots](#screenshots) · [Documentation](#documentation) · [Issues](https://github.com/Axlirr/larchscan/issues)

</div>

## Overview

Choose a file, a folder, or the Windows system drive. LarchScan checks what it can read and shows the reason for each finding, including suspicious filenames, matching file fingerprints, and optional Windows antimalware verdicts. Review the evidence before quarantining a file, or export a report to keep a record.

![LarchScan desktop dashboard with quick scan and file, folder, and system-drive scan options](docs/images/desktop-overview.png)

## What's new in v0.2.0

| Feature | What you can do |
| --- | --- |
| **Desktop scanning** | Run a quick scan of Downloads and Desktop, choose a file or folder, or scan the system drive. Follow progress and stop a scan with a partial report. |
| **Findings and quarantine** | Review rule explanations and SHA-256 fingerprints, archive a file after confirmation, and restore its verified contents to a new location. |
| **Scan history** | Reopen recent reports and export findings, skipped files, and scan totals as JSON. |
| **Custom checks** | Load a JSON list of SHA-256 fingerprints or opt in to verdicts from your installed Windows antimalware provider through AMSI. |
| **Scheduled quick scans** | Set an interval for Downloads and Desktop scans while the app is open. |

## Screenshots

<details>
<summary>Inside the app</summary>
<table>
<tr>
<td width="50%"><img src="docs/images/desktop-results.png" alt="Scan results with file counts, a rule explanation and a quarantine action"><br><strong>Scan results</strong></td>
<td width="50%"><img src="docs/images/desktop-settings.png" alt="Desktop app settings for AMSI, scheduled scans, and custom rules"><br><strong>Scanner settings</strong></td>
</tr>
</table>
</details>

## Quick start

1. Download and extract the **Windows x64 ZIP**. [Get the release](https://github.com/Axlirr/larchscan/releases/tag/v0.2.0)
2. Open **LarchScan.exe**.
3. Select **Start quick scan**, or choose a file or folder. To verify the workflow, select the bundled `examples/demo.txt` file. The expected finding is `demo.fixture`.

The portable executable is unsigned. It requires Microsoft Edge WebView2 Runtime. [Microsoft WebView2 download](https://developer.microsoft.com/microsoft-edge/webview2/)

## Documentation

- [Desktop guide](docs/desktop-guide.md) covers scan options, reports, recovery, and current limits.
- [CLI guide](docs/cli-guide.md) covers the command-line executable included under `tools/`.
- [Research notes](RESEARCH.md) describe the initial release-artifact research and test scope.

### Build from source

On Windows x64, use the Rust MSVC toolchain, Visual Studio C++ Build Tools, and a Windows SDK.

```powershell
cargo build --locked --release --features desktop --bins
cargo run --locked --features desktop --bin larchscan-desktop
cargo test --locked --features desktop
```

LarchScan provides on-demand and scheduled file scans. The current release has no real-time blocking or maintained signature feed. [License](LICENSE)
