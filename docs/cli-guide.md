# LarchScan CLI guide

LarchScan is an on-demand Windows file triage tool written in Rust. Scan a directory and each file gets a SHA-256 digest, the rules it matched, and the reason for each finding. Review a finding and pass its digest back to quarantine exactly those bytes. The CLI emits JSON Lines for scripts and incident records.

LarchScan targets Windows x64 and local NTFS directories. Its built-in rules recognize the harmless verification fixture and Windows executables with misleading document or image names. You can load your own SHA-256 indicators or ask your installed Windows antimalware provider for a verdict with `--amsi`. A filename mismatch calls for review. An empty findings list means the selected checks found no match.

## Try it on a harmless file

Extract the Windows release ZIP, open PowerShell in the extracted directory, and run the following commands. The demo works on a temporary copy of the included fixture.

```powershell
$lab = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid().ToString()))
$file = Join-Path $lab.FullName 'sample.txt'
$vault = Join-Path $lab.FullName 'vault'
$scanner = '.\tools\larchscan.exe'
[IO.File]::WriteAllBytes($file, [IO.File]::ReadAllBytes((Resolve-Path '.\examples\demo.txt').Path))
$events = & $scanner scan $file | ForEach-Object { $_ | ConvertFrom-Json }
$events[0].verdict.findings
$result = & $scanner quarantine $file --expect $events[0].verdict.sha256 --vault $vault | ConvertFrom-Json
& $scanner list --vault $vault
& $scanner restore $result.receipt.id --to $file --vault $vault
Get-FileHash -LiteralPath $file
```

The expected finding is `demo.fixture`. The restored digest is `3d4d3fb8ab38ddc7a54e0eebcd574e7b4d74419d7877e206c86e9b688b8ebe8b`.

## Scan and interpret the result

```powershell
.\tools\larchscan.exe scan C:\cases\incoming
.\tools\larchscan.exe scan C:\cases\incoming --rules .\indicators.json --amsi
```

Each `file` event includes the digest, finding IDs and reasons. With AMSI enabled it also includes the provider's numeric result or error. `amsi.policy` identifies an administrative block. `amsi.detected` identifies a malware verdict. The provider controls its own definitions, connectivity and data handling. [Microsoft AMSI result definitions](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)

The final `summary` counts successfully hashed files, files with findings, and incomplete checks. Access failures, reparse points and files over 32 MiB appear as `unscanned` events. An optional provider failure on an individual file retains its hash result and increments the incomplete count. A provider initialization failure ends the command with a diagnostic on stderr.

| Scan exit code | Meaning |
| --- | --- |
| 0 | All requested checks completed with zero findings |
| 1 | All requested checks completed and at least one file matched |
| 2 | Incomplete coverage or command failure. Inspect the events and stderr even when findings are present |

An indicator file is a JSON array. This example matches the three ASCII bytes `abc` and can be used to verify local rule loading.

```json
[{"id":"lab.abc","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","reason":"Harmless analyst-supplied verification indicator"}]
```

## Quarantine and restore

Quarantine rechecks the rules and the reviewed hash using an exclusive file handle. It writes a receipt and Base64-encoded file contents to one archive, reads them back, checks the digest, then requests deletion through the original handle. If source removal fails, the diagnostic names the recovery archive. An interruption between archival and removal can leave both copies. `list` enumerates archive receipts. `restore` checks the contents, writes to a new destination with an Internet-zone marker and retains the archive.

The default vault is `%LOCALAPPDATA%\LarchScan\vault`. Use a private directory under your own account. Anyone with write access to the vault can replace a receipt and payload together. Encoding prevents accidental execution of the archived bytes and provides no confidentiality. Restore recovers primary file contents into a new file with permissions inherited from its destination. The original ACL and timestamps are outside the archive format.

Quarantine refuses files with additional NTFS streams (including existing download-zone markers), multiple hard links, read-only or EFS-encrypted files, and reparse points. These results leave the source in place. This release covers on-demand file inspection. Real-time interception, archive unpacking, managed threat feeds, automatic remediation and central fleet management are future work.

## Build and test

Use a Windows x64 Rust MSVC toolchain and the Visual Studio C++ build tools with a Windows SDK. Run from the source directory.

```powershell
cargo build --locked --release
cargo test --locked --release
cargo clippy --locked --all-targets -- -D warnings
```

The executable is written to `target\release\larchscan.exe`. The integration tests exercise the public CLI using benign fixtures.

## Research and roadmap

The first release prioritizes findings with inspectable reasons, explicit incomplete-scan reporting, and recovery of the exact bytes quarantined. Detection superiority over commercial antivirus requires independent evaluation. The research notes describe the observed product architecture, supporting sources, release validation, and the proposed comparison. [Research notes](../RESEARCH.md)

LarchScan is an independent project released under the MIT license. [License](../LICENSE)
