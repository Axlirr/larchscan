# LarchScan CLI guide

LarchScan is an on-demand Windows file triage tool written in Rust. Scan a file or directory and each file receives a SHA-256 digest, matched rule IDs, and human-readable reasons. Review a finding and pass its digest back to quarantine those exact bytes. The CLI emits JSON Lines (`stdout`) for scripts and incident records and diagnostics on `stderr`.

LarchScan targets Windows x64 and local NTFS directories. Built-in rules detect:

- `demo.fixture`: Harmless verification fixture (`examples/demo.txt`).
- `triage.document-named-pe`: Windows PE executables with document, image, media, or archive names, including double extensions and space-padded stems (e.g., `invoice.pdf .exe`, `deck.pptx`, `receipt.jpg.com`).
- `triage.double-extension-script`: Document or image names paired with Windows script or shortcut launcher extensions (`.lnk`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.hta`, `.msi`).
- `triage.bidi-filename`: Filenames containing Unicode bidirectional override/isolate control characters (`U+202A..=U+202E`, `U+2066..=U+2069`).

You can also load custom SHA-256 indicators (`--rules`) or query the installed Windows antimalware provider (`--amsi`).

## Try it on a harmless file

Extract the Windows release ZIP, open PowerShell in the extracted directory, and run the following commands on a temporary copy of the bundled fixture:

```powershell
$lab = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ([guid]::NewGuid().ToString()))
$file = Join-Path $lab.FullName 'sample.txt'
$vault = Join-Path $lab.FullName 'vault'
$scanner = '.\tools\larchscan.exe'
Copy-Item '.\examples\demo.txt' $file
$events = & $scanner scan $file | ForEach-Object { $_ | ConvertFrom-Json }
$events[0].verdict.findings
$result = & $scanner quarantine $file --expect $events[0].verdict.sha256 --vault $vault | ConvertFrom-Json
& $scanner list --vault $vault
& $scanner restore $result.receipt.id --to $file --vault $vault
Get-FileHash -LiteralPath $file
& $scanner delete $result.receipt.id --vault $vault
```

The expected finding is `demo.fixture`. The restored SHA-256 digest is `3d4d3fb8ab38ddc7a54e0eebcd574e7b4d74419d7877e206c86e9b688b8ebe8b`. Even if `examples\demo.txt` carries a Windows `Zone.Identifier` stream from the downloaded ZIP, LarchScan preserves and restores it cleanly.

## Scan options and exit codes

```powershell
.\tools\larchscan.exe scan C:\cases\incoming
.\tools\larchscan.exe scan C:\cases\incoming --rules .\indicators.json --amsi
.\tools\larchscan.exe scan C:\cases\incoming --max-mb 64 --exclude C:\cases\incoming\cache --exclude C:\cases\incoming\vault
```

- `--rules <PATH>`: JSON array of custom SHA-256 indicators.
- `--amsi`: Submit non-empty file contents to the installed Windows AMSI provider (`amsi.detected` for malware verdicts, `amsi.policy` for admin policy blocks). Empty 0-byte files are skipped cleanly without provider errors. [Microsoft AMSI result definitions](https://learn.microsoft.com/en-us/windows/win32/api/amsi/ne-amsi-amsi_result)
- `--max-mb <1..=1024>`: Override the default 32 MiB per-file scan limit.
- `--exclude <PATH>`: Repeatable path exclusion. Note that unlike `LarchScan.exe`, the CLI `scan` command does not automatically exclude `%LOCALAPPDATA%\LarchScan` unless you pass `--exclude`.
- `--vault <PATH>`: Global flag overriding the default `%LOCALAPPDATA%\LarchScan\vault` directory.

| Scan exit code | Meaning |
| --- | --- |
| `0` | All requested checks completed with zero findings |
| `1` | All requested checks completed and at least one file matched |
| `2` | Incomplete coverage (unreadable files, reparse points, size-limit skips, per-file AMSI error) or command failure |

### Custom rules JSON format

An indicator file is a JSON array of objects with `id`, `sha256`, and `reason` (IDs starting with `amsi.` or `triage.` are reserved):

```json
[
  {
    "id": "lab.abc",
    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "reason": "Harmless analyst-supplied verification indicator"
  }
]
```

## Quarantine, list, restore, and delete

```powershell
.\tools\larchscan.exe quarantine <PATH> --expect <SHA256> [--rules <RULES>] [--amsi] [--vault <VAULT>]
.\tools\larchscan.exe list [--vault <VAULT>]
.\tools\larchscan.exe restore <UUID> --to <NEW_PATH> [--vault <VAULT>]
.\tools\larchscan.exe delete <UUID> [--vault <VAULT>]
```

> **Important:** `quarantine` rechecks the file against the active detection engine before archiving. If the finding came from `--rules` or `--amsi`, pass the same `--rules` and/or `--amsi` flags to `quarantine`, or it will reject the file with `"no matching rule or provider finding"`.

Quarantine opens the file with an exclusive handle (`share_mode(0)` and `DELETE`), verifies single hard link and allowed streams (`::$DATA` plus optional `:Zone.Identifier:$DATA` up to 16 KiB), checks the reviewed SHA-256 and findings, streams Base64 bytes into a temporary file, fsyncs, persists with no-clobber, streams the archive back to verify the SHA-256 digest, and only then marks the original handle for deletion on close.

- `list` enumerates valid `.lsq` receipts newest-first. Corrupt or stray `.lsq` files produce warnings on `stderr` without hiding valid archives.
- `restore` verifies the full archive digest before publishing to a new NTFS file path (refusing to overwrite existing files), reapplying the recorded `Zone.Identifier` stream or `[ZoneTransfer]\r\nZoneId=3\r\n` if none was recorded. The archive remains in the vault.
- `delete` verifies the receipt header under an exclusive handle and permanently removes `<UUID>.lsq`.

Files with alternate data streams other than `Zone.Identifier`, multiple hard links, read-only or EFS-encrypted attributes, or reparse points are refused and left untouched. The default vault is `%LOCALAPPDATA%\LarchScan\vault`; keep it private under your account, as Base64 encoding prevents accidental execution rather than providing confidentiality.

## JSON Lines events and `.lsq` archive format

### CLI `stdout` event shapes

- `file`: `{"event":"file","path":"...","verdict":{"sha256":"...","findings":[{"id":"...","reason":"..."}],"amsi_result":null,"provider_error":null}}`
- `unscanned`: `{"event":"unscanned","path":"...","reason":"..."}`
- `summary`: `{"event":"summary","files_scanned":1,"files_with_findings":1,"incomplete":0}`
- `quarantined`: `{"event":"quarantined","receipt":{...}}`
- `archived` (`list`): `{"event":"archived","receipt":{...}}`
- `restored`: `{"event":"restored","id":"...","to":"...","sha256":"..."}`
- `deleted`: `{"event":"deleted","receipt":{...}}`

### `.lsq` archive format (`larchscan/2`)

Each archive is stored as `<vault>\<uuid>.lsq` with two parts separated by a single `\n` (`0x0A`):

1. **Line 1 (≤ 128 KiB UTF-8 JSON receipt):**
   ```json
   {
     "format": "larchscan/2",
     "id": "uuid-v4",
     "original": "C:\\path\\to\\file",
     "sha256": "64-hex-lowercase",
     "bytes": 49,
     "findings": [{"id": "demo.fixture", "reason": "..."}],
     "quarantined_at": 1795838400,
     "zone_identifier_b64": "W1pvbmVUcmFuc2Zlcl0NClpvbmVJZD0zDQo="
   }
   ```
   (`quarantined_at` and `zone_identifier_b64` are optional; `larchscan/1` archives without them remain fully readable and restorable.)
2. **Payload:** Standard Base64 (no line breaks) of the exact primary file bytes (`bytes` raw bytes, `ceil(bytes / 3) * 4` Base64 bytes).

## Build and test

Use a Windows x64 Rust MSVC toolchain, Visual Studio C++ Build Tools, and a Windows 10/11 SDK (`rc.exe`). Run from the repository root:

```powershell
cargo build --locked --release --features desktop --bins
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

The CLI executable is written to `target\release\larchscan.exe` and the desktop executable to `target\release\larchscan-desktop.exe`.

## Research and roadmap

See [Research notes](../RESEARCH.md) for the initial endpoint research, architectural choices, and evaluation methodology. LarchScan is released under the [MIT License](../LICENSE).
