# LarchScan CLI guide

LarchScan is an on-demand Windows file triage, startup audit, and reversible quarantine CLI written in Rust. It emits JSON Lines on `stdout` for automation and diagnostics on `stderr`.

## Commands overview

```powershell
.\tools\larchscan.exe scan <PATH> [--rules <FILE>] [--rules-pubkey <HEX>] [--amsi] [--max-mb <1..=1024>] [--exclude <PATH>]...
.\tools\larchscan.exe startup [--rules <FILE>] [--rules-pubkey <HEX>] [--amsi]
.\tools\larchscan.exe quarantine <PATH> --expect <SHA256> [--rules <FILE>] [--rules-pubkey <HEX>] [--amsi] [--vault <DIR>]
.\tools\larchscan.exe list [--vault <DIR>]
.\tools\larchscan.exe restore <UUID> --to <NEW_PATH> [--vault <DIR>]
.\tools\larchscan.exe delete <UUID> [--vault <DIR>]
.\tools\larchscan.exe rules keygen --out <DIR>
.\tools\larchscan.exe rules sign <BUNDLE.json> --key <KEY_FILE> --out <SIGNED.json>
.\tools\larchscan.exe rules verify <SIGNED.json> --pubkey <HEX>
```

## Built-in triage rules

- `demo.fixture`: Built-in harmless SHA-256 verification fixture (`examples/demo.txt`).
- `triage.document-named-pe`: Windows PE executables with document, image, media, or archive names (including space-padded double extensions such as `invoice.pdf .exe`, `.pptx`, `.pdf.com`).
- `triage.double-extension-script`: Document or image names paired with Windows script/shortcut launcher extensions (`.lnk`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf`, `.hta`, `.msi`).
- `triage.bidi-filename`: Filenames containing Unicode bidirectional override/isolate control characters (`U+202A..=U+202E`, `U+2066..=U+2069`).
- `triage.invalid-authenticode`: Embedded Windows Authenticode signature failed `WinVerifyTrust` verification.
- `triage.packed-unsigned-pe`: Unsigned PE with a known packer section (`UPX0`, `.themida`, `.vmp0`, etc.) or high executable code section Shannon entropy (≥ 7.45).
- `archive.<rule>`: Rules matched on files inspected in memory inside `.zip` archives (bounded to 256 files, 8 MiB per entry, 32 MiB total uncompressed).
- `persistence.*` (`startup` command): `persistence.script-host`, `persistence.temp-or-downloads`, `persistence.unsigned-user-binary`, `persistence.missing-target`, plus file rules evaluated on each resolved target binary.

## Try it on a harmless file

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
& $scanner delete $result.receipt.id --vault $vault
```

## Scan exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | All checks completed with zero findings |
| `1` | All checks completed and at least one file or startup entry matched |
| `2` | Incomplete coverage (unreadable files, reparse points, size-limit skips, per-file AMSI error) or command/verification failure |

## Custom rules & Ed25519-signed pattern bundles

LarchScan accepts both the legacy SHA-256 JSON array (`[{"id","sha256","reason"}]`) and structured `larchscan-rules/1` bundles supporting hashes, YARA-style string/hex/UTF-16LE pattern rules, and Ed25519 signatures:

```json
{
  "format": "larchscan-rules/1",
  "version": "2026.11.28",
  "publisher": "Incident Response Team",
  "hashes": [
    {
      "id": "lab.abc",
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "reason": "Harmless verification hash"
    }
  ],
  "patterns": [
    {
      "id": "pat.ps-encoded",
      "reason": "PowerShell Base64 decode pattern",
      "extensions": ["ps1", "bat", "cmd"],
      "pe_only": false,
      "min_entropy": null,
      "match_all": true,
      "strings": [
        { "kind": "ascii_nocase", "value": "FromBase64String" },
        { "kind": "utf16le", "value": "Invoke" }
      ]
    }
  ]
}
```

Supported `strings[].kind` values: `ascii`, `ascii_nocase`, `hex` (e.g. `"4D 5A 90 00"`), and `utf16le`. Reserved rule ID prefixes: `amsi.`, `triage.`, `archive.`, `persistence.`.

Sign and enforce verification:

```powershell
.\tools\larchscan.exe rules keygen --out .\keys
.\tools\larchscan.exe rules sign .\bundle.json --key .\keys\larchscan-rules.key --out .\bundle.signed.json
$pub = (Get-Content .\keys\larchscan-rules.pub).Trim()
.\tools\larchscan.exe rules verify .\bundle.signed.json --pubkey $pub
.\tools\larchscan.exe scan C:\cases\incoming --rules .\bundle.signed.json --rules-pubkey $pub
```

When `--rules-pubkey` is set, unsigned arrays, unsigned bundles, wrong keys, or tampered bundles fail closed with exit code `2`.

## Quarantine, list, restore, and delete

> **Important:** `quarantine` rechecks the file against the active detection engine before archiving. If the finding came from `--rules`, `--rules-pubkey`, or `--amsi`, pass the same flags to `quarantine`.

- `quarantine` opens the source exclusively (`share_mode(0)` + `DELETE`), checks single hard link and allowed streams (`::$DATA` + optional `:Zone.Identifier:$DATA` ≤ 16 KiB), streams Base64 into a temp file, fsyncs, persists no-clobber, verifies via streaming SHA-256 readback, and marks the handle for delete-on-close.
- `list` enumerates valid `.lsq` receipts newest-first (logging warnings on `stderr` for corrupt/stray `.lsq` files without breaking healthy items).
- `restore` verifies the full payload digest before writing to a new NTFS path and reapplying the original `Zone.Identifier` stream (or `ZoneId=3`).
- `delete` verifies the receipt header under an exclusive handle and permanently removes `<UUID>.lsq`.

### `.lsq` archive format (`larchscan/2`)

Line 1 (≤ 128 KiB UTF-8 JSON receipt, terminated by `\n`) followed immediately by standard Base64 bytes (`ceil(bytes / 3) * 4` bytes, no newlines). `larchscan/1` archives without `quarantined_at` / `zone_identifier_b64` remain fully readable and restorable.

## Build and test

```powershell
cargo build --locked --release --features desktop --bins
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
```

See [Research notes](../RESEARCH.md) and [MIT License](../LICENSE).
