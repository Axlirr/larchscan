# Windows endpoint research and release scope

## What the installed build reveals

On 22 November 2026, we used Reverse-Engineer-Anything (REA 6.10.1, a local binary metadata inspection tool) to inspect Windows release artifacts in an installed Malwarebytes desktop distribution. The inspection read local files without launching them. The observations below identify this build and may differ across versions.

| Artifact | Direct observation | SHA-256 |
| --- | --- | --- |
| MBAM.exe | The version resource reports 5.1.0.1885. REA reads a 311,368-byte x64 PE32+ image, 11 resource entries, one icon group and a PKCS#7 certificate table. A separate Windows Authenticode check reported a valid signature from Malwarebytes Inc. | `dc86d02aaf095b8ba12e65e267169c64ec25a37c68ca495c6cf177d86a1001f4` |
| Malwarebytes.dll | REA identifies an x64 managed assembly, version 5.1.0.1885, targeting .NET 10. Its metadata declares 66 assembly references and two manifest resources. | `f4a7c5355b2864f7202edc81b44fe0d09059e800fb7dba7e23fe3754fd5502b7` |
| Malwarebytes.UI.Controls.dll | REA identifies an AnyCPU managed controls library targeting .NET 6, with references to PresentationFramework and WindowsBase. | `4c3d97304af4e091ee4ed390f2c75deb04de900ab404bc41e529a0c5bbbd04c9` |

The installed runtime configuration requests Microsoft.NETCore.App and Microsoft.WindowsDesktop.App 10.0. The adjacent file MBAMService.exe describes itself as Malwarebytes Service. Taken together these facts support a desktop application with a managed presentation layer and a separately shipped service. File metadata alone cannot establish how a scan request reaches the service, which engine produces a particular verdict, or detection performance.

To reproduce the artifact inspection, run the following against a local installation. Compare hashes before attributing a result to this version.

```powershell
$install = Join-Path $env:ProgramFiles 'Malwarebytes\Anti-Malware'
rea inspect-pe-certificates (Join-Path $install 'MBAM.exe') --json
rea inspect-pe-resources (Join-Path $install 'MBAM.exe') --json
rea inspect-managed-artifact (Join-Path $install 'Malwarebytes.dll') --json
rea inspect-managed-artifact (Join-Path $install 'Malwarebytes.UI.Controls.dll') --json
Get-AuthenticodeSignature -LiteralPath (Join-Path $install 'MBAM.exe')
```

## Product behavior and implementation choices

| Published product behavior | LarchScan v0.4 decision |
| --- | --- |
| Malwarebytes distinguishes custom filesystem scans from broader quick, threat and deep scans. [Scan types](https://help.malwarebytes.com/hc/en-us/articles/31589479207579-Scan-types-in-Malwarebytes-for-Windows-and-Mac) | Desktop provides Quick scan (Downloads/Desktop), Single file, Folder, System drive, and Startup/persistence audit (Registry Run/RunOnce, Startup folders, Scheduled Tasks); file scanning also inspects `.zip` interiors in memory and verifies Authenticode/PE entropy. |
| Malwarebytes presents findings for review and keeps scheduled scan reports. [Scan and report workflow](https://help.malwarebytes.com/hc/en-us/articles/31589496411291-Run-and-schedule-scans-in-Malwarebytes-for-Windows-and-Mac) | CLI emits JSON Lines; Desktop saves up to 100 local JSON reports with live filtering, export, system tray support, and optional per-user Windows Task Scheduler background execution (`--background-quick`). |
| Commercial AV ships authenticated rule updates and multi-signal engines. | Supports `larchscan-rules/1` bundles with exact SHA-256 hashes, YARA-style byte/string/UTF-16LE pattern rules, and fail-closed Ed25519 signature verification (`rules keygen/sign/verify` + `--rules-pubkey`). |
| The quarantine history lets an operator review, restore, or delete archived items. [Quarantine management](https://help.malwarebytes.com/hc/en-us/articles/31589479169179-Manage-quarantined-items-in-Windows-and-Mac) | Quarantine rechecks findings and digest under an exclusive handle, preserves Windows `Zone.Identifier` streams (`larchscan/2`), verifies streaming readback before removal, restores without clobbering, and supports explicit deletion. |
| Enterprise EDR products provide kernel real-time blocking, fleet isolation, and ransomware rollback. [Enterprise response policies](https://support.threatdown.com/hc/en-us/articles/4413802859667-Endpoint-Detection-and-Response-policy-settings-in-OneView) | Out of scope for user-mode LarchScan; kernel minifilters, fleet isolation, and ransomware rollback require separate privileged designs and validation. |

LarchScan's PE/entropy analyzer, in-memory ZIP reader, pattern rule engine, Ed25519 bundle verifier, persistence scanner, desktop shell, and archive format are original Rust code. Optional AMSI and Authenticode verification use documented Windows APIs (`AmsiScanBuffer`, `WinVerifyTrust`). [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) · [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

## Evaluation

The Windows automated test suite covers benign positive/negative fixtures, legacy SHA-256 rules, signed `larchscan-rules/1` pattern bundles (keygen, sign, verify, tamper rejection, unsigned fail-closed rejection), ZIP archive inspection (Deflate & Stored nested threats), PE entropy & packer detection (verifying zero false positives on LarchScan's own binary), Authenticode verification, persistence/startup rule evaluation and CLI output, empty-file AMSI handling, `ReadWrite`-shared file scanning, path exclusions and cancellation, `Zone.Identifier` stream preservation, legacy `larchscan/1` compatibility, corrupt vault resilience, permanent deletion, and desktop history pruning. Comparative malware detection recall, false-positive rate per 10,000 benign files, and latency benchmarks on an isolated corpus remain future evaluation work.

Next engineering priorities are Authenticode code signing for LarchScan's own Windows binaries and installer (e.g., SignPath / Azure Trusted Signing), parallel file scanning for large drives, and Office macro / nested archive inspection.
