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

| Published product behavior | LarchScan v0.3 decision |
| --- | --- |
| Malwarebytes distinguishes custom filesystem scans from broader quick, threat and deep scans. [Scan types](https://help.malwarebytes.com/hc/en-us/articles/31589479207579-Scan-types-in-Malwarebytes-for-Windows-and-Mac) | Desktop offers Quick scan (Downloads and Desktop), Single file, Folder, and System drive scopes; CLI supports arbitrary paths with configurable `--max-mb` and `--exclude`. Every unreadable or excluded entry is reported explicitly. |
| Malwarebytes presents findings for review and keeps scan reports. [Scan and report workflow](https://help.malwarebytes.com/hc/en-us/articles/31589496411291-Run-and-schedule-scans-in-Malwarebytes-for-Windows-and-Mac) | CLI emits JSON Lines records with digests and reasons; Desktop stores up to 100 local JSON reports with export, filtering, and in-app scheduled quick scans. |
| The quarantine history lets an operator review and restore items after a false positive. [Quarantine management](https://help.malwarebytes.com/hc/en-us/articles/31589479169179-Manage-quarantined-items-in-Windows-and-Mac) | Quarantine rechecks findings and digest under an exclusive handle, preserves Windows `Zone.Identifier` streams (`larchscan/2`), verifies readback before removal, supports verified restore without clobbering, and supports explicit permanent deletion. |
| The enterprise ThreatDown product documents endpoint isolation and ransomware rollback. [Enterprise response policies](https://support.threatdown.com/hc/en-us/articles/4413802859667-Endpoint-Detection-and-Response-policy-settings-in-OneView) | Restoring explicitly archived files is the scope here. Fleet isolation and recovery of files changed by ransomware require separate designs and validation. |

LarchScan's detectors, command interface, desktop shell, and archive format are original Rust code. The optional AMSI integration uses the documented Windows interface. The executable-name, double-extension script, and bidirectional-filename checks inspect Microsoft PE headers and Unicode filename properties and label each result for human review. [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) · [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

## Evaluation

The Windows automated test suite (`tests/workflow.rs`, `tests/scan_control.rs`, and `src/desktop/storage.rs` unit tests) verifies benign positive and negative fixtures, custom rule loading, disguised executable headers (including space-padded and expanded extensions), script/shortcut double extensions, Unicode BiDi filename spoofing, empty-file AMSI handling, concurrent `ReadWrite`-shared file scanning, path exclusions and cancellation, `Zone.Identifier` stream round-trip preservation, legacy `larchscan/1` archive compatibility, corrupt vault file resilience, permanent deletion, changed source bytes, incomplete coverage, damaged archives, destination collisions, and desktop report history pruning. These remain functional checks: comparative malware detection, false-positive rates, and response time on representative workloads remain unmeasured.

For the next evaluation, freeze engine and rule versions, record corpus hashes and independent labels, and use identical scan scopes on an isolated Windows image. Report false positives per 10,000 benign files, detection recall, unreadable or skipped files, median and p95 scan duration, peak memory, and exact-byte restore success. Score LarchScan's native checks separately from AMSI-assisted results so the host provider's contribution is visible.

With `Zone.Identifier` preservation now implemented in v0.3.0, the next engineering priorities are authenticating distributed rule updates, code-signing Windows release binaries, and optional multi-threaded scanning for large drives. Each requires explicit rejection and recovery tests before becoming a default.
