# Windows endpoint research and release scope

## What the installed build reveals

On 22 November 2026, we used REA 6.10.1 to inspect Windows release artifacts in an installed Malwarebytes desktop distribution. The inspection read local files without launching them. The observations below identify this build and may differ across versions.

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

| Published product behavior | LarchScan v0.1 decision |
| --- | --- |
| Malwarebytes distinguishes custom filesystem scans from broader quick, threat and deep scans. [Scan types](https://help.malwarebytes.com/hc/en-us/articles/31589479207579-Scan-types-in-Malwarebytes-for-Windows-and-Mac) | The user selects a file or directory. Every unreadable or excluded entry encountered is reported. |
| Malwarebytes presents findings for review and keeps scan reports. [Scan and report workflow](https://help.malwarebytes.com/hc/en-us/articles/31589496411291-Run-and-schedule-scans-in-Malwarebytes-for-Windows-and-Mac) | Each file emits a JSON record with a digest and reasons. The caller can retain a report by redirecting stdout to a location outside the scan tree. |
| The quarantine history lets an operator review and restore items after a false positive. [Quarantine management](https://help.malwarebytes.com/hc/en-us/articles/31589479169179-Manage-quarantined-items-in-Windows-and-Mac) | Quarantine requires a current finding and a reviewed digest. A restore verifies bytes before publishing to a new destination. |
| The enterprise ThreatDown product documents endpoint isolation and ransomware rollback. [Enterprise response policies](https://support.threatdown.com/hc/en-us/articles/4413802859667-Endpoint-Detection-and-Response-policy-settings-in-OneView) | Restoring one explicitly archived file is the scope here. Fleet isolation and recovery of files changed by ransomware require separate designs and validation. |

LarchScan's detectors, command interface and archive format are original Rust code. The optional AMSI integration uses the documented Windows interface. The executable-name check interprets Microsoft PE fields and labels the result for review. [AMSI](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) · [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)

## Evaluation

The initial Windows tests cover a benign positive fixture, benign negatives, custom rule loading, valid and malformed executable headers, changed source bytes, incomplete coverage, damaged archives, destination collisions, and round-trip content recovery. An installed AMSI provider also returned result 1 on a benign Cargo manifest during a release smoke test. These are functional checks. Comparative malware detection, false-positive rates and response time on representative workloads remain unmeasured.

For the next evaluation, freeze engine and rule versions, record corpus hashes and independent labels, and use identical scan scopes on an isolated Windows image. Report false positives per 10,000 benign files, detection recall, unreadable or skipped files, median and p95 scan duration, peak memory, and exact-byte restore success. Score LarchScan's native checks separately from AMSI-assisted results so the host provider's contribution is visible.

The next engineering priorities are preserving download-zone streams on quarantine and authenticating distributed rule updates. Each needs rejection and recovery tests before becoming a default.
