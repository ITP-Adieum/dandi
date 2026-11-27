# Security Policy

Security and filesystem safety are first-class invariants in Dandi. Archives are untrusted input by default.

---

## 1. Threat Model & Built-In Defenses

Dandi's `dandi-core` safety layer (`crates/dandi-core/src/safety.rs` and `crates/dandi-core/src/archive/extract_sink.rs`) enforces the following protections across all supported formats (ZIP, 7z, TAR):

| Threat Class | Countermeasure |
|---|---|
| **Zip Slip / Path Traversal** | Rejects `..` components, leading `/` or `\`, Windows drive prefixes (`C:\`), UNC paths (`\\server\share`), and NUL bytes before creating any file or directory. Verified output targets stay strictly inside the extraction root. |
| **Symlink Escape & Chaining** | Rejects absolute symlink targets and any relative symlink whose lexical resolution escapes the extraction root. Never follows symlinks along parent directories when writing extracted files; skips unprivileged symlinks with explicit `UnpackWarning::SymlinkSkipped` instead of failing silently. |
| **Zip Bombs & Unbounded Allocations** | `SafetyBudget` uses checked arithmetic to enforce maximum total uncompressed bytes (default 64 GiB), maximum entry count (default 500,000), and maximum compression expansion ratio (default 200× past a 10 MiB threshold), aborting before exhausting disk or memory. |
| **Windows Path Hazards** | Under `PathPolicy::WindowsCompat`, deterministically sanitizes illegal characters (`: * ? " < > |`, ASCII `0x00..=0x1F`), trailing dots/spaces, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`9`, `LPT1`–`9`), and uses extended-length (`\\?\`) paths on Windows to survive `>260`-char paths. |
| **Case-Insensitive Overwrites** | Tracks normalized lowercase destinations across entries and disambiguates collisions (`file (2).ext`) instead of silently clobbering files on APFS/NTFS. Respects `overwrite = false` by default and fails with `DandiError::AlreadyExists`. |
| **Mark-of-the-Web (`Zone.Identifier`)** | On Windows, propagates NTFS `Zone.Identifier` Alternate Data Streams from downloaded archives to extracted files by default, surfacing `UnpackWarning::ZoneIdPropagateFailed` if propagation fails. |
| **Weak Archive Encryption** | Creates encrypted ZIPs exclusively with **WinZip AES-256** (UTF-8 NFC password encoding), never weak ZipCrypto. |
| **Partial Write Cleanup** | Packing writes to a sibling temporary file and atomically renames only on full success; cancellation or error deletes partial outputs cleanly. |

All security checks are continuously verified in `dandi-eval` (`SEC-01` through `SEC-06`, mandatory **20/20** release gate).

---

## 2. Supported Versions

Security fixes are applied to the latest minor release on the `main` branch.

| Version | Supported |
|---|---|
| `main` / latest `0.x` | Yes |

---

## 3. Reporting a Vulnerability

**Please do not report security vulnerabilities in public GitHub issues.**

Instead, report vulnerabilities privately through **GitHub Security Advisories**:

1. Go to `https://github.com/ITP-Adieum/dandi/security/advisories/new`
2. Include:
   - Affected crate/component (`dandi-core`, `dandi-cli`, `apps/desktop`, or `packaging/`)
   - Reproduction steps or a minimal proof-of-concept archive (hex/script preferred over large binaries)
   - Platform/OS version and observed vs. expected behavior

### Response Process

- We aim to acknowledge private reports within **72 hours**.
- Once confirmed, we will develop a fix with regression tests (including a `dandi-eval` security check where applicable), coordinate disclosure with the reporter, and credit the reporter in the advisory unless anonymity is requested.
