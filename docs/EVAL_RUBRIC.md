# Dandi Autonomous AI Evaluation & Scoring Rubric (100 Points)

> **Purpose**: Allow AI workers to test, score, diagnose, and iteratively improve `dandi` **without manual human QA**, using real macOS native tools AND our real Korean Windows (`ko-KR`) test machine via SSH (plus GitHub Actions `macos-latest` + `windows-latest`).

---

## 1. How the Autonomous Eval Loop Works

```text
[dandi-core + dandi-cli]
        │
        ▼
[dandi-eval] generates 30+ adversarial & real-world fixtures
        │
        ├──► Local OS Native Checks (macOS: ditto, unzip / Windows: Expand-Archive, Explorer COM, tar.exe)
        │
        ├──► Remote Real-Windows Round-Trip (--windows-ssh <host>, e.g. a real ko-KR Windows host)
        │      • Mac dandi pack → SCP to Windows → Extract with REAL Windows Explorer COM + PowerShell
        │      • Verify exact NFC filenames, SHA-256 bytes, timestamps, 0 junk files
        │      • Generate REAL Korean CP949 & Windows ZIP on Windows → SCP to Mac → Mac dandi unpack → verify 0 mojibake
        │
        └──► Outputs:
               • eval-report.json  (machine-readable per-check pass/fail, latency, MB/s, score)
               • eval-report.md    (human-readable scorecard & failure diagnostics for next AI iteration)
```

> **Note**: Never hardcode hostnames or credentials in the repo. Pass `--windows-ssh <alias>` or `DANDI_EVAL_WINDOWS_SSH=<alias>` at runtime. When omitted (e.g. local offline dev), remote Windows checks report `SKIPPED` and local checks still execute; CI runs native checks directly on `windows-latest` and `macos-latest`.

---

## 2. 100-Point Scoring Rubric

### Release Gate
- **Total Score**: **≥ 95 / 100**
- **Zero Critical Blockers**:
  - Category A (Cross-OS Compatibility) = **30 / 30**
  - Category C (Security & Filesystem Safety) = **20 / 20**

---

### Category A — Cross-OS Native Compatibility (30 pts)
| ID | Weight | Test Scenario | Pass Criteria |
|---|---:|---|---|
| `COMPAT-01` | 8 | **Mac → Windows Native Explorer Round-Trip**: Pack macOS NFD folder (Hangul + Japanese dakuten + European accents + Emoji + `.DS_Store` + `._foo` + `Icon\r`) with `dandi pack`; extract on Windows with **real Explorer COM (`Shell.Application`) & `Expand-Archive`** | 100% SHA-256 match, all filenames NFC (0 decomposed codepoints), **0 OS junk files** |
| `COMPAT-02` | 6 | **Windows → Mac Native Archive Utility Round-Trip**: Pack on Windows (`dandi` & PowerShell); extract on macOS with `ditto -x -k` and `unzip` | 100% SHA-256 match, valid UTF-8 Bit 11 header, 0 redundant `0x7075` |
| `COMPAT-03` | 5 | **macOS `.app`-like Executable & Symlink Round-Trip**: Pack bundle with `+x` script + relative intra-bundle symlink; unpack with `dandi` on macOS | `+x` bit preserved (never `000`), relative symlink intact & valid |
| `COMPAT-04` | 4 | **UTC Timestamp Fidelity (`0x5455`)**: Pack files with explicit mtimes; inspect raw ZIP headers + verify unpacked mtime within ≤ 2s | `0x5455` UTC extra field present; no timezone shift on unpack |
| `COMPAT-05` | 3 | **ZIP64 & Large Entry Count**: Pack/unpack archive with >1,000 files + verify external ZIP64 fixture | Clean unpack, exact entry count & hashes, ZIP64 omitted on small archives |
| `COMPAT-06` | 2 | **WinZip AES-256 + 7z AES-256 + Unicode Password**: Pack ZIP with `단디-Pass!2026` and `.7z` with `단디-7z!2026`; unpack with `dandi` using the NFD form of each password | Exact byte recovery; wrong password returns structured `InvalidPassword`; `.7z` without password returns `PasswordRequired` and leaks no file names |
| `COMPAT-07` | 2 | **Extended Formats & Split Volumes**: Unpack `.7z`, `.tar.gz`, `.tar.zst`, `.tar.bz2`, `.tar.xz` fixtures and RAR4/RAR5 corpus fixtures; pack PKWARE `.z01`/`.zip`, numeric `.zip.001` and `.7z.001` sets and unpack each from a middle volume; delete one volume | 100% SHA-256 match; RAR output matches libarchive `bsdtar` ≥ 3.6 when available (macOS/Linux); `overwrite: false` honoured; Info-ZIP `zip -s 0` merges the PKWARE set when available; missing volume reported by name |

---

### Category B — Multilingual & Encoding Fidelity (25 pts)
| ID | Weight | Test Scenario | Pass Criteria |
|---|---:|---|---|
| `I18N-01` | 6 | **All-Script NFD → NFC Pack Verification**: Raw ZIP Central Directory inspection for Hangul (`가나다라_보고서.pdf`), Japanese (`がぎぐげご_ぱぴぷ.txt`), European (`café_über_niño_Ångström.md`), Vietnamese (`Tiếng_Việt.txt`), Emoji (`🎉_최종_v2.xlsx`) | Bit 11 ON; raw header bytes are valid UTF-8 **and** `name == nfc(name)` |
| `I18N-02` | 5 | **Legacy Korean CP949 (Real Windows-generated & synthetic)**: Multi-file non-UTF-8 CP949 ZIP → `dandi inspect` + `dandi unpack` | Auto-detected as CP949/EUC-KR; 100% exact Korean filenames recovered |
| `I18N-03` | 4 | **Legacy Japanese Shift_JIS (CP932) incl. `0x5C` byte (`表`, `能`, `ソ`)**: Non-UTF-8 Shift_JIS ZIP → `dandi unpack` | Auto-detected as Shift_JIS; `0x5C` trailing byte NOT split as path separator |
| `I18N-04` | 3 | **Legacy Simplified Chinese (GB18030/GBK) & Traditional Chinese (Big5)** | Auto-detected cleanly; 100% exact filenames recovered |
| `I18N-05` | 3 | **Cyrillic (`CP866`/`Windows-1251`) + Western (`Windows-1252`) + Non-ASCII Archive Path** (`MacPacker#107`) | Archive whose own filename is Cyrillic/Korean opens non-empty & decodes cleanly |
| `I18N-06` | 2 | **Manual Encoding Override & `repack_nfc`**: Ambiguous single-file CP949 ZIP forced via `--encoding cp949` and repaired via `dandi fix` | Repaired ZIP passes `COMPAT-01` with Bit 11 ON & NFC |
| `I18N-07` | 1 | **Mixed-Script Deep Nesting**: 5-level nested folders combining Korean + Japanese + Arabic + Emoji | 100% exact path round-trip |
| `I18N-08` | 1 | **Info-ZIP `0x7075` Extra Field**: Bit 11 OFF + valid `0x7075` (matching CRC32) vs tampered `0x7075` (mismatched CRC32) | Valid `0x7075` honored; mismatched CRC32 safely ignored |

---

### Category C — Security & Filesystem Edge Cases (20 pts — Must be 20/20)
| ID | Weight | Test Scenario | Pass Criteria |
|---|---:|---|---|
| `SEC-01` | 5 | **Zip Slip Attacks**: `../evil.txt`, `a/../../evil.txt`, `/etc/evil`, `C:\Windows\evil.dll`, `..\\evil.txt`, plus RAR4/RAR5 archives with a `../evil.txt` member | All rejected with `UnsafePath`; zero files created outside destination |
| `SEC-02` | 5 | **Symlink Escape Attacks**: Symlink `out -> /tmp` followed by `out/pwned.txt`, plus absolute symlink `/etc/passwd` | Rejected with `UnsafeSymlink`; zero writes outside destination |
| `SEC-03` | 4 | **Zip Bomb Defense**: 100 MB all-zeros compressed to ~100 KB, multi-entry ZIP, `.tar.gz` stream and RAR5 ratio bombs tested against tight `SafetyBudget` | Rejected with `BudgetExceeded` before writing past budget; bounded RAM |
| `SEC-04` | 3 | **Windows Illegal Chars, Reserved Names & Long Paths**: `a:b*c?.txt`, `CON.txt`, `NUL`, `trailing. `, 280-char path | Sanitized deterministically without crashing on Windows; all files extracted cleanly |
| `SEC-05` | 2 | **Case-Insensitive Collisions**: `Readme.md` + `README.md` in same folder | Both preserved (deterministic disambiguation), zero silent data loss |
| `SEC-06` | 1 | **Corrupt / Truncated Archive Handling**: Truncated ZIP & bad CRC32 entry | Structured error returned (zero panic), partial output cleaned up |

---

### Category D — Performance & Efficiency (15 pts)
| ID | Weight | Test Scenario | Pass Criteria |
|---|---:|---|---|
| `PERF-01` | 6 | **Multi-File Parallel Deflate Throughput**: Pack 200 mixed text/JSON/code files (~50 MB) | ≥ 80 MB/s on Apple Silicon / modern x64, faster than single-threaded baseline |
| `PERF-02` | 5 | **Smart Store (Pre-Compressed Media)**: Pack 50 MB of `.jpg`/`.png`/`.mp4` random-entropy files | Automatically stored as Method 0; ≥ 250 MB/s throughput, ≤ 0.5% overhead |
| `PERF-03` | 4 | **Extraction Throughput & Peak Memory**: Unpack 50 MB archive | ≥ 150 MB/s extraction, bounded peak RSS (streaming, no whole-archive buffering) |

---

### Category E — Reliability & Smart UX (10 pts)
| ID | Weight | Test Scenario | Pass Criteria |
|---|---:|---|---|
| `UX-01` | 4 | **Smart Extraction**: Single-root archive (no `foo/foo/` double wrap) vs multi-root tarbomb (auto-wrapped in `<stem>/`) | Both behaviors exact; existing folder collision handled cleanly |
| `UX-02` | 3 | **Cancellation & Cleanup**: Trigger `CancellationToken` mid-pack and mid-unpack | Stops promptly (< 200 ms), returns `Cancelled`, zero orphan temp files left |
| `UX-03` | 3 | **Implicit Directories & Selective Extraction**: ZIP missing explicit `dir/` entries; extract 2 selected files out of 20 | Tree inspection synthesizes `dir/`; selective unpack writes only chosen 2 files |
