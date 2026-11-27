# Existing Archiver Issue Audit (Issue Archaeology)

> Before writing code, we audited open and closed high-impact issues across **MacPacker**, **Keka**, **NanaZip**, **PeaZip**, **ouch**, **Bandizip**, and **libarchive** (Windows 11 native engine).
> Every known production failure mode below is mapped to a concrete architectural countermeasure in `dandi-core` and a scored test ID in [`EVAL_RUBRIC.md`](EVAL_RUBRIC.md).

---

## 1. Encoding & Unicode Failures (Cross-OS & Multilingual)

| # | Source Issue(s) | Real-World Failure Mode | Dandi Countermeasure | Eval ID |
|---|---|---|---|---|
| 1 | macOS Finder / Keka / PeaZip | macOS writes **Unicode NFD** (`한`→`ㅎ+ㅏ+ㄴ`, `が`→`か+゙`, `é`→`e+́`); Windows Explorer shows decomposed/broken filenames. | Normalize every packed entry path to **Unicode NFC** (`unicode-normalization`) and set ZIP Bit 11 (`0x0800`). | `COMPAT-01`, `I18N-01` |
| 2 | `MacPacker#373`, `#385` / Bandizip | Legacy Windows ZIPs omit Bit 11 and store **CP949, Shift_JIS, GB18030/GBK, Big5, CP1251/CP866, Win-1252** raw bytes → mojibake on macOS/other locales. | Implement 3-tier decode: (1) Bit 11 UTF-8 → (2) `0x7075` CRC32-verified UTF-8 → (3) **archive-wide corpus `chardetng` detection** + OS locale tie-breaker + 1-click GUI override. | `I18N-02`..`06` |
| 3 | `libarchive#587` (76 comments) | Decoding relies on C process `LC_CTYPE` locale, causing silent failures in UTF-8/non-UTF-8 mixed environments. | Pure Rust raw `&[u8]` header parsing; **never** depend on process locale. | `I18N-02` |
| 4 | `MacPacker#107` | Archive path or internal entry containing Cyrillic/non-ASCII causes archive to appear **empty**. | End-to-end UTF-8 `OsStr`/`Path` handling on macOS & Windows wide-char APIs; explicit tests with Cyrillic, Korean, Japanese, Chinese, Arabic, Emoji archive names AND inside paths. | `I18N-05`, `I18N-07` |
| 5 | `NanaZip#973` | **Non-ASCII / UTF-8 passwords** fail to decrypt WinZip AES-256 archives across OSes. | Encode AES passwords as UTF-8 NFC consistently (with raw fallback check on legacy decrypt) and test Korean/Unicode passwords cross-OS. | `COMPAT-06` |
| 6 | PKWARE APPNOTE 6.3.10 | Writing both Bit 11 and `0x7075` unnecessarily confuses some legacy parsers. | When Bit 11 is set (all Dandi-created ZIPs), **omit** `0x7075` per spec; when reading, honor `0x7075` only if `NameCRC32` matches raw header bytes. | `COMPAT-02`, `I18N-08` |

---

## 2. ZIP Format & Boundary Edge Cases

| # | Source Issue(s) | Real-World Failure Mode | Dandi Countermeasure | Eval ID |
|---|---|---|---|---|
| 7 | `Keka#423` (52 comments), `libarchive#1834` (28 comments) | **ZIP64** archives created by Go/Java or entries near the exact `0xFFFFFFFF` (4GB) boundary fail extraction. | Auto-enable ZIP64 strictly when entry ≥ 4GB, archive ≥ 4GB, or entry count ≥ 65,535; test ZIP64 readers against externally generated ZIP64 files. | `COMPAT-05` |
| 8 | `MacPacker#47` | Extracting folders fails when a ZIP contains `dir/file.txt` **without** an explicit `dir/` directory entry. | Synthesize parent directory tree from normalized entry paths for both preview and extraction. | `UX-03` |
| 9 | macOS `ditto` / `libarchive` | ZIP with only DOS local timestamp (or only Windows `0x000a` without `0x5455`) causes **timezone-shifted future timestamps** on macOS. | Always write **DOS mtime + Info-ZIP Extended Timestamp `0x5455` (UTC)**; when reading, prefer `0x5455` UTC → `0x000a` NTFS → DOS local. | `COMPAT-04` |
| 10 | `MacPacker#121`, `#175` | Extracted macOS `.app` bundles become **inexecutable** because Unix mode (`+x`) or relative symlinks were stripped or corrupted. | Preserve valid Unix mode bits (`0644`/`0755`, never `000` when `version_made_by` is Unix!) and preserve **intra-archive relative symlinks** safely on Unix/macOS. | `COMPAT-03`, `SEC-02` |
| 11 | `MacPacker#190`, `#216`, `#306` | Packing or unpacking macOS folders leaks `__MACOSX/`, `.DS_Store`, `._*` AppleDouble sidecars, and broken `Icon\r` (`Icon?`) files onto Windows. | Filter OS junk (`__MACOSX/`, `.DS_Store`, `._*`, `Icon\r`, `Thumbs.db`, `desktop.ini`) by default on pack (toggleable in advanced options) and hide/skip `__MACOSX/` noise cleanly on unpack. | `COMPAT-01`, `COMPAT-03` |
| 12 | Windows Explorer / macOS Archive Utility | Using ZIP Method 93 (Zstd) or Deflate64 (Method 9) as default write format breaks macOS native Archive Utility and older Windows tools. | **Write default strictly locked to Method 8 (Deflate) + Method 0 (Store)** for incompressible media; support Zstd/Deflate64/Bzip2/7z/tar.zst on **read**. | `COMPAT-01`, `PERF-02` |
| 13 | Windows 11 Explorer (`libarchive`) | Windows 11 native Explorer **cannot open password-protected AES-256 ZIP/7z/RAR** archives. | Use WinZip AES-256 (never weak ZipCrypto by default) and surface an explicit UX note when password-protecting. | `COMPAT-06` |

---

## 3. Filesystem Safety & Security Vulnerabilities

| # | Source Issue(s) | Real-World Failure Mode | Dandi Countermeasure | Eval ID |
|---|---|---|---|---|
| 14 | Bandizip / 7-Zip / CVE class | **Zip Slip** (`../../etc/passwd`, `C:\Windows\...`, mixed `\`/`/` separators) writes outside destination directory. | Canonicalize & reject any `..`, root prefix, drive letter, or UNC path before opening any output file; verify resolved path stays inside extraction root. | `SEC-01` |
| 15 | `ouch#789`, CVE class | **Symlink escape**: archive creates symlink `a -> /etc` then writes `a/pwned`. | Never follow existing symlinks during extraction; allow creating relative symlinks only if target resolves strictly inside extraction root (and materialize symlinks after validation). | `SEC-02` |
| 16 | `libarchive#3560` | **Zip Bomb / integer overflow**: tiny archive claims 100TB or expands 10,000×, crashing RAM/disk. | `SafetyBudget` enforces checked arithmetic, max uncompressed bytes, max entry count, and max expansion ratio (configurable override for trusted archives). | `SEC-03` |
| 17 | `libarchive#2095` | **Windows illegal characters & reserved names**: `: * ? " < > |`, control chars `0x00–0x1F`, trailing `.`/space, `CON/PRN/AUX/NUL/COM1–9/LPT1–9`, and >260 char `MAX_PATH`. | Deterministic cross-OS path sanitizer (Windows target mode + `\\?\` extended-length path prefix on Windows) with collision-free disambiguation. | `SEC-04`, `COMPAT-07` |
| 18 | Cross-OS Linux → Mac/Win | **Case-insensitive collisions**: archive has both `README.md` and `readme.md` → silent overwrite on APFS/NTFS. | Pre-scan normalized lowercase paths before extraction; resolve collisions deterministically (`readme (2).md`) and report in result summary. | `SEC-05` |
| 19 | `NanaZip#425` (20 comments) | Extracted executables lose Windows **Mark-of-the-Web (`Zone.Identifier` ADS)**. | On Windows, if source archive carries `Zone.Identifier` ADS, propagate it to extracted files by default (configurable). | `SEC-06` |

---

## 4. Performance, Reliability & Desktop UX

| # | Source Issue(s) | Real-World Failure Mode | Dandi Countermeasure | Eval ID |
|---|---|---|---|---|
| 20 | `Keka#345` / Bandizip | Single-threaded zlib is slow on large multi-file folders; re-compressing `.jpg/.mp4/.pdf/.docx` wastes CPU for 0% savings. | **Auto-Store (Method 0)** for pre-compressed extensions + **`flate2` (`zlib-ng`)** + **`rayon` parallel per-file compression**. | `PERF-01`, `PERF-02`, `PERF-03` |
| 21 | `ouch#151` (19 comments) | Extracting a "tarbomb" (50 loose files) clutters Desktop; always wrapping creates ugly `foo/foo/` double folders. | **Smart Extraction (default)**: 1 single root folder → extract directly; multiple top-level entries → auto-wrap in `<archive_stem>/` (with collision-safe suffix). | `UX-01` |
| 22 | `ouch#632` / `Keka#247` | Unresponsive UI, no real cancellation, and half-written corrupt `.zip` or half-extracted debris left behind on cancel/error. | Cooperative `CancellationToken` + throttled progress callback + atomic temp-file pack & automatic cleanup of partial target on abort. | `UX-02` |
| 23 | `MacPacker#278`, `#279`, `#305`, `#345`, `Keka#38` | Finder extension fails on iCloud Drive/external volumes; quick actions pop up launcher window; careless UTI overrides hijack Finder disk icons. | In M3: scoped UTIs strictly to archive extensions (never generic folder/disk types); headless CLI background execution for context-menu actions without opening main window. | M3 Gate |
| 24 | `NanaZip#328` (51 comments), `#974`, `#51` | Windows 11 vs Windows 10 context menu duplication or missing entries. | In M3: clean MSI/NSIS registry verbs for classic menu + optional signed Sparse MSIX package for Win11 top-level menu (never duplicate registrations). | M3 Gate |
