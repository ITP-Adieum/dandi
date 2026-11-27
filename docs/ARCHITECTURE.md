# Dandi Architecture (Deep-Module Design)

> Designed using **deep modules** (small interfaces, rich implementations, clear seams) so `dandi-core`, `dandi-cli`, `dandi-eval`, and `apps/desktop` share one source of truth with zero duplicated logic.

---

## 1. Workspace Topology

```text
dandi/
├── Cargo.toml                  # Rust workspace root (resolver = "2")
├── crates/
│   ├── dandi-core/             # Pure library: ALL encoding, safety, archive I/O, progress/cancel
│   │   └── src/
│   │       ├── lib.rs          # Tiny public surface (re-exports 5 deep modules)
│   │       ├── error.rs        # Structured DandiError (zero unwrap in prod)
│   │       ├── codec.rs        # Deep Module 1: Unicode NFC + multi-script encoding detection
│   │       ├── safety.rs       # Deep Module 2: Zip Slip, symlinks, Win paths, collisions, Zip Bomb
│   │       ├── archive/        # Deep Module 3: Unified inspect / pack / unpack / repack_nfc
│   │       │   ├── mod.rs      # Public ArchiveEngine interface + SmartExtract planner
│   │       │   ├── extract_sink.rs # Unified disk-write sink (ZIP/TAR/7z): safety, atomic overwrite, warnings, rollback
│   │       │   ├── format.rs   # Magic-byte + extension format detection
│   │       │   ├── zip/        # Modular ZIP engine (header.rs, writer.rs, reader.rs, mod.rs)
│   │       │   ├── sevenz.rs   # 7z reader (sevenz-rust2 -> ExtractionSink)
│   │       │   └── tar_io.rs   # tar / tar.gz / tar.zst / tar.bz2 / tar.xz reader (-> ExtractionSink)
│   │       ├── progress.rs     # Cooperative CancellationToken + ProgressEvent sink
│   │       └── platform.rs     # OS-specific adapters (Unix perms/symlinks, Windows \\?\ & Zone.ID)
│   ├── dandi-cli/              # Thin CLI adapter (clap) -> calls dandi-core only
│   └── dandi-eval/             # Autonomous 100-point AI eval harness (local + remote Windows SSH)
└── apps/
    └── desktop/                # (M2) Thin Tauri v2 + React/TS GUI -> IPC directly to dandi-core
```

---

## 2. Deep Module Seams & Interfaces

### Module 1: `codec` (Encoding & Unicode Normalization)
**Seam responsibility**: Convert between raw archive header bytes and clean UTF-8 NFC paths across all languages, **completely independent of process locale**.

- **Public Interface** (4 functions):
  1. `normalize_for_pack(path: &str) -> String`
     - Applies Unicode **NFC** normalization (fixes macOS NFD for Hangul, Japanese dakuten/handakuten, Latin accents, Vietnamese).
     - Converts path separators to POSIX `/`, strips leading `./` or `/`.
  2. `detect_archive_encoding(raw_names: &[&[u8]], locale_hint: Option<EncodingId>) -> EncodingDetection`
     - Concatenates all non-UTF-8 raw entry names into a single corpus separated by `\n` (prevents single short-filename misclassification).
     - Runs `chardetng::EncodingDetector` + byte-validity scoring across CJK/Cyrillic/Western/Vietnamese/Thai codepages (`CP949`, `Shift_JIS`, `GB18030`, `Big5`, `Windows-1251`, `IBM866`, `Windows-1252`, `CP437`, `Windows-1258`, `Windows-874`).
     - Returns `{ encoding, confidence, candidates }` so GUI can show detected encoding and offer 1-click switch.
  3. `decode_entry_name(raw: &[u8], flags: EntryEncodingFlags, unicode_extra_0x7075: Option<&[u8]>, forced: EncodingId) -> DecodedName`
     - Priority: (1) Bit 11 UTF-8 → (2) `0x7075` Info-ZIP Unicode Path if `NameCRC32` matches `crc32(raw)` → (3) valid UTF-8 check → (4) `forced` / corpus-detected legacy codepage.
     - Always normalizes decoded output to **Unicode NFC**.
  4. `supported_encodings() -> &'static [EncodingId]`

### Module 2: `safety` (Path Sanitizer & Security Guard)
**Seam responsibility**: Guarantee that no untrusted archive can escape the target directory, corrupt the filesystem, crash Windows path rules, or exhaust disk/RAM.

- **Public Interface**:
  1. `sanitize_entry_path(raw_relative: &str, policy: PathPolicy) -> Result<SanitizedPath, DandiError>`
     - Rejects `..`, root `/`, drive letters (`C:`), UNC (`\\server\share`), NUL bytes.
     - Under `WindowsCompat` (active on Windows and available cross-OS): replaces `: * ? " < > |` and ASCII `0x00..=0x1F` with `_`, strips trailing `.`/space on path segments, escapes Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`9`, `LPT1`–`9` with or without extensions).
     - Tracks case-insensitive collisions (e.g. `README.md` vs `readme.md`) and deterministically suffixes colliding names (`readme (2).md`) instead of silently overwriting.
  2. `validate_symlink_target(dest_root: &Path, link_rel: &Path, target: &str) -> Result<PathBuf, DandiError>`
     - Rejects absolute symlink targets and any relative target whose lexical resolution escapes `dest_root`.
  3. `is_os_junk(rel_path: &str) -> bool`
     - Detects `__MACOSX/`, `.DS_Store`, `._*`, `Icon\r`, `Thumbs.db`, `desktop.ini`.
  4. `SafetyBudget` (checked arithmetic):
     - Enforces `max_total_bytes` (default 64 GiB), `max_entries` (default 500,000), and `max_compression_ratio` (default 200× after 10 MiB threshold) to block Zip Bombs without false-positiving legitimate highly compressible text/logs.

### Module 3: `archive` (Unified Format Engine)
**Seam responsibility**: All inspecting, packing, unpacking, and in-place NFC repairing behind 4 high-leverage operations.

- **Public Interface**:
  1. `inspect(archive_path: &Path, opts: &InspectOptions) -> Result<ArchiveSummary, DandiError>`
     - Detects format by magic bytes (fallback to extension).
     - Performs corpus-level encoding detection once across all entries.
     - Synthesizes missing parent directories (`MacPacker#47`).
     - Supports `encoding_override: Option<EncodingId>` for instant GUI preview switching.
  2. `pack(inputs: &[PathBuf], output_zip: &Path, opts: &PackOptions, observer: &dyn ProgressObserver) -> Result<PackReport, DandiError>`
     - **Golden ZIP spec**:
       - Writes to sibling temp file `.dandi-tmp-<pid>-<rand>.zip`, atomically renames on completion, deletes temp file on error or cancel.
       - **Parallel Deflate**: hashes/compresses eligible files in parallel using `rayon` + `flate2` (`zlib-ng` backend) with bounded memory queue, writing entries sequentially to the ZIP stream.
       - **Smart Store**: skips Deflate (uses Method 0 Store) for pre-compressed formats (`jpg, jpeg, png, webp, avif, gif, mp4, mov, mkv, mp3, aac, flac, pdf, docx, xlsx, pptx, zip, 7z, rar, gz, zst, woff2`).
       - **NFC + UTF-8 Bit 11** on every entry (no redundant `0x7075`), POSIX `/` separators, automatic **ZIP64** only when needed.
       - **Metadata**: DOS mtime + `0x5455` UTC Extended Timestamp; explicit Unix mode (`0644` files / `0755` dirs & executables, never `000`).
       - **Junk filter**: skips OS junk by default (`exclude_os_junk: true`).
       - **Optional Encryption**: WinZip AES-256 with UTF-8 NFC password.
  3. `unpack(archive_path: &Path, dest_dir: &Path, opts: &UnpackOptions, observer: &dyn ProgressObserver) -> Result<UnpackReport, DandiError>`
     - **Smart Extraction** (`ExtractMode::Smart` default):
       - Inspects top-level visible entries (ignoring `__MACOSX/`): 1 root directory → extract directly into `dest_dir` (conflict-checked); ≥2 top-level items or single loose file → wrap inside `<dest_dir>/<archive_stem>/`.
     - Supports selective extraction (`selected_entries: Option<HashSet<usize>>`).
     - Formats: ZIP (Store, Deflate, Deflate64, Bzip2, Zstd, AES-256, ZipCrypto read, ZIP64), 7z, TAR (plain, `.gz`/`.tgz`, `.zst`/`.tzst`, `.bz2`, `.xz`).
     - Preserves valid Unix `+x` bits and safe relative symlinks (so macOS `.app` bundles stay executable!).
     - Propagates `Zone.Identifier` ADS on Windows when present on source archive.
     - Cleans up partial extraction directory on cancellation if Dandi created it.
  4. `repack_nfc(src_zip: &Path, dst_zip: &Path, opts: &RepackOptions, observer: &dyn ProgressObserver) -> Result<RepackReport, DandiError>`
     - Rewrites legacy CP949/Shift_JIS/GBK or macOS NFD ZIPs into clean NFC UTF-8 ZIPs without mangling file contents.

---

## 3. Desktop Shell & OS Integration (M2–M3)

- **Tauri v2 (`apps/desktop`)**:
  - Rust backend invokes `dandi-core` directly on blocking worker threads (`tauri::async_runtime::spawn_blocking`) and streams `ProgressEvent` over Tauri channels.
  - `tauri-plugin-single-instance` handles double-clicked archive paths on macOS & Windows.
  - Frontend (React + TypeScript + Tailwind): zero archive logic — pure presentation (drop zone, virtualized archive tree, encoding switcher dropdown, progress/cancel modal, settings).
- **OS Shell Integration (M3)**:
  - **macOS**: Scoped `CFBundleDocumentTypes` for archive extensions only (never hijack volume/folder UTIs — prevents `MacPacker#345`), plus headless Finder Quick Action invoking `dandi-cli` silently without popping the main window (`MacPacker#279`).
  - **Windows**: Clean registry context menu verbs for Windows 10/11 + optional Sparse MSIX package for Windows 11 top-level Explorer menu (single registration, zero duplication — prevents `NanaZip#328`).
