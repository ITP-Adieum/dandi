<p align="center">
  <strong>English</strong> | <a href="README.ko.md">한국어</a> | <a href="README.ja.md">日本語</a>
</p>

# Dandi (단디)

> **Fast, open-source macOS, Windows & Linux archiver that never breaks filenames.**
>
> *Dandi (단디)* — Korean dialect for **"tightly, properly, without a hitch."**

---

## Why Dandi?

Sharing archives across macOS, Windows, and Linux still corrupts filenames and breaks security assumptions:

- **macOS → Windows**: macOS writes Korean (`한` → `ㅎ+ㅏ+ㄴ`), Japanese dakuten (`が` → `か+゙`), European accents (`é`, `ü`, `ñ`), and Vietnamese tone marks as **Unicode NFD** and leaks `__MACOSX/`, `.DS_Store`, and `._*`. Dandi packs **Unicode NFC UTF-8** (ZIP Bit 11) with zero OS junk by default.
- **Windows → macOS**: Legacy Windows ZIPs omit Bit 11 and store raw **CP949**, **Shift_JIS (incl. `0x5C` byte)**, **GB18030/GBK**, **Big5**, **Windows-1251/IBM866**, or **Windows-1252** bytes. Dandi runs **archive-wide corpus detection** independent of OS locale and offers a 1-click preview switcher and NFC repair (`dandi fix`).
- **Real-world edge cases & safety**: Writes UTC `0x5455` timestamps, preserves Unix `+x` modes and safe intra-archive relative symlinks, blocks **Zip Slip**, **symlink chaining**, and **Zip Bombs**, sanitizes Windows illegal characters and reserved names (`CON`, `NUL`, `COM1`–`9`), handles case-insensitive collisions without silent overwrite, and propagates Windows `Zone.Identifier` ADS.

---

## Verified Scorecard & Performance

Every change is graded by [`dandi-eval`](docs/EVAL_RUBRIC.md) against real native OS tools (macOS `ditto`/`unzip` and real Windows Explorer COM / `Expand-Archive`):

| Category | Score | Highlights |
|---|---:|---|
| Cross-OS Native Compatibility | **30 / 30** | Real macOS ↔ Windows Explorer round-trips, `.app` `+x` & symlinks, UTC `0x5455`, ZIP64, AES-256 Unicode passwords, `.7z`/`.tar.*` |
| Multilingual & Encoding Fidelity | **25 / 25** | All-script NFD → NFC, CP949, Shift_JIS (`0x5C`), GB18030, Big5, Cyrillic, `0x7075` CRC32 validation |
| Security & Filesystem Safety | **20 / 20** | Zip Slip, symlink escape, Zip Bomb `SafetyBudget`, Windows reserved names & `MAX_PATH`, collision safety |
| Performance & Efficiency | **15 / 15** | **454 MB/s** parallel Deflate pack (`rayon` + `zlib-rs`) + Smart Store; **718 MB/s** streaming unpack |
| Reliability & Smart UX | **10 / 10** | Smart Extraction (no `foo/foo/` double-wrap or tarbombs), instant cancel & rollback, implicit dirs |
| **Total** | **100 / 100** | **0 skipped, 0 security blockers** |

---

## Quickstart (CLI)

```bash
# Install from source
cargo install --path crates/dandi-cli

# Pack files or folders into a clean cross-OS UTF-8 NFC ZIP (auto-excludes OS junk)
dandi pack ./project -o project.zip

# Unpack ZIP, 7z, or TAR (.tar/.tgz/.tar.gz/.tar.zst/.tar.bz2/.tar.xz) with Smart layout
dandi unpack archive.zip --dest ./out --mode smart

# Inspect format, corpus-detected encoding, and synthesized folder tree
dandi inspect legacy_cp949.zip

# Override filename encoding for ambiguous legacy archives
dandi list legacy.zip --encoding cp949
dandi unpack legacy.zip --dest ./out --encoding shift_jis

# Repair a legacy CP949/Shift_JIS/NFD ZIP into a clean UTF-8 NFC ZIP
dandi fix broken.zip -o clean_nfc.zip
```

All commands also support `--json` for scripting and automation.

---

## Desktop App & Right-Click Shell Integration

The Tauri v2 desktop app (`apps/desktop`) is a thin shell over `dandi-core` with drag-and-drop inspect/pack, live encoding switching, Smart/Direct/Wrap extraction, overwrite guard, expandable extraction warnings, and cancellation.

### macOS Finder Quick Actions

Install two headless Quick Actions (`Compress with Dandi` and `Extract with Dandi`) into `~/Library/Services/` — runs silently without popping the main window and works on local folders, iCloud Drive, and external drives:

```bash
./packaging/macos/install-quick-actions.sh
# Optional flags: --dandi-bin /path/to/dandi --dry-run

# Remove cleanly
./packaging/macos/uninstall-quick-actions.sh
```

### Windows Explorer Context Menu

Register per-user `HKCU` right-click entries (no Administrator UAC required, no Win10/Win11 duplication):

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\windows\install-context-menu.ps1
# Optional flags: -DandiBin C:\path\to\dandi.exe -DesktopBin C:\path\to\Dandi.exe -DryRun

# Remove cleanly
powershell -ExecutionPolicy Bypass -File .\packaging\windows\uninstall-context-menu.ps1
```

This adds **Compress with Dandi (Clean ZIP)** for files/folders and **Extract with Dandi (Smart)** + **Open in Dandi** for `.zip`, `.7z`, `.tar`, `.tgz`, `.gz`, `.zst`, `.bz2`, `.xz`, `.tzst`, `.tbz2`, and `.txz`.

---

## First-Launch Instructions (Unsigned Builds)

Pre-built releases may be unsigned while code-signing certificates are being provisioned:

- **macOS**: After dragging `Dandi.app` to `/Applications`, clear the quarantine attribute if Gatekeeper warns about an unidentified developer:
  ```bash
  xattr -dr com.apple.quarantine /Applications/Dandi.app
  # For the standalone CLI binary:
  xattr -d com.apple.quarantine /path/to/dandi
  ```
- **Windows**: If Microsoft Defender SmartScreen displays *"Windows protected your PC"*, click **More info** → **Run anyway**. Always verify downloads against `SHA256SUMS.txt` on the release page.

---

## Architecture

```text
dandi/
├── crates/
│   ├── dandi-core/    # Deep engine: codec (NFC/CP949/Shift_JIS/GB18030), safety, ExtractionSink, zip/7z/tar
│   ├── dandi-cli/     # Thin CLI (`pack`, `unpack`, `list`, `inspect`, `fix`)
│   └── dandi-eval/    # 100-point automated compatibility, security & performance harness
├── apps/
│   └── desktop/       # Thin Tauri v2 + React/TypeScript GUI (macOS + Windows)
├── packaging/
│   ├── macos/         # Headless Finder Quick Actions installer/uninstaller
│   └── windows/       # Per-user HKCU Explorer context menu installer/uninstaller
└── docs/
    ├── ARCHITECTURE.md
    ├── ISSUE_AUDIT.md
    └── EVAL_RUBRIC.md
```

---

## Roadmap

- [x] **M0 — Research & Architecture**: 24-bug cross-archiver audit ([`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md)), deep-module architecture ([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)), 100-point eval rubric ([`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md)).
- [x] **M1 — Core Engine + CLI + Eval Harness**: `dandi-core`, `dandi-cli`, `dandi-eval` scoring **100/100** with real macOS ↔ Windows round-trips, hardened in M1.5 with `ExtractionSink`, structured warnings, and `SanitizedPath`.
- [x] **M2 — Tauri v2 Desktop GUI**: Drag-and-drop inspect/pack, archive tree preview, 1-click legacy encoding switcher, NFC repair, smart extraction, progress & clean cancellation.
- [x] **M3 — OS Shell Integration & Automated Releases**: Desktop warning/overwrite UX, macOS Finder Quick Actions, Windows HKCU Explorer context menu, cross-OS GitHub release pipeline with SHA-256 checksums, and multilingual OSS docs.

---

## Contributing & Security

- Read [`CONTRIBUTING.md`](CONTRIBUTING.md) for local build instructions, coding standards, and `dandi-eval` merge gates.
- Read [`SECURITY.md`](SECURITY.md) for Dandi's security threat model and private vulnerability reporting process.

## License & Trademark

- **Source Code**: Licensed under the [GNU General Public License v3.0](LICENSE) (`GPL-3.0-only`) © [ITP-Adieum](https://github.com/ITP-Adieum). Free for personal and commercial/company use.
- **Trademark**: The **Dandi** name and logo are trademarks of ITP-Adieum and are not covered by the GPL-3.0 license. Forks must use a distinct name and icon.
- **Commercial / Dual Licensing**: Commercial redistribution or proprietary embedding licenses are available from ITP-Adieum.
