# Dandi (단디)

> **Fast, open-source macOS & Windows archiver that never breaks filenames.**
>
> *Dandi (단디)* — Korean dialect for **"tightly, properly, without a hitch."**

---

## Why Dandi?

Sharing `.zip` files between macOS, Windows, and Linux still breaks filenames every day:

- **macOS → Windows**: macOS stores Korean (`한` → `ㅎ+ㅏ+ㄴ`), Japanese dakuten (`が` → `か+゙`), European accents (`é`, `ü`, `ñ`), and Vietnamese tone marks in **Unicode NFD** and injects `__MACOSX/`, `.DS_Store`, and `._*`. Windows expects **NFC**.
- **Windows → macOS**: Legacy Windows tools pack non-UTF-8 archives using local codepages (**CP949**, **Shift_JIS**, **GB18030/GBK**, **Big5**, **CP1251**, **Windows-1252**) without UTF-8 flags, causing mojibake on macOS.
- **Hidden traps**: Broken timestamps (missing UTC `0x5455`), `000` Unix permissions on macOS, broken `.app` symlinks, Zip Slip vulnerabilities, and Windows reserved filename crashes (`CON`, `NUL`, `: * ?`, >260 chars).

Dandi solves all of these **by default**, in a single lightweight cross-platform codebase (**Rust core + Tauri v2**, MIT licensed).

---

## Architecture

Dandi is built around **deep, testable Rust modules** shared by both the CLI and the desktop GUI, backed by an **autonomous cross-OS evaluation harness (`dandi-eval`)** that scores every change out of 100 against real macOS and Windows native tools.

```text
dandi/
├── crates/
│   ├── dandi-core/    # Deep archive engine: codec (NFC/CP949/Shift_JIS/GBK), safety, zip/7z/tar
│   ├── dandi-cli/     # Fast CLI (`dandi pack`, `unpack`, `list`, `inspect`, `fix`)
│   └── dandi-eval/    # 100-point automated compatibility, security & performance benchmark harness
├── apps/
│   └── desktop/       # Thin Tauri v2 + React/TS desktop shell (macOS + Windows)
└── docs/
    ├── ARCHITECTURE.md  # Deep-module seams, interfaces & invariants
    ├── ISSUE_AUDIT.md   # 24 real-world bugs audited from MacPacker, Keka, NanaZip, ouch, libarchive
    └── EVAL_RUBRIC.md   # 100-point cross-OS self-grading specification
```

---

## Roadmap

- [x] **M0 — Research & Architecture**: Cross-archiver issue archaeology ([`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md)), deep-module architecture ([`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)), 100-point eval rubric ([`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md)).
- [ ] **M1 — Core Engine + CLI + Eval Harness**: Rust `dandi-core`, `dandi-cli`, `dandi-eval` passing **≥ 95/100** (with 100% Security & Cross-OS native round-trip on macOS + Windows).
- [ ] **M2 — Tauri v2 Desktop GUI**: Drag-and-drop pack/unpack, archive tree preview, 1-click legacy encoding preview switcher, smart extraction, progress & clean cancellation.
- [ ] **M3 — OS Shell Integration & Releases**: macOS `.dmg` + Finder integration, Windows `.msi` + Explorer context menu, GitHub Actions CI & automated releases.

---

## License

MIT © [ITP-Adieum](https://github.com/ITP-Adieum)
