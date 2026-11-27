# Contributing to Dandi

Thank you for your interest in contributing to **Dandi**. Every line in this repository is public open-source code, and we hold contributions to strict architectural, security, and cross-OS verification standards.

---

## 1. Read the Blueprints First

Before opening a PR, familiarize yourself with:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — deep-module seams, public interfaces, and invariants
- [`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md) — real-world failure modes across existing archivers that Dandi prevents
- [`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md) — the 100-point cross-OS evaluation harness

### Core Design Rules

1. **Deep modules, thin adapters**: All archive, encoding, normalization, safety, and extraction sink logic belongs in `crates/dandi-core`. `crates/dandi-cli` and `apps/desktop` are thin adapters—never duplicate archive logic in CLI or TypeScript.
2. **Never rely on OS process locale**: All filename decoding must operate on raw byte slices (`&[u8]`) with explicit ZIP Bit 11 / `0x7075` / corpus-level encoding detection.
3. **Zero `.unwrap()` or `.expect()` in production paths**: Return structured `DandiError` variants with actionable messages. `.unwrap()` / `.expect()` are permitted only in test code.
4. **Bounded allocations & atomic writes**: Clamp untrusted archive header sizes, enforce `SafetyBudget`, write packed ZIPs to sibling temporary files before atomic rename, and clean up partial outputs on cancel or error.
5. **No secrets or personal paths**: Never commit internal hostnames, credentials, or local user paths. Remote Windows eval targets must be passed at runtime via `--windows-ssh <alias>` or `DANDI_EVAL_WINDOWS_SSH`.

---

## 2. Local Development Setup

### Prerequisites

- **Rust** stable toolchain (`rustfmt` + `clippy` components)
- **Node.js 22+** and **pnpm 10+** (for `apps/desktop`)
- **Tauri v2 platform dependencies** (Xcode Command Line Tools on macOS; MSVC Build Tools + WebView2 on Windows)

### Useful Commands

```bash
# Format & lint Rust workspace + desktop backend
cargo fmt --all --check
cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings

# Run Rust tests
cargo test --workspace
cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml

# Frontend checks & build
pnpm --dir apps/desktop install --frozen-lockfile
pnpm --dir apps/desktop exec tsc --noEmit
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build

# Run the 100-point real-tool evaluation harness
cargo run --release -p dandi-eval
# Optional: include real remote Windows round-trip verification
cargo run --release -p dandi-eval -- --windows-ssh <your-windows-ssh-alias>
```

---

## 3. Mandatory Merge Gates

Every PR must pass all automated checks before merge:

- `cargo fmt --all --check` and `cargo fmt --manifest-path apps/desktop/src-tauri/Cargo.toml --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo clippy --manifest-path apps/desktop/src-tauri/Cargo.toml --all-targets -- -D warnings`
- `cargo test --workspace` and `cargo test --manifest-path apps/desktop/src-tauri/Cargo.toml`
- `pnpm --dir apps/desktop exec tsc --noEmit`, `pnpm --dir apps/desktop test`, and `pnpm --dir apps/desktop build`
- `dandi-eval` scorecard: **Security = 20/20** (0 blockers), **Cross-OS Compatibility = 30/30**, total **≥ 95/100** (target 100/100)

If a change fixes a bug or adds a feature, include focused unit/integration tests and verify real OS tool compatibility via `dandi-eval`.

---

## 4. License & Contribution Policy

- Dandi is licensed under the **GNU General Public License v3.0 (`GPL-3.0-only`)** — see [`LICENSE`](LICENSE).
- By submitting a pull request, you agree that your contributions are licensed under `GPL-3.0-only` and that you have the right to contribute them.
- The **Dandi** name and logo are trademarks of **ITP-Adieum** and are not covered by the GPL-3.0 license.
