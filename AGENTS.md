# AGENTS.md — Engineering Discipline for Dandi (pstack-inspired)

> **"If you want to go fast, go deep first."**
> Every line in `dandi` is public open-source code. Zero slop, zero guesswork, zero unverified claims.

---

## 1. Core Principles (pstack + Deep Modules)

1. **Read the blueprints first**: Before changing code, read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/ISSUE_AUDIT.md`](docs/ISSUE_AUDIT.md), and [`docs/EVAL_RUBRIC.md`](docs/EVAL_RUBRIC.md).
2. **Deep modules, small seams**:
   - All archive, encoding, normalization, safety, and format logic lives in `crates/dandi-core`.
   - `crates/dandi-cli` and `apps/desktop` are **thin adapters**. Never duplicate business logic in CLI or TypeScript.
   - Apply the **deletion test**: if removing a wrapper module makes complexity vanish, delete the wrapper.
3. **Never rely on OS process locale**:
   - All filename decoding operates on raw byte slices (`&[u8]`) with explicit Bit 11 / `0x7075` / corpus-level encoding detection.
4. **Prove it works against real tools**:
   - Unit tests are necessary, never sufficient.
   - A change is **not done** until `dandi-eval` runs against real OS tools (macOS `ditto`/`unzip` and Windows `Expand-Archive`/Explorer COM/`tar.exe`) and publishes an updated scorecard.
5. **Clean rollback of dead ends**:
   - If an experiment fails or adds complexity without measurable scorecard gain, strip it out completely. Do not leave commented-out code, dead flags, or half-wired abstractions.

---

## 2. Verification & Self-Grading Loop

Every milestone and PR follows this loop:

```text
1. Plan/Design   → Verify seam & invariants against docs/ARCHITECTURE.md & docs/ISSUE_AUDIT.md
2. Implement     → Small, cohesive commits; zero clippy warnings; clean rustfmt
3. Unit + Prop   → cargo test --workspace
4. Real Eval     → cargo run --release -p dandi-eval -- [--windows-ssh <ssh-alias>]
5. Inspect Score → Fix every Security/Compat blocker first; improve lowest-scoring rubric items
6. Cross-Review  → Independent reviewer checks architecture, edge cases, and real eval output
```

### Mandatory Gates Before Merging
- `cargo fmt --all --check` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- `cargo test --workspace` passes
- `dandi-eval` score: **Security = 20/20** (0 blockers), **Cross-OS Compatibility = 30/30**, total **≥ 95/100** (or explicitly justified milestone target in PR description).

---

## 3. Hard Coding Standards

- **No `.unwrap()` or `.expect()`** in `dandi-core` production paths (tests only). Return structured `DandiError` variants with actionable messages.
- **No unbounded allocations** from untrusted archive headers: always clamp header-declared sizes and enforce `SafetyBudget` limits against Zip Bombs.
- **Atomic writes & cancel cleanup**: Packing writes to a sibling temporary file and atomically renames on success; cancellation or error deletes partial outputs cleanly.
- **Never commit secrets, personal paths, or internal server credentials** (this is a **public** open-source repository!). Hostnames like remote Windows test targets must be passed via CLI flag / env var (`DANDI_EVAL_WINDOWS_SSH`), never hardcoded.
