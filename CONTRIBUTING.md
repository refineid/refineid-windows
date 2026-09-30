# Contributing

RefineID is security-sensitive identity middleware. Small, reviewable changes
with evidence are preferred.

Before submitting:

```powershell
cargo fmt --all -- --check
dotnet tool restore
dotnet csharpier check .
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p refineid-lib-core
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Architecture x64,arm64
```

Formatting is owned by dedicated tools: rustfmt for Rust and CSharpier for C#,
XAML, and the project files. CSharpier is pinned in `.config/dotnet-tools.json`
and its style is fixed, so `dotnet csharpier format .` fixes any formatting the
check reports.

## Commit and push gates

The mandatory local hooks are the quality gate for formatting, lint, core
tests, and dependency freshness. `.github/workflows/ci.yml` runs manually or
weekly on Windows to check the native bridge and WinUI app builds; it does not
run on pull requests or act as a merge gate.

Enable the local hooks once per clone so defects and stale dependencies are
caught before leaving the machine:

```sh
git config core.hooksPath .githooks
```

The hooks enforce standards locally:

- **Pre-commit (`.githooks/pre-commit`)**: runs on every host to catch defects before
  committing: `cargo fmt`, `dotnet csharpier check`, `cargo clippy` (both native
  host and `x86_64-pc-windows-msvc` for Windows-specific crates), and core
  unit tests (`cargo test -p refineid-lib-core`).
- **Pre-push (`.githooks/pre-push`)**: verifies that Git dependencies in `Cargo.lock`
  (such as `refineid-core`) are synchronized with the latest upstream revisions
  before pushing. Run `cargo update -p refineid-remote` when stale.
- **Commit message (`.githooks/commit-msg`)**: enforces that commit messages do not
  contain forbidden trailers (such as AI attribution).

Rules:

- Never log or commit a PIN, personal certificate, identity code, or private
  card trace.
- Keep protocol and parsing logic in safe Rust.
- New `unsafe` code belongs only at a documented Windows ABI boundary and must
  state its pointer, length, ownership, and lifetime invariants.
- Replace magic protocol values with named constants and cite the primary
  specification or Windows SDK contract.
- Fail closed on malformed input and unsupported operations.
- Hardware claims require sanitized card/reader evidence.
- Do not add AI attribution trailers to commits.
