# Toolchain

RefineID for Windows is Rust (the Card Module and the requester bridge) and C#
(the WinUI apps). This collects the toolchain details beyond the quick build in
the [README](../README.md).

## Windows

Set up a Windows 11 development machine with one command from the repository
root, in a normal (non-elevated) PowerShell:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/setup-dev-tools.ps1
```

Visual Studio and the SDKs are always kept at their latest release: the script
installs what is missing and updates what is already installed, so rerun it
whenever you start on a machine that has been idle. It uses `winget` and the
Visual Studio Installer for:

- Git (with Git Bash, which runs the `.githooks` and
  `scripts/agent-housekeeping.sh`) and the GitHub CLI;
- the latest Visual Studio Build Tools (2026 or later) with the C++ build
  tools workload, the MSVC x64 and ARM64 tools, and the Windows 11 SDK it
  recommends (including `signtool.exe`). An existing Visual Studio 2026 or
  later instance, Community or Build Tools, is updated and extended instead of
  installing a second one;
- `rustup`, updated to its latest release, and the toolchain pinned by
  `rust-toolchain.toml`;
- the latest .NET SDK of the major the WinUI apps target
  (`TargetFramework` in `apps/RefineID-winui/RefineID.csproj`) and the
  repository's .NET local tools (`csharpier`);
- the Python Install Manager and, through it, the latest stable Python 3
  (`pymanager install --update --yes 3`);
- `core.hooksPath` set to `.githooks`.

Open a new terminal afterwards so the updated `PATH` applies.

The requirements it satisfies:

- **Rust** through `rustup`. The channel, components, and targets are pinned
  only by `rust-toolchain.toml`; update the release there and nowhere else.
  `rustup toolchain install` in the repository, or the first `cargo`
  invocation, installs them.
- **.NET 10 SDK** for the WinUI apps. The apps obtain their Windows App SDK
  build tooling from NuGet (`Microsoft.Windows.SDK.BuildTools.WinApp`), so the
  C# build does not need a full Visual Studio install.
- **Python 3**, the latest stable release, through the
  [Python Install Manager](https://docs.python.org/3/using/windows.html),
  python.org's recommended installer; the per-version installer and the
  legacy `py` launcher are deprecated since 3.14, and no per-version
  installer is produced for 3.16 or later. It provides the `python3` command that
  `scripts/test-browser-edge.py` and the refineid-core gate scripts call; a
  per-version installer provides only `python`, and `python3` then resolves
  to the Microsoft Store placeholder. Remove the legacy Python Launcher if an
  older installer left one, since its `py.exe` shadows the manager's.
- **Visual Studio 2026** (Community or Build Tools) with the *Desktop
  development with C++* workload. The Rust components link with the MSVC
  linker, which this workload provides together with the Windows 11 SDK.

  Install the MSVC C++ build tools **for the host architecture**. On an ARM64
  machine the ARM64/ARM64EC build tools are required: Rust builds procedural
  macros for the host target, so the x64/x86 tools alone cannot link them, and
  both `cargo build` and `cargo test` fail at link time (`link.exe` errors
  `LNK2019`/`LNK2001`, or `link.exe` is not found) until the ARM64 tools are
  present.

## Building for the Windows target from macOS or Linux

The Rust components cross-build without a Windows machine using the LLVM MinGW
toolchain and the `*-pc-windows-gnullvm` targets. With the `llvm-mingw` `bin`
directory on `PATH`:

```sh
rustup target add aarch64-pc-windows-gnullvm
CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER=aarch64-w64-mingw32-clang \
  cargo build --target aarch64-pc-windows-gnullvm -p refineid-rapp-ffi
```

Ship `libunwind.dll` from the same toolchain beside the produced binary.

Formatting and lint can be checked for the Windows target from any host,
because clippy only compiles and needs no linker:

```sh
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
```

The mandatory pre-commit hook runs this check when the Windows target is
installed. The scheduled or manually dispatched Windows workflow instead
builds the bridges and WinUI apps on a native Windows host.
