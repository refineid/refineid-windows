# Toolchain

RefineID for Windows is Rust (the Card Module and the requester bridge) and C#
(the WinUI apps). This collects the toolchain details beyond the quick build in
the [README](../README.md).

## Windows

Set up a Windows 11 development machine from nothing, with no Git, no Rust and
no Visual Studio. Run every step at the machine's desktop in a normal
(non-elevated) PowerShell, with someone there to answer the prompts:

- The machine-wide installers each ask for User Account Control consent on the
  desktop: Git, the GitHub CLI, the Visual Studio Build Tools, .NET, and the
  Visual Studio Installer. A prompt nobody answers ends as a declined install
  (`You cancelled the installation`, `winget` exit code `-1978334964`); rerun
  the step.
- `winget` refuses to start in an SSH logon (`Access is denied`), because that
  logon has no desktop session, and the script stops with this message there.
  See [Without anyone at the desktop](#without-anyone-at-the-desktop).

1. Install Git, then open a new PowerShell so `PATH` has it:

   ```powershell
   winget install --id Git.Git --exact --source winget
   ```

2. Get the repository and enter it:

   ```powershell
   git clone https://github.com/refineid/refineid-windows.git
   cd refineid-windows
   ```

3. Install and update everything else, from the repository root:

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
- `rustup`, updated to its latest release, and the latest stable Rust with
  the components and targets `rust-toolchain.toml` names;
- the latest .NET SDK of the major the WinUI apps target
  (`TargetFramework` in `apps/RefineID-winui/RefineID.csproj`) and the
  repository's .NET local tools (`csharpier`);
- the Python Install Manager and, through it, the latest stable Python 3
  (`pymanager install --update --yes 3`);
- `core.hooksPath` set to `.githooks`.

Open a new terminal afterwards so the updated `PATH` applies.

### Without anyone at the desktop

With the owner's permission to elevate on that machine, and a user logged on at
its desktop, run the two parts of the script separately. Each runs in the
logged-on session through a temporary scheduled task with `/IT`. Only
`-Part MachineWide` runs elevated (`/RL HIGHEST`), which answers its prompts
without a person; `-Part User`, the rest, needs no elevation and does not get
it. Give each task a small `.cmd` that changes to the checkout and writes the
script's output to a file, since the task has no console to read:

```powershell
schtasks /Create /TN refineid-setup /TR <cmd> /SC ONCE /ST 23:59 /IT /RL HIGHEST /F
schtasks /Run /TN refineid-setup
# once the output file ends, with the task's work done:
schtasks /Delete /TN refineid-setup /F
```

Install Git the same way, with the `winget install` of step 1 in the elevated
task and `--accept-package-agreements --accept-source-agreements
--disable-interactivity` added. Then run `-Part User` in a task without
`/RL HIGHEST`. Builds and tests need no desktop session and run over SSH, apart
from tests of the Windows Credential Manager, which need the desktop session's
logon.

### Line endings

The repository stores text with LF line endings, and the tracked
`.gitattributes` (`* text=auto eol=lf`) keeps every checkout LF. It takes
precedence over the `core.autocrlf=true` that the Git for Windows installer
sets in its system configuration by default, so no local Git setting is
needed, and none should be changed to work around it. Without it a Windows
checkout gets CRLF and CSharpier rejects every C# file.

A checkout made before `.gitattributes` existed keeps its CRLF files until
they are written again; `git ls-files --eol` shows them as `w/crlf`. Commit or
stash any work first, since this replaces every tracked file from the index,
close editors and build servers that hold files open, then run in Git Bash:

```sh
cd "$(git rev-parse --show-toplevel)"
git ls-files -z | xargs -0 rm -f
git checkout -- .
git ls-files --eol | grep -c w/crlf   # 0
```

The requirements it satisfies:

- **Rust** through `rustup`. `rust-toolchain.toml` selects the stable channel,
  so every build uses the latest stable release; it also names the
  components and targets. `rustup update` moves to a new release.
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

### ARM64 machines

Windows on ARM64 builds natively. `winget` picks the ARM64 Git installer, the
host Rust toolchain is `aarch64-pc-windows-msvc`, and `cargo test` runs the
tests natively. `rust-toolchain.toml` also installs `x86_64-pc-windows-msvc`,
so the same machine cross-builds the x64 Card Module with the MSVC x64 tools
(`scripts/build.ps1 -Architecture x64,arm64`). That is a build only: run x64
behaviour on an x64 machine.

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
