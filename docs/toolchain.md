# Toolchain

RefineID for Windows is Rust (the Card Module and the requester bridge) and C#
(the WinUI apps). This collects the toolchain details beyond the quick build in
the [README](../README.md).

## Windows

- **Rust** through `rustup`. The channel, components, and targets are pinned by
  `rust-toolchain.toml`; the first `cargo` invocation installs them.
- **.NET 10 SDK** for the WinUI apps. The apps obtain their Windows App SDK
  build tooling from NuGet (`Microsoft.Windows.SDK.BuildTools.WinApp`), so the
  C# build does not need a full Visual Studio install.
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
