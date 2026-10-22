# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

[CmdletBinding()]
param(
    [string[]]$Architecture = @('x64', 'arm64'),
    # Debug is the development build: it reports every error to the Windows
    # Event Log (crate refineid-dev-errors). Release reports nothing.
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    # Rust build artifacts older than this many days are pruned before the
    # build. cargo never garbage-collects target/, so stale dependency and
    # toolchain outputs accumulate for weeks. Set to 0 to skip pruning.
    [int]$PruneStaleDays = 7
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
$rustup = Get-Command rustup -ErrorAction SilentlyContinue

if (-not $cargo) {
    $defaultCargoPath = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path -LiteralPath $defaultCargoPath) {
        $cargo = Get-Item -LiteralPath $defaultCargoPath
    }
}
if (-not $rustup) {
    $defaultRustupPath = Join-Path $env:USERPROFILE '.cargo\bin\rustup.exe'
    if (Test-Path -LiteralPath $defaultRustupPath) {
        $rustup = Get-Item -LiteralPath $defaultRustupPath
    }
}
if (-not $cargo -or -not $rustup) {
    throw 'Rust is not installed. Install rustup before building.'
}

$cargoPath = if ($cargo -is [System.IO.FileInfo]) { $cargo.FullName } else { $cargo.Source }
$rustupPath = if ($rustup -is [System.IO.FileInfo]) { $rustup.FullName } else { $rustup.Source }

$targets = [ordered]@{
    x64   = 'x86_64-pc-windows-msvc'
    arm64 = 'aarch64-pc-windows-msvc'
}

# Cargo's dev profile is the debug build; its output directory is `debug`.
$profileArguments = if ($Configuration -eq 'Release') { @('--release') } else { @() }
$profileDirectory = if ($Configuration -eq 'Release') { 'release' } else { 'debug' }

# Prunes Rust build artifacts not touched in the last $Days days. Uses
# cargo-sweep, which reads cargo's fingerprints and removes only unreferenced
# output -- unlike deleting by modification time, which can strand an
# incremental build. Housekeeping is best-effort: a missing tool, no network,
# or a sweep error warns and continues rather than failing the build.
function Invoke-StaleArtifactPrune {
    param(
        [Parameter(Mandatory)][string]$CargoExecutable,
        [Parameter(Mandatory)][int]$Days
    )

    if ($Days -le 0) {
        return
    }

    if (-not (Get-Command cargo-sweep -ErrorAction SilentlyContinue)) {
        Write-Host 'Installing cargo-sweep to prune stale Rust artifacts...'
        & $CargoExecutable install cargo-sweep --locked
        if ($LASTEXITCODE -ne 0) {
            Write-Warning 'cargo-sweep is unavailable; skipping the stale-artifact prune.'
            return
        }
    }

    Write-Host "Pruning Rust artifacts older than $Days days..."
    & $CargoExecutable sweep --time $Days
    if ($LASTEXITCODE -ne 0) {
        Write-Warning 'cargo sweep reported a problem; continuing with the build.'
    }
}

$requested = foreach ($value in $Architecture) {
    foreach ($name in $value -split ',') {
        $normalized = $name.Trim().ToLowerInvariant()
        if (-not $targets.Contains($normalized)) {
            throw "Unsupported architecture '$name'. Use x64 or arm64."
        }
        $normalized
    }
}

Push-Location $repositoryRoot
try {
    Invoke-StaleArtifactPrune -CargoExecutable $cargoPath -Days $PruneStaleDays

    foreach ($name in $requested | Select-Object -Unique) {
        $target = $targets[$name]
        & $rustupPath target add $target
        if ($LASTEXITCODE -ne 0) {
            throw "rustup target add failed for $target"
        }

        & $cargoPath build --locked @profileArguments --target $target -p refineid-minidriver
        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed for $target"
        }

        $outputDirectory = Join-Path $repositoryRoot "dist\$name"
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
        $builtDll = Join-Path $repositoryRoot "target\$target\$profileDirectory\refineid_minidriver.dll"
        Copy-Item -LiteralPath $builtDll -Destination $outputDirectory -Force
    }

    $hashLines = foreach ($name in $requested | Select-Object -Unique) {
        $relativePath = "$name/refineid_minidriver.dll"
        $dll = Join-Path $repositoryRoot "dist\$relativePath"
        $hash = (Get-FileHash -LiteralPath $dll -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $relativePath"
    }
    $hashLines | Set-Content -LiteralPath (Join-Path $repositoryRoot 'dist\SHA256SUMS') -Encoding ascii
} finally {
    Pop-Location
}
