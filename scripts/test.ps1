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

<#
.SYNOPSIS
Runs the RefineID Windows test suites (doc/testing.md).

.DESCRIPTION
Each tier reports passed, failed or not run; the script fails when a tier
failed or could not run. Test reports land in target/test-results, coverage
in target/llvm-cov/html. No tier needs a card, a phone or a PIN; the checks
that do are listed in doc/testing.md.

  rust      every Rust test, each in its own process (cargo-nextest)
  contract  the app's boundaries, read from source
  ui        the built app, driven through UI Automation
  coverage  Rust line coverage, reported and not enforced
  fast      rust and contract
  all       rust, contract and ui

.EXAMPLE
pwsh scripts/test.ps1 -Tier fast
#>
[CmdletBinding()]
param(
    [ValidateSet('fast', 'rust', 'contract', 'ui', 'coverage', 'all')]
    [string]$Tier = 'fast',
    [ValidateSet('default', 'ci')]
    [string]$NextestProfile = 'default'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$passed = 'passed'
$failed = 'failed'
$notRun = 'not run'

$root = Split-Path -Parent $PSScriptRoot
$results = Join-Path $root 'target/test-results'

function Test-Tool([string]$Subcommand) {
    & cargo $Subcommand --version *> $null
    return $LASTEXITCODE -eq 0
}

# The outcome of the command before it.
function Get-Outcome {
    return ($LASTEXITCODE -eq 0) ? $passed : $failed
}

function Invoke-DotnetTests([string]$Project) {
    & dotnet test (Join-Path $root "tests/$Project") `
        --logger "junit;LogFilePath=$results/$Project.xml" `
        --logger 'console;verbosity=normal' | Out-Host
    return Get-Outcome
}

function Invoke-RustTier {
    if (-not (Test-Tool 'nextest')) {
        Write-Warning 'cargo-nextest is missing: run scripts/setup-dev-tools.ps1.'
        return $notRun
    }
    & cargo nextest run --workspace --locked --profile $NextestProfile | Out-Host
    $outcome = Get-Outcome
    $report = Join-Path $root 'target/nextest/ci/junit.xml'
    if (Test-Path $report) {
        Copy-Item $report (Join-Path $results 'rust.xml')
    }
    # nextest does not run documentation examples.
    & cargo test --workspace --locked --doc | Out-Host
    return ($outcome -eq $passed) ? (Get-Outcome) : $failed
}

function Invoke-UiTier {
    if ((Get-Process -Id $PID).SessionId -eq 0) {
        Write-Warning 'UI Automation needs an interactive desktop session.'
        return $notRun
    }
    & cargo build --locked -p refineid-rapp-ffi -p refineid-settings-ffi | Out-Host
    if ($LASTEXITCODE -ne 0) {
        return $failed
    }
    $platform = [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString().ToLowerInvariant()
    & dotnet build (Join-Path $root 'apps/RefineID-winui/RefineID.csproj') `
        -c Debug "-p:Platform=$platform" -p:SkipRustBuild=true `
        -p:WindowsPackageType=None -p:EnableMsixTooling=false | Out-Host
    if ($LASTEXITCODE -ne 0) {
        return $failed
    }
    return Invoke-DotnetTests 'RefineID.Ui.Tests'
}

function Invoke-CoverageTier {
    if (-not (Test-Tool 'llvm-cov')) {
        Write-Warning 'cargo-llvm-cov is missing: run scripts/setup-dev-tools.ps1.'
        return $notRun
    }
    & cargo llvm-cov nextest --workspace --locked --html | Out-Host
    return Get-Outcome
}

Set-Location $root
New-Item -ItemType Directory -Force $results | Out-Null

$tiers = switch ($Tier) {
    'fast' { 'rust', 'contract' }
    'all' { 'rust', 'contract', 'ui' }
    default { $Tier }
}
$outcomes = [ordered]@{}
foreach ($name in $tiers) {
    $outcomes[$name] = switch ($name) {
        'rust' { Invoke-RustTier }
        'contract' { Invoke-DotnetTests 'RefineID.Contract.Tests' }
        'ui' { Invoke-UiTier }
        'coverage' { Invoke-CoverageTier }
    }
}

Write-Host ''
foreach ($entry in $outcomes.GetEnumerator()) {
    Write-Host ('{0,-10}{1}' -f $entry.Key, $entry.Value)
}
exit (($outcomes.Values | Where-Object { $_ -ne $passed }) ? 1 : 0)
