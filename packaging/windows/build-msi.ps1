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
    Builds the driver-only MSI for each requested architecture.

    .DESCRIPTION
    Packaging needs nothing beyond Windows itself: refineid-msi writes the
    installer database through the Windows Installer API, and the payload
    cabinet comes from makecab.exe. There is no third-party packaging
    toolchain to install, license, or keep current.

    MSI packages are architecture-specific, so this produces one file per
    architecture rather than a single universal installer.

    Signing is optional. Without -CertificateThumbprint the output is
    unsigned. With a self-signed certificate the output carries a verifiable
    author identity and tamper-evidence, but the chain does not validate on
    a machine that has not chosen to trust that certificate; Windows still
    reports an unknown publisher there. Only a certificate from a CA in the
    Microsoft Trusted Root Program removes that prompt for everyone.

    .EXAMPLE
    .\build-msi.ps1

    .EXAMPLE
    # -CodeSigningCert selects by extended key usage, so it finds the right
    # certificate without needing to match a subject name.
    Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
    .\build-msi.ps1 -CertificateThumbprint <thumbprint>
#>
[CmdletBinding()]
param(
    [ValidateSet('x64', 'arm64')]
    [string[]]$Architecture = @('x64', 'arm64'),

    [string]$OutputDirectory,

    # Thumbprint of a code-signing certificate in the current user's store.
    [string]$CertificateThumbprint,

    # RFC 3161 timestamp authority. A timestamped signature stays verifiable
    # after the signing certificate expires, so this is worth keeping even
    # for a self-signed identity.
    [string]$TimestampUrl = 'http://timestamp.digicert.com'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot 'artifacts\msi'
}

function Get-HostArchitecture {
    # Windows PowerShell 5.1 runs emulated on ARM64, where both
    # $env:PROCESSOR_ARCHITECTURE and RuntimeInformation::OSArchitecture
    # report the emulated x64 rather than the real machine. Win32_Processor
    # reports the hardware, so ask that instead.
    $architecture = (Get-CimInstance Win32_Processor | Select-Object -First 1).Architecture
    switch ([int]$architecture) {
        12 { 'arm64' }
        9  { 'x64' }
        default { 'x86' }
    }
}

function Get-SignTool {
    # Prefer the host architecture's build, then any other, newest SDK first.
    $architectureName = Get-HostArchitecture
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\$architectureName\signtool.exe",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\*\signtool.exe")
    foreach ($root in $roots) {
        $found = Get-ChildItem $root -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw 'signtool.exe was not found. Install the Windows SDK signing tools.'
}

function Invoke-Signing([string]$SignTool, [string]$Path) {
    # SHA-256 file digest and SHA-256 timestamp digest; SHA-1 is not
    # acceptable for either on current Windows.
    & $SignTool sign `
        /fd SHA256 `
        /td SHA256 `
        /tr $TimestampUrl `
        /sha1 $CertificateThumbprint `
        $Path
    if ($LASTEXITCODE -ne 0) {
        throw "signtool failed for '$Path'."
    }
}

$signTool = $null
if ($CertificateThumbprint) {
    $certificate = Get-ChildItem "Cert:\CurrentUser\My\$CertificateThumbprint" -ErrorAction SilentlyContinue
    if (-not $certificate) {
        throw "No certificate with thumbprint '$CertificateThumbprint' in Cert:\CurrentUser\My."
    }
    if (-not $certificate.HasPrivateKey) {
        throw 'The selected certificate has no private key.'
    }
    $signTool = Get-SignTool
    Write-Host "Signing as: $($certificate.Subject)"
}

# The version is the UTC build instant as CalVer YY.M.D.B, the same stamp
# ReFineID.csproj gives the app: B is the ten-minute bucket of the day.
$now = [datetime]::UtcNow
$productVersion = '{0}.{1}.{2}.{3}' -f ($now.Year - 2000), $now.Month, $now.Day,
    ($now.Hour * 10 + [math]::Floor($now.Minute / 10))
$env:REFINEID_VERSION = $productVersion

$rustTargets = @{
    'x64'   = 'x86_64-pc-windows-msvc'
    'arm64' = 'aarch64-pc-windows-msvc'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

foreach ($arch in $Architecture) {
    $rustTarget = $rustTargets[$arch]
    Write-Host "Building refineid_minidriver.dll for $rustTarget"
    & cargo build --release --package refineid-minidriver --target $rustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed for $rustTarget."
    }

    $dll = Join-Path $repositoryRoot "target\$rustTarget\release\refineid_minidriver.dll"
    if (-not (Test-Path -LiteralPath $dll)) {
        throw "Expected the built Card Module at '$dll'."
    }

    # Sign the DLL before packaging so the MSI carries the signed image.
    # Signing the package afterwards would leave the loaded binary bare.
    if ($signTool) {
        Invoke-Signing $signTool $dll
    }

    $msi = Join-Path $OutputDirectory "RefineID.CardDriver-$productVersion-$arch.msi"
    Write-Host "Packaging $msi"
    & cargo run --quiet --package refineid-msi -- `
        --architecture $arch `
        --minidriver $dll `
        --output $msi `
        --version $productVersion
    if ($LASTEXITCODE -ne 0) {
        throw "refineid-msi failed for $arch."
    }

    if ($signTool) {
        Invoke-Signing $signTool $msi
    }
}

Write-Host ''
if ($signTool) {
    Write-Host "Signed packages are in $OutputDirectory"
} else {
    Write-Host "Unsigned packages are in $OutputDirectory"
}
