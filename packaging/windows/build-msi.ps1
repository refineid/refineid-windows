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

    Every package replaces an installed RefineID Card Driver of the same or
    an earlier version, refuses to install over a later one, and removes
    what development installs outside the package left
    (doc/installer-upgrade.md).

    The packages carry the Plug and Play driver package that names FINEID
    cards in Device Manager only when its catalog is signed: Windows
    refuses an unsigned driver package. -DriverPackage takes a directory
    holding refineid_card.inf and a signed refineid_card.cat, such as the
    package Microsoft's hardware dashboard returns; its INF must be the one
    `refineid-msi --write-inf` writes. Without it, -CertificateThumbprint
    also generates the INF, catalogs it with makecat.exe and signs the
    catalog. Windows on Arm64 accepts only a Microsoft-signed catalog for a
    release-signed package, so there only -DriverPackage names the cards.

    Signing is optional. Without -CertificateThumbprint the output is
    unsigned. With a self-signed certificate the output carries a verifiable
    author identity and tamper-evidence, but the chain does not validate on
    a machine that has not chosen to trust that certificate; Windows still
    reports an unknown publisher there. Only a certificate from a CA in the
    Microsoft Trusted Root Program removes that prompt for everyone.

    .EXAMPLE
    .\build-msi.ps1

    .EXAMPLE
    .\build-msi.ps1 -DriverPackage C:\Signed\refineid_card

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

    # Directory holding a signed driver package: refineid_card.inf and
    # refineid_card.cat.
    [string]$DriverPackage,

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

function Get-KitTool([string]$Name) {
    # Prefer the host architecture's build, then any other, newest SDK first.
    $architectureName = Get-HostArchitecture
    $roots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\$architectureName\$Name",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\*\$Name")
    foreach ($root in $roots) {
        $found = Get-ChildItem $root -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    throw "$Name was not found. Install the Windows SDK signing tools."
}

function New-DriverCatalog([string]$MakeCat, [string]$Directory) {
    # A SHA-256 catalog of the INF for Windows 10 and later (OSAttr 2:10.0),
    # the attribute Inf2Cat writes for those versions.
    $definition = Join-Path $Directory 'refineid_card.cdf'
    $inf = Join-Path $Directory 'refineid_card.inf'
    $osAttribute = '0x10010001:OSAttr:2:10.0'
    @(
        '[CatalogHeader]',
        'Name=refineid_card.cat',
        "ResultDir=$Directory",
        'CatalogVersion=2',
        'HashAlgorithms=SHA256',
        "CATATTR1=$osAttribute",
        '',
        '[CatalogFiles]',
        "<HASH>refineid_card.inf=$inf",
        "<HASH>refineid_card.infATTR1=$osAttribute",
        ''
    ) | Set-Content -LiteralPath $definition -Encoding ascii
    & $MakeCat -v $definition
    if ($LASTEXITCODE -ne 0) {
        throw 'makecat failed for the driver package.'
    }
    Remove-Item -LiteralPath $definition
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
    $signTool = Get-KitTool 'signtool.exe'
    Write-Host "Signing as: $($certificate.Subject)"
}

# The version is the UTC build instant as CalVer YY.M.D.HHMM, the same stamp
# RefineID.csproj gives the app and refineid-stamp reads: HHMM is the time
# of day as hour * 100 + minute. The MSI's upgrade order follows it, so a
# later build always replaces an earlier one.
$now = [datetime]::UtcNow
$productVersion = '{0}.{1}.{2}.{3}' -f ($now.Year - 2000), $now.Month, $now.Day,
    ($now.Hour * 100 + $now.Minute)
$env:REFINEID_VERSION = $productVersion

# Cargo builds the tree this script belongs to, whatever the current directory,
# with exactly the dependency revisions its committed Cargo.lock pins.
$manifest = Join-Path $repositoryRoot 'Cargo.toml'

$rustTargets = @{
    'x64'   = 'x86_64-pc-windows-msvc'
    'arm64' = 'aarch64-pc-windows-msvc'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

# The driver package is the same for both architectures: one INF decorated
# for x64 and Arm64, and one catalog.
$driverDirectory = $null
if ($DriverPackage) {
    $driverDirectory = (Resolve-Path -LiteralPath $DriverPackage).Path
} elseif ($signTool) {
    $driverDirectory = Join-Path $OutputDirectory 'driver-package'
    New-Item -ItemType Directory -Path $driverDirectory -Force | Out-Null
    $inf = Join-Path $driverDirectory 'refineid_card.inf'
    & cargo run --manifest-path $manifest --locked --quiet --package refineid-msi -- `
        --write-inf $inf `
        --version $productVersion
    if ($LASTEXITCODE -ne 0) {
        throw 'refineid-msi could not write the driver package INF.'
    }
    New-DriverCatalog (Get-KitTool 'makecat.exe') $driverDirectory
    Invoke-Signing $signTool (Join-Path $driverDirectory 'refineid_card.cat')
} else {
    Write-Host 'No signed driver package: Device Manager keeps the inbox name for the cards.'
}
$driverArguments = @()
if ($driverDirectory) {
    $driverArguments = @('--driver-package', $driverDirectory)
}

foreach ($arch in $Architecture) {
    $rustTarget = $rustTargets[$arch]
    Write-Host "Building refineid_minidriver.dll and refineid-agent.exe for $rustTarget"
    & cargo build --manifest-path $manifest --locked --release --package refineid-minidriver --package refineid-agent --target $rustTarget
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed for $rustTarget."
    }

    $dll = Join-Path $repositoryRoot "target\$rustTarget\release\refineid_minidriver.dll"
    if (-not (Test-Path -LiteralPath $dll)) {
        throw "Expected the built Card Module at '$dll'."
    }

    $agent = Join-Path $repositoryRoot "target\$rustTarget\release\refineid-agent.exe"
    if (-not (Test-Path -LiteralPath $agent)) {
        throw "Expected the built agent at '$agent'."
    }

    # Sign the binaries before packaging so the MSI carries the signed images.
    # Signing the package afterwards would leave the loaded binaries bare.
    if ($signTool) {
        Invoke-Signing $signTool $dll
        Invoke-Signing $signTool $agent
    }

    $msi = Join-Path $OutputDirectory "RefineID.CardDriver-$productVersion-$arch.msi"
    Write-Host "Packaging $msi"
    & cargo run --manifest-path $manifest --locked --quiet --package refineid-msi -- `
        --architecture $arch `
        --minidriver $dll `
        --agent $agent `
        @driverArguments `
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
