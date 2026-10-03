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

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$DllPath,

    [switch]$AllowUnsigned,

    [string]$ContactlessAtrHex
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated PowerShell.'
    }
}

function Get-PeMachine([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -lt 64 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
        throw "'$Path' is not a PE image."
    }
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ($peOffset -lt 0 -or $peOffset + 6 -gt $bytes.Length) {
        throw "'$Path' has an invalid PE header."
    }
    if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset + 1] -ne 0x45) {
        throw "'$Path' has an invalid PE signature."
    }
    [BitConverter]::ToUInt16($bytes, $peOffset + 4)
}

function ConvertFrom-AtrHex([string]$Hex) {
    $compact = $Hex -replace '[\s:-]', ''
    if ([string]::IsNullOrEmpty($compact) -or
        $compact -notmatch '\A[0-9A-Fa-f]+\z' -or
        ($compact.Length % 2) -ne 0) {
        throw 'ContactlessAtrHex must contain complete hexadecimal bytes.'
    }

    $byteCount = $compact.Length / 2
    if ($byteCount -lt 2 -or $byteCount -gt 33) {
        throw 'ContactlessAtrHex must contain between 2 and 33 bytes.'
    }

    [byte[]]$bytes = [byte[]]::new($byteCount)
    for ($index = 0; $index -lt $byteCount; $index++) {
        $bytes[$index] = [Convert]::ToByte($compact.Substring($index * 2, 2), 16)
    }
    $bytes
}

function Set-CardRegistration(
    [string]$Name,
    [byte[]]$Atr,
    [byte[]]$AtrMask
) {
    $key = "HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\$Name"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name ATR -PropertyType Binary -Value $Atr -Force | Out-Null
    New-ItemProperty -Path $key -Name ATRMask -PropertyType Binary -Value $AtrMask -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Crypto Provider' -PropertyType String `
        -Value 'Microsoft Base Smart Card Crypto Provider' -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Smart Card Key Storage Provider' `
        -PropertyType String -Value 'Microsoft Smart Card Key Storage Provider' `
        -Force | Out-Null
    New-ItemProperty -Path $key -Name '80000001' -PropertyType String `
        -Value 'refineid_minidriver.dll' -Force | Out-Null
}

Assert-Administrator

$contactlessAtr = $null
if ($PSBoundParameters.ContainsKey('ContactlessAtrHex')) {
    [byte[]]$contactlessAtr = ConvertFrom-AtrHex $ContactlessAtrHex
}

$source = (Resolve-Path -LiteralPath $DllPath).Path
if ([IO.Path]::GetFileName($source) -ne 'refineid_minidriver.dll') {
    throw 'Expected a file named refineid_minidriver.dll.'
}

$machineNames = @{
    0x8664 = 'X64'
    0xAA64 = 'Arm64'
}
$machine = Get-PeMachine $source
if (-not $machineNames.ContainsKey([int]$machine)) {
    throw ('Unsupported PE machine 0x{0:X4}.' -f $machine)
}
$operatingSystemArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
if ($machineNames[[int]$machine] -ne $operatingSystemArchitecture) {
    throw "DLL architecture $($machineNames[[int]$machine]) does not match Windows $operatingSystemArchitecture."
}

$signature = Get-AuthenticodeSignature -LiteralPath $source
if ($signature.Status -ne 'Valid' -and -not $AllowUnsigned) {
    throw "Authenticode status is $($signature.Status). Use -AllowUnsigned only on an isolated test system."
}

$destination = Join-Path $env:windir 'System32\refineid_minidriver.dll'
$backupDirectory = Join-Path $env:ProgramData 'RefineID\backup'
$backup = Join-Path $backupDirectory 'refineid_minidriver.dll'
$services = @('CertPropSvc', 'SCardSvr')

if (-not $PSCmdlet.ShouldProcess($destination, 'Install RefineID development minidriver')) {
    return
}

New-Item -ItemType Directory -Path $backupDirectory -Force | Out-Null
if (Test-Path -LiteralPath $destination) {
    Copy-Item -LiteralPath $destination -Destination $backup -Force
}

try {
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }

    Copy-Item -LiteralPath $source -Destination $destination -Force

    Set-CardRegistration -Name 'FINEID-S4-1-v3.1' `
        -Atr ([byte[]](0x3B,0x7F,0x96,0x00,0x00,0x80,0x31,0xB8,0x65,0xB0,0x85,0x04,0x02,0x1B,0x12,0x00,0xF6,0x82,0x90,0x00)) `
        -AtrMask ([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF))

    Set-CardRegistration -Name 'FINEID-S4-1-v4.0' `
        -Atr ([byte[]](0x3B,0x7F,0x96,0x00,0x00,0x80,0x31,0xB8,0x65,0xB0,0x85,0x05,0x00,0x00,0x00,0x00,0x00,0x82,0x90,0x00)) `
        -AtrMask ([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF))

    Set-CardRegistration -Name 'FINEID-RAPP-Remote' `
        -Atr ([byte[]](0x3B,0x7F,0x96,0x00,0x00,0x80,0x31,0xB8,0x65,0xB0,0x85,0x05,0x52,0x41,0x50,0x50,0x00,0x82,0x90,0x00)) `
        -AtrMask ([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF))

    Set-CardRegistration -Name 'FINEID-RAPP-Virtual' `
        -Atr ([byte[]](0x3B,0x8D,0x01,0x80,0xFB,0xA0,0x00,0x00,0x03,0x97,0x42,0x54,0x46,0x59,0x04,0x01,0xCF)) `
        -AtrMask ([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF))

    Set-CardRegistration -Name 'FINEID-Dev-CCID' `
        -Atr ([byte[]](0x3B,0xFD,0x13,0x00,0x00,0x81,0x31,0xFE,0x15,0x80,0x73,0xC0,0x21,0xC0,0x57,0x59,0x75,0x62,0x69,0x4B,0x65,0x79,0x40)) `
        -AtrMask ([byte[]](0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF))

    if ($null -ne $contactlessAtr) {
        [byte[]]$contactlessMask = [byte[]]::new($contactlessAtr.Length)
        for ($index = 0; $index -lt $contactlessMask.Length; $index++) {
            $contactlessMask[$index] = 0xFF
        }
        Set-CardRegistration -Name 'FINEID-S4-1-v4.0-contactless' `
            -Atr $contactlessAtr `
            -AtrMask $contactlessMask
    }
} catch {
    if (Test-Path -LiteralPath $backup) {
        Copy-Item -LiteralPath $backup -Destination $destination -Force
    }
    throw
} finally {
    foreach ($service in @('SCardSvr', 'CertPropSvc')) {
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }
}

Write-Host "Installed $destination"
if ($null -ne $contactlessAtr) {
    Write-Host 'Registered the exact contactless ATR for FINEID S4-1 v4.0.'
}
Write-Host 'Run certutil -scinfo with a FINEID card inserted.'
