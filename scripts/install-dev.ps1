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
    Installs a development build of the Card Module, or removes it.

    .DESCRIPTION
    A development install and the RefineID Card Driver MSI never stand side
    by side. Before it installs, this script uninstalls every MSI product of
    the RefineID UpgradeCode and removes what any earlier development
    install left; -Uninstall does only the removal. What is removed:

    - every Calais card registration, in both registry views, whose
      80000001 value names refineid_minidriver.dll; another vendor's
      registration is left as it is;
    - the RefineID Key Storage Provider registration, through the DLL's own
      entry point;
    - refineid_minidriver.dll in System32, and the backup earlier versions
      of this script kept under ProgramData\RefineID\backup;
    - the RefineID event source development builds report to.

    A DLL a running process has loaded cannot be deleted. It is renamed
    beside itself, the rename is deleted when Windows restarts, and the
    script says so; a restart finishes the removal.

    Per-user state under %LOCALAPPDATA%\RefineID is the user's: the
    pairing store removes what earlier builds left there when it loads
    (doc/installer-upgrade.md).

    .EXAMPLE
    .\install-dev.ps1 -DllPath dist\x64\refineid_minidriver.dll -AllowUnsigned

    .EXAMPLE
    .\install-dev.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')]
    [string]$DllPath,

    [Parameter(ParameterSetName = 'Install')]
    [switch]$AllowUnsigned,

    [Parameter(ParameterSetName = 'Install')]
    [string]$ContactlessAtrHex,

    [Parameter(Mandatory, ParameterSetName = 'Uninstall')]
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The RefineID Card Driver MSI's UpgradeCode (crates/refineid-msi/src/main.rs).
$upgradeCode = '{DBD5521A-AA2C-45D1-B79C-8535E2C262A5}'
$moduleFile = 'refineid_minidriver.dll'
$destination = Join-Path $env:windir "System32\$moduleFile"
$calaisPath = 'SOFTWARE\Microsoft\Cryptography\Calais\SmartCards'
$providerKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Providers\RefineID Key Storage Provider'
$devErrorSourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\RefineID'
$dataDirectory = Join-Path $env:ProgramData 'RefineID'
$backupDirectory = Join-Path $dataDirectory 'backup'
$services = @('CertPropSvc', 'SCardSvr')

# msiexec exit codes (Microsoft, "MsiExec.exe and InstMsi.exe Error
# Messages") that leave the product removed.
$msiSuccess = 0
$msiRebootRequired = 3010
$msiUnknownProduct = 1605

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
    $key = "HKLM:\$calaisPath\$Name"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name ATR -PropertyType Binary -Value $Atr -Force | Out-Null
    New-ItemProperty -Path $key -Name ATRMask -PropertyType Binary -Value $AtrMask -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Crypto Provider' -PropertyType String `
        -Value 'Microsoft Base Smart Card Crypto Provider' -Force | Out-Null
    New-ItemProperty -Path $key -Name 'Smart Card Key Storage Provider' `
        -PropertyType String -Value 'Microsoft Smart Card Key Storage Provider' `
        -Force | Out-Null
    New-ItemProperty -Path $key -Name '80000001' -PropertyType String `
        -Value $moduleFile -Force | Out-Null
}

function Invoke-ProviderEntry([string]$Module, [string]$Entry) {
    # The same DLL is a CNG key storage provider for a paired phone. CNG
    # caches its configuration, so the DLL registers and unregisters itself
    # through the BCrypt registration API rather than through registry
    # writes. The unregistering entry ignores the status, so a provider
    # that is not registered is no error.
    $process = Start-Process -FilePath "$env:SystemRoot\System32\rundll32.exe" `
        -ArgumentList "`"$Module`",$Entry" -Wait -PassThru
    if ($process.ExitCode -ne 0) {
        throw "$Entry failed with exit code $($process.ExitCode)."
    }
}

# Development builds report every error to the Application log as source
# RefineID (crate refineid-dev-errors, the app's DevErrorLog). The source's
# message file is the .NET Framework's EventLogMessages.dll, part of
# Windows, which renders every event identifier as its first string, so
# Event Viewer shows each message as written.
function Register-DevErrorSource {
    $messageFile = @('Framework64', 'FrameworkArm64', 'Framework') |
        ForEach-Object { "Microsoft.NET\$_\v4.0.30319\EventLogMessages.dll" } |
        Where-Object { Test-Path -LiteralPath (Join-Path $env:SystemRoot $_) } |
        Select-Object -First 1
    if (-not $messageFile) {
        throw 'The .NET Framework event message file EventLogMessages.dll was not found.'
    }
    # EVENTLOG_ERROR_TYPE (winnt.h): the only type RefineID writes.
    $eventLogErrorType = 0x0001
    New-Item -Path $devErrorSourceKey -Force | Out-Null
    New-ItemProperty -Path $devErrorSourceKey -Name EventMessageFile `
        -PropertyType ExpandString -Value "%SystemRoot%\$messageFile" -Force | Out-Null
    New-ItemProperty -Path $devErrorSourceKey -Name TypesSupported `
        -PropertyType DWord -Value $eventLogErrorType -Force | Out-Null
}

Add-Type -Namespace RefineIdDev -Name NativeMethods -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern bool MoveFileEx(string existing, string replacement, int flags);
'@
# MOVEFILE_DELAY_UNTIL_REBOOT (winbase.h).
$moveFileDelayUntilReboot = 0x4

# Removes a file; one a running process has loaded is renamed beside itself
# and deleted when Windows restarts. Returns whether a restart is needed.
function Remove-FileOrAtRestart([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    try {
        Remove-Item -LiteralPath $Path -Force
        return $false
    } catch [System.IO.IOException], [System.UnauthorizedAccessException] {
        $aside = "$Path.$([guid]::NewGuid().ToString('N')).delete"
        Move-Item -LiteralPath $Path -Destination $aside -Force
        if (-not [RefineIdDev.NativeMethods]::MoveFileEx($aside, $null, $moveFileDelayUntilReboot)) {
            throw "'$aside' could not be scheduled for deletion at restart."
        }
        Write-Warning "$Path is in use; it is renamed and goes when Windows restarts."
        return $true
    }
}

# Uninstalls every MSI product of the RefineID UpgradeCode.
function Remove-RefineIdProducts {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    foreach ($product in @($installer.RelatedProducts($upgradeCode))) {
        $name = $installer.ProductInfo($product, 'ProductName')
        $version = $installer.ProductInfo($product, 'VersionString')
        Write-Host "Uninstalling $name $version ($product)"
        $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
            -ArgumentList "/x $product /qn /norestart" -Wait -PassThru
        if ($process.ExitCode -eq $msiRebootRequired) {
            Write-Warning "Restart Windows to finish removing $name $version."
        } elseif ($process.ExitCode -notin @($msiSuccess, $msiUnknownProduct)) {
            throw "msiexec could not uninstall $product (exit code $($process.ExitCode))."
        }
    }
}

# Removes every Calais registration, in both registry views, whose
# 80000001 value names this Card Module. Another vendor's is left alone.
function Remove-CardRegistrations {
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', $view)
        $calais = $base.OpenSubKey($calaisPath, $true)
        if ($null -eq $calais) {
            continue
        }
        try {
            foreach ($name in $calais.GetSubKeyNames()) {
                $card = $calais.OpenSubKey($name)
                $module = if ($card) { [string]$card.GetValue('80000001') } else { '' }
                if ($card) { $card.Close() }
                if ([IO.Path]::GetFileName($module.Trim()) -eq $moduleFile) {
                    $calais.DeleteSubKeyTree($name)
                    Write-Host "Removed card registration $name ($view)"
                }
            }
        } finally {
            $calais.Close()
            $base.Close()
        }
    }
}

# Removes what a development install left. Returns whether a restart is
# needed to finish.
function Remove-DevelopmentInstall {
    # The provider is unregistered by the DLL itself, so before the DLL goes;
    # a DLL from before the provider existed has no entry for it.
    if ((Test-Path -LiteralPath $destination) -and (Test-Path -LiteralPath $providerKey)) {
        Invoke-ProviderEntry -Module $destination -Entry 'RefineIdUnregisterProvider'
    }
    Remove-CardRegistrations
    if (Test-Path -LiteralPath $devErrorSourceKey) {
        Remove-Item -LiteralPath $devErrorSourceKey -Recurse -Force
    }
    $restart = Remove-FileOrAtRestart $destination
    if (Test-Path -LiteralPath $backupDirectory) {
        Remove-Item -LiteralPath $backupDirectory -Recurse -Force
    }
    if ((Test-Path -LiteralPath $dataDirectory) -and
        -not (Get-ChildItem -LiteralPath $dataDirectory -Force)) {
        Remove-Item -LiteralPath $dataDirectory -Force
    }
    $restart
}

Assert-Administrator

if ($Uninstall) {
    if (-not $PSCmdlet.ShouldProcess('RefineID Card Driver and development install', 'Uninstall')) {
        return
    }
    Remove-RefineIdProducts
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }
    try {
        $restart = Remove-DevelopmentInstall
    } finally {
        foreach ($service in @('SCardSvr', 'CertPropSvc')) {
            Start-Service -Name $service -ErrorAction SilentlyContinue
        }
    }
    Write-Host 'RefineID development install removed.'
    if ($restart) {
        Write-Host 'Restart Windows to finish removing the Card Module a running program had loaded.'
    }
    return
}

$contactlessAtr = $null
if ($PSBoundParameters.ContainsKey('ContactlessAtrHex')) {
    [byte[]]$contactlessAtr = ConvertFrom-AtrHex $ContactlessAtrHex
}

$source = (Resolve-Path -LiteralPath $DllPath).Path
if ([IO.Path]::GetFileName($source) -ne $moduleFile) {
    throw "Expected a file named $moduleFile."
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

if (-not $PSCmdlet.ShouldProcess($destination, 'Install RefineID development minidriver')) {
    return
}

Remove-RefineIdProducts

try {
    foreach ($service in $services) {
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
    }

    $restart = Remove-DevelopmentInstall

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

    Invoke-ProviderEntry -Module $destination -Entry 'RefineIdRegisterProvider'

    Register-DevErrorSource

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
} finally {
    foreach ($service in @('SCardSvr', 'CertPropSvc')) {
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }
}

Write-Host "Installed $destination"
Write-Host 'Registered the RefineID event source in the Application log.'
if ($null -ne $contactlessAtr) {
    Write-Host 'Registered the exact contactless ATR for FINEID S4-1 v4.0.'
}
if ($restart) {
    Write-Host 'Restart Windows to finish removing the Card Module a running program had loaded.'
}
Write-Host 'Run certutil -scinfo with a FINEID card inserted.'
