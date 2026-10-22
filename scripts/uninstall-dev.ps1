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

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell.'
}

$destination = Join-Path $env:windir 'System32\refineid_minidriver.dll'
$backupDirectory = Join-Path $env:ProgramData 'RefineID\backup'
$backup = Join-Path $backupDirectory 'refineid_minidriver.dll'
$registryKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\FINEID-S4-1-v3.1',
    'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\FINEID-S4-1-v4.0',
    'HKLM:\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards\FINEID-S4-1-v4.0-contactless',
    # The event source development builds report their errors as.
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\RefineID'
)

if (-not $PSCmdlet.ShouldProcess('RefineID development minidriver', 'Uninstall')) {
    return
}

foreach ($service in @('CertPropSvc', 'SCardSvr')) {
    Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
}

try {
    foreach ($key in $registryKeys) {
        if (Test-Path -LiteralPath $key) {
            Remove-Item -LiteralPath $key -Recurse -Force
        }
    }

    if (Test-Path -LiteralPath $backup) {
        Copy-Item -LiteralPath $backup -Destination $destination -Force
        Remove-Item -LiteralPath $backup -Force
    } elseif (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Force
    }

    if ((Test-Path -LiteralPath $backupDirectory) -and
        -not (Get-ChildItem -LiteralPath $backupDirectory -Force)) {
        Remove-Item -LiteralPath $backupDirectory -Force
    }
} finally {
    foreach ($service in @('SCardSvr', 'CertPropSvc')) {
        Start-Service -Name $service -ErrorAction SilentlyContinue
    }
}

Write-Host 'RefineID development minidriver removed.'
