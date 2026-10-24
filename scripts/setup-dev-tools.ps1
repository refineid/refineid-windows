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

# Installs the Windows 11 development toolchain for this repository and
# updates every installed part to its latest release: Git, GitHub CLI, the
# latest Visual Studio Build Tools with the MSVC x64 and ARM64 tools and the
# Windows 11 SDK, rustup with the latest stable toolchain rust-toolchain.toml selects, the
# latest .NET SDK of the major the WinUI apps target, the latest Python 3
# through the Python Install Manager, the repository's .NET local tools, and
# the Git hooks. Rerun it at any time to update. Run it from a
# normal (non-elevated) PowerShell; winget and the Visual Studio Installer ask
# for elevation for the machine-wide installers.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = Split-Path -Parent $PSScriptRoot

# Visual Studio 2026 (18.x) or any later release.
$visualStudioMinimumVersion = '18.0'
$visualStudioComponents = @(
    'Microsoft.VisualStudio.Workload.VCTools',
    'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
    'Microsoft.VisualStudio.Component.VC.Tools.ARM64'
)
$dotnetSdkMajor = 10 # follows TargetFramework in apps/RefineID-winui/RefineID.csproj

$wingetUpdateNotApplicable = -1978335189 # APPINSTALLER_CLI_ERROR_UPDATE_NOT_APPLICABLE
$wingetPackageAlreadyInstalled = -1978335135 # APPINSTALLER_CLI_ERROR_PACKAGE_ALREADY_INSTALLED
$wingetRebootRequiredToFinish = -1978334967 # APPINSTALLER_CLI_ERROR_INSTALL_REBOOT_REQUIRED_TO_FINISH
$installerRestartRequired = 3010

$programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
$visualStudioInstallerDirectory = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer'
$vswhere = Join-Path $visualStudioInstallerDirectory 'vswhere.exe'
$visualStudioSetup = Join-Path $visualStudioInstallerDirectory 'setup.exe'

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    $env:Path = (@($machine, $user, $cargoBin) | Where-Object { $_ }) -join ';'
}

function Test-Command([string]$Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Invoke-Winget([string]$Verb, [string]$Id, [string[]]$ExtraArguments) {
    & winget $Verb --id $Id --exact --source winget `
        --accept-package-agreements --accept-source-agreements --disable-interactivity `
        @ExtraArguments | Out-Host
    $exitCode = $LASTEXITCODE
    Update-SessionPath
    return $exitCode
}

# Installs the package when $Present is false, otherwise upgrades it to the
# latest release.
function Sync-WingetPackage([string]$Id, [bool]$Present, [string[]]$InstallArguments = @()) {
    if ($Present) {
        Write-Host "Updating $Id to the latest release..."
        $exitCode = Invoke-Winget 'upgrade' $Id @()
        if ($exitCode -eq $wingetUpdateNotApplicable) {
            Write-Host "$Id is up to date."
        } elseif ($exitCode -ne 0) {
            # A copy installed outside winget cannot be upgraded by it; the
            # installed copy still satisfies the build.
            Write-Warning "winget upgrade $Id failed with exit code $exitCode; update it manually."
        }
    } else {
        Write-Host "Installing $Id..."
        $exitCode = Invoke-Winget 'install' $Id $InstallArguments
        if ($exitCode -eq $wingetRebootRequiredToFinish) {
            Write-Warning "$Id is installed; restart Windows to finish the installation."
        } elseif ($exitCode -ne 0 -and $exitCode -ne $wingetPackageAlreadyInstalled) {
            throw "winget install $Id failed with exit code $exitCode."
        }
    }
}

function Get-VisualStudioInstance([string[]]$RequiredComponents) {
    if (-not (Test-Path -LiteralPath $vswhere)) {
        return $null
    }
    $arguments = @('-products', '*', '-version', $visualStudioMinimumVersion, '-latest',
        '-property', 'installationPath', '-nologo')
    if ($RequiredComponents) {
        $arguments += '-requires'
        $arguments += $RequiredComponents
    }
    $paths = @(& $vswhere @arguments | Where-Object { $_ })
    if ($paths.Count -eq 0) {
        return $null
    }
    return $paths[0]
}

function Invoke-VisualStudioInstaller([string[]]$Arguments) {
    $quoted = foreach ($argument in $Arguments) {
        if ($argument -match '\s') { "`"$argument`"" } else { $argument }
    }
    $process = Start-Process -FilePath $visualStudioSetup -ArgumentList $quoted -Wait -PassThru -Verb RunAs
    if ($process.ExitCode -eq $installerRestartRequired) {
        Write-Warning "Visual Studio Installer $($Arguments[0]) succeeded; restart Windows before building."
    } elseif ($process.ExitCode -ne 0) {
        throw "Visual Studio Installer $($Arguments[0]) failed with exit code $($process.ExitCode)."
    }
}

# Installs the latest Build Tools when no Visual Studio 2026 or later instance
# exists. Otherwise updates that instance, which also moves the Windows 11 SDK
# to the release it recommends, and adds any missing MSVC component.
function Sync-VisualStudio {
    $componentArguments = foreach ($component in $visualStudioComponents) { '--add'; $component }
    $instance = Get-VisualStudioInstance @()

    if (-not $instance) {
        $override = (@('--wait', '--passive', '--norestart') + $componentArguments + '--includeRecommended') -join ' '
        Sync-WingetPackage 'Microsoft.VisualStudio.BuildTools' $false @('--override', $override)
    } else {
        Write-Host "Updating Visual Studio at $instance to the latest release..."
        Invoke-VisualStudioInstaller @('update', '--installPath', $instance, '--passive', '--norestart')
        # --includeRecommended on modify also adds the workload's recommended
        # Windows 11 SDK when an existing instance lacks it.
        if (-not (Get-VisualStudioInstance $visualStudioComponents) -or -not (Test-WindowsSdk)) {
            Write-Host 'Adding the MSVC x64 and ARM64 tools and the Windows 11 SDK...'
            Invoke-VisualStudioInstaller (@('modify', '--installPath', $instance) + $componentArguments +
                @('--includeRecommended', '--passive', '--norestart'))
        }
    }

    if (-not (Get-VisualStudioInstance $visualStudioComponents)) {
        throw 'Visual Studio with the MSVC x64 and ARM64 tools is still missing after installation.'
    }
    if (-not (Test-WindowsSdk)) {
        throw 'The Windows SDK libraries the MSVC linker needs are still missing after installation.'
    }
}

# The MSVC linker resolves the Windows import libraries from the Windows SDK.
function Test-WindowsSdk {
    $libraries = Join-Path $programFilesX86 'Windows Kits\10\Lib'
    $kernel32 = Get-ChildItem -Path $libraries -Filter kernel32.lib -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    return [bool]$kernel32
}

function Test-DotnetSdk {
    if (-not (Test-Command dotnet)) {
        return $false
    }
    $sdks = @(& dotnet --list-sdks)
    return [bool]($sdks | Where-Object { $_ -match "^$dotnetSdkMajor\." })
}

function Find-SignTool {
    $kits = Join-Path $programFilesX86 'Windows Kits\10\bin'
    return Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

Update-SessionPath

if (-not (Test-Command winget)) {
    throw 'winget was not found. Install App Installer from the Microsoft Store and rerun.'
}

Sync-WingetPackage 'Git.Git' (Test-Command git)
Sync-WingetPackage 'GitHub.cli' (Test-Command gh)
Sync-VisualStudio

if (Test-Command rustup) {
    Write-Host 'Updating rustup to the latest release...'
    Invoke-Checked 'rustup self update' { rustup self update }
} else {
    Sync-WingetPackage 'Rustlang.Rustup' $false
}

Sync-WingetPackage "Microsoft.DotNet.SDK.$dotnetSdkMajor" (Test-DotnetSdk)
if (-not (Test-DotnetSdk)) {
    throw ".NET $dotnetSdkMajor SDK is still missing after installation."
}

# The Python Install Manager provides the python3 command that
# scripts/test-browser-edge.py and the refineid-core gate scripts call; tag 3
# selects the latest stable Python 3 release.
Sync-WingetPackage 'Python.PythonInstallManager' (Test-Command pymanager)
Write-Host 'Installing or updating the latest Python 3...'
Invoke-Checked 'pymanager install' { pymanager install --update --yes 3 }
Invoke-Checked 'python3 --version' { python3 --version }

Push-Location $repositoryRoot
try {
    # With no toolchain name, rustup installs the channel, components, and
    # targets rust-toolchain.toml names.
    Write-Host 'Installing the stable Rust toolchain named by rust-toolchain.toml...'
    Invoke-Checked 'rustup toolchain install' { rustup toolchain install }
    Invoke-Checked 'rustc --version' { rustc --version }

    Write-Host 'Restoring .NET local tools...'
    Invoke-Checked 'dotnet tool restore' { dotnet tool restore }

    Invoke-Checked 'git config core.hooksPath' { git config core.hooksPath .githooks }
    Write-Host 'Git hooks: core.hooksPath set to .githooks.'
} finally {
    Pop-Location
}

if (Find-SignTool) {
    Write-Host 'signtool.exe: present.'
} else {
    Write-Warning 'signtool.exe was not found; packaging/windows/build-msi.ps1 cannot sign until the Windows SDK signing tools are installed.'
}

Write-Host ''
Write-Host 'Development tools are ready. Open a new terminal so PATH changes apply, then run:'
Write-Host '  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Architecture x64,arm64'
