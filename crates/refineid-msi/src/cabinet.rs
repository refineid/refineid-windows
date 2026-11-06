// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Builds the cabinet that carries the package payload.
//!
//! `makecab.exe` ships with Windows, so this adds no dependency beyond the
//! operating system. Each member is stored under its `File` table key rather
//! than its installed name, because that key is what Windows Installer looks
//! for when it extracts the cabinet.

use core::fmt::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Building the cabinet failed.
#[derive(Debug)]
pub enum CabinetError {
    /// The directive file or its directory could not be written.
    Io(std::io::Error),
    /// `SystemRoot` is not set, so the system directory is unknown.
    NoSystemRoot,
    /// `makecab.exe` is not in the system directory.
    NoMakeCab(PathBuf),
    /// `makecab.exe` could not be run.
    Spawn(std::io::Error),
    /// `makecab.exe` ran but reported failure.
    MakeCab {
        /// The process exit code, when one was reported.
        status: Option<i32>,
        /// Captured output, trimmed to the tail that explains the failure.
        output: String,
    },
    /// `makecab.exe` reported success but produced no cabinet.
    Missing(PathBuf),
}

impl fmt::Display for CabinetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "could not stage the cabinet directives: {error}"),
            Self::NoSystemRoot => write!(f, "SystemRoot is not set; makecab.exe cannot be found"),
            Self::NoMakeCab(path) => write!(f, "makecab.exe is missing at {}", path.display()),
            Self::Spawn(error) => write!(f, "could not run makecab.exe: {error}"),
            Self::MakeCab { status, output } => match status {
                Some(status) => write!(f, "makecab.exe exited with {status}: {output}"),
                None => write!(f, "makecab.exe was terminated: {output}"),
            },
            Self::Missing(path) => {
                write!(f, "makecab.exe produced no cabinet at {}", path.display())
            }
        }
    }
}

impl std::error::Error for CabinetError {}

/// The environment variable that names the Windows directory.
const SYSTEM_ROOT_VARIABLE: &str = "SystemRoot";
/// The system directory below `SystemRoot`, where Windows keeps `makecab.exe`.
const SYSTEM_DIRECTORY: &str = "System32";
/// The cabinet maker's file name.
const MAKECAB: &str = "makecab.exe";

/// The absolute path of `makecab.exe` in the Windows system directory, so
/// neither `PATH` nor the current directory chooses the program that runs.
fn makecab_path() -> Result<PathBuf, CabinetError> {
    let root = std::env::var_os(SYSTEM_ROOT_VARIABLE)
        .filter(|root| !root.is_empty())
        .ok_or(CabinetError::NoSystemRoot)?;
    let path = PathBuf::from(root).join(SYSTEM_DIRECTORY).join(MAKECAB);
    if path.is_file() {
        Ok(path)
    } else {
        Err(CabinetError::NoMakeCab(path))
    }
}

/// One payload file and the `File` table key it is stored under.
#[derive(Debug, Clone, Copy)]
pub struct Member<'a> {
    /// Path to the file on disk.
    pub source: &'a Path,
    /// The `File` table key, used as the name inside the cabinet.
    pub key: &'a str,
}

/// Builds `cabinet_name` inside `directory` from `members`.
///
/// Returns the path to the finished cabinet.
///
/// # Errors
///
/// Returns an error if the directives cannot be staged, `makecab.exe` fails,
/// or no cabinet is produced.
pub fn build(
    directory: &Path,
    cabinet_name: &str,
    members: &[Member<'_>],
) -> Result<PathBuf, CabinetError> {
    std::fs::create_dir_all(directory).map_err(CabinetError::Io)?;

    let mut directives = String::from(".OPTION EXPLICIT\n");
    directives.push_str(".Set Cabinet=on\n");
    directives.push_str(".Set Compress=on\n");
    directives.push_str(".Set CompressionType=MSZIP\n");
    // A single cabinet with no size limit: the payload is one small DLL, and
    // splitting would need extra Media rows to describe.
    directives.push_str(".Set MaxDiskSize=0\n");
    directives.push_str(".Set ReservePerCabinetSize=0\n");
    // Writing into a String cannot fail, so the results carry no information.
    let _ = writeln!(directives, ".Set CabinetNameTemplate={cabinet_name}");
    let _ = writeln!(directives, ".Set DiskDirectory1={}", directory.display());
    // makecab writes its manifest and report to the current directory
    // unless told otherwise, which drops build scratch wherever the build
    // happened to be invoked from. Keep them inside the scratch directory.
    let _ = writeln!(
        directives,
        ".Set InfFileName={}",
        directory.join("setup.inf").display()
    );
    let _ = writeln!(
        directives,
        ".Set RptFileName={}",
        directory.join("setup.rpt").display()
    );
    for member in members {
        let _ = writeln!(directives, "\"{}\" {}", member.source.display(), member.key);
    }

    let directive_path = directory.join("payload.ddf");
    std::fs::write(&directive_path, directives).map_err(CabinetError::Io)?;

    let output = Command::new(makecab_path()?)
        .arg("/F")
        .arg(&directive_path)
        .output()
        .map_err(CabinetError::Spawn)?;

    if !output.status.success() {
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        let tail: String = text.lines().rev().take(6).collect::<Vec<_>>().join("; ");
        return Err(CabinetError::MakeCab {
            status: output.status.code(),
            output: tail,
        });
    }

    let cabinet = directory.join(cabinet_name);
    if !cabinet.is_file() {
        return Err(CabinetError::Missing(cabinet));
    }

    // The directives and makecab's report files are build scratch, not output.
    let _ = std::fs::remove_file(&directive_path);
    let _ = std::fs::remove_file(directory.join("setup.inf"));
    let _ = std::fs::remove_file(directory.join("setup.rpt"));

    Ok(cabinet)
}
