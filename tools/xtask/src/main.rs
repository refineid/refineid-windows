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

//! Repository policy tasks, including magic-number enforcement across Rust
//! sources and tests.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use proc_macro2::{Spacing, Span, TokenStream, TokenTree};
use rustc_lexer::TokenKind;
use syn::ext::IdentExt;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Expr, ExprAsync, ExprClosure, ImplItemConst, Item, ItemConst, ItemStatic, ItemUse,
    Lit, LitByte, LitByteStr, LitCStr, LitChar, LitFloat, LitInt, LitStr, Macro, TraitItemConst,
    UseTree, Variant,
};
use walkdir::{DirEntry, WalkDir};

/// Exit code for invalid CLI arguments.
const USAGE_EXIT_CODE: i32 = 2;
/// Exit code when a policy violation is detected.
const POLICY_EXIT_CODE: i32 = 1;
/// Repository-relative path to the checked-in legacy baseline file.
const BASELINE_REL_PATH: &str = "tools/xtask/baseline.json";

/// Diff scope for zero-tolerance touched-line checks.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DiffMode {
    /// Check the whole tree against the ratchet baseline only.
    TreeOnly,
    /// Additionally reject any violation on any added or modified staged line.
    Staged,
    /// Additionally reject any violation on any added or modified line in `base..head`.
    DiffRange { base: String, head: String },
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-magic-numbers"] => DiffMode::TreeOnly,
        ["check-magic-numbers", "--staged"] => DiffMode::Staged,
        ["check-magic-numbers", "--diff-base", base] => DiffMode::DiffRange {
            base: (*base).to_owned(),
            head: "HEAD".to_owned(),
        },
        [
            "check-magic-numbers",
            "--diff-base",
            base,
            "--diff-head",
            head,
        ] => DiffMode::DiffRange {
            base: (*base).to_owned(),
            head: (*head).to_owned(),
        },
        _ => {
            eprintln!(
                "usage: cargo run -q -p xtask -- check-magic-numbers [--staged | --diff-base <rev> [--diff-head <rev>]]"
            );
            process::exit(USAGE_EXIT_CODE);
        }
    };

    if let Err(error) = check_magic_numbers(&workspace_root(), &mode) {
        eprintln!("{error}");
        process::exit(POLICY_EXIT_CODE);
    }
}

/// The workspace this run checks: two directories above the manifest
/// `cargo run` names at run time, never the one compiled in, so a
/// binary built in one checkout and reused from another, as a shared
/// target directory allows, still checks the checkout it runs in.
fn workspace_root() -> PathBuf {
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("cargo run sets CARGO_MANIFEST_DIR for xtask");
    Path::new(&manifest_dir)
        .parent()
        .and_then(Path::parent)
        .expect("xtask is stored at tools/xtask")
        .to_path_buf()
}

fn check_magic_numbers(root: &Path, mode: &DiffMode) -> Result<(), String> {
    validate_cargo_targets(root)?;

    let baseline = load_baseline(root)?;
    let mut violations_by_file: BTreeMap<String, Vec<Violation>> = BTreeMap::new();
    let mut existing_rust_files: BTreeSet<String> = BTreeSet::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| is_source_tree_entry(root, entry))
    {
        let entry = entry.map_err(|error| format!("cannot walk source tree: {error}"))?;
        reject_source_tree_symlink(&entry)?;
        if !entry.file_type().is_file() || entry.path().extension() != Some(OsStr::new("rs")) {
            continue;
        }
        let rel = relative_posix_path(root, entry.path())?;
        existing_rust_files.insert(rel.clone());
        let source = fs::read_to_string(entry.path())
            .map_err(|error| format!("cannot read {rel}: {error}"))?;
        let file_violations = inspect_rust_source(Path::new(&rel), &source)?;
        if !file_violations.is_empty() {
            violations_by_file.insert(rel, file_violations);
        }
    }

    let mut errors = evaluate_ratchet(&violations_by_file, &existing_rust_files, &baseline);

    match mode {
        DiffMode::TreeOnly => {}
        DiffMode::Staged => {
            let added = staged_added_rust_lines(root, true)?;
            errors.extend(check_touched_lines(
                root,
                &added,
                GitBlobSource::Index,
                true,
            )?);
        }
        DiffMode::DiffRange { base, head } => {
            let added = diff_range_added_rust_lines(root, base, head, false)?;
            errors.extend(check_touched_lines(
                root,
                &added,
                GitBlobSource::Commit(head),
                false,
            )?);
        }
    }

    if errors.is_empty() {
        println!("magic-number policy: clean");
        return Ok(());
    }

    for message in &errors {
        eprintln!("{message}");
    }
    Err(format!(
        "magic-number policy rejected {} issue(s); name the domain concept",
        errors.len()
    ))
}

fn load_baseline(root: &Path) -> Result<BTreeMap<String, usize>, String> {
    let path = root.join(BASELINE_REL_PATH);
    let raw = fs::read_to_string(&path)
        .map_err(|error| format!("cannot read {BASELINE_REL_PATH}: {error}"))?;
    let parsed: BTreeMap<String, usize> = serde_json::from_str(&raw)
        .map_err(|error| format!("cannot parse {BASELINE_REL_PATH}: {error}"))?;
    Ok(parsed)
}

fn evaluate_ratchet(
    violations_by_file: &BTreeMap<String, Vec<Violation>>,
    existing_rust_files: &BTreeSet<String>,
    baseline: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut errors = Vec::new();

    for (rel, file_violations) in violations_by_file {
        let mut numeric_violations = Vec::new();
        for violation in file_violations {
            match &violation.kind {
                ViolationKind::SourceIndirection(form) => {
                    errors.push(format!(
                        "{}:{}:{}: source indirection `{form}` is prohibited",
                        violation.path.display(),
                        violation.line,
                        violation.column
                    ));
                }
                ViolationKind::AnonymousLiteral(_) | ViolationKind::TextNumericSpelling(_) => {
                    numeric_violations.push(violation);
                }
            }
        }

        if numeric_violations.is_empty() {
            continue;
        }

        let allowed = baseline.get(rel).copied().unwrap_or(0);
        if numeric_violations.len() > allowed {
            errors.push(format!(
                "{rel}: {} magic-number violation(s) exceed baseline {allowed}",
                numeric_violations.len()
            ));
            for violation in &numeric_violations {
                errors.push(format_violation(violation));
            }
        } else if numeric_violations.len() < allowed {
            eprintln!(
                "magic-number ratchet: {rel} improved ({} < baseline {allowed}); lower its entry in {BASELINE_REL_PATH}",
                numeric_violations.len()
            );
        }
    }

    for (rel, &allowed) in baseline {
        if !existing_rust_files.contains(rel) {
            errors.push(format!(
                "{BASELINE_REL_PATH}: stale entry `{rel}` (file no longer exists); remove it"
            ));
            continue;
        }
        let numeric_count = violations_by_file.get(rel).map_or(0, |items| {
            items
                .iter()
                .filter(|item| !matches!(item.kind, ViolationKind::SourceIndirection(_)))
                .count()
        });
        if numeric_count == 0 {
            errors.push(format!(
                "{BASELINE_REL_PATH}: stale entry `{rel}` (baseline {allowed}, actual 0); remove it"
            ));
        }
    }

    errors
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitBlobSource<'a> {
    Index,
    Commit(&'a str),
}

/// Local Git environment variables that hooks export and that would redirect
/// `git -C <other-repo>` to the caller's repository if inherited.
const LOCAL_GIT_ENV_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
];

fn git_command(root: &Path, preserve_hook_env: bool) -> Command {
    let mut cmd = Command::new("git");
    if !preserve_hook_env {
        for key in LOCAL_GIT_ENV_VARS {
            cmd.env_remove(key);
        }
    }
    cmd.arg("-C").arg(root);
    cmd
}

fn check_touched_lines(
    root: &Path,
    added_lines: &BTreeMap<String, BTreeSet<usize>>,
    source_kind: GitBlobSource<'_>,
    preserve_hook_env: bool,
) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    for (rel, lines) in added_lines {
        if lines.is_empty() {
            continue;
        }
        let Some(source) = read_git_blob(root, rel, source_kind, preserve_hook_env)? else {
            continue;
        };
        let violations = inspect_rust_source(Path::new(rel), &source)?;
        for violation in &violations {
            if lines.contains(&violation.line) {
                errors.push(format!(
                    "{} (added/modified line; zero new magic numbers allowed)",
                    format_violation(violation)
                ));
            }
        }
    }
    Ok(errors)
}

fn read_git_blob(
    root: &Path,
    rel: &str,
    source_kind: GitBlobSource<'_>,
    preserve_hook_env: bool,
) -> Result<Option<String>, String> {
    let spec = match source_kind {
        GitBlobSource::Index => format!(":{rel}"),
        GitBlobSource::Commit(rev) => format!("{rev}:{rel}"),
    };
    let output = git_command(root, preserve_hook_env)
        .arg("show")
        .arg(&spec)
        .output()
        .map_err(|error| format!("cannot run git show {spec}: {error}"))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|error| format!("{spec} is not UTF-8: {error}"))?;
    Ok(Some(text))
}

fn staged_added_rust_lines(
    root: &Path,
    preserve_hook_env: bool,
) -> Result<BTreeMap<String, BTreeSet<usize>>, String> {
    let output = git_command(root, preserve_hook_env)
        .args([
            "-c",
            "core.quotepath=false",
            "diff",
            "--cached",
            "--unified=0",
            "--no-color",
            "--diff-filter=AMCR",
            "--",
            "*.rs",
        ])
        .output()
        .map_err(|error| format!("cannot run git diff --cached: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let diff = String::from_utf8(output.stdout)
        .map_err(|error| format!("git diff --cached output is not UTF-8: {error}"))?;
    Ok(parse_unified_diff_added_lines(&diff))
}

fn diff_range_added_rust_lines(
    root: &Path,
    base_rev: &str,
    head_rev: &str,
    preserve_hook_env: bool,
) -> Result<BTreeMap<String, BTreeSet<usize>>, String> {
    let merge_base = git_command(root, preserve_hook_env)
        .args(["merge-base", base_rev, head_rev])
        .output()
        .map_err(|error| format!("cannot run git merge-base {base_rev} {head_rev}: {error}"))?;
    let base = if merge_base.status.success() {
        String::from_utf8_lossy(&merge_base.stdout)
            .trim()
            .to_owned()
    } else {
        base_rev.to_owned()
    };
    let output = git_command(root, preserve_hook_env)
        .args([
            "-c",
            "core.quotepath=false",
            "diff",
            "--unified=0",
            "--no-color",
            "--diff-filter=AMCR",
            &base,
            head_rev,
            "--",
            "*.rs",
        ])
        .output()
        .map_err(|error| format!("cannot run git diff {base} {head_rev}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git diff {base} {head_rev} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let diff = String::from_utf8(output.stdout)
        .map_err(|error| format!("git diff output is not UTF-8: {error}"))?;
    Ok(parse_unified_diff_added_lines(&diff))
}

/// Parse `git diff --unified=0` output into added/modified 1-based line numbers
/// per repository-relative path.
fn parse_unified_diff_added_lines(diff: &str) -> BTreeMap<String, BTreeSet<usize>> {
    let mut added: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut current_file: Option<String> = None;

    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            current_file = Some(rest.to_owned());
            continue;
        }
        if line.starts_with("+++ ") {
            current_file = None;
            continue;
        }
        if let (Some(file), Some(range)) = (&current_file, parse_hunk_new_range(line)) {
            let entry = added.entry(file.clone()).or_default();
            for line_no in range.0..range.0.saturating_add(range.1) {
                entry.insert(line_no);
            }
        }
    }

    added
}

/// Parse the `+start[,count]` portion of a unified diff hunk header (`@@ ... @@`).
/// Returns `None` for non-hunk lines or pure-deletion hunks (`count == 0`).
fn parse_hunk_new_range(line: &str) -> Option<(usize, usize)> {
    let rest = line.strip_prefix("@@ ")?;
    let header = rest.split(" @@").next()?;
    let plus_part = header
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix('+'))?;
    let (start_str, count_str) = match plus_part.split_once(',') {
        Some((start, count)) => (start, Some(count)),
        None => (plus_part, None),
    };
    let start = start_str.parse::<usize>().ok()?;
    let count = match count_str {
        Some(raw) => raw.parse::<usize>().ok()?,
        None => 1,
    };
    if count == 0 {
        return None;
    }
    Some((start, count))
}

fn format_violation(violation: &Violation) -> String {
    let location = format!(
        "{}:{}:{}",
        violation.path.display(),
        violation.line,
        violation.column
    );
    match &violation.kind {
        ViolationKind::AnonymousLiteral(literal) => {
            format!("{location}: anonymous numeric spelling `{literal}`")
        }
        ViolationKind::SourceIndirection(form) => {
            format!("{location}: source indirection `{form}` is prohibited")
        }
        ViolationKind::TextNumericSpelling(form) => {
            format!("{location}: {form} in a comment is prohibited")
        }
    }
}

fn relative_posix_path(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|error| format!("path {} is outside workspace: {error}", path.display()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        let part = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path: {}", path.display()))?;
        parts.push(part);
    }
    Ok(parts.join("/"))
}

fn inspect_rust_source(path: &Path, source: &str) -> Result<Vec<Violation>, String> {
    let syntax = syn::parse_file(source)
        .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
    let mut violations = Vec::new();
    inspect_rust_comments(path, source, &mut violations);
    let mut visitor = MagicNumberVisitor::new(path);
    visitor.visit_file(&syntax);
    violations.extend(visitor.violations);
    violations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.column.cmp(&right.column))
    });
    Ok(violations)
}

fn validate_cargo_targets(root: &Path) -> Result<(), String> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .arg("metadata")
        .arg("--format-version=1")
        .arg("--locked")
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .map_err(|error| format!("cannot run cargo metadata: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("cannot parse cargo metadata: {error}"))?;
    validate_cargo_metadata(root, &metadata)
}

fn validate_cargo_metadata(root: &Path, metadata: &serde_json::Value) -> Result<(), String> {
    let packages = metadata
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .ok_or("cargo metadata omitted packages")?;

    for package in packages {
        let manifest = package
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or("cargo metadata package omitted manifest_path")?;
        let manifest = Path::new(manifest);
        let is_path_package = package.get("source").is_none_or(serde_json::Value::is_null);
        if is_path_package && !manifest.starts_with(root) {
            return Err(format!(
                "Cargo path dependency must remain inside the repository: {}",
                manifest.display()
            ));
        }
        let targets = package
            .get("targets")
            .and_then(serde_json::Value::as_array)
            .ok_or("cargo metadata package omitted targets")?;
        for target in targets {
            let source = target
                .get("src_path")
                .and_then(serde_json::Value::as_str)
                .ok_or("cargo metadata target omitted src_path")?;
            let source = Path::new(source);
            if is_path_package || source.starts_with(root) {
                validate_cargo_target_source(root, source)?;
            }
        }
    }
    Ok(())
}

fn validate_cargo_target_source(root: &Path, source: &Path) -> Result<(), String> {
    if !source.starts_with(root)
        || source.extension() != Some(OsStr::new("rs"))
        || is_ignored_root_path(root, source)
    {
        return Err(format!(
            "Cargo target source must be an in-repository .rs file: {}",
            source.display()
        ));
    }
    Ok(())
}

fn is_source_tree_entry(root: &Path, entry: &DirEntry) -> bool {
    !is_ignored_root_path(root, entry.path())
}

fn reject_source_tree_symlink(entry: &DirEntry) -> Result<(), String> {
    if entry.file_type().is_symlink() {
        return Err(format!(
            "source-tree symlinks are prohibited: {}",
            entry.path().display()
        ));
    }
    Ok(())
}

fn is_ignored_root_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    matches!(
        relative.components().next(),
        Some(std::path::Component::Normal(name))
            if name == OsStr::new(".git") || name == OsStr::new("target")
    )
}

#[derive(Debug, PartialEq, Eq)]
struct Violation {
    path: PathBuf,
    line: usize,
    column: usize,
    kind: ViolationKind,
}

#[derive(Debug, PartialEq, Eq)]
enum ViolationKind {
    AnonymousLiteral(String),
    SourceIndirection(&'static str),
    TextNumericSpelling(&'static str),
}

fn inspect_rust_comments(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    if let Some(shebang_length) = rustc_lexer::strip_shebang(source) {
        inspect_numeric_bytes(path, &source.as_bytes()[..shebang_length], 1, 0, violations);
    }
    let mut offset = 0;
    let mut line = 1;
    let mut column = 0;
    for token in rustc_lexer::tokenize(source) {
        let token_end = offset + token.len;
        let token_text = &source.as_bytes()[offset..token_end];
        if matches!(
            token.kind,
            TokenKind::LineComment | TokenKind::BlockComment { .. }
        ) {
            inspect_numeric_bytes(path, token_text, line, column, violations);
        }
        advance_location(token_text, &mut line, &mut column);
        offset = token_end;
    }
}

fn inspect_numeric_bytes(
    path: &Path,
    bytes: &[u8],
    mut line: usize,
    mut column: usize,
    violations: &mut Vec<Violation>,
) {
    let mut at = 0;
    while at < bytes.len() {
        if let Some((width, form)) = numeric_spelling_at(bytes, at) {
            violations.push(Violation {
                path: path.to_path_buf(),
                line,
                column,
                kind: ViolationKind::TextNumericSpelling(form),
            });
            advance_location(&bytes[at..at + width], &mut line, &mut column);
            at += width;
        } else {
            advance_location(&bytes[at..=at], &mut line, &mut column);
            at += 1;
        }
    }
}

fn advance_location(bytes: &[u8], line: &mut usize, column: &mut usize) {
    for byte in bytes {
        if *byte == b'\n' {
            *line += 1;
            *column = 0;
        } else {
            *column += 1;
        }
    }
}

const fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Width of a two-character radix prefix (`0x`, `0b`, `0o`).
const RADIX_SPECIFIER_WIDTH: usize = 2;

/// Recognized integer literal suffixes stripped before radix-digit validation.
const INT_SUFFIXES: &[&[u8]] = &[
    b"usize", b"isize", b"u128", b"i128", b"u64", b"i64", b"u32", b"i32", b"u16", b"i16", b"u8",
    b"i8",
];

fn is_binary_literal(bytes: &[u8], at: usize) -> bool {
    let Some(rest) = bytes.get(at..) else {
        return false;
    };
    if !matches!(rest, [b'0', b'b' | b'B', b'0' | b'1', ..]) {
        return false;
    }
    let mut end = at;
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }
    let mut digits = &bytes[at + RADIX_SPECIFIER_WIDTH..end];
    for suffix in INT_SUFFIXES {
        if let Some(stripped) = digits.strip_suffix(*suffix) {
            digits = stripped;
            break;
        }
    }
    !digits.is_empty() && digits.iter().all(|&b| b == b'0' || b == b'1' || b == b'_')
}

fn is_octal_literal(bytes: &[u8], at: usize) -> bool {
    let Some(rest) = bytes.get(at..) else {
        return false;
    };
    if !matches!(rest, [b'0', b'o' | b'O', b'0'..=b'7', ..]) {
        return false;
    }
    let mut end = at;
    while end < bytes.len() && is_word_byte(bytes[end]) {
        end += 1;
    }
    let mut digits = &bytes[at + RADIX_SPECIFIER_WIDTH..end];
    for suffix in INT_SUFFIXES {
        if let Some(stripped) = digits.strip_suffix(*suffix) {
            digits = stripped;
            break;
        }
    }
    !digits.is_empty() && digits.iter().all(|&b| matches!(b, b'0'..=b'7' | b'_'))
}

fn numeric_spelling_at(bytes: &[u8], at: usize) -> Option<(usize, &'static str)> {
    const RADIX_PREFIX_WIDTH: usize = 3;
    const HEX_ESCAPE_WIDTH: usize = 4;
    const UNICODE_ESCAPE_PREFIX_WIDTH: usize = 4;
    const JSON_UNICODE_ESCAPE_WIDTH: usize = 6;
    const LONG_UNICODE_ESCAPE_WIDTH: usize = 10;
    const OCTAL_ESCAPE_PREFIX_WIDTH: usize = 2;
    const ESCAPE_PREFIX_WIDTH: usize = 2;

    let rest = bytes.get(at..)?;

    let at_word_boundary = at == 0 || !is_word_byte(bytes[at - 1]);
    if at_word_boundary {
        match rest {
            [b'0', b'x' | b'X', digit, ..] if digit.is_ascii_hexdigit() => {
                return Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"));
            }
            [b'0', b'b' | b'B', ..] if is_binary_literal(bytes, at) => {
                return Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"));
            }
            [b'0', b'o' | b'O', ..] if is_octal_literal(bytes, at) => {
                return Some((RADIX_PREFIX_WIDTH, "radix numeric spelling"));
            }
            _ => {}
        }
    }

    match rest {
        [b'\\', b'x', high, low, ..] if high.is_ascii_hexdigit() && low.is_ascii_hexdigit() => {
            Some((HEX_ESCAPE_WIDTH, "numeric escape"))
        }
        [b'\\', b'u', b'{', digit, ..] if digit.is_ascii_hexdigit() => {
            Some((UNICODE_ESCAPE_PREFIX_WIDTH, "numeric escape"))
        }
        [b'\\', b'u', first, second, third, fourth, ..]
            if [first, second, third, fourth]
                .iter()
                .all(|digit| digit.is_ascii_hexdigit()) =>
        {
            Some((JSON_UNICODE_ESCAPE_WIDTH, "numeric escape"))
        }
        [b'\\', b'U', digits @ ..]
            if digits.len() >= LONG_UNICODE_ESCAPE_WIDTH - ESCAPE_PREFIX_WIDTH =>
        {
            let digits = &digits[..LONG_UNICODE_ESCAPE_WIDTH - ESCAPE_PREFIX_WIDTH];
            if digits.iter().all(u8::is_ascii_hexdigit) {
                Some((LONG_UNICODE_ESCAPE_WIDTH, "numeric escape"))
            } else {
                None
            }
        }
        [b'\\', b'0'..=b'7', ..] => Some((OCTAL_ESCAPE_PREFIX_WIDTH, "numeric escape")),
        _ => None,
    }
}

struct MagicNumberVisitor<'path> {
    path: &'path Path,
    named_value_depth: usize,
    violations: Vec<Violation>,
}

impl<'path> MagicNumberVisitor<'path> {
    const fn new(path: &'path Path) -> Self {
        Self {
            path,
            named_value_depth: 0,
            violations: Vec::new(),
        }
    }

    fn visit_named_value(&mut self, expression: &Expr) {
        self.named_value_depth += 1;
        self.visit_expr(expression);
        self.named_value_depth -= 1;
    }

    fn visit_constant_value(&mut self, name: &str, expression: &Expr) {
        if name == "_" {
            self.visit_expr(expression);
        } else {
            self.visit_named_value(expression);
        }
    }

    fn record(&mut self, span: Span, kind: ViolationKind) {
        let start = span.start();
        self.violations.push(Violation {
            path: self.path.to_path_buf(),
            line: start.line,
            column: start.column,
            kind,
        });
    }

    fn inspect_integer(&mut self, literal: &LitInt) {
        if self.named_value_depth > 0 || is_tier_zero_literal(literal) {
            return;
        }
        self.record(
            literal.span(),
            ViolationKind::AnonymousLiteral(literal.to_string()),
        );
    }

    fn inspect_float(&mut self, literal: &LitFloat) {
        if self.named_value_depth == 0 {
            self.record(
                literal.span(),
                ViolationKind::AnonymousLiteral(literal.to_string()),
            );
        }
    }

    fn inspect_encoded_literal(&mut self, span: Span, spelling: String) {
        if self.named_value_depth == 0 && contains_numeric_spelling(&spelling) {
            self.record(span, ViolationKind::AnonymousLiteral(spelling));
        }
    }

    fn inspect_literal(&mut self, literal: Lit) {
        match literal {
            Lit::Int(integer) => self.inspect_integer(&integer),
            Lit::Float(float) => self.inspect_float(&float),
            Lit::Byte(byte) => {
                self.inspect_encoded_literal(byte.span(), byte.token().to_string());
            }
            Lit::ByteStr(bytes) => {
                self.inspect_encoded_literal(bytes.span(), bytes.token().to_string());
            }
            Lit::CStr(text) => {
                self.inspect_encoded_literal(text.span(), text.token().to_string());
            }
            Lit::Char(character) => {
                self.inspect_encoded_literal(character.span(), character.token().to_string());
            }
            Lit::Str(text) => {
                self.inspect_encoded_literal(text.span(), text.token().to_string());
            }
            _ => {}
        }
    }

    fn inspect_tokens(&mut self, tokens: TokenStream) {
        const TOKEN_PAIR_WIDTH: usize = 2;

        let tokens: Vec<_> = tokens.into_iter().collect();
        for pair in tokens.windows(TOKEN_PAIR_WIDTH) {
            if let [TokenTree::Ident(ident), TokenTree::Punct(punctuation)] = pair {
                let name = normalized_ident(ident);
                // A joint `!` opens the `!=` operator, not a macro call.
                if punctuation.as_char() == '!' && punctuation.spacing() == Spacing::Alone {
                    if name == "include" {
                        self.record(
                            ident.span(),
                            ViolationKind::SourceIndirection("macro-generated include!"),
                        );
                    }
                } else if name == "path" && punctuation.as_char() == '=' {
                    self.record(
                        ident.span(),
                        ViolationKind::SourceIndirection("macro-generated path attribute"),
                    );
                }
            }
        }
        for token in tokens {
            match token {
                TokenTree::Group(group) => self.inspect_tokens(group.stream()),
                TokenTree::Literal(literal) => self.inspect_literal(Lit::new(literal)),
                TokenTree::Ident(_) | TokenTree::Punct(_) => {}
            }
        }
    }

    fn inspect_use_tree(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(path) => {
                if ident_is(&path.ident, "include") {
                    self.record(
                        path.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                }
                self.inspect_use_tree(&path.tree);
            }
            UseTree::Name(name) => {
                if ident_is(&name.ident, "include") {
                    self.record(
                        name.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                }
            }
            UseTree::Rename(rename) => {
                if ident_is(&rename.ident, "include") {
                    self.record(
                        rename.ident.span(),
                        ViolationKind::SourceIndirection("include! import"),
                    );
                }
            }
            UseTree::Glob(_) => {}
            UseTree::Group(group) => {
                for item in &group.items {
                    self.inspect_use_tree(item);
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for MagicNumberVisitor<'_> {
    fn visit_item(&mut self, node: &'ast Item) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_item(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.inspect_use_tree(&node.tree);
        visit::visit_item_use(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_expr_closure(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_expr_async(&mut self, node: &'ast ExprAsync) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        visit::visit_expr_async(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_attribute(&mut self, node: &'ast Attribute) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        if path_is_ident(node.path(), "path") {
            self.record(
                node.path().span(),
                ViolationKind::SourceIndirection("path attribute"),
            );
        } else if path_is_ident(node.path(), "macro_use") {
            self.record(
                node.path().span(),
                ViolationKind::SourceIndirection("macro_use attribute"),
            );
        }
        visit::visit_attribute(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_item_const(&mut self, node: &'ast ItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_item_static(&mut self, node: &'ast ItemStatic) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_static_mutability(&node.mutability);
        self.visit_ident(&node.ident);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_impl_item_const(&mut self, node: &'ast ImplItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_visibility(&node.vis);
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        self.visit_constant_value(&node.ident.to_string(), &node.expr);
    }

    fn visit_trait_item_const(&mut self, node: &'ast TraitItemConst) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_ident(&node.ident);
        self.visit_generics(&node.generics);
        self.visit_type(&node.ty);
        if let Some((_, expression)) = &node.default {
            self.visit_constant_value(&node.ident.to_string(), expression);
        }
    }

    fn visit_variant(&mut self, node: &'ast Variant) {
        for attribute in &node.attrs {
            self.visit_attribute(attribute);
        }
        self.visit_ident(&node.ident);
        self.visit_fields(&node.fields);
        if let Some((_, expression)) = &node.discriminant {
            self.visit_named_value(expression);
        }
    }

    fn visit_lit_int(&mut self, node: &'ast LitInt) {
        self.inspect_integer(node);
    }

    fn visit_lit_float(&mut self, node: &'ast LitFloat) {
        self.inspect_float(node);
    }

    fn visit_lit_byte(&mut self, node: &'ast LitByte) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_byte_str(&mut self, node: &'ast LitByteStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_cstr(&mut self, node: &'ast LitCStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_char(&mut self, node: &'ast LitChar) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_lit_str(&mut self, node: &'ast LitStr) {
        self.inspect_encoded_literal(node.span(), node.token().to_string());
    }

    fn visit_macro(&mut self, node: &'ast Macro) {
        let outer_depth = self.named_value_depth;
        self.named_value_depth = 0;
        let is_include = node
            .path
            .segments
            .last()
            .is_some_and(|segment| ident_is(&segment.ident, "include"));
        if is_include {
            self.record(
                node.path.span(),
                ViolationKind::SourceIndirection("include!"),
            );
        }
        visit::visit_macro(self, node);
        self.named_value_depth = outer_depth;
    }

    fn visit_token_stream(&mut self, tokens: &'ast TokenStream) {
        self.inspect_tokens(tokens.clone());
    }
}

fn normalized_ident(ident: &syn::Ident) -> String {
    ident.unraw().to_string()
}

fn ident_is(ident: &syn::Ident, expected: &str) -> bool {
    normalized_ident(ident) == expected
}

fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    let mut segments = path.segments.iter();
    let Some(segment) = segments.next() else {
        return false;
    };
    path.leading_colon.is_none() && segments.next().is_none() && ident_is(&segment.ident, expected)
}

fn contains_numeric_spelling(spelling: &str) -> bool {
    let bytes = spelling.as_bytes();
    let is_raw =
        spelling.starts_with('r') || spelling.starts_with("br") || spelling.starts_with("cr");

    let mut at = 0;
    while at < bytes.len() {
        if let Some((_, form)) = numeric_spelling_at(bytes, at) {
            if form == "numeric escape" && is_raw {
                at += 1;
                continue;
            }
            return true;
        }
        at += 1;
    }
    false
}

fn is_tier_zero_literal(literal: &LitInt) -> bool {
    let spelling = literal.to_string();
    let has_domain_base = spelling.starts_with("0x")
        || spelling.starts_with("0X")
        || spelling.starts_with("0b")
        || spelling.starts_with("0B")
        || spelling.starts_with("0o")
        || spelling.starts_with("0O");
    !has_domain_base && matches!(literal.base10_digits(), "0" | "1")
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::process;

    use syn::visit::Visit;
    #[cfg(unix)]
    use walkdir::WalkDir;

    #[cfg(unix)]
    use super::reject_source_tree_symlink;
    use super::{
        GitBlobSource, MagicNumberVisitor, Violation, ViolationKind, check_touched_lines,
        diff_range_added_rust_lines, evaluate_ratchet, inspect_rust_comments, inspect_rust_source,
        is_ignored_root_path, parse_unified_diff_added_lines, staged_added_rust_lines,
        validate_cargo_target_source,
    };

    /// Sample line numbers for unified diff parser tests.
    const LINE_TEN: usize = 10;
    const LINE_ELEVEN: usize = 11;
    const LINE_TWELVE: usize = 12;
    const LINE_FORTY: usize = 40;
    /// Baseline count used in ratchet tests.
    const SAMPLE_BASELINE: usize = 2;

    fn literals(source: &str) -> Vec<String> {
        let syntax = syn::parse_file(source).expect("test source parses");
        let mut visitor = MagicNumberVisitor::new(Path::new("fixture.rs"));
        visitor.visit_file(&syntax);
        visitor
            .violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::AnonymousLiteral(literal) => Some(literal),
                ViolationKind::SourceIndirection(_) | ViolationKind::TextNumericSpelling(_) => None,
            })
            .collect()
    }

    fn source_indirections(source: &str) -> Vec<&'static str> {
        let syntax = syn::parse_file(source).expect("test source parses");
        let mut visitor = MagicNumberVisitor::new(Path::new("fixture.rs"));
        visitor.visit_file(&syntax);
        visitor
            .violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::SourceIndirection(form) => Some(form),
                ViolationKind::AnonymousLiteral(_) | ViolationKind::TextNumericSpelling(_) => None,
            })
            .collect()
    }

    fn rust_comment_issues(source: &str) -> Vec<&'static str> {
        let mut violations: Vec<Violation> = Vec::new();
        inspect_rust_comments(Path::new("fixture.rs"), source, &mut violations);
        violations
            .into_iter()
            .filter_map(|violation| match violation.kind {
                ViolationKind::TextNumericSpelling(form) => Some(form),
                ViolationKind::AnonymousLiteral(_) | ViolationKind::SourceIndirection(_) => None,
            })
            .collect()
    }

    #[test]
    fn allows_literals_in_named_constant_definitions() {
        let source = concat!(
            "const ISO_COMMAND_CLASS: u8 = 0",
            "x00; enum Tag { Application = 0",
            "x60 }"
        );
        assert!(literals(source).is_empty());
    }

    #[test]
    fn catches_raw_apdu_hex_vectors_and_macro_tokens() {
        let raw_apdu = concat!(
            "fn f() { let _ = vec![0",
            "x00, 0",
            "xA4, 0",
            "x02, 0",
            "x0C, 0",
            "x02, 0",
            "x50, 0",
            "x35]; }"
        );
        assert_eq!(
            literals(raw_apdu),
            [
                concat!("0", "x00"),
                concat!("0", "xA4"),
                concat!("0", "x02"),
                concat!("0", "x0C"),
                concat!("0", "x02"),
                concat!("0", "x50"),
                concat!("0", "x35"),
            ]
        );
    }

    #[test]
    fn catches_nested_patterns_masks_and_decimals() {
        for source in [
            concat!(
                "fn f(x: Option<u8>) { match x { Some(0",
                "x80) => (), _ => () } }"
            ),
            concat!("fn f(x: u8) { let _ = x & 0", "x80; }"),
            concat!("fn f() { let _ = [0", "x01, 0", "x02]; }"),
            concat!("fn f(x: u8) { let _ = matches!(x, 0", "x80); }"),
            "fn f() { let _ = 128; }",
            "fn f() { let _ = 128.0 as u8; }",
            "const _: u8 = 128;",
        ] {
            assert!(!literals(source).is_empty(), "missed source: {source}");
        }
    }

    #[test]
    fn delayed_executable_bodies_do_not_inherit_a_constant_name() {
        assert_eq!(literals("static CALLBACK: fn() -> u8 = || 128;"), ["128"]);
        assert_eq!(
            literals("const WRAPPER: () = { fn delayed() -> u8 { 128 } };"),
            ["128"]
        );
        assert_eq!(
            literals("const FUTURE: () = async { let _ = 128; };"),
            ["128"]
        );
    }

    #[test]
    fn source_indirection_is_prohibited() {
        assert_eq!(
            source_indirections("include!(\"hidden.inc\");"),
            ["include!"]
        );
        assert_eq!(
            source_indirections("std::include!(\"hidden.inc\");"),
            ["include!"]
        );
        assert_eq!(
            source_indirections("#[path = \"hidden.inc\"] mod hidden;"),
            ["path attribute"]
        );
        assert_eq!(
            source_indirections("#[macro_use] extern crate hidden;"),
            ["macro_use attribute"]
        );
        assert_eq!(
            source_indirections("macro_rules! hidden { () => { include!(\"hidden.inc\"); } }"),
            ["macro-generated include!"]
        );
    }

    #[test]
    fn ordinary_rust_comments_are_checked_lexically_without_sha_false_positives() {
        let source = concat!(
            "const NAMED: u8 = 0",
            "x80; // anonymous 0",
            "x81\n/* escape \\",
            "x7f */"
        );
        assert_eq!(
            rust_comment_issues(source),
            ["radix numeric spelling", "numeric escape"]
        );
        assert!(
            rust_comment_issues("// commit 3d3c42e5aac5ba805825da76410c181273ba90b1").is_empty()
        );
    }

    #[test]
    fn tier_zero_control_values_remain_available() {
        assert!(literals("fn f() { let _ = 0; let _ = 1; }").is_empty());
        assert_eq!(
            literals(concat!("fn f() { let _ = 0", "x0; }")),
            [concat!("0", "x0")]
        );
    }

    #[test]
    fn unified_diff_parser_extracts_only_added_and_modified_lines() {
        let diff = concat!(
            "diff --git a/crates/a/src/lib.rs b/crates/a/src/lib.rs\n",
            "--- a/crates/a/src/lib.rs\n",
            "+++ b/crates/a/src/lib.rs\n",
            "@@ -5,2 +10,3 @@ fn example()\n",
            "+line ten\n",
            "+line eleven\n",
            "+line twelve\n",
            "@@ -20,2 +30,0 @@ fn deleted_only()\n",
            "@@ -35 +40 @@ fn single_line()\n",
            "+line forty\n",
        );
        let parsed = parse_unified_diff_added_lines(diff);
        let lines = parsed
            .get("crates/a/src/lib.rs")
            .expect("file present in diff");
        assert_eq!(
            *lines,
            BTreeSet::from([LINE_TEN, LINE_ELEVEN, LINE_TWELVE, LINE_FORTY])
        );
    }

    #[test]
    fn ratchet_blocks_new_files_growth_and_stale_entries() {
        let path = "crates/legacy/src/lib.rs".to_owned();
        let existing = BTreeSet::from([path.clone()]);
        let one_violation =
            inspect_rust_source(Path::new(&path), "fn f() { let _ = 42; }").expect("parses");
        let three_violations =
            inspect_rust_source(Path::new(&path), "fn f() { let _ = (42, 43, 44); }")
                .expect("parses");

        // Unlisted file with any violation is rejected.
        let map_one = BTreeMap::from([(path.clone(), one_violation)]);
        assert!(!evaluate_ratchet(&map_one, &existing, &BTreeMap::new()).is_empty());

        // Listed file within baseline passes.
        let baseline = BTreeMap::from([(path.clone(), SAMPLE_BASELINE)]);
        assert!(evaluate_ratchet(&map_one, &existing, &baseline).is_empty());

        // Listed file exceeding baseline is rejected.
        let map_three = BTreeMap::from([(path, three_violations)]);
        assert!(!evaluate_ratchet(&map_three, &existing, &baseline).is_empty());

        // Stale entry (zero violations remaining) is rejected so baseline shrinks.
        assert!(!evaluate_ratchet(&BTreeMap::new(), &existing, &baseline).is_empty());

        // Stale entry (deleted file) is rejected.
        assert!(!evaluate_ratchet(&BTreeMap::new(), &BTreeSet::new(), &baseline).is_empty());
    }

    #[test]
    fn cargo_targets_must_be_in_repository_rust_files() {
        let root = Path::new("/workspace");
        assert!(validate_cargo_target_source(root, Path::new("/workspace/src/lib.rs")).is_ok());
        assert!(validate_cargo_target_source(root, Path::new("/workspace/src/lib.inc")).is_err());
        assert!(validate_cargo_target_source(root, Path::new("/elsewhere/lib.rs")).is_err());
        assert!(validate_cargo_target_source(root, Path::new("/workspace/target/lib.rs")).is_err());
        assert!(is_ignored_root_path(root, Path::new("/workspace/target")));
        assert!(is_ignored_root_path(
            root,
            Path::new("/workspace/.git/HEAD")
        ));
        assert!(!is_ignored_root_path(
            root,
            Path::new("/workspace/src/target/mod.rs")
        ));
    }

    #[test]
    #[cfg(unix)]
    fn source_tree_symlinks_are_rejected() {
        let root = std::env::temp_dir().join(format!("refineid-xtask-symlink-{}", process::id()));
        let link = root.join("linked.rs");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("temporary fixture directory is created");
        symlink("missing.rs", &link).expect("fixture symlink is created");

        let entry = WalkDir::new(&root)
            .into_iter()
            .filter_map(Result::ok)
            .find(|entry| entry.path() == link)
            .expect("fixture symlink is walked");
        let result = reject_source_tree_symlink(&entry);

        fs::remove_dir_all(&root).expect("temporary fixture directory is removed");
        assert!(result.is_err());
    }

    #[test]
    fn touched_line_checks_reject_magic_hex_edits_even_when_count_is_unchanged() {
        let root =
            std::env::temp_dir().join(format!("refineid-xtask-diff-check-{}", process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("src")).expect("fixture dir created");

        let git = |args: &[&str]| {
            let mut cmd = process::Command::new("git");
            for key in [
                "GIT_DIR",
                "GIT_WORK_TREE",
                "GIT_INDEX_FILE",
                "GIT_COMMON_DIR",
                "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            ] {
                cmd.env_remove(key);
            }
            let status = cmd
                .arg("-C")
                .arg(&root)
                .args(args)
                .status()
                .expect("git command runs");
            assert!(status.success(), "git {args:?} failed");
        };

        git(&["init", "-q", "-b", "main"]);
        git(&["config", "user.name", "Synthetic Author"]);
        git(&["config", "user.email", "author@example.com"]);

        let legacy_before = concat!("fn f() { let _ = vec![0", "x00, 0", "xA4, 0", "x09]; }\n");
        fs::write(root.join("src/lib.rs"), legacy_before).expect("write initial file");
        git(&["add", "src/lib.rs"]);
        git(&["-c", "core.hooksPath=/dev/null", "commit", "-qm", "base"]);

        // Edit one hex literal in place: total violation count stays identical,
        // so only touched-line enforcement catches it.
        let legacy_after = concat!("fn f() { let _ = vec![0", "x00, 0", "xA4, 0", "x02]; }\n");
        fs::write(root.join("src/lib.rs"), legacy_after).expect("write modified file");
        git(&["add", "src/lib.rs"]);

        let staged_lines = staged_added_rust_lines(&root, false).expect("staged diff parses");
        let staged_errors = check_touched_lines(&root, &staged_lines, GitBlobSource::Index, false)
            .expect("check runs");
        assert!(
            !staged_errors.is_empty(),
            "staged check must reject modified magic hex line"
        );

        git(&["-c", "core.hooksPath=/dev/null", "commit", "-qm", "edit"]);
        let diff_lines =
            diff_range_added_rust_lines(&root, "HEAD~1", "HEAD", false).expect("head diff parses");
        let head_errors =
            check_touched_lines(&root, &diff_lines, GitBlobSource::Commit("HEAD"), false)
                .expect("check runs");
        assert!(
            !head_errors.is_empty(),
            "diff-base check must reject committed magic hex line"
        );

        // Replacing the touched line with named constants passes both checks.
        let cleaned = concat!(
            "const CLA: u8 = 0",
            "x00;\nconst INS_SELECT: u8 = 0",
            "xA4;\nconst P1_EF: u8 = 0",
            "x02;\nfn f() { let _ = vec![CLA, INS_SELECT, P1_EF]; }\n"
        );
        fs::write(root.join("src/lib.rs"), cleaned).expect("write cleaned file");
        git(&["add", "src/lib.rs"]);
        let clean_staged = staged_added_rust_lines(&root, false).expect("staged diff parses");
        let clean_errors = check_touched_lines(&root, &clean_staged, GitBlobSource::Index, false)
            .expect("check runs");
        assert!(
            clean_errors.is_empty(),
            "named constants must pass: {clean_errors:?}"
        );

        // Committing the clean file makes HEAD clean, while targeting the
        // non-HEAD commit (`HEAD~1`) via `--diff-head` still rejects it.
        git(&["-c", "core.hooksPath=/dev/null", "commit", "-qm", "clean"]);
        let non_head_lines = diff_range_added_rust_lines(&root, "HEAD~2", "HEAD~1", false)
            .expect("non-HEAD diff parses");
        let non_head_errors = check_touched_lines(
            &root,
            &non_head_lines,
            GitBlobSource::Commit("HEAD~1"),
            false,
        )
        .expect("non-HEAD check runs");
        assert!(
            !non_head_errors.is_empty(),
            "diff-head check must inspect the targeted commit rather than HEAD"
        );

        fs::remove_dir_all(&root).expect("fixture dir cleaned up");
    }
}
