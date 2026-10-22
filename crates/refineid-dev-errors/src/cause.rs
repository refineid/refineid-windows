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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

//! What a reported failure came from, as a name.

use core::fmt::Debug;

use crate::status::StatusCode;

/// The cause of a reported failure: a fixed text, the case of an error
/// value, or a Windows status by its name. Nothing a value carries
/// passes, so no secret, count or label can reach the log through it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cause(String);

impl Cause {
    /// A fixed description.
    #[must_use]
    pub fn text(text: &'static str) -> Self {
        Self(text.to_owned())
    }

    /// The case `value` is, from its `Debug` form: `Name(Inner)` where its
    /// one payload is itself a case, and `Name` where it carries anything
    /// else. Numbers, text, lists and fields never pass. A value that is no
    /// case at all is named by its type.
    #[must_use]
    pub fn case<T: Debug + ?Sized>(value: &T) -> Self {
        let described = format!("{value:?}");
        Self(reduced(&described).unwrap_or_else(|| type_name::<T>().to_owned()))
    }

    /// A Windows status by its name: `SCARD_E_NO_SERVICE`, `NTE_FAIL`,
    /// `E_ACCESSDENIED`, `ERROR_BROKEN_PIPE`. A code with no name here is
    /// written in hexadecimal.
    #[must_use]
    pub fn status(code: impl StatusCode) -> Self {
        Self(crate::status::describe(code.bits()))
    }

    /// The cause as written in an entry.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// `described` reduced to its case names, or `None` when it is no case.
fn reduced(described: &str) -> Option<String> {
    let head_end = described.find(['(', '{', ' ']).unwrap_or(described.len());
    let (head, payload) = described.split_at(head_end);
    if !is_identifier(head) {
        return None;
    }
    let inner = payload
        .strip_prefix('(')
        .and_then(|rest| rest.strip_suffix(')'))
        .filter(|_| is_one_group(payload))
        .and_then(reduced);
    Some(inner.map_or_else(|| head.to_owned(), |inner| format!("{head}({inner})")))
}

/// Whether `text` is one Rust identifier.
fn is_identifier(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// Whether `group` is one parenthesised group from its first character
/// to its last.
fn is_one_group(group: &str) -> bool {
    let mut depth = 0_usize;
    for (index, character) in group.char_indices() {
        match character {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 {
            return index.saturating_add(character.len_utf8()) == group.len();
        }
    }
    false
}

/// The last path segment of `T`'s name, without references or generic
/// arguments.
fn type_name<T: ?Sized>() -> &'static str {
    let full = core::any::type_name::<T>();
    let plain = full.split('<').next().unwrap_or(full);
    let last = plain.rsplit("::").next().unwrap_or(plain);
    last.trim_start_matches('&').trim()
}

#[cfg(test)]
mod tests {
    use super::Cause;

    #[derive(Debug)]
    enum Inner {
        Closed,
    }

    #[derive(Debug)]
    #[expect(
        dead_code,
        reason = "the payloads exist only to be dropped by the case reduction"
    )]
    enum Outer {
        Transport(Inner),
        Ended(Option<Inner>),
        Code(u32),
        Pair(Inner, Inner),
        Labelled(String),
        Fields { expected: usize, got: usize },
        Unit,
    }

    #[derive(Debug)]
    struct Holder {
        name: String,
    }

    const SECRET_TEXT: &str = "sample holder";
    const SECRET_COUNT: u32 = 4;
    const SECRET_LENGTH: usize = 6;

    #[test]
    fn a_unit_case_is_its_name() {
        assert_eq!(Cause::case(&Outer::Unit).as_str(), "Unit");
    }

    #[test]
    fn a_case_payload_is_kept() {
        assert_eq!(
            Cause::case(&Outer::Transport(Inner::Closed)).as_str(),
            "Transport(Closed)"
        );
        assert_eq!(
            Cause::case(&Outer::Ended(Some(Inner::Closed))).as_str(),
            "Ended(Some(Closed))"
        );
    }

    #[test]
    fn numbers_text_and_fields_are_dropped() {
        assert_eq!(Cause::case(&Outer::Code(SECRET_COUNT)).as_str(), "Code");
        assert_eq!(
            Cause::case(&Outer::Labelled(SECRET_TEXT.to_owned())).as_str(),
            "Labelled"
        );
        assert_eq!(
            Cause::case(&Outer::Fields {
                expected: SECRET_LENGTH,
                got: SECRET_LENGTH,
            })
            .as_str(),
            "Fields"
        );
        assert_eq!(
            Cause::case(&Outer::Pair(Inner::Closed, Inner::Closed)).as_str(),
            "Pair"
        );
    }

    #[test]
    fn a_struct_is_named_and_its_fields_dropped() {
        let holder = Holder {
            name: SECRET_TEXT.to_owned(),
        };
        let cause = Cause::case(&holder);
        assert_eq!(cause.as_str(), "Holder");
        assert!(!cause.as_str().contains(&holder.name));
    }

    #[test]
    fn a_value_that_is_no_case_is_named_by_its_type() {
        assert_eq!(Cause::case(&SECRET_TEXT.to_owned()).as_str(), "String");
        assert_eq!(Cause::case(&SECRET_COUNT).as_str(), "u32");
        assert_eq!(Cause::case(SECRET_TEXT).as_str(), "str");
    }

    #[test]
    fn a_borrowed_error_is_named_as_the_error() {
        let error = &Outer::Transport(Inner::Closed);
        assert_eq!(Cause::case(&error).as_str(), "Transport(Closed)");
    }
}
