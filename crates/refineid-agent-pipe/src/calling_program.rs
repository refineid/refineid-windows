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

//! The program inside whose process a provider runs, as the phone is told
//! of it (Windows STPA W-R-10, W-R-20).
//!
//! A platform signing call hands the provider a hash and nothing else: no
//! site and no document. What the provider knows of the caller is what
//! Windows reports: the path of its image and the version resource in that
//! image. Nothing the program passes in its call names it.

use std::path::Path;

/// The separators of a Windows path.
const PATH_SEPARATORS: [char; 2] = ['\\', '/'];
/// The separator of a file's extension.
const EXTENSION_SEPARATOR: char = '.';
/// The most bytes of a program's display name a description carries; a
/// longer name is cut at a character boundary and ends with
/// [`ELLIPSIS`].
pub const PROGRAM_NAME_BYTES: usize = 64;
/// The most bytes of the computer's name a description carries. A DNS host
/// name label has at most 63 octets (RFC 1035 section 2.3.4).
pub const COMPUTER_NAME_BYTES: usize = 63;
/// What ends a shortened name.
const ELLIPSIS: char = '\u{2026}';

/// The program a provider runs inside.
///
/// Built only from the image path Windows reports for this process and the
/// `FileDescription` of that image's version resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallingProgram {
    /// The image's file name, `msedge.exe`.
    file_name: String,
    /// The name a person knows the program by: the image's file description,
    /// or its file stem when the image describes itself with none.
    display_name: String,
}

impl CallingProgram {
    /// The program whose image is `image`, which describes itself as
    /// `file_description` in its version resource. `None` when `image` names
    /// no file.
    ///
    /// A description that is blank or holds a control character counts as
    /// none.
    #[must_use]
    pub fn of_image(image: &Path, file_description: Option<&str>) -> Option<Self> {
        let image = image.to_string_lossy();
        let file_name = image.rsplit(PATH_SEPARATORS).next()?.trim();
        if file_name.is_empty() {
            return None;
        }
        let stem = file_name
            .rsplit_once(EXTENSION_SEPARATOR)
            .map_or(file_name, |(stem, _extension)| stem)
            .trim();
        let described = file_description
            .map(str::trim)
            .filter(|text| !text.is_empty() && !text.chars().any(char::is_control));
        let display_name = described
            .or_else(|| (!stem.is_empty()).then_some(stem))
            .unwrap_or(file_name);
        Some(Self {
            file_name: file_name.to_owned(),
            display_name: bounded(display_name, PROGRAM_NAME_BYTES),
        })
    }

    /// The image's file name.
    #[must_use]
    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    /// The name a person knows the program by.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// The language the computer's user interface is shown in, as far as a
/// description carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceLanguage {
    /// English, for every language without its own text.
    English,
    /// Finnish.
    Finnish,
    /// Swedish.
    Swedish,
}

/// The bits of a Windows language identifier that hold its primary
/// language (`PRIMARYLANGID`, winnt.h).
const PRIMARY_LANGUAGE_MASK: u16 = 0x03ff;
/// `LANG_FINNISH` (Microsoft, "Language Identifier Constants and Strings").
const LANGUAGE_FINNISH: u16 = 0x0b;
/// `LANG_SWEDISH` (Microsoft, "Language Identifier Constants and Strings").
const LANGUAGE_SWEDISH: u16 = 0x1d;

impl InterfaceLanguage {
    /// The language of a Windows language identifier, judged by its primary
    /// language whatever its region, as the app judges it.
    #[must_use]
    pub const fn for_windows_language(language_id: u16) -> Self {
        match language_id & PRIMARY_LANGUAGE_MASK {
            LANGUAGE_FINNISH => Self::Finnish,
            LANGUAGE_SWEDISH => Self::Swedish,
            _ => Self::English,
        }
    }
}

/// The `document_name` of a qualified signature that `program` on
/// `computer` asks for with a hash alone: a description saying so, in
/// `language` (RAPP v26.11.2 section 9.3, section 11 item 1).
///
/// It fits the field's 256 bytes whatever the names: each is bounded by
/// [`PROGRAM_NAME_BYTES`] and [`COMPUTER_NAME_BYTES`]. An empty `computer` is
/// left out.
#[must_use]
pub fn unnamed_document_description(
    program: &CallingProgram,
    computer: &str,
    language: InterfaceLanguage,
) -> String {
    let program = program.display_name();
    let computer = bounded(computer.trim(), COMPUTER_NAME_BYTES);
    match (language, computer.is_empty()) {
        (InterfaceLanguage::English, false) => format!(
            "{program} on {computer} asks for a signature (the program did not name the document)"
        ),
        (InterfaceLanguage::English, true) => {
            format!("{program} asks for a signature (the program did not name the document)")
        }
        (InterfaceLanguage::Finnish, false) => format!(
            "{program} tietokoneella {computer} pyytää allekirjoitusta (ohjelma ei nimennyt asiakirjaa)"
        ),
        (InterfaceLanguage::Finnish, true) => {
            format!("{program} pyytää allekirjoitusta (ohjelma ei nimennyt asiakirjaa)")
        }
        (InterfaceLanguage::Swedish, false) => format!(
            "{program} på {computer} begär en underskrift (programmet namngav inte dokumentet)"
        ),
        (InterfaceLanguage::Swedish, true) => {
            format!("{program} begär en underskrift (programmet namngav inte dokumentet)")
        }
    }
}

/// `text`, cut at a character boundary to at most `limit` bytes with
/// [`ELLIPSIS`] at its end when it was longer.
fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let room = limit.saturating_sub(ELLIPSIS.len_utf8());
    let mut end = room;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut shortened = text[..end].trim_end().to_owned();
    shortened.push(ELLIPSIS);
    shortened
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The most bytes `document_name` holds (RAPP v26.11.2 section 9.3).
    const DOCUMENT_NAME_BYTES: usize = 256;
    const WORD_IMAGE: &str = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";

    fn program(image: &str, description: Option<&str>) -> CallingProgram {
        CallingProgram::of_image(Path::new(image), description).expect("the image names a file")
    }

    #[test]
    fn a_program_is_known_by_its_file_description() {
        let word = program(WORD_IMAGE, Some("Microsoft Word"));
        assert_eq!(word.display_name(), "Microsoft Word");
        assert_eq!(word.file_name(), "WINWORD.EXE");
    }

    #[test]
    fn without_a_description_a_program_is_its_file_stem() {
        assert_eq!(
            program(r"C:\Tools\signer.exe", None).display_name(),
            "signer"
        );
        assert_eq!(
            program(r"C:\Tools\signer.exe", Some("  ")).display_name(),
            "signer"
        );
        assert_eq!(program("C:/Tools/signer", None).display_name(), "signer");
        assert_eq!(program(r"C:\Tools\.exe", None).display_name(), ".exe");
    }

    #[test]
    fn a_description_with_a_control_character_counts_as_none() {
        assert_eq!(
            program(r"C:\Tools\signer.exe", Some("Word\nPress Allow")).display_name(),
            "signer"
        );
    }

    #[test]
    fn an_image_that_names_no_file_is_no_program() {
        assert_eq!(CallingProgram::of_image(Path::new(""), Some("Word")), None);
        assert_eq!(
            CallingProgram::of_image(Path::new(r"C:\Tools\"), None),
            None
        );
    }

    #[test]
    fn the_description_names_the_program_the_computer_and_the_missing_name() {
        let word = program(WORD_IMAGE, Some("Microsoft Word"));
        assert_eq!(
            unnamed_document_description(&word, "work-laptop", InterfaceLanguage::English),
            "Microsoft Word on work-laptop asks for a signature (the program did not name the document)"
        );
        assert_eq!(
            unnamed_document_description(&word, "work-laptop", InterfaceLanguage::Finnish),
            "Microsoft Word tietokoneella work-laptop pyytää allekirjoitusta (ohjelma ei nimennyt asiakirjaa)"
        );
        assert_eq!(
            unnamed_document_description(&word, "work-laptop", InterfaceLanguage::Swedish),
            "Microsoft Word på work-laptop begär en underskrift (programmet namngav inte dokumentet)"
        );
        assert_eq!(
            unnamed_document_description(&word, " ", InterfaceLanguage::English),
            "Microsoft Word asks for a signature (the program did not name the document)"
        );
    }

    #[test]
    fn the_description_fits_the_field_whatever_the_names() {
        let long = "Ä".repeat(DOCUMENT_NAME_BYTES);
        let named = program(WORD_IMAGE, Some(&long));
        assert!(named.display_name().len() <= PROGRAM_NAME_BYTES);
        assert!(named.display_name().ends_with(ELLIPSIS));
        for language in [
            InterfaceLanguage::English,
            InterfaceLanguage::Finnish,
            InterfaceLanguage::Swedish,
        ] {
            let description = unnamed_document_description(&named, &long, language);
            assert!(description.len() <= DOCUMENT_NAME_BYTES, "{language:?}");
        }
    }

    #[test]
    fn a_windows_language_is_judged_by_its_primary_language() {
        const FINNISH_FINLAND: u16 = 0x040b;
        const SWEDISH_FINLAND: u16 = 0x081d;
        const GERMAN_GERMANY: u16 = 0x0407;
        assert_eq!(
            InterfaceLanguage::for_windows_language(FINNISH_FINLAND),
            InterfaceLanguage::Finnish
        );
        assert_eq!(
            InterfaceLanguage::for_windows_language(SWEDISH_FINLAND),
            InterfaceLanguage::Swedish
        );
        assert_eq!(
            InterfaceLanguage::for_windows_language(GERMAN_GERMANY),
            InterfaceLanguage::English
        );
    }
}
