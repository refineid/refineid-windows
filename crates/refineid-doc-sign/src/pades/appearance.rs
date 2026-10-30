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

//! Visible appearance for a PDF signature widget.
//!
//! The appearance is presentation, not evidence. The enclosing `PAdES`
//! signature authenticates the widget and document. This module renders
//! the round mark advising the reader to check the electronic signature.

use super::stamp::{self, StampLanguage};

/// The mark shown on the signed page: the round mark advising the
/// reader to check the electronic signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisibleSignature {
    language: StampLanguage,
}

impl VisibleSignature {
    /// The verification mark with its middle lines in `language`.
    #[must_use]
    pub const fn verification(language: StampLanguage) -> Self {
        Self { language }
    }

    /// Render a self-contained Form `XObject` content stream.
    pub(super) fn render(self) -> RenderedAppearance {
        RenderedAppearance {
            side: stamp::SIDE,
            font: stamp::BASE_FONT,
            operators: stamp::operators(self.language),
        }
    }
}

/// Content, natural dimensions, and the base font of one signature
/// appearance.
pub(super) struct RenderedAppearance {
    pub(super) side: f64,
    pub(super) font: &'static str,
    pub(super) operators: Vec<u8>,
}

/// The name the form registers its one font under, without the slash.
pub(super) const FONT_RESOURCE_NAME: &str = "F1";

#[cfg(test)]
mod tests {
    use super::{StampLanguage, VisibleSignature, stamp};

    /// The suffix naming the bold face of a standard 14 font family.
    const BOLD_SUFFIX: &str = "-Bold";

    #[test]
    fn the_verification_mark_is_set_in_bold_in_its_own_box() {
        let rendered = VisibleSignature::verification(StampLanguage::Finnish).render();
        assert!(rendered.font.ends_with(BOLD_SUFFIX), "bold face");
        assert_eq!(
            rendered.side,
            stamp::REACH + stamp::REACH,
            "the box holds the mark's reach both ways from its centre"
        );
        let text = String::from_utf8(rendered.operators).expect("ASCII operators");
        assert!(text.contains("(TARKASTA) Tj"));
    }
}
