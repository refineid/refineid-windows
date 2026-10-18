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

//! The round red mark that tells a reader to check the document's
//! electronic signature.
//!
//! Two rings, the advice along the top and bottom of the band between
//! them in the two other languages, and the advice in the reader's own
//! language on four lines in the middle. The mark is presentation only:
//! the signature in the file is the evidence.

use core::f64::consts::PI;
use core::fmt::Write as _;

use refineid_lib_core::rng;

use super::appearance::FONT_RESOURCE_NAME;

/// The language the middle lines are in; the band carries the other two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampLanguage {
    /// Finnish in the middle; Swedish along the top, English along the bottom.
    Finnish,
    /// Swedish in the middle; Finnish along the top, English along the bottom.
    Swedish,
    /// English in the middle; Finnish along the top, Swedish along the bottom.
    English,
}

impl StampLanguage {
    /// The language of a BCP 47 tag such as `fi-FI` or `sv`; English for
    /// any other.
    #[must_use]
    pub fn from_language_tag(tag: &str) -> Self {
        let language = tag
            .split(['-', '_'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match language.as_str() {
            "fi" => Self::Finnish,
            "sv" => Self::Swedish,
            _ => Self::English,
        }
    }
}

/// The outer ring's radius, in points.
pub(super) const RADIUS: f64 = 64.0;
/// Stroke bleed outside the outer ring.
const BLEED: f64 = 2.0;
/// The mark's reach from its centre, bleed included.
pub(super) const REACH: f64 = RADIUS + BLEED;
/// The form box's side: the whole reach both ways.
pub(super) const SIDE: f64 = REACH * 2.0;
/// The form box's centre, where the mark's origin is placed.
const CENTRE: f64 = REACH;

/// The counterclockwise tilt, in degrees: a stamp put down by hand.
const LEAST_TILT_DEGREES: f64 = 5.0;
const MOST_TILT_DEGREES: f64 = 15.0;

const BORDER_INNER_RADIUS: f64 = 48.0;
/// The ink, #C62828, as the fractions PDF reads.
const INK: &str = "0.7765 0.1569 0.1569";
/// The Bezier control distance that makes four curves a circle.
const KAPPA: f64 = 0.552_284_749_830_793_5;
const OUTER_RING_LINE_WIDTH: f64 = 1.8;
const BORDER_SEPARATOR_LINE_WIDTH: f64 = 0.9;
const ARC_FONT_SIZE: f64 = 4.8;
const ARC_BAND_CENTRE_RADIUS: f64 = 56.0;
const ARC_SWEEP_DEGREES: f64 = 156.0;
const CENTRE_FONT_SIZE: f64 = 9.0;
const CENTRE_LINE_GAP: f64 = 4.0;
/// The share of the inner ring's diameter the middle lines may span.
const CENTRE_WIDTH_SHARE: f64 = 0.82;
const BULLET_RADIUS: f64 = 0.55;
/// Font units per em in the metrics below.
const UNITS_PER_EM: f64 = 1000.0;
/// The base font the metrics below belong to.
pub(super) const BASE_FONT: &str = "Helvetica-Bold";

/// A glyph of the base font: its advance and outline box, in font units.
#[derive(Debug, Clone, Copy)]
struct Glyph {
    advance: f64,
    left: f64,
    bottom: f64,
    right: f64,
    top: f64,
}

/// The outline bottom of a glyph standing on the baseline.
const ON_BASELINE: f64 = 0.0;
/// The outline top of a flat capital.
const CAPITAL_TOP: f64 = 719.7;
/// The overshoot a round capital reaches below the baseline.
const ROUND_BOTTOM: f64 = -20.0;
/// The overshoot a round capital reaches above the capital height.
const ROUND_TOP: f64 = 741.7;

const SPACE: Glyph = Glyph {
    advance: 277.8,
    left: 0.0,
    bottom: 0.0,
    right: 0.0,
    top: 0.0,
};
const LETTER_A: Glyph = Glyph {
    advance: 722.2,
    left: 25.4,
    bottom: ON_BASELINE,
    right: 707.0,
    top: CAPITAL_TOP,
};
const LETTER_C: Glyph = Glyph {
    advance: 722.2,
    left: 44.9,
    bottom: ROUND_BOTTOM,
    right: 685.1,
    top: 733.4,
};
const LETTER_D: Glyph = Glyph {
    advance: 722.2,
    left: 76.2,
    bottom: ON_BASELINE,
    right: 685.1,
    top: CAPITAL_TOP,
};
const LETTER_E: Glyph = Glyph {
    advance: 667.0,
    left: 80.6,
    bottom: ON_BASELINE,
    right: 626.0,
    top: CAPITAL_TOP,
};
const LETTER_G: Glyph = Glyph {
    advance: 777.8,
    left: 41.5,
    bottom: -19.0,
    right: 710.4,
    top: 738.3,
};
const LETTER_H: Glyph = Glyph {
    advance: 722.2,
    left: 75.2,
    bottom: ON_BASELINE,
    right: 654.8,
    top: CAPITAL_TOP,
};
const LETTER_I: Glyph = Glyph {
    advance: 277.8,
    left: 64.5,
    bottom: ON_BASELINE,
    right: 213.9,
    top: CAPITAL_TOP,
};
const LETTER_J: Glyph = Glyph {
    advance: 556.2,
    left: 22.0,
    bottom: -17.6,
    right: 483.4,
    top: CAPITAL_TOP,
};
const LETTER_K: Glyph = Glyph {
    advance: 722.2,
    left: 78.6,
    bottom: ON_BASELINE,
    right: 713.9,
    top: CAPITAL_TOP,
};
const LETTER_L: Glyph = Glyph {
    advance: 610.8,
    left: 76.2,
    bottom: ON_BASELINE,
    right: 583.0,
    top: CAPITAL_TOP,
};
const LETTER_M: Glyph = Glyph {
    advance: 833.0,
    left: 73.7,
    bottom: ON_BASELINE,
    right: 769.5,
    top: CAPITAL_TOP,
};
const LETTER_N: Glyph = Glyph {
    advance: 722.2,
    left: 73.7,
    bottom: ON_BASELINE,
    right: 658.2,
    top: CAPITAL_TOP,
};
const LETTER_O: Glyph = Glyph {
    advance: 777.8,
    left: 49.3,
    bottom: ROUND_BOTTOM,
    right: 739.3,
    top: ROUND_TOP,
};
const LETTER_R: Glyph = Glyph {
    advance: 722.2,
    left: 79.6,
    bottom: ON_BASELINE,
    right: 680.2,
    top: CAPITAL_TOP,
};
const LETTER_S: Glyph = Glyph {
    advance: 667.0,
    left: 41.5,
    bottom: -18.6,
    right: 631.8,
    top: 740.7,
};
const LETTER_T: Glyph = Glyph {
    advance: 610.8,
    left: 16.1,
    bottom: ON_BASELINE,
    right: 599.1,
    top: CAPITAL_TOP,
};
const LETTER_U: Glyph = Glyph {
    advance: 722.2,
    left: 76.2,
    bottom: -18.6,
    right: 654.8,
    top: CAPITAL_TOP,
};
const LETTER_A_DIAERESIS: Glyph = Glyph {
    advance: 722.2,
    left: 25.4,
    bottom: ON_BASELINE,
    right: 707.0,
    top: 902.3,
};
const LETTER_O_DIAERESIS: Glyph = Glyph {
    advance: 777.8,
    left: 49.3,
    bottom: ROUND_BOTTOM,
    right: 739.3,
    top: 924.3,
};

/// A with diaeresis, and its `WinAnsiEncoding` byte as an octal escape.
const A_DIAERESIS: char = '\u{00C4}';
const A_DIAERESIS_LITERAL: &str = "\\304";
/// O with diaeresis, and its `WinAnsiEncoding` byte as an octal escape.
const O_DIAERESIS: char = '\u{00D6}';
const O_DIAERESIS_LITERAL: &str = "\\326";

/// The glyph of one character the mark's texts are made of.
const fn glyph(character: char) -> Option<Glyph> {
    Some(match character {
        ' ' => SPACE,
        'A' => LETTER_A,
        'C' => LETTER_C,
        'D' => LETTER_D,
        'E' => LETTER_E,
        'G' => LETTER_G,
        'H' => LETTER_H,
        'I' => LETTER_I,
        'J' => LETTER_J,
        'K' => LETTER_K,
        'L' => LETTER_L,
        'M' => LETTER_M,
        'N' => LETTER_N,
        'O' => LETTER_O,
        'R' => LETTER_R,
        'S' => LETTER_S,
        'T' => LETTER_T,
        'U' => LETTER_U,
        A_DIAERESIS => LETTER_A_DIAERESIS,
        O_DIAERESIS => LETTER_O_DIAERESIS,
        _ => return None,
    })
}

/// Whether every character of `text` has a glyph and a literal, judged
/// when the texts are built so a text outside the set does not compile.
const fn representable(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let character = if byte.is_ascii() {
            byte as char
        } else if index + 1 < bytes.len() {
            // Two-byte UTF-8: five bits of the lead, six of the trail.
            let lead = (byte & 0b0001_1111) as u32;
            let trail = (bytes[index + 1] & 0b0011_1111) as u32;
            index += 1;
            match char::from_u32((lead << 6) | trail) {
                Some(character) => character,
                None => return false,
            }
        } else {
            return false;
        };
        if glyph(character).is_none() {
            return false;
        }
        index += 1;
    }
    true
}

const FINNISH_WORDS: [&str; 4] = [
    "TARKASTA",
    "ASIAKIRJAN",
    "S\u{00C4}HK\u{00D6}INEN",
    "ALLEKIRJOITUS",
];
const SWEDISH_WORDS: [&str; 4] = ["KONTROLLERA", "DOKUMENTETS", "ELEKTRONISKA", "SIGNATUR"];
const ENGLISH_WORDS: [&str; 4] = ["CHECK", "DOCUMENT", "ELECTRONIC", "SIGNATURE"];
const FINNISH_BAND: &str = "TARKASTA ASIAKIRJAN S\u{00C4}HK\u{00D6}INEN ALLEKIRJOITUS";
const SWEDISH_BAND: &str = "KONTROLLERA DOKUMENTETS ELEKTRONISKA SIGNATUR";
const ENGLISH_BAND: &str = "CHECK DOCUMENT ELECTRONIC SIGNATURE";

const _: () = {
    let mut index = 0;
    while index < FINNISH_WORDS.len() {
        assert!(representable(FINNISH_WORDS[index]));
        assert!(representable(SWEDISH_WORDS[index]));
        assert!(representable(ENGLISH_WORDS[index]));
        index += 1;
    }
    assert!(representable(FINNISH_BAND));
    assert!(representable(SWEDISH_BAND));
    assert!(representable(ENGLISH_BAND));
};

/// The band's text sits on the axis of a flat capital's outline, the
/// same for every language whatever letters it carries.
const BAND_TEXT_MID_Y: f64 = f64::midpoint(ROUND_BOTTOM, ROUND_TOP);

/// What the mark says: the middle in the reader's language, the band in
/// the other two, the first of them along the top.
struct Texts {
    middle: [&'static str; 4],
    top: &'static str,
    bottom: &'static str,
}

const fn texts(language: StampLanguage) -> Texts {
    match language {
        StampLanguage::Finnish => Texts {
            middle: FINNISH_WORDS,
            top: SWEDISH_BAND,
            bottom: ENGLISH_BAND,
        },
        StampLanguage::Swedish => Texts {
            middle: SWEDISH_WORDS,
            top: FINNISH_BAND,
            bottom: ENGLISH_BAND,
        },
        StampLanguage::English => Texts {
            middle: ENGLISH_WORDS,
            top: FINNISH_BAND,
            bottom: SWEDISH_BAND,
        },
    }
}

/// The glyph outline box of one line of text, in font units.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Bounds {
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

impl Bounds {
    /// The box of `text`: from the first glyph's left edge to the last
    /// glyph's right edge, as tall as its tallest and deepest glyphs.
    fn of(text: &str) -> Self {
        let glyphs: Vec<Glyph> = text.chars().filter_map(glyph).collect();
        let Some((first, rest)) = glyphs.split_first() else {
            return Self {
                min_x: 0.0,
                min_y: 0.0,
                max_x: 0.0,
                max_y: 0.0,
            };
        };
        let last = rest.last().unwrap_or(first);
        let before_last: f64 = glyphs[..glyphs.len() - 1]
            .iter()
            .map(|glyph| glyph.advance)
            .sum();
        Self {
            min_x: first.left,
            min_y: glyphs
                .iter()
                .map(|glyph| glyph.bottom)
                .fold(f64::INFINITY, f64::min),
            max_x: before_last + last.right,
            max_y: glyphs
                .iter()
                .map(|glyph| glyph.top)
                .fold(f64::NEG_INFINITY, f64::max),
        }
    }

    const fn width(self) -> f64 {
        self.max_x - self.min_x
    }

    const fn mid_x(self) -> f64 {
        f64::midpoint(self.min_x, self.max_x)
    }

    const fn scaled(self, size: f64) -> Self {
        let factor = size / UNITS_PER_EM;
        Self {
            min_x: self.min_x * factor,
            min_y: self.min_y * factor,
            max_x: self.max_x * factor,
            max_y: self.max_y * factor,
        }
    }
}

/// The advance of one character of the mark's texts, in font units.
fn advance(character: char) -> f64 {
    glyph(character).map_or(0.0, |glyph| glyph.advance)
}

/// The content stream of the mark, drawn about the form box's centre
/// with a tilt no two stamps share.
pub(super) fn operators(language: StampLanguage) -> Vec<u8> {
    operators_tilted(language, tilt_degrees(random_fraction()))
}

/// A fraction of one from the system's random bytes; the middle when
/// they cannot be read, since the tilt is presentation and the signature
/// stands either way.
fn random_fraction() -> f64 {
    rng::array::<4>().map_or(0.5, |bytes| {
        f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX)
    })
}

/// The tilt `fraction` of the way from the least to the most.
fn tilt_degrees(fraction: f64) -> f64 {
    fraction.mul_add(MOST_TILT_DEGREES - LEAST_TILT_DEGREES, LEAST_TILT_DEGREES)
}

fn operators_tilted(language: StampLanguage, degrees: f64) -> Vec<u8> {
    let (sine, cosine) = degrees.to_radians().sin_cos();
    let mut out = String::from("q\n");
    let _ignored = writeln!(&mut out, "1 0 0 1 {CENTRE:.4} {CENTRE:.4} cm");
    let _ignored = writeln!(
        &mut out,
        "{cosine:.8} {sine:.8} {minus_sine:.8} {cosine:.8} 0 0 cm",
        minus_sine = -sine
    );
    let _ignored = writeln!(&mut out, "{INK} RG {INK} rg");
    rings(&mut out);
    let words = texts(language);
    arc(&mut out, words.top, true);
    arc(&mut out, words.bottom, false);
    bullets(&mut out);
    centre_lines(&mut out, &words.middle);
    out.push_str("Q\n");
    out.into_bytes()
}

fn rings(out: &mut String) {
    let _ignored = writeln!(out, "{OUTER_RING_LINE_WIDTH} w");
    circle(out, RADIUS);
    out.push_str("S\n");
    let _ignored = writeln!(out, "{BORDER_SEPARATOR_LINE_WIDTH} w");
    circle(out, BORDER_INNER_RADIUS);
    out.push_str("S\n");
}

/// A closed circle about the origin, as four Bezier quarters starting at
/// the rightmost point.
fn circle(out: &mut String, radius: f64) {
    let pull = radius * KAPPA;
    let _ignored = writeln!(out, "{radius:.2} 0.00 m");
    let _ignored = writeln!(
        out,
        "{radius:.2} {pull:.2} {pull:.2} {radius:.2} 0.00 {radius:.2} c"
    );
    let _ignored = writeln!(
        out,
        "-{pull:.2} {radius:.2} -{radius:.2} {pull:.2} -{radius:.2} 0.00 c"
    );
    let _ignored = writeln!(
        out,
        "-{radius:.2} -{pull:.2} -{pull:.2} -{radius:.2} 0.00 -{radius:.2} c"
    );
    let _ignored = writeln!(
        out,
        "{pull:.2} -{radius:.2} {radius:.2} -{pull:.2} {radius:.2} 0.00 c"
    );
    out.push_str("h\n");
}

/// The advice along the band, each glyph turned to the ring at its own
/// angle and the glyphs spread evenly over the sweep.
fn arc(out: &mut String, text: &str, top: bool) {
    let quarter_turn = PI / 2.0;
    let sweep = ARC_SWEEP_DEGREES.to_radians();
    let mid_y = BAND_TEXT_MID_Y * ARC_FONT_SIZE / UNITS_PER_EM;
    let radius = if top {
        ARC_BAND_CENTRE_RADIUS - mid_y
    } else {
        ARC_BAND_CENTRE_RADIUS + mid_y
    };
    let advances: Vec<f64> = text
        .chars()
        .map(|character| advance(character) * ARC_FONT_SIZE / UNITS_PER_EM)
        .collect();
    let total: f64 = advances.iter().sum();
    let gaps = advances.len().saturating_sub(1);
    let gap_count = u32::try_from(gaps).map_or(0.0, f64::from);
    let tracking = (radius * sweep - total) / gap_count.max(1.0);
    let length = tracking.mul_add(gap_count, total);
    let mut distance = -length / 2.0;
    let direction = if top { -1.0 } else { 1.0 };
    let centre_angle = if top { quarter_turn } else { -quarter_turn };
    out.push_str("BT\n");
    let _ignored = writeln!(out, "/{FONT_RESOURCE_NAME} {ARC_FONT_SIZE:.2} Tf");
    for (character, glyph_advance) in text.chars().zip(advances) {
        let angle = centre_angle + direction * (distance + glyph_advance / 2.0) / radius;
        let text_angle = if top {
            angle - quarter_turn
        } else {
            angle + quarter_turn
        };
        let (sine, cosine) = text_angle.sin_cos();
        let point_x = radius.mul_add(angle.cos(), -(glyph_advance / 2.0 * cosine));
        let point_y = radius.mul_add(angle.sin(), -(glyph_advance / 2.0 * sine));
        let _ignored = writeln!(
            out,
            "{cosine:.4} {sine:.4} {minus_sine:.4} {cosine:.4} {point_x:.2} {point_y:.2} Tm",
            minus_sine = -sine
        );
        let _ignored = writeln!(out, "({}) Tj", literal(character));
        distance += glyph_advance + tracking;
    }
    out.push_str("ET\n");
}

/// The two dots that part the band's upper and lower advice, each drawn
/// in its own graphics state.
fn bullets(out: &mut String) {
    for point_x in [-ARC_BAND_CENTRE_RADIUS, ARC_BAND_CENTRE_RADIUS] {
        let _ignored = writeln!(out, "q 1 0 0 1 {point_x:.2} 0 cm");
        circle(out, BULLET_RADIUS);
        out.push_str("f\nQ\n");
    }
}

/// One placed middle line: its text, size, and origin about the centre.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PlacedLine {
    text: &'static str,
    size: f64,
    x: f64,
    y: f64,
}

/// The middle lines, one size for all so the widest fills its share of
/// the inner ring, stacked by their outline boxes and centred as a block.
fn centre_layout(lines: &[&'static str; 4]) -> [PlacedLine; 4] {
    let room = BORDER_INNER_RADIUS * 2.0 * CENTRE_WIDTH_SHARE;
    let boxes = lines.map(Bounds::of);
    let widest = boxes
        .iter()
        .map(|bounds| bounds.scaled(CENTRE_FONT_SIZE).width())
        .fold(0.0_f64, f64::max);
    let size = if widest > room {
        CENTRE_FONT_SIZE * room / widest
    } else {
        CENTRE_FONT_SIZE
    };
    let mut baseline = 0.0;
    let mut previous: Option<(f64, Bounds)> = None;
    let mut placed = [PlacedLine {
        text: "",
        size,
        x: 0.0,
        y: 0.0,
    }; 4];
    for (slot, (text, bounds)) in placed.iter_mut().zip(lines.iter().zip(boxes)) {
        let bounds = bounds.scaled(size);
        if let Some((previous_y, previous_bounds)) = previous {
            baseline = previous_y + previous_bounds.min_y - CENTRE_LINE_GAP - bounds.max_y;
        }
        previous = Some((baseline, bounds));
        *slot = PlacedLine {
            text,
            size,
            x: -bounds.mid_x(),
            y: baseline,
        };
    }
    let ink_top = placed
        .iter()
        .zip(boxes)
        .map(|(line, bounds)| line.y + bounds.scaled(size).max_y)
        .fold(f64::NEG_INFINITY, f64::max);
    let ink_bottom = placed
        .iter()
        .zip(boxes)
        .map(|(line, bounds)| line.y + bounds.scaled(size).min_y)
        .fold(f64::INFINITY, f64::min);
    let ink_mid_y = f64::midpoint(ink_top, ink_bottom);
    for line in &mut placed {
        line.y -= ink_mid_y;
    }
    placed
}

fn centre_lines(out: &mut String, lines: &[&'static str; 4]) {
    out.push_str("BT\n");
    for line in centre_layout(lines) {
        let _ignored = writeln!(out, "/{FONT_RESOURCE_NAME} {:.2} Tf", line.size);
        let _ignored = writeln!(
            out,
            "1.0000 0.0000 0.0000 1.0000 {:.2} {:.2} Tm",
            line.x, line.y
        );
        let _ignored = writeln!(
            out,
            "({}) Tj",
            line.text.chars().map(literal).collect::<String>()
        );
    }
    out.push_str("ET\n");
}

/// One character of the mark's texts as a PDF literal under
/// `WinAnsiEncoding`: the texts hold only ASCII capitals, spaces, and the
/// two diaereses, as judged when they are built.
fn literal(character: char) -> String {
    match character {
        '(' | ')' | '\\' => format!("\\{character}"),
        A_DIAERESIS => A_DIAERESIS_LITERAL.to_owned(),
        O_DIAERESIS => O_DIAERESIS_LITERAL.to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        A_DIAERESIS_LITERAL, ARC_BAND_CENTRE_RADIUS, BORDER_INNER_RADIUS, Bounds, CENTRE_FONT_SIZE,
        CENTRE_WIDTH_SHARE, ENGLISH_BAND, ENGLISH_WORDS, FINNISH_BAND, FINNISH_WORDS,
        LEAST_TILT_DEGREES, MOST_TILT_DEGREES, O_DIAERESIS_LITERAL, RADIUS, SIDE, SWEDISH_BAND,
        SWEDISH_WORDS, StampLanguage, centre_layout, literal, operators, operators_tilted,
        representable, tilt_degrees,
    };

    fn text(language: StampLanguage) -> String {
        String::from_utf8(operators(language)).expect("ASCII operators")
    }

    /// The glyphs each `BT` block writes, joined back into its text.
    fn text_blocks(mark: &str) -> Vec<String> {
        mark.split("BT\n")
            .skip(1)
            .map(|block| {
                block
                    .lines()
                    .filter_map(|line| line.strip_suffix(") Tj"))
                    .filter_map(|line| line.strip_prefix('('))
                    .map(|glyph| {
                        glyph
                            .replace(A_DIAERESIS_LITERAL, "\u{00C4}")
                            .replace(O_DIAERESIS_LITERAL, "\u{00D6}")
                    })
                    .collect::<String>()
            })
            .collect()
    }

    #[test]
    fn a_language_tag_picks_the_middle_language() {
        assert_eq!(
            StampLanguage::from_language_tag("fi-FI"),
            StampLanguage::Finnish
        );
        assert_eq!(
            StampLanguage::from_language_tag("sv"),
            StampLanguage::Swedish
        );
        assert_eq!(
            StampLanguage::from_language_tag("en_US"),
            StampLanguage::English
        );
        assert_eq!(
            StampLanguage::from_language_tag("de-DE"),
            StampLanguage::English
        );
    }

    #[test]
    fn the_mark_has_two_closed_rings_and_two_bullets_in_their_own_states() {
        let mark = text(StampLanguage::Finnish);
        assert!(mark.starts_with("q\n"));
        assert!(mark.ends_with("Q\n"));
        assert!(mark.contains("0.7765 0.1569 0.1569 RG 0.7765 0.1569 0.1569 rg"));
        assert!(mark.contains(&format!("{RADIUS:.2} 0.00 m")), "outer ring");
        assert!(
            mark.contains(&format!("{BORDER_INNER_RADIUS:.2} 0.00 m")),
            "inner ring"
        );
        assert_eq!(
            mark.matches("h\nS\n").count(),
            2,
            "two closed, stroked rings"
        );
        assert_eq!(
            mark.matches("h\nf\nQ\n").count(),
            2,
            "two closed, filled bullets"
        );
        assert_eq!(
            mark.matches(&format!("q 1 0 0 1 {ARC_BAND_CENTRE_RADIUS:.2} 0 cm"))
                .count(),
            1
        );
        assert_eq!(mark.matches(" c\n").count(), 16, "four quarters per circle");
    }

    #[test]
    fn the_band_carries_the_other_two_languages_and_the_middle_the_readers() {
        for (language, top, bottom, middle) in [
            (
                StampLanguage::Finnish,
                SWEDISH_BAND,
                ENGLISH_BAND,
                FINNISH_WORDS,
            ),
            (
                StampLanguage::Swedish,
                FINNISH_BAND,
                ENGLISH_BAND,
                SWEDISH_WORDS,
            ),
            (
                StampLanguage::English,
                FINNISH_BAND,
                SWEDISH_BAND,
                ENGLISH_WORDS,
            ),
        ] {
            let blocks = text_blocks(&text(language));
            assert_eq!(blocks.len(), 3, "two arcs and the middle");
            assert_eq!(blocks[0], top, "top arc, glyph by glyph");
            assert_eq!(blocks[1], bottom, "bottom arc, glyph by glyph");
            assert_eq!(blocks[2], middle.concat(), "middle lines in order");
        }
    }

    #[test]
    fn the_tilt_spans_its_range_counterclockwise() {
        assert_eq!(tilt_degrees(0.0), LEAST_TILT_DEGREES);
        assert_eq!(tilt_degrees(1.0), MOST_TILT_DEGREES);
        assert_eq!(tilt_degrees(0.5), 10.0);
        for degrees in [LEAST_TILT_DEGREES, 10.0, MOST_TILT_DEGREES] {
            let mark = String::from_utf8(operators_tilted(StampLanguage::English, degrees))
                .expect("ASCII operators");
            let matrix = mark.lines().nth(2).expect("tilt line");
            let parts: Vec<&str> = matrix.split_whitespace().collect();
            assert_eq!(parts.last(), Some(&"cm"));
            let cosine: f64 = parts[0].parse().expect("cosine");
            let sine: f64 = parts[1].parse().expect("sine");
            assert!((sine.atan2(cosine).to_degrees() - degrees).abs() < 0.001);
            let placed = mark.lines().nth(1).expect("centring line");
            assert_eq!(
                placed,
                format!("1 0 0 1 {:.4} {:.4} cm", SIDE / 2.0, SIDE / 2.0)
            );
        }
    }

    #[test]
    fn the_middle_lines_fit_the_inner_ring_and_are_centred() {
        let room = BORDER_INNER_RADIUS * 2.0 * CENTRE_WIDTH_SHARE;
        for words in [FINNISH_WORDS, SWEDISH_WORDS, ENGLISH_WORDS] {
            let placed = centre_layout(&words);
            assert_eq!(
                placed[0].size, CENTRE_FONT_SIZE,
                "the words fit at full size"
            );
            let boxes = words.map(|word| Bounds::of(word).scaled(placed[0].size));
            let top = placed[0].y + boxes[0].max_y;
            let bottom = placed[3].y + boxes[3].min_y;
            assert!((top + bottom).abs() < 0.01, "block centred on the axis");
            for (line, bounds) in placed.iter().zip(boxes) {
                assert!((line.x + bounds.mid_x()).abs() < 0.01, "line centred");
                assert!(bounds.width() <= room);
            }
            assert!(placed.windows(2).all(|pair| pair[0].y > pair[1].y));
        }
    }

    #[test]
    fn an_over_long_line_shrinks_every_line_to_the_room() {
        let room = BORDER_INNER_RADIUS * 2.0 * CENTRE_WIDTH_SHARE;
        let words = ["MMMMMMMMMMMMMMMM", "CHECK", "DOCUMENT", "SIGNATURE"];
        let placed = centre_layout(&words);
        let size = placed[0].size;
        assert!(size < CENTRE_FONT_SIZE);
        assert!(
            placed
                .iter()
                .all(|line| (line.size - size).abs() < f64::EPSILON)
        );
        let widest = words
            .map(|word| Bounds::of(word).scaled(size).width())
            .into_iter()
            .fold(0.0_f64, f64::max);
        assert!(
            (widest - room).abs() < 0.01,
            "the widest line fills the room"
        );
    }

    #[test]
    fn a_box_runs_from_the_first_left_edge_to_the_last_right_edge() {
        let bounds = Bounds::of("TARKASTA");
        assert!((bounds.min_x - 16.1).abs() < 0.01);
        assert!((bounds.max_x - 5484.3).abs() < 0.5);
        assert!((bounds.min_y - -18.6).abs() < 0.01);
        assert!((bounds.max_y - 740.7).abs() < 0.01);
    }

    #[test]
    fn only_the_texts_characters_are_representable_and_the_diaereses_are_escaped() {
        assert!(representable(FINNISH_BAND));
        assert!(!representable("Z"));
        assert!(!representable("\u{00E4}"));
        assert_eq!(literal('\u{00C4}'), "\\304");
        assert_eq!(literal('\u{00D6}'), "\\326");
        assert_eq!(literal('('), "\\(");
        assert_eq!(literal('A'), "A");
    }
}
