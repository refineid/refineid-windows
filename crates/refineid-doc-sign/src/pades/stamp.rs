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
/// The resource name the form's font is registered under.
const FONT_RESOURCE: &str = "/F1";
/// The base font the metrics below belong to.
pub(super) const BASE_FONT: &str = "Helvetica-Bold";

/// The glyph outline box of one line of text, in font units.
#[derive(Debug, Clone, Copy)]
struct Bounds {
    min_x: f64,
    min_y: f64,
    max_x: f64,
    max_y: f64,
}

impl Bounds {
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

/// One line of the mark's text with the outline box its font gives it.
#[derive(Debug, Clone, Copy)]
struct Line {
    text: &'static str,
    bounds: Bounds,
}

/// The outline bottom of the capitals used, in font units.
const CAPITAL_MIN_Y: f64 = -20.0;
/// The outline top of the plain capitals, in font units.
const CAPITAL_MAX_Y: f64 = 741.7;
/// The outline top of a capital carrying a diaeresis, in font units.
const DIAERESIS_MAX_Y: f64 = 924.3;

const FINNISH_WORDS: [Line; 4] = [
    Line {
        text: "TARKASTA",
        bounds: Bounds {
            min_x: 16.1,
            min_y: -18.6,
            max_x: 5484.4,
            max_y: 740.7,
        },
    },
    Line {
        text: "ASIAKIRJAN",
        bounds: Bounds {
            min_x: 25.4,
            min_y: -18.6,
            max_x: 6047.9,
            max_y: 740.7,
        },
    },
    Line {
        text: "S\u{00C4}HK\u{00D6}INEN",
        bounds: Bounds {
            min_x: 41.5,
            min_y: CAPITAL_MIN_Y,
            max_x: 5936.5,
            max_y: DIAERESIS_MAX_Y,
        },
    },
    Line {
        text: "ALLEKIRJOITUS",
        bounds: Bounds {
            min_x: 25.4,
            min_y: CAPITAL_MIN_Y,
            max_x: 7909.7,
            max_y: CAPITAL_MAX_Y,
        },
    },
];

const SWEDISH_WORDS: [Line; 4] = [
    Line {
        text: "KONTROLLERA",
        bounds: Bounds {
            min_x: 78.6,
            min_y: CAPITAL_MIN_Y,
            max_x: 7650.9,
            max_y: CAPITAL_MAX_Y,
        },
    },
    Line {
        text: "DOKUMENTETS",
        bounds: Bounds {
            min_x: 76.2,
            min_y: CAPITAL_MIN_Y,
            max_x: 7687.0,
            max_y: CAPITAL_MAX_Y,
        },
    },
    Line {
        text: "ELEKTRONISKA",
        bounds: Bounds {
            min_x: 80.6,
            min_y: CAPITAL_MIN_Y,
            max_x: 7874.0,
            max_y: CAPITAL_MAX_Y,
        },
    },
    Line {
        text: "SIGNATUR",
        bounds: Bounds {
            min_x: 41.5,
            min_y: -19.0,
            max_x: 5180.2,
            max_y: 740.7,
        },
    },
];

const ENGLISH_WORDS: [Line; 4] = [
    Line {
        text: "CHECK",
        bounds: Bounds {
            min_x: 44.9,
            min_y: CAPITAL_MIN_Y,
            max_x: 3547.4,
            max_y: 733.4,
        },
    },
    Line {
        text: "DOCUMENT",
        bounds: Bounds {
            min_x: 76.2,
            min_y: CAPITAL_MIN_Y,
            max_x: 5765.6,
            max_y: CAPITAL_MAX_Y,
        },
    },
    Line {
        text: "ELECTRONIC",
        bounds: Bounds {
            min_x: 80.6,
            min_y: CAPITAL_MIN_Y,
            max_x: 6462.9,
            max_y: CAPITAL_MAX_Y,
        },
    },
    Line {
        text: "SIGNATURE",
        bounds: Bounds {
            min_x: 41.5,
            min_y: -19.0,
            max_x: 5848.1,
            max_y: 740.7,
        },
    },
];

/// The advice on one line, as the band carries it.
#[derive(Debug, Clone, Copy)]
struct Border {
    text: &'static str,
    /// The outline's vertical middle, in font units.
    mid_y: f64,
}

const FINNISH_BORDER: Border = Border {
    text: "TARKASTA ASIAKIRJAN S\u{00C4}HK\u{00D6}INEN ALLEKIRJOITUS",
    mid_y: f64::midpoint(CAPITAL_MIN_Y, DIAERESIS_MAX_Y),
};
const SWEDISH_BORDER: Border = Border {
    text: "KONTROLLERA DOKUMENTETS ELEKTRONISKA SIGNATUR",
    mid_y: f64::midpoint(CAPITAL_MIN_Y, CAPITAL_MAX_Y),
};
const ENGLISH_BORDER: Border = Border {
    text: "CHECK DOCUMENT ELECTRONIC SIGNATURE",
    mid_y: f64::midpoint(CAPITAL_MIN_Y, CAPITAL_MAX_Y),
};

/// What the mark says: the middle in the reader's language, the band in
/// the other two, the first of them along the top.
struct Texts {
    middle: [Line; 4],
    top: Border,
    bottom: Border,
}

const fn texts(language: StampLanguage) -> Texts {
    match language {
        StampLanguage::Finnish => Texts {
            middle: FINNISH_WORDS,
            top: SWEDISH_BORDER,
            bottom: ENGLISH_BORDER,
        },
        StampLanguage::Swedish => Texts {
            middle: SWEDISH_WORDS,
            top: FINNISH_BORDER,
            bottom: ENGLISH_BORDER,
        },
        StampLanguage::English => Texts {
            middle: ENGLISH_WORDS,
            top: FINNISH_BORDER,
            bottom: SWEDISH_BORDER,
        },
    }
}

/// The advance of one character in the base font, in font units.
const fn advance(character: char) -> f64 {
    match character {
        ' ' | 'I' => 278.0,
        'J' => 556.0,
        'F' | 'L' | 'T' | 'Z' => 611.0,
        'E' | 'P' | 'S' | 'V' | 'X' | 'Y' => 667.0,
        'A' | 'B' | 'C' | 'D' | 'H' | 'K' | 'N' | 'R' | 'U' | '\u{00C4}' | '\u{00C5}' => 722.0,
        'G' | 'O' | 'Q' | '\u{00D6}' => 778.0,
        'M' => 833.0,
        'W' => 944.0,
        _ => 0.0,
    }
}

/// The content stream of the mark, drawn about the form box's centre
/// with a tilt no two stamps share.
pub(super) fn operators(language: StampLanguage) -> Vec<u8> {
    operators_tilted(language, tilt_degrees())
}

/// A tilt between the least and the most, from the system's random
/// bytes; the middle of the range when they cannot be read, since the
/// tilt is presentation and the signature stands either way.
fn tilt_degrees() -> f64 {
    let fraction = rng::array::<4>().map_or(0.5, |bytes| {
        f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX)
    });
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

/// A circle about the origin, as four Bezier quarters starting at the
/// rightmost point.
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
}

/// The advice along the band, each glyph turned to the ring at its own
/// angle and the glyphs spread evenly over the sweep.
fn arc(out: &mut String, border: Border, top: bool) {
    let quarter_turn = PI / 2.0;
    let sweep = ARC_SWEEP_DEGREES.to_radians();
    let mid_y = border.mid_y * ARC_FONT_SIZE / UNITS_PER_EM;
    let radius = if top {
        ARC_BAND_CENTRE_RADIUS - mid_y
    } else {
        ARC_BAND_CENTRE_RADIUS + mid_y
    };
    let advances: Vec<f64> = border
        .text
        .chars()
        .map(|character| advance(character) * ARC_FONT_SIZE / UNITS_PER_EM)
        .collect();
    let total: f64 = advances.iter().sum();
    let gaps = advances.len().saturating_sub(1).max(1);
    let gap_count = u32::try_from(gaps).map_or(1.0, f64::from);
    let tracking = (radius * sweep - total) / gap_count;
    let spread_count = u32::try_from(advances.len().saturating_sub(1)).map_or(0.0, f64::from);
    let length = tracking.mul_add(spread_count, total);
    let mut distance = -length / 2.0;
    let direction = if top { -1.0 } else { 1.0 };
    let centre_angle = if top { quarter_turn } else { -quarter_turn };
    out.push_str("BT\n");
    let _ignored = writeln!(out, "{FONT_RESOURCE} {ARC_FONT_SIZE:.2} Tf");
    for (character, glyph_advance) in border.text.chars().zip(advances) {
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
        let _ignored = writeln!(out, "({}) Tj", escaped(character));
        distance += glyph_advance + tracking;
    }
    out.push_str("ET\n");
}

/// The two dots that part the band's upper and lower advice.
fn bullets(out: &mut String) {
    for point_x in [-ARC_BAND_CENTRE_RADIUS, ARC_BAND_CENTRE_RADIUS] {
        let _ignored = writeln!(out, "1 0 0 1 {point_x:.2} 0 cm");
        circle(out, BULLET_RADIUS);
        out.push_str("f\n");
        let _ignored = writeln!(out, "1 0 0 1 {back:.2} 0 cm", back = -point_x);
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
fn centre_layout(lines: &[Line; 4]) -> [PlacedLine; 4] {
    let room = BORDER_INNER_RADIUS * 2.0 * CENTRE_WIDTH_SHARE;
    let widest = lines
        .iter()
        .map(|line| line.bounds.scaled(CENTRE_FONT_SIZE).width())
        .fold(0.0_f64, f64::max);
    let size = if widest > room {
        CENTRE_FONT_SIZE * room / widest
    } else {
        CENTRE_FONT_SIZE
    };
    let mut baseline = 0.0;
    let mut previous: Option<(f64, Bounds)> = None;
    let mut placed = lines.map(|line| {
        let bounds = line.bounds.scaled(size);
        if let Some((previous_y, previous_bounds)) = previous {
            baseline = previous_y + previous_bounds.min_y - CENTRE_LINE_GAP - bounds.max_y;
        }
        previous = Some((baseline, bounds));
        PlacedLine {
            text: line.text,
            size,
            x: -bounds.mid_x(),
            y: baseline,
        }
    });
    let ink_top = placed
        .iter()
        .zip(lines)
        .map(|(line, source)| line.y + source.bounds.scaled(size).max_y)
        .fold(f64::NEG_INFINITY, f64::max);
    let ink_bottom = placed
        .iter()
        .zip(lines)
        .map(|(line, source)| line.y + source.bounds.scaled(size).min_y)
        .fold(f64::INFINITY, f64::min);
    let ink_mid_y = f64::midpoint(ink_top, ink_bottom);
    for line in &mut placed {
        line.y -= ink_mid_y;
    }
    placed
}

fn centre_lines(out: &mut String, lines: &[Line; 4]) {
    out.push_str("BT\n");
    for line in centre_layout(lines) {
        let _ignored = writeln!(out, "{FONT_RESOURCE} {:.2} Tf", line.size);
        let _ignored = writeln!(
            out,
            "1.0000 0.0000 0.0000 1.0000 {:.2} {:.2} Tm",
            line.x, line.y
        );
        let _ignored = writeln!(
            out,
            "({}) Tj",
            line.text.chars().map(escaped).collect::<String>()
        );
    }
    out.push_str("ET\n");
}

/// One character as a PDF literal under `WinAnsiEncoding`.
fn escaped(character: char) -> String {
    const OCTAL_BYTE_MODULUS: u32 = 256;
    match character {
        '(' | ')' | '\\' => format!("\\{character}"),
        ' '..='~' => character.to_string(),
        other => format!("\\{:03o}", u32::from(other) % OCTAL_BYTE_MODULUS),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ARC_BAND_CENTRE_RADIUS, BORDER_INNER_RADIUS, Bounds, CENTRE_FONT_SIZE, CENTRE_WIDTH_SHARE,
        ENGLISH_WORDS, FINNISH_WORDS, RADIUS, SIDE, SWEDISH_WORDS, StampLanguage, centre_layout,
        operators, operators_tilted,
    };

    fn text(language: StampLanguage) -> String {
        String::from_utf8(operators(language)).expect("ASCII operators")
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
    fn the_mark_has_two_rings_two_bullets_and_the_advice_in_three_languages() {
        let mark = text(StampLanguage::Finnish);
        assert!(mark.starts_with("q\n"));
        assert!(mark.ends_with("Q\n"));
        assert!(mark.contains("0.7765 0.1569 0.1569 RG 0.7765 0.1569 0.1569 rg"));
        assert!(mark.contains(&format!("{RADIUS:.2} 0.00 m")), "outer ring");
        assert!(
            mark.contains(&format!("{BORDER_INNER_RADIUS:.2} 0.00 m")),
            "inner ring"
        );
        assert_eq!(mark.matches("\nS\n").count(), 2, "two stroked rings");
        assert_eq!(mark.matches("\nf\n").count(), 2, "two filled bullets");
        assert!(mark.contains(&format!("1 0 0 1 {ARC_BAND_CENTRE_RADIUS:.2} 0 cm")));
        assert_eq!(mark.matches("BT\n").count(), 3, "two arcs and the middle");
        for word in ["(TARKASTA) Tj", "(ASIAKIRJAN) Tj", "(S\\304HK\\326INEN) Tj"] {
            assert!(mark.contains(word), "{word}");
        }
        assert!(mark.contains("(K) Tj"), "the Swedish band, glyph by glyph");
        assert!(mark.contains("(C) Tj"), "the English band, glyph by glyph");
    }

    #[test]
    fn the_middle_is_in_the_readers_language_and_the_band_in_the_others() {
        let english = text(StampLanguage::English);
        assert!(english.contains("(CHECK) Tj"));
        assert!(english.contains("(SIGNATURE) Tj"));
        assert!(!english.contains("(TARKASTA) Tj"));
        let swedish = text(StampLanguage::Swedish);
        assert!(swedish.contains("(KONTROLLERA) Tj"));
        assert!(!swedish.contains("(CHECK) Tj"));
    }

    #[test]
    fn the_tilt_is_counterclockwise_within_its_range() {
        let mark = text(StampLanguage::English);
        let matrix = mark.lines().nth(2).expect("tilt line");
        let parts: Vec<&str> = matrix.split_whitespace().collect();
        assert_eq!(parts.last(), Some(&"cm"));
        let cosine: f64 = parts[0].parse().expect("cosine");
        let sine: f64 = parts[1].parse().expect("sine");
        let degrees = sine.atan2(cosine).to_degrees();
        assert!((4.99..=15.01).contains(&degrees), "got {degrees}");
        let placed = mark.lines().nth(1).expect("centring line");
        assert_eq!(
            placed,
            format!("1 0 0 1 {:.4} {:.4} cm", SIDE / 2.0, SIDE / 2.0)
        );
    }

    #[test]
    fn a_fixed_tilt_draws_the_same_mark_twice() {
        assert_eq!(
            operators_tilted(StampLanguage::Finnish, 10.0),
            operators_tilted(StampLanguage::Finnish, 10.0)
        );
    }

    #[test]
    fn the_middle_lines_fit_the_inner_ring_and_are_centred() {
        let room = BORDER_INNER_RADIUS * 2.0 * CENTRE_WIDTH_SHARE;
        for words in [FINNISH_WORDS, SWEDISH_WORDS, ENGLISH_WORDS] {
            let placed = centre_layout(&words);
            let size = placed[0].size;
            assert!(size <= CENTRE_FONT_SIZE);
            let widest = words
                .iter()
                .map(|line| line.bounds.scaled(size).width())
                .fold(0.0_f64, f64::max);
            assert!(widest <= room + 0.01, "{widest} within {room}");
            let top = placed[0].y + words[0].bounds.scaled(size).max_y;
            let bottom = placed[3].y + words[3].bounds.scaled(size).min_y;
            assert!((top + bottom).abs() < 0.01, "block centred on the axis");
            for (line, source) in placed.iter().zip(&words) {
                let bounds: Bounds = source.bounds.scaled(size);
                assert!((line.x + bounds.mid_x()).abs() < 0.01, "line centred");
            }
            assert!(placed.windows(2).all(|pair| pair[0].y > pair[1].y));
        }
        assert!(
            [FINNISH_WORDS, SWEDISH_WORDS, ENGLISH_WORDS]
                .iter()
                .all(|words| centre_layout(words)[0].size == CENTRE_FONT_SIZE),
            "every language's widest word fits at the full size"
        );
    }
}
