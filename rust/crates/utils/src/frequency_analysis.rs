//! # Frequency Analysis
//!
//! Utility functions for performing frequency analysis on English language text.
//! The hardcoded frequency data was derived from the [Reuters-21578] corpus.
//!
//! ## Usage
//!
//! ```rust
//! use cryptopals_utils::frequency_analysis;
//!
//! let score = frequency_analysis::string_score("cryptopals-solutions");
//! assert!(score > 0.0);
//! ```
//!
//! [Reuters-21578]: https://www.daviddlewis.com/resources/testcollections/reuters21578/

#[derive(Clone, Debug)]
struct AsciiHistogram {
    frequencies: [f64; 256],
    num_chars_aggregated: u32,
}

impl Default for AsciiHistogram {
    fn default() -> Self {
        Self {
            frequencies: [0.0; 256],
            num_chars_aggregated: 0,
        }
    }
}

impl AsciiHistogram {
    fn add_char(&mut self, ascii_char: u8) {
        self.frequencies[usize::from(ascii_char)] += 1.0;
        self.num_chars_aggregated += 1;
    }

    fn normalize(&mut self) {
        for f in self.frequencies.iter_mut() {
            *f /= self.num_chars_aggregated as f64;
        }
    }

    fn chi_squared(&self) -> f64 {
        let mut total = 0.0;
        for ascii_char in 0u8..=255 {
            let observed = self.frequencies[usize::from(ascii_char)];
            let expected = char_score(ascii_char as char);
            total += (observed - expected).powi(2) / expected;
        }
        total
    }

    // XXX: might still be broken...
    fn cross_entropy(&self) -> f64 {
        let mut total = 0.0;
        for ascii_char in 0u8..=255 {
            let p = self.frequencies[usize::from(ascii_char)];
            let q = char_score(ascii_char as char);
            total += p * q.log2();
        }
        -total
    }
}

const LETTER_FREQUENCIES: [f64; 26] = [
    0.0612553996079051,
    0.01034644514338097,
    0.02500268898936656,
    0.03188948073064199,
    0.08610229517681191,
    0.015750347191785568,
    0.012804659959943725,
    0.02619237267611581,
    0.05480626188138746,
    0.000617596049210692,
    0.004945712204424292,
    0.03218192615049607,
    0.018140172626462205,
    0.05503703643138501,
    0.0541904405334676,
    0.017362092874808832,
    0.00100853739070613,
    0.051525029341199825,
    0.0518864979648296,
    0.0632964962389326,
    0.019247776378510318,
    0.007819143740853554,
    0.009565830104169261,
    0.0023064144740073764,
    0.010893686962847832,
    0.0005762708620098124,
];

const UPPERCASE_FREQUENCIES: [f64; 26] = [
    0.0024774830020061096,
    0.0017387002075069484,
    0.002987392712176473,
    0.0010927723198318497,
    0.0012938206232079082,
    0.001220297284016159,
    0.0009310209736100016,
    0.0008752446473266058,
    0.0020910417959267183,
    0.0008814561018445294,
    0.0003808001912620934,
    0.0010044809306127922,
    0.0018134911904778657,
    0.0012758834637326799,
    0.0008210528757671701,
    0.00138908405321239,
    0.00010001709417636208,
    0.0011037374385216535,
    0.0030896915651553373,
    0.0030701064687671904,
    0.0010426370083657518,
    0.0002556203680692448,
    0.0008048270353938186,
    0.00006572732994986532,
    0.00025194420110965734,
    0.00008619977698342993,
];

const DIGIT_FREQUENCIES: [f64; 10] = [
    0.005918945715880591,
    0.004937789430804492,
    0.002756237869045172,
    0.0021865587546870337,
    0.0018385271551164353,
    0.0025269211093936652,
    0.0019199098857390264,
    0.0018243295447897528,
    0.002552781042488694,
    0.002442242504945237,
];

/// Gives a frequency analysis score for `s`.
///
/// This is context-unaware, based solely on individual character frequencies.
///
/// Returns a score between `0.0` and `1.0`.
/// The higher the score, the more likely the string is English.
/// The score is normalized by the length of the string.
// TODO: use n-gram frequencies
pub fn string_score(s: &str) -> f64 {
    let mut histogram = AsciiHistogram::default();
    for c in s.chars() {
        if !c.is_ascii() {
            histogram.add_char(255);
        }
        histogram.add_char(c as u8);
    }
    histogram.normalize();
    1e9 - histogram.chi_squared()
}

pub fn naive_string_score(s: &str) -> f64 {
    let mut total = 0.0;
    for c in s.chars() {
        total += char_score(c);
    }

    // normalize by length
    total / s.len() as f64
}

/// Gives
pub fn char_score(c: char) -> f64 {
    if c.is_ascii_alphabetic() {
        if c.is_ascii_lowercase() {
            let index = c as usize - 'a' as usize;
            LETTER_FREQUENCIES[index]
        } else {
            let index = c as usize - 'A' as usize;
            UPPERCASE_FREQUENCIES[index]
        }
    } else if c.is_ascii_digit() {
        let index = c as usize - '0' as usize;
        DIGIT_FREQUENCIES[index]
    } else if c == ' ' {
        0.167564443682168
    } else if c == '\n' {
        0.019578060965172565
    } else if c == '.' {
        0.011055184780313847
    } else if c == ',' {
        0.008634492219614468
    } else if c == '-' {
        0.002076717421222119
    } else if c == '"' {
        0.0015754276887500987
    } else if c == '\'' {
        0.0015078622753204398
    } else if c.is_control() {
        1e-9
    } else {
        1e-6
    }
}
// '/': 0.000519607185080999
// '<': 0.00044107665296153596
// '>': 0.0004404428310719519
// ')': 0.0003314254660634964
// ':': 0.00012036277683200988
// '(': 0.0003307916441739124
// ';': 0.00000741571610813331
// '?': 0.000004626899793963519
// '': 0.0000031057272589618137
// '^': 0.0000022183766135441526
// '&': 0.0000020282300466689395
// '+': 0.0000015211725350017046
// '[': 0.000000697204078542448
// ']': 0.0000006338218895840436
// '$': 0.0000005070575116672349
// '!': 0.0000005070575116672349
// '*': 0.0000004436753227088305
// '=': 0.00000025352875583361743
// '~': 0.00000019014656687521307
// '_': 0.00000012676437791680872
// '{': 0.00000006338218895840436
// '@': 0.00000006338218895840436

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        let score1 = string_score("Chancellor on brink of second bailout for banks");
        let score2 =
            string_score("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert!(score1 > score2);
    }

    #[test]
    fn strings() {
        let score1 = string_score("cryptopals-solutions");
        let score2 = string_score("HPmWFCA1k5yKqGvEwfu7");
        assert!(score1 > score2);

        let score1 = string_score("cryptopals-solutions");
        let score2 = string_score("abcdefghij-klmnopqrs");
        assert!(score1 > score2);

        let score1 = string_score("cryptopals-solutions");
        let score2 = string_score("eeeeeeeeeeeeeeeeeeee");
        assert!(score1 > score2);

        let score1 = string_score("cryptopals-solutions");
        let score2 = string_score("                    ");
        assert!(score1 > score2);
    }

    #[test]
    fn chars() {
        let score1 = char_score('e');
        let score2 = char_score('E');
        assert!(score1 > score2);

        let score1 = char_score('e');
        let score2 = char_score('x');
        assert!(score1 > score2);

        let score1 = char_score('1');
        let score2 = char_score('7');
        assert!(score1 > score2);
    }
}
