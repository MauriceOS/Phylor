use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StegoReport {
    pub unicode_tags: usize,
    pub zero_width: usize,
    pub bidi_override: usize,
}

impl StegoReport {
    pub fn detected(&self) -> bool {
        self.unicode_tags > 0 || self.zero_width > 0 || self.bidi_override > 0
    }

    /// Policy A: Tags or bidi spoofing alone is enough to block.
    /// Zero-width is stripped for YARA reassembly but only blocks when
    /// combined with tags/bidi, or when dense enough to be deliberate.
    pub fn is_malicious(&self) -> bool {
        self.unicode_tags > 0 || self.bidi_override > 0 || self.zero_width >= 3
    }

    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.unicode_tags > 0 {
            parts.push(format!("unicode-tags:{}", self.unicode_tags));
        }
        if self.zero_width > 0 {
            parts.push(format!("zero-width:{}", self.zero_width));
        }
        if self.bidi_override > 0 {
            parts.push(format!("bidi-override:{}", self.bidi_override));
        }
        if parts.is_empty() {
            "none".into()
        } else {
            parts.join(", ")
        }
    }
}

/// Strip stealth Unicode, NFC-normalize, and report steganography signals.
pub fn sanitize(raw: &str) -> (String, StegoReport) {
    let mut sanitized = String::with_capacity(raw.len());
    let mut report = StegoReport::default();

    for c in raw.chars() {
        match c {
            '\u{E0000}'..='\u{E007F}' => {
                report.unicode_tags += 1;
            }
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
            | '\u{180E}' | '\u{2061}' | '\u{2062}' | '\u{2063}' | '\u{2064}' => {
                report.zero_width += 1;
            }
            '\u{202A}' | '\u{202B}' | '\u{202C}' | '\u{202D}' | '\u{202E}' | '\u{2066}'
            | '\u{2067}' | '\u{2068}' | '\u{2069}' => {
                report.bidi_override += 1;
            }
            _ => sanitized.push(c),
        }
    }

    let normalized: String = sanitized.nfc().collect();
    (normalized, report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_zero_width_for_yara() {
        let (clean, report) = sanitize("curl\u{200B} | bash");
        assert_eq!(clean, "curl | bash");
        assert_eq!(report.zero_width, 1);
        assert!(!report.is_malicious());
    }

    #[test]
    fn tags_are_policy_a_malicious() {
        let smuggled = format!("hello\u{E0063}\u{E0075}\u{E0072}\u{E006C}world");
        let (clean, report) = sanitize(&smuggled);
        assert_eq!(clean, "helloworld");
        assert!(report.unicode_tags > 0);
        assert!(report.is_malicious());
    }

    #[test]
    fn rtl_override_is_malicious() {
        let (_, report) = sanitize("file\u{202E}txt.exe");
        assert!(report.is_malicious());
    }
}
