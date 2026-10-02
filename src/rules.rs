//! The only "business logic" in the whole program: parse block/allow lists and
//! answer "is this name blocked?".
//!
//! Matching works on label suffixes, most specific first:
//!
//!   query  a.b.example.com
//!   tries  a.b.example.com -> b.example.com -> example.com -> com
//!
//! At each step the allow set is checked before the block set, so the most
//! specific rule wins and, on a tie, allow beats block. That means
//!   block `example.com`, allow `cdn.example.com`  => cdn.example.com is allowed
//!   allow `example.com`, block `ads.example.com`  => ads.example.com is blocked

use std::{collections::HashSet, net::IpAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Allow,
    Block,
}

#[derive(Debug, Default)]
pub struct Rules {
    allow: HashSet<Box<str>>,
    block: HashSet<Box<str>>,
}

impl Rules {
    pub fn new(allow: HashSet<Box<str>>, block: HashSet<Box<str>>) -> Self {
        Self { allow, block }
    }

    pub fn block_len(&self) -> usize {
        self.block.len()
    }

    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    /// `name` must already be lowercase with no trailing dot.
    /// Returns the winning rule (a suffix of `name`), if any.
    pub fn lookup<'a>(&self, name: &'a str) -> Option<(Kind, &'a str)> {
        let mut s = name;
        loop {
            if self.allow.contains(s) {
                return Some((Kind::Allow, s));
            }
            if self.block.contains(s) {
                return Some((Kind::Block, s));
            }
            match s.find('.') {
                Some(i) => s = &s[i + 1..],
                None => return None,
            }
        }
    }

    pub fn is_blocked(&self, name: &str) -> bool {
        matches!(self.lookup(name), Some((Kind::Block, _)))
    }
}

/// Normalise and validate one domain. Returns None for anything that isn't a
/// plausible hostname (IP literals, single labels like `localhost`, junk).
pub fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw
        .trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.');
    if d.is_empty() || d.len() > 253 || !d.contains('.') {
        return None;
    }
    // "0.0.0.0" contains dots, so it would otherwise sneak through.
    if d.parse::<IpAddr>().is_ok() {
        return None;
    }
    let d = d.to_ascii_lowercase();
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        // '_' is not a valid hostname char but is common in real DNS names.
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return None;
        }
    }
    if d == "localhost.localdomain" {
        return None;
    }
    Some(d)
}

/// Parse one list into `out`. Understands the formats Pi-hole lists come in:
///   * hosts files:        `0.0.0.0 ads.example.com`   (also 127.0.0.1, ::, several names per line)
///   * plain domain lists: `ads.example.com`
///   * simple adblock:     `||ads.example.com^`
/// Comments (`#`, `!`) and everything unrecognised are skipped.
pub fn parse_into(text: &str, out: &mut HashSet<Box<str>>) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("||") {
            if let Some(d) = rest.strip_suffix('^').and_then(normalize_domain) {
                out.insert(d.into());
            }
            continue;
        }
        let line = line.split('#').next().unwrap_or("");
        let mut toks = line.split_whitespace();
        let Some(first) = toks.next() else { continue };
        if first.parse::<IpAddr>().is_ok() {
            for t in toks {
                if let Some(d) = normalize_domain(t) {
                    out.insert(d.into());
                }
            }
        } else if toks.next().is_none() {
            if let Some(d) = normalize_domain(first) {
                out.insert(d.into());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(text: &str) -> HashSet<Box<str>> {
        let mut s = HashSet::new();
        parse_into(text, &mut s);
        s
    }

    #[test]
    fn parses_hosts_format() {
        let s = set("# comment\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 Ads.Example.com # trailing\n::1 a.test b.test\n");
        assert!(s.contains("ads.example.com"));
        assert!(s.contains("a.test") && s.contains("b.test"));
        assert_eq!(s.len(), 3, "got {s:?}");
    }

    #[test]
    fn parses_domain_and_adblock_formats() {
        let s = set("tracker.example.net\n! comment\n||cdn.bad.org^\n||cdn.bad.org^$third-party\n*.wild.example\n");
        assert!(s.contains("tracker.example.net"));
        assert!(s.contains("cdn.bad.org"));
        assert!(s.contains("wild.example"));
        assert_eq!(s.len(), 3, "got {s:?}");
    }

    #[test]
    fn rejects_junk() {
        assert!(normalize_domain("localhost").is_none());
        assert!(normalize_domain("1.2.3.4").is_none());
        assert!(normalize_domain("bad domain.com").is_none());
        assert!(normalize_domain("a..com").is_none());
        assert_eq!(normalize_domain("Example.COM.").as_deref(), Some("example.com"));
        assert_eq!(normalize_domain("_dmarc.example.com").as_deref(), Some("_dmarc.example.com"));
    }

    #[test]
    fn suffix_matching_and_precedence() {
        let r = Rules::new(set("cdn.example.com\nexample.org"), set("example.com\nads.example.org"));
        assert!(r.is_blocked("example.com"));
        assert!(r.is_blocked("x.y.example.com")); // subdomain of a blocked name
        assert!(!r.is_blocked("cdn.example.com")); // more specific allow wins
        assert!(!r.is_blocked("a.cdn.example.com"));
        assert!(!r.is_blocked("example.org")); // allowed parent
        assert!(r.is_blocked("ads.example.org")); // more specific block wins
        assert!(!r.is_blocked("notexample.com")); // suffix match is per label, not per char
        assert!(!r.is_blocked("com"));
    }
}
