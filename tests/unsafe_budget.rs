//! Enforces the rule that exactly one place in the project may use `unsafe`.
//!
//! It counts the actual `unsafe` keyword in code (blocks, functions, impls), not the attribute
//! that opens the exception — attributes come as `#[allow]`, `#![allow]` and combined forms, so
//! matching only one of them would miss the rest. Occurrences inside comments and strings do
//! not count.
//! The scan covers `src/`, `tests/`, `fuzz/fuzz_targets/` and `build.rs`.
//! What breaks if you change it: before raising the budget, answer what the new `unsafe` buys
//! and say so in the pull request.

use std::path::{Path, PathBuf};

/// Files permitted to contain `unsafe`, and how many occurrences each may have.
///
/// The only exception today is adopting launchd's descriptors as sockets: the price of the
/// service never running as root, which buys not giving root to a program with a network port
/// open to the world.
const BUDGET: &[(&str, usize)] = &[("src/dns/launchd.rs", 2)];

/// Directories and individual files to scan, relative to the repository root. Missing ones are
/// skipped.
const SCANNED: &[&str] = &["src", "tests", "fuzz/fuzz_targets", "build.rs"];

#[test]
fn the_projects_unsafe_usage_stays_within_budget() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut findings: Vec<(String, usize)> = Vec::new();
    for entry in SCANNED {
        collect(&root.join(entry), &root, &mut findings);
    }
    findings.sort();

    let mut expected: Vec<(String, usize)> = BUDGET
        .iter()
        .map(|(path, count)| ((*path).to_string(), *count))
        .collect();
    expected.sort();

    assert_eq!(
        findings, expected,
        "unsafe usage does not match the budget.\n\
         An extra file means someone used unsafe elsewhere, which voids every memory-safety\n\
         claim this project makes.\n\
         If it is genuinely needed, update BUDGET in tests/unsafe_budget.rs and state what it\n\
         buys."
    );
}

#[test]
fn every_budgeted_occurrence_has_a_safety_note() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for (path, count) in BUDGET {
        let full = root.join(path);
        assert!(
            full.exists(),
            "the budget lists {path}, but that file does not exist"
        );
        let text = std::fs::read_to_string(&full).unwrap();
        assert!(
            text.matches("// SAFETY:").count() >= *count,
            "{path} has {count} unsafe occurrences and fewer SAFETY notes than that"
        );
    }
}

/// The checker's own control: everything that should count does, and prose mentioning the word
/// does not.
#[test]
fn the_counter_catches_every_form_without_false_positives() {
    let should_count = [
        ("let x = unsafe { f() };", 1),
        ("unsafe fn danger() {}", 1),
        ("unsafe impl Send for X {}", 1),
        ("pub unsafe extern \"C\" fn g() {}", 1),
        ("#![allow(unsafe_code)]\nunsafe {}\nunsafe {}", 2),
        ("a(unsafe{b()})", 1),
        // Quote characters that are not strings must not hide the code after them.
        ("let q = '\"'; unsafe { f() }; let r = '\"';", 1),
        ("let q = b'\"'; unsafe { f() }; let r = b'\"';", 1),
        ("let q = '\\''; unsafe { f() }; let s = \"'\";", 1),
        ("fn f<'a>(x: &'a str) { unsafe { g() } }", 1),
        ("let s = r#\"a \" b\"#; unsafe { f() }; let t = r#\"\"#;", 1),
        ("let s = br\"\\\"; unsafe { f() }; let t = \"\";", 1),
    ];
    for (code, expected) in should_count {
        assert_eq!(count_unsafe(code), expected, "should have counted: {code}");
    }

    let should_not_count = [
        "// unsafe { } must not be used here",
        "/// documentation for an unsafe fn",
        "let s = \"unsafe { }\";",
        "#[allow(unsafe_code)]",
        "#![deny(unsafe_code)]",
        "let not_unsafe = 1;",
        "/* unsafe { } inside a block comment */",
        "let s = r#\"unsafe { } with a \" inside\"#;",
        "let s = br\"unsafe\";",
        "let c = '\"'; let s = \"unsafe\";",
    ];
    for code in should_not_count {
        assert_eq!(count_unsafe(code), 0, "should not have counted: {code}");
    }
}

fn collect(path: &Path, root: &Path, findings: &mut Vec<(String, usize)>) {
    if path.is_dir() {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            collect(&entry.path(), root, findings);
        }
        return;
    }
    if path.extension().is_none_or(|ext| ext != "rs") {
        return;
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let count = count_unsafe(&text);
    if count > 0 {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        findings.push((relative, count));
    }
}

/// Counts the `unsafe` keyword in code. Comments and strings are stripped first, then whole
/// words are matched (`unsafe_code` does not count).
fn count_unsafe(source: &str) -> usize {
    let code = strip_comments_and_strings(source);
    let bytes = code.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    code.match_indices("unsafe")
        .filter(|(at, word)| {
            let before = at.checked_sub(1).map(|i| bytes[i]);
            let after = bytes.get(at + word.len()).copied();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .count()
}

/// Replaces comments, string literals (plain, byte, C and raw, with any number of `#`) and
/// character literals with a space, following the Rust Reference's lexical rules. A lifetime
/// such as `'a` is code and kept.
///
/// What breaks if you change it: a literal the scanner does not recognise shifts where it
/// thinks strings start and end — `'"'` read as opening a string hides the code after it.
/// Block comments are ended at the first `*/` rather than nested, which can only show more
/// code, never less.
fn strip_comments_and_strings(source: &str) -> String {
    let chars: Vec<char> = source.chars().collect();
    let is_ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::with_capacity(source.len());
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let starts_token = i == 0 || !is_ident(chars[i - 1]);
        if c == '/' && next == Some('/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && next == Some('*') {
            i += 2;
            while i < chars.len() && !(chars[i - 1] == '*' && chars[i] == '/') {
                i += 1;
            }
            i += 1;
            out.push(' ');
        } else if let Some(end) = starts_token.then(|| raw_string_end(&chars, i)).flatten() {
            i = end;
            out.push(' ');
        } else if c == '"' {
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.push(' ');
        } else if c == '\'' && next == Some('\\') {
            i += 2;
            while i < chars.len() && chars[i] != '\'' {
                i += 1;
            }
            i += 1;
            out.push(' ');
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            i += 3;
            out.push(' ');
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// If a raw string literal (`r"…"`, `br#"…"#`, `cr##"…"##`) starts at `start`, the index just
/// past its end; otherwise `None`.
fn raw_string_end(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    if matches!(chars.get(i), Some('b' | 'c')) {
        i += 1;
    }
    if chars.get(i) != Some(&'r') {
        return None;
    }
    i += 1;
    let hashes = chars[i..].iter().take_while(|&&c| c == '#').count();
    i += hashes;
    if chars.get(i) != Some(&'"') {
        return None;
    }
    i += 1;
    while i < chars.len() {
        if chars[i] == '"'
            && chars[i + 1..]
                .iter()
                .take(hashes)
                .filter(|&&c| c == '#')
                .count()
                == hashes
        {
            return Some(i + 1 + hashes);
        }
        i += 1;
    }
    Some(chars.len())
}
