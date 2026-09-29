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

/// Replaces `//` and `/* */` comments and `"..."` strings with whitespace. Raw strings and char
/// literals are not handled: this repository has none containing the word `unsafe`, and if one
/// appears the budget test goes red rather than silently missing it.
fn strip_comments_and_strings(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut chars = source.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '/' if chars.peek() == Some(&'/') => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = ' ';
                for next in chars.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
                out.push(' ');
            }
            '"' => {
                let mut escaped = false;
                for next in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if next == '\\' {
                        escaped = true;
                    } else if next == '"' {
                        break;
                    }
                }
                out.push(' ');
            }
            other => out.push(other),
        }
    }
    out
}
