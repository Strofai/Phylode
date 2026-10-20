//! Runs the program with its output going to a reader that has already gone, as
//! `phylode report | head -1` leaves it once `head` has its line.
//!
//! The write fails with a broken pipe rather than a signal, because Rust ignores SIGPIPE;
//! `println!` turns that failure into a panic and the program ends with a crash message.

use std::process::{Command, Stdio};

#[test]
fn a_closed_reader_ends_the_program_quietly() {
    let (reader, writer) = std::io::pipe().expect("could not create a pipe");
    drop(reader);
    let output = Command::new(env!("CARGO_BIN_EXE_phylode"))
        .arg("help")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .expect("could not run phylode");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stderr.is_empty(),
        "phylode help with its reader gone exited with {:?} and printed {stderr:?}",
        output.status.code()
    );
}
