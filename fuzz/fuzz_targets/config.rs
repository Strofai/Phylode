//! Configuration files: our own parser must return either a configuration or an error for any
//! text, and never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|text: &str| {
    let _ = phylode::config::Config::parse(text);
});
