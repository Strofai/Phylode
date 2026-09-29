//! Blocklists downloaded from the network: arbitrary text is parsed and then queried, without
//! panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use phylode::policy::Blocklist;

fuzz_target!(|text: &str| {
    let list = Blocklist::new();
    list.load_from_str(text);
    for line in text.lines().take(8) {
        let _ = list.lookup(line.trim());
    }
});
