//! Packets from home devices: arbitrary bytes run through parsing, the decision and response
//! assembly without panicking or hanging.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    phylode::dns::fuzz_request(data);
});
