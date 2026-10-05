//! Packets from upstream: arbitrary bytes treated as an answer and run through our own handling
//! (TTLs, addresses, aliases, rebinding defence, cache) without panicking or hanging. Parsing
//! itself is hickory's job; what is under test here is our code after the parse.
#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use phylode::cache::{Cache, Cached};
use phylode::dns::{Name, Query, RecordType};
use phylode::policy::RebindGuard;

fuzz_target!(|data: &[u8]| {
    let Some(records) = phylode::dns::fuzz_upstream_records(data) else {
        return;
    };
    let _ = records.min_ttl();
    // The elapsed time includes the u64 maximum, checking TTL subtraction does not overflow on
    // conversion to the wire's u32.
    for elapsed in [
        Duration::ZERO,
        Duration::from_secs(3600),
        Duration::from_secs(u64::MAX),
    ] {
        let _ = records.aged(elapsed);
    }

    let addresses = records.addresses();
    let guard = RebindGuard::with_internal_domains(["home.arpa"]);
    let _ = guard.inspect("example.com", &addresses);
    for target in records.alias_targets() {
        let _ = guard.inspect(&target, &addresses);
    }

    let cache = Cache::new(4, Duration::from_secs(12 * 60 * 60));
    let query = Query::new(Name::parse("example.com"), RecordType::A);
    cache.insert(query.clone(), Cached::Records(records));
    let _ = cache.get(&query);
});
