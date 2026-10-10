# Contributing

Thanks for looking. Phylode is small and opinionated; reading the four product principles in
[CLAUDE.md](CLAUDE.md) first will save you a round trip — when two goals conflict, keeping the
network online wins over blocking more, and Apple's own services always pass.

## Before you open a pull request

- `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass. CI runs
  the same on macOS, plus `cargo deny check`.
- Changes under `src/` or `deploy/` are also installed and uninstalled for real on a throwaway
  macOS runner (`.github/workflows/install.yml`). You do not need to install the service on your
  own machine to test them.
- One commit per coherent change. The summary line starts with one of `Feat:`, `Fix:`,
  `Docs:`, `Test:` or `Chore:`, then says in the imperative, within 72 characters, what
  changes for someone using Phylode — `Fix: Keep the journal within its retention on a Mac
  that sleeps at night`, not `Fix: Update writer.rs` — and the body says why it was needed,
  what changed and what is now true. Plain English, the way release notes read; the full
  rules are under "Commits and pushes" in [CLAUDE.md](CLAUDE.md).
- No details of any real network: no ISP names, device models, address ranges or keys, in
  code, comments, tests or commit messages. Use the RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918 ranges.
- A new dependency needs a reason in the pull request, and its license must be on the list in
  `deny.toml`.

## Reporting a bug

Use the bug report form. It follows the structure Apple asks for in its own bug reports: a title
that names the problem and what triggers it, numbered steps to reproduce, expected results,
actual results and your configuration. It also asks for the output of `phylode diagnostics`,
which is written to be safe to post publicly (no domains, addresses or names). Do not paste
the query journal, `phylode status` or the raw service log into an issue.
Security problems go through private reporting instead — see [SECURITY.md](SECURITY.md).

## License

Contributions are dual licensed under MIT and Apache-2.0, as described in the README.
