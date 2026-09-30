# fuzz/ — fuzzing

- Runs on stable Rust with `-s none`:
  `cargo fuzz run -s none request fuzz/corpus/request fuzz/seeds/request -- -max_total_time=600`.
  **`fuzz/corpus/<target>` must come first**: newly generated cases are written to the first
  directory given, and `corpus/` is gitignored. Put `seeds/` first and thousands of
  generated cases land in the repository.
  The targets are `request` (packets from devices on the network), `upstream` (packets from upstream
  resolvers), `blocklist` and `config`.
- **A run saturates one core.** Run one target at a time locally, and use the workflow below
  for anything longer than a few minutes.
- For long runs use the **Fuzz** workflow on GitHub Actions instead
  (`.github/workflows/fuzz.yml`, manual trigger, `seconds` input per target): all four
  targets run in parallel, corpora persist between runs, and a crashing input is uploaded
  as an artifact.
- `libfuzzer-sys` is NCSA-licensed, which is accepted **for `fuzz/` only**: `deny.toml`
  carries an exception scoped to it, and the main program's license allowlist is unchanged.
  To check licensing under `fuzz/`:
  `cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml check`.
