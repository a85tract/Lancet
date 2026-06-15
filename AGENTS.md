# Repository Guidelines

## Project Structure & Module Organization
- `src/` contains the Rust analyzer library and CLI. `main.rs` handles argument parsing; `lib.rs` exposes `run_klancet`; modules such as `qlt.rs`, `legacy.rs`, `trace.rs`, `analyzer.rs`, `ownership.rs`, and `report.rs` implement trace decoding, analysis, and report output.
- `tests/e2e.rs` holds end-to-end tests that synthesize traces and validate generated JSON summaries.
- `qemu_tcg/` contains the optional QEMU TCG plugin source (`hello.c`) and build notes for producing QLT traces.
- Generated artifacts belong in `target/`, `out/`, or temporary directories; `.qlt` and `.so` files are ignored by Git.

## Build, Test, and Development Commands
- `cargo build` compiles the Rust crate and CLI.
- `cargo test --verbose` runs the e2e suite with detailed output.
- `cargo run -- klancet <trace> <config.json> <output_dir> --trace-format auto` runs the analyzer; use `qlt` or `legacy` to force a format.
- `cargo fmt --all` formats Rust sources before committing.
- `cargo clippy --all-targets --all-features` checks common Rust mistakes when Clippy is available.
- To build the QEMU plugin, follow `qemu_tcg/README.md` in an environment with `qemu-plugin.h`, `glib-2.0`, and `libzstd`.

## Coding Style & Naming Conventions
- Use Rust 2024 idioms and standard `rustfmt` formatting: 4-space indentation, grouped imports, and trailing commas where rustfmt adds them.
- Name modules and functions in `snake_case`, types and traits in `PascalCase`, and constants in `SCREAMING_SNAKE_CASE`.
- Keep parsing, trace I/O, analysis, and reporting logic in their existing modules rather than growing `main.rs`.

## Testing Guidelines
- Add regression tests to `tests/e2e.rs` for behavior visible through `run_klancet` or trace readers.
- Use descriptive test names such as `invalid_free_for_interior_pointer` and assert exact summary counters.
- Prefer generated temporary traces/configs over checked-in binary fixtures unless a fixture is essential.

## Commit & Pull Request Guidelines
- The current history has only `first commit`; use concise, imperative subjects going forward, e.g. `Add legacy trace edge case test`.
- PRs should include a short problem statement, implementation summary, commands run (`cargo test`, `cargo fmt`), and sample output or JSON changes when report behavior changes.
- Link related issues and note any required QEMU/plugin environment details.
