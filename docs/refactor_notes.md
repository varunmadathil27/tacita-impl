# Refactor Notes

This refactor keeps the current prototype behavior available while moving cryptographic and protocol code out of the binary `main.rs` files.

## What Changed

- `hints`
  - Added a library target at [`hints/src/lib.rs`](/Users/varun/Documents/tacita-impl/hints/src/lib.rs).
  - Moved the old binary-heavy protocol logic into [`hints/src/protocol.rs`](/Users/varun/Documents/tacita-impl/hints/src/protocol.rs).
  - Kept [`hints/src/main.rs`](/Users/varun/Documents/tacita-impl/hints/src/main.rs) as a thin wrapper that calls the library entry point.
  - Added [`hints/examples/legacy_hints_demo.rs`](/Users/varun/Documents/tacita-impl/hints/examples/legacy_hints_demo.rs) so the old benchmark/demo flow remains available as an example target.

- `ste`
  - Added [`ste/src/bench.rs`](/Users/varun/Documents/tacita-impl/ste/src/bench.rs) for the old end-to-end benchmark driver.
  - Exported that module from [`ste/src/lib.rs`](/Users/varun/Documents/tacita-impl/ste/src/lib.rs).
  - Reduced [`ste/src/main.rs`](/Users/varun/Documents/tacita-impl/ste/src/main.rs) to a thin wrapper over the library.
  - Added [`ste/examples/legacy_ste_bench.rs`](/Users/varun/Documents/tacita-impl/ste/examples/legacy_ste_bench.rs) so the old benchmark flow is also reachable as an example target.
  - Removed the duplicate [`ste/src/mod.rs`](/Users/varun/Documents/tacita-impl/ste/src/mod.rs).

## Behavioral Intent

- No protocol redesign was attempted.
- Existing benchmark/demo behavior should remain reachable through the thin wrapper binaries and the example targets.
- The purpose of this change is structural: make the cryptographic logic importable and reusable from library code.

## Follow-Up Work

- Split [`hints/src/protocol.rs`](/Users/varun/Documents/tacita-impl/hints/src/protocol.rs) into smaller reusable modules (`setup`, `prove`, `verify`, etc.).
- Unify arkworks versions across `hints` and `ste` before attempting an integrated `tacita` crate.
- Replace demo-oriented entry points with explicit client/server/committee message APIs once the protocol composition layer is implemented.
