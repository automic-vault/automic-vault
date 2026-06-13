# Phase 1 Kernel Carve-Out Plan

## Summary

Implement the Phase 1 / first-cuts portion of `REFACTOR.md`: make
`src/lib/rs/lib.rs` mostly module wiring by extracting catalog/data loading and
package runtime state into owned internal modules. Do not split repositories in
this pass.

## Key Changes

- Add `src/lib/rs/DOMAIN_MAP.md` mapping current `lib.rs` constants, caches,
  types, and helpers to owners: catalog, package runtime/state, secrets/dotenv,
  trace, runtime boundary, and shared infrastructure.
- Add a `catalog` module tree for embedded/remote combined data, `Db`, package
  metadata structs, catalog caches, schema validation, remote refresh,
  package-prefix constants, formula/cask alias indexes, security
  recommendations, and stub exclusions.
- Add a `package` module tree for package DTOs and persistence: receipt/source
  types, install/search/status/info structs, package selection/request aliases,
  install plan/options/intent, package mutation lock, root receipt paths,
  ownership manifests, and receipt read/write helpers.
- Keep `config.rs` as the owner of install roots and endpoint roots; remove
  only redundant root wrappers from `lib.rs` after imports are updated.
- Move private tests with the code they verify where practical. Use
  `pub(crate)` only for functions/types consumed across modules, not as a
  blanket escape hatch.

## Interfaces And Compatibility

- No public protocol, helper, XPC, CLI output, receipt, manifest, or `/db.json`
  shape changes.
- Do not bump `DB_SCHEMA_VERSION`, `../av.db/scripts/build-db.py` `SCHEMA_VERSION`,
  `PROTOCOL_VERSION`, `NUKE_PROTOCOL_VERSION`, or `NUKE_HELPER_VERSION`.
- Keep existing crate public exports stable: `main_entry`,
  `scanner_main_entry`, dotenv policy/mode exports, helper command exports,
  isotope entry, and vault entry/types.
- Keep `/db.json` additive/backward-compatible; this refactor only moves Rust
  ownership.

## Implementation Order

1. Commit 1: domain map plus empty module shells and root module wiring.
2. Commit 2: catalog/data extraction, preserving all serde field names and
   remote-cache behavior.
3. Commit 3: package type and package-state extraction, preserving
   receipt/manifest JSON.
4. Commit 4: cleanup imports/re-exports so `lib.rs` is facade-level wiring plus
   any intentionally retained glue.

Leave untracked `REFACTOR.md` as an input artifact unless explicitly asked to
stage it.

## Test Plan

- Pre/post baseline: `cargo llvm-cov --workspace --summary-only --
  --test-threads=1`; current baseline is 93.08% line coverage and 91.33%
  region coverage. Final coverage must not drop below that.
- Run `/usr/bin/python3 scripts/generate-coverage-fixtures.py` and
  `git diff --exit-code -- data/combined.json
  src/lib/rs/fixtures/coverage-combined.json`.
- Run `cargo fmt --check`.
- Run `cargo test --workspace -- --test-threads=1`.
- Run targeted tests after each extraction: catalog/schema/remote-data tests,
  package receipt/state tests, `ops` search/list/info tests, and `protocol`
  package dispatch tests.

## Assumptions

- Scope is Phase 1 only because `REFACTOR.md` is a multi-phase roadmap.
- No new repositories are created in this pass.
- Existing ahead-of-origin commits are user/other-thread work and must not be
  rewritten.
