# Flower's exact-pinned `im` read extension

## Provenance and license

- Upstream package: **`im` 15.1.0**, unchanged package name/version.
- Registry archive: `im-15.1.0.crate` from the local Cargo registry cache.
- Archive SHA-256 (also the original Flower lockfile registry checksum):
  `d0acd33ff0285af998aaf9b57342af478078f53492322fafc47450e09397e0e9`.
- Source copied from
  `/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/im-15.1.0`.
  All 38 upstream files were checked byte-for-byte against that archive before
  modification. `UPSTREAM-SHA256SUMS` records their original contents.
- `LICENCE.md`, all original MPL source headers, README, changelog,
  code-of-conduct, original and Cargo-normalized manifests, and build script
  are preserved. New Rust extension/test files carry the same MPL-2.0 notice.
  Cargo extraction markers/checksum metadata are not copied.
- Upstream repository is recorded in both original manifests. This is a narrow
  local extension, not an upstream release or a relicensing of `im` as Flower's
  MIT license. Distribute the retained MPL notices and corresponding modified
  source in accordance with the upstream license.

## Scope and rationale

Flower's SQL snapshot-retention/resource gate cannot use `OrdMap::range` to
traverse an overlay if allocating its heap-backed ancestor path is outside the
admitted native budget. Nor can it substitute upstream `get_next`: in 15.1.0,
`Node::lookup_next` returns a selected child's exhausted search directly and
loses a qualifying ancestor separator. This is reproducible in the tests below.

The opt-in, default-off **`flower-bounded-reads`** feature adds only:

```rust
impl<K: Ord, V> OrdMap<K, V> {
    pub fn get_next_bounded<BK>(
        &self,
        key: &BK,
    ) -> Result<Option<(&K, &V)>, BoundedReadError>
    where
        BK: Ord + ?Sized,
        K: std::borrow::Borrow<BK>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedReadError {
    Depth,
    InvalidNode,
}
```

The error is publicly exported as both `im::BoundedReadError` and
`im::ordmap::BoundedReadError`, only when the feature is enabled. There is no
`Clone` bound on keys or values for this read method. All returned references
borrow the original map. Errors are fixed enum values, never formatted or boxed.

The node implementation is a separate iterative inclusive-successor search.
For insertion index `i`, `keys[i]`, when present, becomes a borrowed candidate;
then only `children[i]` is followed. An exact key returns immediately. A child's
exhaustion returns the last retained candidate, even when it came from a parent.
Every deeper candidate is less than its ancestor candidate by the ordinary
B-tree ordering invariant. No ancestor vector, iterator, recursive call, map,
root, key or value clone, allocation, or writer operation is involved.

The maximum is **128 visited nodes**, including the terminal node. A child
requiring visit 129 returns `Depth`, not a partial candidate. Each visited node
checks `children.len() == keys.len() + 1`; an invalid count/index returns
`InvalidNode`. These are local defensive checks, not full validation of key
ordering, balance, all off-path child shapes, or arbitrary unsafe memory damage.
The hard depth bound is enforced even on an artificially unbalanced chain.

Existing methods (including the buggy ordinary `get_next`), writer algorithms,
map representation, ordering/value semantics and serialization are unchanged.
The only changes to original files are the manifest's empty opt-in feature and
feature-gated module/re-export declarations in `src/lib.rs`, `src/ord/map.rs`
and `src/nodes/btree.rs`. `Cargo.toml.orig` remains the exact upstream manifest.
With the feature off, none of the extension code or exports are compiled.

## Source-derived height and CPU bounds

This admission argument is for supported **64-bit** Flower targets, ordinary
safe `im` writers, and the upstream ordering/balancing invariants:

1. `src/config.rs` fixes `OrdChunkSize` to `U64`. Nodes therefore hold at most
   **64 keys / 65 child slots**, regardless of map length or query length.
   `src/nodes/btree.rs` sets `MEDIAN = (NODE_SIZE + 1) >> 1 = 32`.
2. `Node::split` promotes one separator and its explicit postconditions leave
   both siblings with 32 keys / 33 child slots. `new_from_split` creates a root
   with one separator and two children. Insertion preserves equal leaf depth.
3. `too_small` means fewer than 32 keys. `remove_index` may delete a key from a
   32-key child, leaving **31 keys**, but must first steal or merge when
   descending into a smaller child. Stealing supplies one key before removal;
   merging combines both children plus their separator. The `Merge` and
   `MergeFirst` paths replace an empty root with its surviving merged child.
   These operations preserve balanced leaf depth and do not leave a zero-key
   nonroot branch. Thus every nonroot node has at least 31 keys and each
   nonroot internal node at least 32 children. `OrdMap` cardinality is `usize`.
4. Let `h` count visited levels root-to-leaf. For nonempty height `h`, minimum
   cardinality is
   `1 + 2*31*(1 + 32 + ... + 32^(h-2)) = 2*32^(h-1) - 1`.
   Height 14 requires `2*32^13 - 1 = 2^66 - 1`, beyond `usize::MAX = 2^64 - 1`;
   hence **h <= 13**. Even the weaker invariant of one key / two children in
   every balanced node gives `n >= 2^h - 1`, hence **h <= 64**. Both are below
   128. Checked `u128` arithmetic in the harness verifies these boundaries.
   The read limit itself does not rely on either proof being true for a
   malformed tree: it always fails closed after 128 visits.
5. A node uses the existing `BTreeValue::search_key`. For Flower's `String`/`str`
   keys on the stable toolchain, this is binary search over at most 64 keys;
   comparison count is bounded independently of map cardinality. Upstream's
   nightly Copy-key specialization can use linear search, still at most 64
   entries. No source-wide specialization or lookup behavior was modified.

This generic method does **not** bound user-defined `Ord`/`Borrow` cost or their
allocations. Flower uses lexicographic `str` comparisons. Its caller admits and
prepares a **fixed 4097-byte query buffer**: an initial inclusive lower bound,
or `last_key + NUL` for strict succession. Appending NUL is the least extension
of a finite UTF-8 string (including empty strings and strings already containing
NUL); no stored key lies strictly between `key` and `key + NUL`. A 4096-byte
returned key fits with that extra byte. Query length bounds comparison work;
there is no need to add a generic stored-key or query-length cap to `OrdMap`.
The caller separately validates its key/query representation, checks the upper
bound, admits output storage, limits iterations, and observes deadlines.

## Isolated checks, without new dependency versions

`bounded-harness/` is a separate, nonpublished Cargo workspace using a path
dependency on this vendor and only versions already in Flower's lockfile.
Its private-node tests include the actual vendored `btree.rs`, `config.rs`,
`util.rs`, and `fakepool.rs`, avoiding unrelated upstream dev-dependencies.
The test-only tuple-key implementation supplies binary comparison for synthetic
nodes; public-map tests use the real `im` implementation and its Arc nodes.
The single-thread executable installs an allocator **only in that executable**,
not the library or Flower. It counts `alloc`, `alloc_zeroed`, `realloc` and
key/value clones separately. Map construction, snapshots, reference ranges,
queries and output reservation happen outside measured regions. Actual scans
include fixed-buffer query updates and external upper-bound checks.

Run from `vendor/im/bounded-harness`:

```sh
RUSTFLAGS='-A unexpected_cfgs' cargo test --offline --locked
RUSTFLAGS='-A unexpected_cfgs' cargo run --offline --locked
RUSTFLAGS='-A unexpected_cfgs' cargo run --offline --locked --release
RUSTFLAGS='-A unexpected_cfgs' cargo run --offline --locked --no-default-features
RUSTFLAGS='-A unexpected_cfgs' cargo clippy --offline --locked --all-targets
RUSTFLAGS='-A unexpected_cfgs' cargo clippy --offline --locked -p im --lib
```

The warning suppression is only for legacy upstream `has_specialisation`,
`threadsafe`, and `pool` cfg declarations, not a production source change.
Tests cover:

- Empty nodes/maps, invalid child counts, 128-node success / 129-node `Depth`.
- More than 10,000 keys across multiple tree levels, every exact numeric key
  and absent gap, and differential equality with `range(query..).next()`.
- Explicit upstream child-exhaustion reproductions, exact parent separators,
  and parent-key-plus-NUL successors.
- Ordinary writer removals, rebalance/merge/root collapse and shared snapshots.
- Empty/Unicode/NUL/prefix keys and 4096-byte keys/4097-byte strict queries.
- Every valid inclusive/exclusive/unbounded range combination over the boundary
  matrix, comparing complete pre-reserved forward scans with ordinary ranges.
- Zero allocation/reallocation and key/value clones around every bounded lookup
  and every complete forward loop; borrowed entry pointer identity.
- Feature-off upstream API compilation without the extension.

### Observed results (October 3, 2026)

- Isolated unit tests: **7 passed**.
- Debug and optimized executable probes both passed: **20,002** numeric queries,
  **302** child-exhaustion reproducers (plus each separator's exact/NUL queries),
  **593** complete forward ranges before removals and **593** after removals.
  All measured allocation/reallocation and key/value-clone counters were zero.
- Feature-off executable passed. Isolated `cargo clippy --all-targets` and direct
  `cargo clippy -p im --lib` completed successfully. The direct vendor check
  confirmed `flower-bounded-reads` was enabled and reported **zero new-module
  diagnostics**. Existing warnings are confined to preserved upstream source
  and its test-only inclusion/re-export. No ordinary cleanup was performed.
- `cargo fmt -- --check --config skip_children=true` for the harness and direct
  `rustfmt --check` for both new extension modules passed. Child skipping keeps
  the untouched upstream modules byte-identical instead of reformatting them.
- All six registry dependencies in the harness lockfile match versions and
  checksums already present in Flower's root lockfile. All 38 original files
  were re-audited; only the four documented additive extension sites differ.
- The full upstream dev-dependency suite and Flower/Ultimator end-to-end checks
  were not run by this delegated vendor-only change; integration owns those.

These checks establish only this vendor traversal's properties. They do **not**
close Flower's total native-stack admission, controller/deadline, redb resident
cursor, serializer/output, snapshot-retention, or end-to-end SQL safety gates.
Those remain the integrating session's separate work. No overall gate-PASS
claim is made by this extension.

`src/hash/map.rs` retains upstream CRLF bytes. A directory-local `.gitattributes`
preserves those exact bytes and recognizes carriage-return line endings during
whitespace checks; no ordinary source body is normalized or reformatted.
