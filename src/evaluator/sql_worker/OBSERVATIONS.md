# Local native HOST worker observations — October 4, 2026

**Whole-native HOST/source/controller/physical/serving gate: HOLD.**

## Exact local platform / libc audit

- Linux x86-64, kernel6.18.45, native page4096.
- Rust1.99.0 `b940084d7eb6a299eb4bfeb8e34901bc051e7ac4`.
- `libc6:amd64 2.41-12+deb13u4`; GNU libc2.41.
- Actual `/usr/lib/x86_64-linux-gnu/libc.so.6` SHA256
  `9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92`;
  ELF build ID `5e5b51f4c39af9ac589408c1dc432ba390a273cc`.
- Actual `/lib64/ld-linux-x86-64.so.2` SHA256
  `c8438e4fde1934e61c88311633f00949ff645d5c04cdb8671fa3d78164d2f307`.
- Harness Rust bindings exactlylibc0.2.189. Optional actual native allocator
  mimalloc0.1.52/libmimalloc-sys0.1.49, matching the current Flower lock graph.

These identify this sandbox, **not** the production Flower libc/kernel/ELF.
The diagnostic ELF is not the Flower serving constructor or its module graph.
No rlimits/capabilities were raised or production hosts accessed.

Audited the exact Debian source package corresponding to the installed package,
not merely a generic pthread manual. Source location (inside code, not a serving
runtime lookup):

```
https://sources.debian.org/data/main/g/glibc/2.41-12%2Bdeb13u4/
```

| Source file | Exact package-source SHA256 | Relevant schema |
|---|---|---|
| nptl/allocatestack.c | 69da1112339ca5f95f776563ea4fef0fb3adc0d2ffee6b9c9beb51572e9c0438 | custom stack lays pthread descriptor/static TLS inside supplied extent; line307 still invokes `_dl_allocate_tls` |
| nptl/pthread_getattr_np.c | 866c28b5f3252624b290633e2ee2f256f201b06586708f4f6cd21ff69a638b4c | line180 reallocates affinity scratch; line194 creates owned attr affinity state |
| nptl/pthread_attr_setaffinity.c | 991d85a551a43456b30838452db6ca939c7a5dcad69dddaa61fb2616a0fd9529 | copies/reallocates attribute-owned CPU bitmap |
| nptl/pthread_attr_extension.c | 311e41f0b0ec8cdbe9c6b233ed828b9df0b4ab3d49d8c94c88cf6a958943e37e | line28 calloc allocates the current attribute extension |
| nptl/pthread_attr_destroy.c | 303f6511c142cde691669ab23829136157dd567e7da5cd89b958f74f000a78d7 | lines38/39 free attribute-owned bitmap and extension |
| elf/dl-tls.c | 1abef25001cfb7243e8c24f36535bfcd6696e291a91293a65bdb7f59ad3ad598 | lines461/462 derive DTV from current max module ID + DTV surplus and calloc; later resizing/dynamic TLS can allocate |
| sysdeps/x86_64/nptl/tls.h | 504babb5c8a64d3f5e13102a0575b861a4c35ce2897ce1d7614f1cddd04fbe81 | line110 TLS_TCB_SIZE is current `sizeof(struct pthread)`, not zero/native-free |
| sysdeps/nptl/pthreadP.h | f17281ac8d1563fda9abc8314c046e45957a27f7b0a068cfb49dd52478d4ff75 | current internal pthread declarations; not public ABI to guess headers from |

Cold standalone source-free ELF and serial test-window interposition both
observed startup request sizes **[304,32,152,32]**, two calloc + two realloc,
**520 gross requested bytes**, plus3 free calls. These are consistent with DTV,
affinity scratch and current attr extension/bitmap schema. They do **not** prove
simultaneous live allocation, allocator usable size/backing/retained arenas,
static TLS/TCB usable-stack subtraction, global loader/module history, native
signal machinery, kernel task/VMA/page tables or physical/cgroup safety.

The fixed diagnostic interposer uses current glibc `__libc_*` functions and
bounded atomic counters/16 request samples. Hidden/internal loader calls,
direct syscalls and native mimalloc paths may bypass ELF interposition. Free
counts include null frees; they are not an ownership-release/backing proof.
The counters do not establish an upper bound, and must never become a520-byte
production admission margin or a claim of0TLS. No production profile verifier
or positive NativeOwner implementation is installed.

## Concrete mapped extents

The standalone lab lease/task are zero-sized **fixture types**, not a real
node/job/source owner. Final fixture control Layout=160B/align8; actual caller
handle Layout=104B. With caller-selected2,097,152-byte stack and native4096-byte
pages, actual maps are2,105,344-byte stack+two guards and4,096-byte control, total
**2,109,440 bytes**. Real parent lease/task/scratch layouts can be larger and must
be queried. The whole-control mapping is pre-touched before native creation.
Actual pthread self attributes match the owned RW extent; libc guardsize0 is
expected for custom stacks and does not replace the two actual PROT_NONE guards.

## Native evidence and interpretation

Final suite: **24 tests** =22 worker tests (including3 child-entry helpers) +2
unchanged actual JobControl units. The isolated build directly compiles actual
`sql_control.rs`; only the exact current SqlError enum is extracted at build time
from `sqlite/mod.rs`, without inventing Consensus/Store/source machinery.

- Native pthread base/length/custom guardsize/local-stack address match before
  Ready; actual `/proc/self/maps` RW and both PROT_NONE permissions checked.
- Page rounding, actual task/lease/handle Layout, alignment, minimum and overflow
  refusal; actual impossible native mmap refusal; no new capacity on refusal.
- Unsafe dummy owner enforces ONE slot shared by two factories and holds the
  lease through callback/TLS destructor/native join/actual mapping-ID munmaps.
  It is deliberately not a production backing/job/node proof.
- Dummy `SourceOwned` is constructed after the post-Ready permit only; typed
  epoch/drop lifetime, original admitted/deadline/cancellation Arc identity and
  replacement/refusal tested. This is **not** actual source GC/root retention.
- Cancel while native callback is blocked, requester-drop while blocked,
  callback panic cleanup and blocked real Rust native TLS destructor preserve
  capacity; release follows actual pthread_join and both successful munmaps.
- Native lifetime observer matches original mapping IDs/base/length. A separate
  isolated reuse child successfully MAP_FIXED_NOREPLACE-remaps released addresses;
  later address reuse does not substitute for original-owner munmap proof.
- Two disposable children actually SIGSEGV: direct owned-guard write and growing
  recursive native stack. The parent test process survives. These are fault
  enforcement tests, not code/cert/JSON/capture sufficiency tests. Only these
  disposable fault children set their own dumpability0 before faults, to avoid
  leaving process/TLS/environment core images; no host/serving limits change.
- Six isolated **injected-error** children exercise create EAGAIN, stack-attribute
  mismatch, join EINVAL, munmap EBUSY, mprotect EACCES, and partial-map mprotect+
  munmap uncertainty. Join/unmap-uncertain cases retain/leak the actual strong
  fixture lease and slot; successful partial cleanup returns it only after every
  original mapping is released. Injections are not actual physical OOM proofs.
- Serial ELF interposition observes nonzero native startup allocations. The
  source-free NoSource post-Ready callback/enrollment/join path observes0 public
  C allocation requests; frees21(System)/20(mimalloc). This is not an all-source,
  all-Rust/mimalloc, backing or async-runtime0allocation certificate.

`harness/run-native.sh` runs debug+release real-pthread/child-fault/interposition
suites with System and pinned mimalloc, uninstrumented2-thread regressions,
strict offline all-target Clippy (`-D warnings`, jobs2), and fmt-check. Optional
interposer cases return without executing when preload is absent; all six native
fault injections and allocation diagnostics really execute in the serial
preloaded runs. Three child-entry helpers similarly do nothing in their parent
suite invocation; their subprocess cases are separately exercised. Do not
inflate the test count by counting duplicate diagnostic-binary tests.

No whole Flower/SDK/npm/Nix/HTTP/server activation checks were run for this
unimported new-only component. The parent must run coherent integration tests.
Actual current source/capture code, depth128 code/cert/JSON, SourceScratch,
Tokio fences/abort, original whole10s, HostCtxSourceRoots/native physical and
production resource installation remain HOLD, regardless of harness success.

## Partial-construction lifetime correction — October 4, 2026

The published pre-correction constructor could drop its admitted lease before
the still-local original JobControl/factory cancellation owners on pre-State
refusals. A deterministic real-mapping lease-destructor regression failed on
exact prior production source (strong count2 rather than external-owner-only1).
Every pre-State refusal now explicitly ends those owners before cleanup can
return job/node credit. The regression covers native first-map refusal,
cancellation after stack mapping, and cancellation after control mapping.

The immutable `reports/run-worker-partial-v1.sh` repeat completed all **25**
current tests under System and pinned mimalloc, serial native interposition,
two-thread regressions and optimized release, with strict Clippy/fmt and
unchanged runtime/test/input hashes. The prior24-test evidence is historical.
Normal join/TLS/unmap uncertainty continues to retain rather than mint credit.
No production NativeOwner/SourceTask, TLS/allocator/kernel/backing/deep-callgraph
profile or serving readiness is implied by this component repair.
