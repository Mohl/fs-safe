# Linux checked component type — external proof packet

This packet qualifies the three-line Rust optimization pinned in `pins.json`. Both `pins.ready` and `protocol.ready` are **true** for final candidate `e00c407db4e602ace9f6b6040d10a72fa057a300`; each packet revision requires a clean managed P2 review before dispatch. Its additional `test/api-coverage.test.ts` delta isolates a Windows-only semantic test using the existing device-flush helper and scoped restoration; production behavior, assertions, options and timeouts are unchanged. The parent owns transport and dispatch.

The packet is transport-neutral trusted Linux code. The parent's configured Crabbox provider remains authoritative (currently AWS); no workflow or provider change is required. Do not modify or merge the prior #735 carrier. Do not copy one native binary into both arms.

## Remote contract

Provide clean, task-owned `WORKSPACE/A` and `WORKSPACE/B` at the exact committed heads/trees. Both package versions are 0.21.2, pnpm is 12.4.2, and the runtime paths must supply Node 24.21.0 and Node 22.23.2. Use a nonroot user for preparation and timing; the separate conditional Rust owner intentionally uses root in a private mount namespace. Record actual host allocation, filesystem, tool versions and provider/lease identity. No host migration or runtime change after preflight.

The host must supply pnpm, an existing Rust 1.98.1 toolchain, Python 3, a C compiler, strace, Git, tar, sudo and unshare. `bootstrap-toolchains.py --prepare-only` first installs exact official checksum-verified Node archives and privately copies the existing Rust toolchain, preserving compiler bytes while adding its verified wasm32 std component. It invokes the pinned first-party archive LLVM installer with its own RUNNER_TEMP/GITHUB_ENV. Rustup is not required. The AWS hydration workflow alone does not prepare these tools. No credentials belong in this packet or its proof environment.

Verify the declared pnpm version outside a source checkout too: Corepack's host default supplies the preparation version probe. After the conditional root owner completes and settles its resources, its generated receipts must be readable by the nonroot preparation owner. Ownership correction must preserve their contents, identities and modes and retain a separate receipt.

Toolchain preparation uses the explicit prepare-only switch and a clean exact A or B checkout; it does not require measurement readiness:

```sh
python3 packet/bootstrap-toolchains.py --prepare-only SOURCE UNUSED_BOOTSTRAP_DIR
```

This runs first-party tool installation/version probes only; no product build or tests. The completed `bootstrap1` remains reusable because its recorded source is unchanged baseline A, its environment hash matches, and its children settled. Its historical prior-B pin records tool-preparation context, not a candidate build. Preparation receipts and environment remain required by the source/package runner. Both readiness fields are now enabled and `packet-manifest.json` has been regenerated. Any subsequent file change invalidates the frozen packet. The parent runs these entrypoints in order, using an unused work directory:

```sh
python3 packet/run-prepare.py WORKSPACE WORK BOOTSTRAP_DIR
sudo -n unshare --mount --propagation private -- python3 packet/run-conditional-native.py WORKSPACE WORK
python3 packet/run-study.py WORKSPACE WORK
python3 packet/collect.py WORK
```

Do not put the conditional root owner under an outer timeout/process-group killer. It directly uses the unchanged bounded process helper, joins every child, and unmounts only its exact privately owned mount. Signals trigger settlement; an unresolved mount or missing receipt blocks collection. The existing `bounded.py`, `settlement_control.py` and `step-owner.py` are byte-identical to the proven #735 versions. No replacement supervisor framework was introduced.

Preparation separately builds A and B native addons and package tarballs. It retains source, toolchain, Cargo test-executable, root/native integrity, distribution, installed lock and loaded-binary evidence. JS/WASM/declaration distributions must be identical; the native binaries must be distinct and each match their own arm throughout. Focused source tests execute on normal and forced-fallback routes with no selected skips; real ENOSYS/EPERM source fixtures run separately. Full checks and package smoke use ordinary mode, because bounded cleanup success tests deliberately require openat2.

The conditional helper reuses verified compiled Rust test binaries. Its six checks are A/B × nonroot search-permission body, root foreign-owner sticky-link body, and owned nosymfollow-mount body. It records exact credentials, namespace, mount flags and test identity. `fs.protected_symlinks` must already be 1; the helper does not change host policy. Missing privilege, namespace or mount capability is incomplete qualification, never a substituted pass. `run-study.py` requires all six bodies and resource settlement. Diagnostic collection may retain a failed conditional result only when its resource/child settlement is fully proven; that archive does not claim qualification success.

## Fixed scope

- 12 installed behavior processes: A/B × Node 22/24 × real openat2/ENOSYS/EPERM. Each runs the declared 16 public behavior cases through normal package exports and the default native loader.
- 32 selected installed public syscall calls: A/B × Node 22/24 × the eight rows in protocol.json. Metadata removals must be exactly the immediate duplicate component fstats, with all later descriptor/path/link/security/publication/close observations retained.
- 64 timing leg processes: 32 ENOSYS legs with four rows; 32 real-openat2 legs with one control row. There are exactly 8,000 measured calls, 800 sample means, and 960 declared warmup/check calls. Every cell must pass the unchanged 1.05 paired, order and upper95 gates.

Mechanism selection is process-cached: every mechanism uses a fresh process. The initial real filter/probe is outside selected-call markers and timing, but retained in trace evidence. ENOSYS and EPERM selection and selected-call sequences are both proved; only ENOSYS is timed because their steady-state fallback is identical after admission. Latency conclusions cover Linux x64 glibc Node 24; Node 22 receives behavior and syscall proof only.

Trace output is privately owned and bounded to 32 MiB. The trace launcher holds an exclusive no-follow output descriptor and invokes strace in the same existing bounded group, using that descriptor through procfs. It records exact runtime/argv, compiled denial wrapper and first-party source hashes in an adjacent launch receipt. Raw exec environments remain abbreviated. No traced durations are used as timing evidence.

The comparator records volatile structured eventfd counters while requiring stable descriptor identity and semaphore mode. Outside the selected call, it classifies only complete main-thread procfs census reads of known anonymous resources and the exact previously closed enumeration handle; observed anonymous occupancy still blocks unclosed descriptor reuse. Component flags may include rustix's `O_LARGEFILE`, which remains literal in A/B comparison. Only the exact invocation-bound common fixture parent receives a separate normalization token; unrelated paths and ancestors remain literal. Selected-call identity, publication, closure and expected metadata-delta checks are unchanged.

This parser revision leaves source pins, workload scripts, process owners and timing gates unchanged. Preserve earlier failed traces and their packet manifest. A complete fresh study may reuse the exact verified builds, packages, installed consumers and conditional receipts after all prior processes settle and failed study outputs are retained without replacement. No prior timing samples may be pooled or excluded.

## Construction checks and remaining gaps

Construction checks and synthetic offline harness tests are not product tests. Offline scripts under `offline-tests/` must use synthetic data or fake public APIs only. Readiness is enabled only for the exact current source pair and unchanged workload protocol; it does not claim completed product qualification.

Unresolved until remote proof: actual source/package build success, emitted syscall spellings/order on the target libc/kernel, real native loader/ABI behavior, exact expected metadata deltas, kernel mount/credential prerequisites, runtime resource settlement, and all latency gates. A parser refusal is inconclusive evidence, not a product regression; preserve its raw trace and investigate without retuning latency gates or selectively rerunning cells. Never pool old #735 samples.
