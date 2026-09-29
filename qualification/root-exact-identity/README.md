# Root exact identity v2: remote functional qualification

Source packet only; executionReady remains false in pins.json and MANIFEST.json. No local product, package build, test, benchmark, network or lease operation was performed to prepare this packet. Parent owns transport, approved activation, actual host admission, remote dispatch and independent audit.

Copy these contents to `qualification/root-exact-identity/` in the proof checkout. All helper paths are relative to the driver's own file. The CLI is:

```text
python3 qualification/root-exact-identity/run-functional.py CLEAN_A_CHECKOUT CLEAN_B_CHECKOUT NEW_OUTPUT_DIRECTORY
```

The output must be a new real directory outside both source checkouts. Run as the unprivileged proof owner on Linux x64 glibc with 16 available CPUs. Parent must bind a fresh AWS lease/instance, public networking with no Tailscale or instance role, and verified terminal/process ownership before dispatch. The pinned bootstrap expects the existing Rust 1.98.1 toolchain at the standard Crabbox location; it copies it privately, verifies Node 22.23.2/24.21.0 and WASM toolchains, and records first-party LLVM setup. Failure is evidence, not permission to substitute an unreviewed bootstrap or runner.

## Source pins and build ownership

A is ae83cc9a851f325a7e047baf4b8cc6402c613bb3, tree 2090874a4b407ed90a28175f2eb7c2297f2f69a9. B is 3488b411206b8031db5a122ec25fe1d6e3630a9e, tree fbd58c12c921a0d4248d76bf108b4e2127220e46. Four production files and the new regression test are hash-bound. Public source/package checkouts must begin and finish clean.

All 73 native/Cargo/dependency-lock/build/staging/host-package inputs match exactly between A and B and are hash-checked again remotely. One fresh `pnpm native:build` runs at A. Its exact binary is staged into B's two ignored native output paths and packaged once as the host addon. All four consumer installations receive that same explicitly requested addon tarball, while A and B root packages are built and packed independently. This isolates the TypeScript change and avoids assuming independent native builds are byte-reproducible. Required-mode installed calls must load this exact binary and dispatch actual observeDirectory calls. Off mode uses the same installation layout but must make no addon-load attempt. The recorder appends every attempt before validation or forwarding can throw, and tracks successful loads separately; swallowed failed loads cannot appear as native-off success.

The source commands are the declared pnpm version, `pnpm install --frozen-lockfile`, `pnpm native:build`, one candidate `pnpm check`, and bounded focused `pnpm test` commands. The full candidate check runs once with serial test scheduling; a failure stops the driver with retained logs. It is not automatically rerun. Explicit `pnpm build` before packing creates clean dist output and reuses the candidate WASM build cache. Packing/install use the existing repository's isolated npm environment and exact local tarballs with lifecycle scripts disabled; nothing is published.

## Focused source proof

Four unchanged suites run in both source arms with native mode off: root-context-identity, root-context-owner, root-stat-list-observation and root-walk-include. Both reports must contain the same nonempty case-name set with every case passed and no skips or retries. Candidate `pnpm check` supplies the broader source coverage; GitHub CI owns the other operating systems.

The new `test/root-exact-identity.test.ts` is copied only into a separate baseline test worktree. A's package source is never changed. Its exact source-confirmed contrast is 12 cases: A must fail the eight invalid retained-state cases and the numeric-device short-circuit case, and pass the two getter-ownership cases plus the high-bit identity case. B must pass all 12. Only this exact A regression command is permitted to exit 1; all other child exits must be 0. Case names/statuses and raw failure messages are retained for independent inspection. The overlay is hash-checked and removed before packaging.

## Installed public behavior and package contract

Four independent consumers B0/B1/C0/C1 retain root/addon tarball SHA256 and SHA512 integrity, exact npm locks, full compiled inventory, native binary hash and source identity. B0 and C0 run nine scenarios under Node 22 and 24 with modes off and require (eight fresh processes). Scenarios cover construction/resolve, ordinary stat, names and typed list, complete skip/include walks, the published initial-stat hook, an admitted in-root alias, root replacement refusal, and parent redirection refusal. Outside/original/replacement sentinels, hook restoration and descriptor census are checked. The forwarding dlopen/observeDirectory recorder invokes the actual installed binding; it never supplies a fake native result. A public stat preflight warms one-time loader state before per-case FD census and records real native availability.

Package exports, every exported entrypoint declaration, the repository's actual public API snapshot and a separately executed strict installed TypeScript consumer must remain equal between A and B. Exactly three internal `.d.ts` files are expected to change: root-context, root-observed-path and root-walk. The full dist difference set must be exactly the four intended JavaScript modules plus those three declarations; unexpected artifacts refuse qualification with the complete inventory difference retained. Their full A/B text and diffs are retained. They are not automatically approved merely because their filenames match. No full internal-declarations-equal gate is inherited from previous studies.

The driver ends with `readiness-candidate.json`, `launch:false`, and an explicit pending independent audit/declaration-inspection disposition. Parent must inspect the three emitted diffs and the expected baseline failures before accepting functional qualification or constructing an enabled performance binding. No performance command is invoked here, and previous verdicts or measurement data are not inputs.

## Evidence and settlement

Every child has immutable request, stdout/stderr and exit/cleanup receipts under evidence/processes; the unchanged bounded/settlement helpers own termination and joining. Bootstrap retains its own nested process receipts. The final functional receipt contains source contrast, native build/input provenance, eight installed reports, complete public declaration evidence, package inventories and final source/runtime checks. Preserve the entire new output tree and outer provider/terminal receipt, including partial failure evidence. No retries or timing retuning occur automatically.

Before remote dispatch, parent must review this packet, bind its proof commit, preserve the frozen false manifests and create a recorded activation copy with matching pins/manifest digests. Required later pins are the fresh provider/lease/instance/transport, absolute A/B/output paths and the outer command identity. Candidate A/B pins and test expectations are already frozen. Performance has its own source-only protocol and pending harness/runtime/consumer/audit bindings.
