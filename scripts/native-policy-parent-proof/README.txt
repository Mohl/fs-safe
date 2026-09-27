NATIVE POLICY-PARENT OWNER — PREPARATION PACKET

A = 305ff575ce134bb596c0eb4bc9205fac8575a884
B = 0aa0fa5ee942d117abfda15b1b93aa6cf732310e
Both package versions are 0.21.1. Parent owns dispatch and final acceptance.
No local pnpm, product execution, benchmark, network, or lease work is performed
by packet preparation. Inventories and local preparation receipts are not carrier
files. Publish only this README, protocol.json, qualification.json, pins.json,
packet-manifest.json, and the exact harness files listed in that manifest.

Parent-owned common GHA carrier setup

Use existing Node 24.21.0, pnpm 12.4.2, Rust and archive LLVM setup. Linux is
ubuntu-latest. The Windows matrix label windows-latest uses the existing
fs-safe-windows-16core runner and verify-windows-ci-runner action. Pair A/B on
one host per platform; never compare absolute times across the two hosts.

Create separate clean A and B worktrees. Verify public commit/tree pins and
native/Cargo/lock/build-tool equality. Build JavaScript independently. Build
native once from A per host, record its hash, copy those exact bytes to B, and
run existing stage-host-native.mjs there. Never share candidate dist bytes.
Run focused common safety tests in both arms and new owner regressions in B.
Run pnpm package:smoke --output PACKAGE_DIR with FS_SAFE_EXPECTED_SOURCE_COMMIT
for each arm. Install that manifest's real root and host-native tarballs into
separate neutral consumers using the repository isolatedConsumerEnv helper and
npm install --offline --ignore-scripts --omit=optional --no-audit --no-fund.

Interfaces (all source/build/install commands above are remote and parent-owned)

  node harness/bind-consumer.mjs SOURCE CONSUMER PACKAGE_DIR A|B

PACKAGE_DIR contains package:smoke manifest.json and its .tgz files. Binder
checks clean source/version/tarball integrity, writes CONSUMER/expected.json,
and verifies installed dist/native bytes and lockfile integrity. Preserve the
expected.json and lockfile in evidence. All execution inputs are runner paths.

  node harness/qualify.mjs CONSUMER PRIVATE_BASE OUTPUT.json
  node harness/benchmark-leg.mjs CONSUMER PRIVATE_BASE LEG_INDEX OUTPUT.json

PRIVATE_BASE is an existing dedicated task temporary directory. Fresh child
fixtures live below it. Each leg uses the zero-based schedule index 0..31.
Use role A/B selected by protocol.timing.schedule. Do not alternate platforms
inside a host. Qualifier expects 38 Linux / 34 Windows checks per arm: all timing
shapes, four partial-parent and four all-missing controls, twelve policy/mkdir/
authority refusals, and two create collisions. It preserves unexpected fixtures.

Run qualifier (180s) and each leg (180s) through the corresponding step owner:

  python harness/step-owner.py PROCESS_DIR LABEL CAP NODE ARGUMENTS...
  python harness/windows-step-owner.py PROCESS_DIR LABEL CAP NODE ARGUMENTS...

Use an absolute native Node executable on Windows. The Windows owner atomically
assigns a kill-on-close Job Object during suspended process creation, restricts
inherited handles, resumes only after membership checks, and joins the root plus
all job processes. Linux keeps the reviewed group owner unchanged. Missing or
failed settlement invalidates evidence; stop before another leg or publication.
Windows source reviews are clean; actual runtime qualification remains required.

Write legs as LEG_DIRECTORY/leg-01.json ... leg-32.json. Each report is atomic,
cumulative, and incomplete until every row, owned cleanup, and installed-byte
verification succeeds. The timer covers the complete public method promise;
caller setup/reset/verification and reports are outside it. Missing timing
parents mean first of eight exists, remaining seven are absent. Ordinary and
raw-dot routes use the same existing unrelated deny directory. Complete Windows
parents precede native session creation and therefore have only one route row.

  python harness/assess.py linux|win32 LEG_DIRECTORY OUTPUT.json

Assessor cap: 120s. It checks exact schedule, row order, descriptors, all raw
5x10 samples, means, cleanup, source pins, and common native bytes. It evaluates
8 complete quartets, including separate ABBA/BAAB strata, and 100000 deterministic
whole-quartet bootstrap resamples (seed 734). Exit 0 means complete valid input,
including a hold/inconclusive result. Parent combines the performance outcome
with safety/package/provenance/process/fixture gates. Only both platforms passing
all cells under 1.05 is overall pass. No timeout-based retry, sample omission,
result-based protocol adjustment, or pooling with prior partial/held studies.

The parent-owned orchestrator should record environment/tool hashes and idle
state, run phases serially, verify immutable source/dist/native inputs again at
end, and finalize an evidence-only archive after settlement checks. The job and
step caps are declared in protocol.json. Keep build fixtures, node_modules,
Cargo targets and unverified archives out of published evidence.
