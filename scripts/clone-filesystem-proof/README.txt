CLONE FILESYSTEM ADMISSION — PREPARATION ONLY

Source: PR #732, A 0187ca58aba3feddbd15d79a85f441dd30689d22;
B 1538b2dd47644a592542d5f4ac025614ba8a1ec1.
Only native/src/clone_unix.rs and CHANGELOG.md differ. No LOC tuning.

Execution is not authorized. pins.json ready remains false. The parent owns
runtime approval, the fresh Crabbox blacksmith-testbox lease, transport, and
provider stop plus exact Testbox/Actions terminal verification. Never reuse an
old lease. Node 24.21.0/pnpm 12.4.2 and the existing fs-safe-testbox environment
wrapper are required. Record actual available CPUs, without assuming label size.

After explicit authorization, transport this complete packet separately from
the exact clean B source checkout. Create a fresh empty canonical Linux WORK
matching /tmp/fs-safe-clone-admission-*. Through the established environment
wrapper, execute:
  python3 PACKET/harness/clone-supervise.py WORK TRANSPORT
The only permitted post-audit packet mutation is pins.ready false -> true.
Source pins, protocol, harness, and packet-manifest.json must stay frozen.

The coordinator prepares all three mount intents first, then owns the sole 120m
workload deadline. Existing process owners bound builds, tests, traces and timing. Coordinator
prepare/cleanup use reviewed bounded.run directly; Node setup steps use the
asynchronous step-owner path. None bypasses settlement. Product groups must settle
before any cleanup. Every volume receives a separate 30s cleanup attempt even
when an earlier one fails, for at most 111s including settlement. All three mount
and loop receipts must pass before archive. Images remain outside evidence and
are never archived. Failure to prove process/mount settlement means stop the
owned lease and report the blocker; no lazy/force unmount or foreign loop detach.

A/B native addons are built independently with separate CARGO_TARGET_DIRs.
Actual root plus corresponding native tarballs are installed offline into
separate neutral consumers. Source trees, build inputs, dist and installed addon
bytes, tarball integrity, and lockfile integrity are recorded/checked.

Correctness includes real source tests (one native-loader mock excluded by
exact name), installed require/off controls, unsupported host /tmp, Btrfs plain
directory rejection, XFS no-reflink strict refusal and auto/never fallback, and
FIEMAP shared/separate storage proof. Symlink contract is literal target/type;
portable fallback does not preserve symlink timestamps. Failed unexpected
fixtures are retained; success requires expected entries before owned deletion.

Untraced owned steps prepare and clean trace fixtures, keeping sudo outside
unprivileged ptrace. 12 separately bounded strace runs prove the expected parent fstatfs reduction
A=3 -> B=2 while copy-source probes stay 1. Timing has no strace: 64 fixed ABBA/BAAB
legs, six cells, five 30-call samples plus five warmups and one checked call per
row/leg. 28,800 measured calls. Raw per-call values and sample means retained.
Btrfs identity-checked subvolume deletion is outside intervals; subvolume sync
is fixed before row qualification, after warmups, and after each sample.

assess.py reports performance only. Every paired/order/upper95 ratio must be
<=1.05; point/order failure means hold, confidence-only failure inconclusive.
No sample removal, retuning or selective rerun. final-gates.json combines timing
with correctness, trace, provenance, process and mount receipts. Provider cleanup
remains separately required. No percentage speedup claim is made in preparation.

harness/supervise.py is an unchanged reference, not the clone entrypoint.
../unused-preparation/filesystems-unselected.py is a retired alternative, excluded
from the executable manifest and all runtime ownership paths.
