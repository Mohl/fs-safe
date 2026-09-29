# Isolated macOS qualification carrier

This task branch replaces the registered benchmark workflow with a dispatch-only
carrier for PR #770. It is not a proposed replacement for the default branch's
benchmark automation. Dispatch exactly the independently reviewed carrier commit
and supply that same commit as `expected_harness_sha` after recording the complete
carrier hashes. Attempts other than the first are rejected.

The [protocol](PROTOCOL.md) defines the prospective hypothesis, environmental
admission, baseline-only diagnostic, conditional source comparison, and limits.
Both sources are freshly built with disjoint Cargo targets on macOS 15 arm64,
Node 24.21.0, Rust 1.98.1, and pnpm 12.4.2. Rust tests, native-required integration
tests, real host package smoke, and the frozen installed-package probe must pass
before the fixed quiet interval. The integration suite has one declared
Windows-only skip; the eight installed probe cases and all four timing endpoints
must execute with no skips and the actual loaded native addon.

`prepare.py` pins the reviewed workflow, source bytes and executable modes,
runtime, package tarballs, built and installed addons, and consumer files. The
consumers install their exact native tarball through both a direct dependency
and pnpm's workspace override. `experiment.py` runs 24 baseline-only processes;
only all four original 5% equivalence gates admit the separate frozen 48-process
campaign. Its original `measure.mjs`, `campaign.py`, and `PROTOCOL.md` bytes live
in `frozen/`. Calibration results are never pooled into that campaign.

Every command retains its invocation, stdout, and stderr; observed returns,
failures, and timeouts have terminal receipts.
`stage2.py` observes the frozen driver's original `subprocess.run` calls and
forwards their arguments unchanged. Each Node receipt records the driver's group
and the group the child inherits by default, and links to the outer campaign's
terminal receipt, which owns group cleanup. The adapter does not observe child
PIDs or independently prove per-child group absence. Fixed receipt writes add
orchestration I/O outside each Node process and are part of this reviewed carrier.
Forced outer termination may leave a partial child receipt; it remains evidence
of an incomplete run, with group cleanup owned by the outer carrier.
This adds evidence around each call without changing the frozen
driver, Node invocation, environment, process flags, schedule, or analysis.
The artifact includes source archives, exact packages, installed
consumer archives, native binaries, raw timing reports, complete schedules,
admission telemetry, analyses, failure records, and a final SHA-256 manifest.
Source/build/runtime setup steps also retain their ordinary Actions logs.
Failure stops the procedure. There are no sample exclusions, threshold changes,
fallback runners, or automatic retries.

The job has a 120-minute ceiling, with preparation capped at 45 minutes, the
measurement step capped at 60 minutes, and the complete stage-two subprocess
capped at 2,700 seconds. Each measurement process
retains the original 600-second deadline. An overall deadline makes the study
incomplete, triggers process-group cleanup, and preserves its evidence; it never
permits truncation to a passing subset or another attempt. These bounds leave
room for final collection instead of relying on job cancellation.

Inside that step, a fixed 3,300-second resource budget reserves each command's
full existing timeout plus ten seconds for cleanup before launch. The fixed
quiet interval also needs room for its following telemetry command. Stage two
must fit both before its admission begins and again before its driver launches;
a slow admission can therefore stop it. Budget failure preserves an incomplete
study and never shortens a child deadline or selects a smaller sample set.

Consumers are archived before the installed probe, then checked for changes.
The always-run collector also archives each consumer's final tree, including
partial installations and failed probes, separately from the admitted snapshot.

The previous shared-runner macOS result remains inconclusive. A passing result
here applies only to these rebuilt artifacts, four workloads, and the admitted
macOS 15 arm64 environment; it neither explains the earlier variability nor
qualifies PR #769 or another platform.

Static qualification of the carrier uses `python3 -I selftest.py`, Python AST
parsing, JavaScript syntax checks, and workflow review. The self-test creates
synthetic records only and never executes library code or a timing workload.
