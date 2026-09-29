# One-shot isolated macOS suitability and PR770 qualification

Status: source-only, not executed. Freeze the complete workflow, drivers, this protocol, source refs, runtime/toolchain versions, and schedules after independent review and before dispatch. One GitHub-hosted `macos-15` job only; no automatic retry, alternate runner, optional extra pair, sample removal, or limit change. Failure stops this procedure and preserves all evidence. Original SF campaigns remain visible and inconclusive.

## Hypothesis and fixed environment

H: on this isolated runner after a fixed CPU/load admission, fresh processes using the identical baseline artifact satisfy the original 5% A/A equivalence limits for every declared endpoint. This tests suitability for the following source comparison, not the historical cause of SF variability.

Assert `uname -m = arm64` and actual macOS major version 15 before building or loading. Record the GitHub run/job identity, image version, OS build, CPU model/count, filesystem, fixture volume, free space, Node executable version/hash, and actual architecture. A mismatching image or architecture stops the run; do not change labels and retry. Pin Node 24.21.0, Rust 1.98.1, and pnpm 12.4.2.

Build A from `e85a5ec94704eed140d68affa72ec12174ca788c` and B from `66b80a1e94eedc3ef822590e67f2227fd8d1faf1`, using identical release settings and disjoint Cargo targets. These are fresh same-source builds, **not the SF binary bytes**. Complete both builds, package installation into isolated consumers, and necessary native functional/capability proof before environmental admission. Retain Git tree/source manifests, build and package receipts, package/runtime/native hashes, and actual loader/shared-image witnesses. Every timed call uses require mode and must exercise the admitted native primitive; no unsupported endpoint skip is permitted on macOS.

Pin these newly built artifacts once. Stage one, every control pseudo-role, and stage-two A all reuse the exact same A consumer and bytes. Stage-two B reuses the exact B admitted before calibration. No build, install, source change, functional test, or artifact replacement occurs between calibration and qualification. Both consumers and their loaded binaries remain hash-pinned across the full job.

## Bounded CPU/load admission before each stage

All task-owned build and functional handles must be terminal; no parallel task work runs in this job. Record a process-name/CPU snapshot without environment values or full command arguments. Ordinary runner/system services remain observable and are not stopped.

Use a fixed 60-second quiet interval, then collect exactly six consecutive five-second OS intervals. For example, `/usr/sbin/iostat -w 5 -c 7` supplies one initial since-boot row, retained but excluded from the six interval checks, followed by six actual intervals. Retain raw output and parsed CPU utilization, disk I/O rates, and 1/5/15-minute load averages. Pin and review the parser; an absent or unparseable field fails admission.

Every one of the six intervals must have CPU idle **at least 75%** and one-minute load average divided by recorded logical CPU count **at most 0.50**. These are prospectively fixed CPU/load criteria, not a claim of complete host idleness. Disk I/O is retained as descriptive telemetry, not retrospectively used to reject particular timing observations. The subsequent A/A equivalence gate independently tests whether residual scheduling/filesystem/runtime variability prevents the intended precision.

There is no wait-until-good loop. Any interval failure ends the procedure before that stage; retain all admission evidence. Run this same one-shot admission once before stage one and, only after stage one passes, once before stage two. Do not conditionally lengthen either quiet interval. During measurement, lightweight fixed-interval OS telemetry may run only if its exact command/cadence is frozen and identical for both stages; otherwise keep telemetry at the declared boundaries.

## Stage one: baseline-only calibration

Exactly 12 pseudo-A/pseudo-B pairs, **24 fresh serial Node processes**, all using A. Pseudo-role order is BA for odd pairs and AB for even pairs, six of each. Freeze a separate output directory and the entire schedule before the first launch. Pseudo-role labels cannot affect consumer paths, binaries, arguments other than report names, environment, fixture construction, or endpoint ordering.

Use the unchanged PR770 `measure.mjs`, SHA256 `8963c048806c5c3b0aa4b8c5e2ccaef207776941b335dbb01f3198e6c027c0ba`. Each process runs the original four endpoints in the original order: remove file, remove empty directory, move over an existing destination, remove the seven-entry tree. Preserve payloads, checks, native-capability admission, all five warmups per endpoint, and eight groups of 50 measured calls per endpoint. Preserve all raw group means and verification counts. Time only the complete awaited public operation as before. No new product instrumentation, forced GC, reordered methods, fixture changes, or additional warmups are allowed.

For each endpoint, compute one arithmetic mean per process from its eight group means. For pair i, `d_i = log(mean_pseudoB / mean_pseudoA)`. With n=12, compute `m ± 1.795884818703669 * sd(d)/sqrt(12)` and exponentiate. Every endpoint's central 90% interval must lie wholly in **[1/1.05, 1.05]**, exactly the original pair of one-sided 95% equivalence tests. Use all twelve pairs equally. If any endpoint fails, any process fails, or any record is missing, stop: no stage-two launch.

## Stage two: independent source/control qualification

Only after all calibration gates pass, perform the fixed second CPU/load admission. If that also passes, execute exactly the unchanged original PR770 48-process schedule: 12 source A/B pairs, each followed by one A/A control pair. Source order AB on odd pairs and BA on even pairs; control pseudo-role order BA on odd pairs and AB on even pairs. All are fresh processes and fresh fixtures. Calibration processes are not pooled into qualification, substituted for controls, or included in its confidence bounds.

Use unchanged measurement source, counts, endpoint order, verification, and original inference. Each source endpoint's one-sided 95% upper geometric ratio must be **≤1.05**. Each stage-two A/A control endpoint's central 90% interval must be wholly inside **[1/1.05, 1.05]**. All four source and all four control gates must pass. A failed control means inconclusive, even if every source endpoint passes. Passing controls plus a source lower one-sided 95% ratio above 1.05 flags that endpoint as a material regression under the original exploratory interpretation. Other failures to clear remain inconclusive.

The existing qualification driver may be used unchanged, SHA256 `ee73d7c1b21fdf5f3d391feea3a3d187fbe82a7a4405019ce0f3b93787787b16`, alongside its original frozen packet `PROTOCOL.md`. The outer conditional controller and baseline-only schedule/analyzer need their own pre-dispatch hashes and independent source review. Never overwrite or silently modify the original packet protocol to make its hashes agree.

## Terminal outcomes and retained proof

Keep the original 600-second child deadline; any timeout/nonzero result stops its stage with no retry. Confirm task-owned children are gone before reporting or releasing the runner. Keep stdout, stderr, invocation, loaded artifact witnesses, state/OS admissions, complete schedules, raw group means, all checks and bounds, and failure/cleanup records. Hash the final collected evidence. No observed timing, admitted endpoint, or failed process is removed from the record.

- Admission or calibration failure: this proposed environment was not qualified; stage two does not run.
- Stage-two control failure or source non-clearance: preserve the original verdict rules and stop; no further candidate campaign is authorized by this procedure.
- All stage-two source and control gates pass: report performance preservation only for these rebuilt artifacts and workloads on this admitted macOS 15 arm64 environment. Report calibration separately and retain the original SF inconclusive result beside it.

No outcome establishes that external noise caused the earlier SF campaigns. No outcome clears PR769, grants general macOS/version/architecture equivalence, substitutes for Windows/Linux functional or performance requirements, or waives ordinary PR review, CI, security, and landing gates.
