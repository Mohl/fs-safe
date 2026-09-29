# Prospective PR770 larger-VM and private-path suitability trial

Status: source-only preregistration; not dispatched. This is a distinct, single prospective trial for integrated sources, using a documented five-CPU managed VM and a fixed task-private `.noindex` layout. Existing SF campaigns, the three-CPU run 36633270293, and their exact results remain preserved. No original sample is reclassified or discarded. The earlier fixed protocol is not retried.

## Joint hypothesis and scope

H: the combined configuration of `macos-15-xlarge` and task-private `.noindex` preparation satisfies the **unchanged** CPU/load admission and original 5% same-artifact control equivalence for the four frozen workloads. This is an environment-suitability question. It does not isolate a CPU-size effect from an indexing effect, prove that `.noindex` prevented indexing, attribute the earlier saturation, or assert dedicated physical hardware.

One GitHub Actions job selects exactly `runs-on: macos-15-xlarge`. Assert actual macOS major version 15, arm64, and exactly five logical CPUs before any product preparation. Record the run/job/attempt, reviewed carrier commit, runner image version, OS build, actual CPU model/count, filesystem/volume/free space, tool versions, and source/artifact hashes. A mismatch, inaccessible label, billing/access rejection, or unavailable capacity ends this attempted trial; no fallback label, extra dispatch, or retry is part of it. The first run attempt only is admitted.

Pin Node 24.21.0, Rust 1.98.1, and pnpm 12.4.2. Build exact A `9543f52cc075385e149c130c32927a25e77dc4f6` and exact B `d27b43ac9373869af42548b6f296d9bd9b130936`, with identical release settings and disjoint Cargo targets. Independently review the integrated delta and carrier before dispatch. These require fresh source, build, functional, package, and loaded-addon proof; earlier e85/66 receipts do not qualify the new bytes.

## Fixed private-path treatment

At the first task-owned workflow step, create `$GITHUB_WORKSPACE/fs-safe-preobservation.noindex` before any source checkout, dependency installation, or task tool download. This is the fixed task root. Place the carrier, A/B checkouts, evidence, tooling downloads, Cargo home, Rustup home, pnpm home/store, npm cache, disjoint A/B targets, installed consumers, and synthetic temporary fixtures beneath it. Use a `tmp` child as `TMPDIR` before any Node/probe execution; the unchanged measurement's `os.tmpdir()` must resolve there.

The carrier must freeze exact subpaths and verify their resolved containment before preparation and again before each stage. Existing preinstalled OS/tools may be read outside the task root. GitHub's own checkout/action metadata, runner service files, and provider-managed logs may remain outside; record those limits. Any task-installed Node/pnpm/Rust/LLVM payload or sizable cache must resolve inside the private root. If setup actions cannot honor this layout, use reviewed pinned installation into that root before dispatch; do not change layout adaptively after an admission result. Preserve `HOME` and all provider/system services. Do not disable Spotlight globally, alter volume indexing policy, kill metadata workers, or change host configuration.

Record the directory layout and its `.noindex` spelling as the preparation treatment, not proof that every OS service honored the hint. The fixture-root placement is deliberately part of this joint treatment. Relative fixture names, payloads, methods, endpoint ordering, timing intervals, warmups, counts, verification, and statistical inference remain unchanged.

## Preparation and fixed identity

Finish both source builds, all relevant native functional checks, package smoke, and the frozen installed-consumer probe before the first fixed quiet period. Match exact tracked source bytes/modes to the pinned Git trees. Preserve source archives, build/tool/runtime receipts, tarball integrity, built and installed addon bytes/hashes, CJS-cache and OS-loaded-image witnesses, and both pre-probe and final consumer archives.

For the integrated sources, native integration must execute **25 passing macOS cases out of 28 total**, with only these three Windows-only skips:

- `fails closed for unsupported Windows recursive directories`
- `preserves a nonempty Windows directory with not-empty (force=false)`
- `preserves a nonempty Windows directory with not-empty (force=true)`

The frozen installed probe still requires eight passing cases per source and zero skips: sixteen installed cases total. All four timed macOS endpoints require the actual native capability and permit no skip or synthetic fallback. The additional declared integration skips reflect the new Windows regression tests, not weakened macOS coverage.

Pin both freshly built installations before calibration. All calibration roles, every qualification control role, and qualification A reuse the same A consumer and bytes. Qualification B reuses the pre-admitted B. No source/build/install/artifact change or further functional workload occurs between calibration and qualification. Record and verify unchanged runtime, package, addon, consumer, carrier, and frozen packet identities throughout.

## Unchanged one-shot environmental admission, twice

All task-owned preparation groups must be terminal; no task build/test work overlaps either stage. Record the process-name/CPU snapshot without secrets or full command arguments. Then perform exactly 60 seconds of quiet followed by seven `iostat -w 5 -c 7` rows: retain the initial cumulative row and use exactly the six subsequent five-second intervals.

Each actual interval must satisfy **CPU idle ≥75%** and **one-minute load/logical CPU count ≤0.50**. These are the same thresholds as the failed three-CPU trial, normalized by its actual CPU count. Retain raw and parsed CPU, disk I/O, and 1/5/15-minute load data. Disk I/O stays descriptive. Unparseable or missing data fails admission. There is no wait-until-quiet loop, extra settling period, service change, interval replacement, or second admission attempt.

Run this admission once before baseline calibration. If and only if calibration passes, run this identical admission once before source qualification. Any failure stops the trial with the original failure evidence retained; do not proceed to dependent work.

## Frozen measurement and calibration

Keep original `measure.mjs` bytes, SHA256 `8963c048806c5c3b0aa4b8c5e2ccaef207776941b335dbb01f3198e6c027c0ba`. Each fresh Node process executes the same four endpoints in the same order: file removal, empty-directory removal, overwrite move, seven-entry recursive removal. Keep five warmups per endpoint, eight groups of fifty measured calls, public require-mode entry, all original postconditions, and the same measured interval. No extra product instrumentation, forced GC, additional warmup, ordering change, or adjusted payload is allowed.

Stage one is exactly **24 fresh serial A-only processes**, twelve paired pseudo-roles, BA on odd pairs and AB on even pairs. Freeze the complete schedule and fresh output directory before launch. For each endpoint, each process contributes the arithmetic mean of its eight groups. Compute twelve paired logs `log(pseudoB/pseudoA)`, equal pair weights, mean and sample standard deviation. Use `t11 = 1.795884818703669` and central 90% bounds `mean ± t11*sd/sqrt(12)`, exponentiated. Every endpoint's interval must lie wholly in **[1/1.05, 1.05]**. Any endpoint or process failure, incomplete record, or identity mismatch stops the trial; no source-comparison process launches.

## Conditional independent qualification

Only a complete passing calibration and passing second environmental admission permit stage two: exactly the original **48 fresh serial processes**, twelve source A/B pairs, each followed by an A/A control pair. Source order is AB on odd pairs and BA on even pairs; controls are BA on odd pairs and AB on even pairs. New processes and fixtures supply every observation. Calibration data are never pooled into, substituted for, or used to adjust qualification.

Keep frozen `campaign.py` SHA256 `ee73d7c1b21fdf5f3d391feea3a3d187fbe82a7a4405019ce0f3b93787787b16` and its original packet `PROTOCOL.md` SHA256 `6635e1dea370ef8b55f588d129aed20b7878349409bbc51e017ec1b401ce3f54`. The new outer carrier pins the new sources/environment; it must not edit those frozen packet files. Any reviewed observational wrapper may add exact invocation/outcome receipts outside Node measurement while preserving original subprocess arguments, environment, flags, deadline, schedule, and inference. State whether child identity is observed or inherited and link the actual cleanup authority.

For each of the four source endpoints, require the original one-sided 95% upper geometric ratio **≤1.05**. Every stage-two A/A control's central 90% interval must be wholly in **[1/1.05, 1.05]**. All eight gates must pass. Failed controls mean inconclusive even if source endpoints pass. With passing controls, a source lower one-sided 95% ratio above 1.05 flags that endpoint's material regression under the original exploratory interpretation. Other non-clearance remains inconclusive. Retain every observation and bound.

## Resource bounds, failure evidence, and disposition

One job has a 120-minute ceiling. Establish a conservative absolute task-work deadline at the first task-owned step, no later than 110 minutes from that timestamp, leaving a separate cleanup/evidence window inside the job ceiling. Preserve preparation's 45-minute limit, the measurement step's 60-minute limit, its 3,300-second controller work budget, original 600-second child deadlines, the full 2,700-second outer qualification allowance, and existing bounded child-group settlement. Before launching any command or fixed admission sequence, require sufficient remaining budget for its **whole unchanged timeout plus cleanup**; before stage two recheck after admission. If insufficient, record incomplete/no launch and stop. Never shorten a child timeout, truncate a schedule, accept a passing prefix, or retry.

On every outcome retain command invocations, stdout/stderr, terminal/group receipts, admission observations, complete schedules, raw groups, source/package/native/consumer archives, all failures and analyses, and a final hash manifest. Verify task-owned groups are gone before releasing the runner. Failure collection must retain partial installation/probe artifacts too. At the published $0.102/minute, 120 execution minutes correspond to $12.24 compute, with possible rounding/storage/other billing outside that estimate. Parent dispatch is required; no payment or credential discovery is part of this protocol.

Admission or calibration failure means the composite environment was not admitted and stage two does not run. A qualification failure uses the unchanged verdict rules and terminates this trial. A complete pass supports only these rebuilt integrated artifacts, workloads, and admitted five-CPU macOS 15 arm64 VM/private-path environment. It does not explain old failures, prove either treatment independently effective, qualify PR769, replace other platform proof, or waive review/security/CI/landing gates. No outcome authorizes a further run under this protocol.
