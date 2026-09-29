# PR770 native pre-observation timing protocol v1

This is a new fixed campaign for PR770 only. It uses no timing data or clearance from PR769; the macOS watch-owner hold remains unchanged. Functional installed-package qualification is separate and must already have admitted each platform. This packet has not executed product timings.

## Frozen experiment

Use one fixed Node 24 executable and exact installed A (baseline) / B (PR770) consumers per platform: Linux, macOS, and Windows. Parent-owned existing build/package receipts pin source, tarballs, and independently expected native digests. Run each platform serially on its assigned runner without overlapping task-owned builds, tests, or benchmarks; verify prior functional command handles are terminal before launch. Ordinary system services may remain active, and absolute host idleness is not claimed. Record ambient load in the parent receipt. Do not change host configuration midway. Preserve the actual provider/id, filesystem, runtime and artifacts in the campaign's parent receipt. These results apply to those environments and payloads, not all installations or call latency tails.

There are **12 source pairs plus 12 same-artifact A/A control pairs**, exactly **48 fresh Node processes per platform**. Each source pair is immediately followed by one control pair. Source order is AB on odd pairs, BA on even pairs. Control pseudo-role order is BA on odd pairs, AB on even pairs; both control roles execute the same A consumer and expected artifact. Thus both pair classes contain six orders of each kind. There is no optional stopping, selective retry, extra timing pass, discarded sample, changed limit, or post-result tuning. Any failed process or incomplete report makes the campaign incomplete/inconclusive; preserve its evidence and investigate before considering a separately designed experiment.

Each process warms each endpoint with exactly **5 complete calls**, then collects **8 sample means of 50 calls** for each endpoint. All warmups run before timing begins. Every timed invocation measures only the complete awaited public method with `performance.now()`. Fixture preparation, result verification and external cleanup occur outside the timer. All 405 calls per measured endpoint receive the same postcondition verification. Raw retained observations are the eight arithmetic sample means plus counts; the inferential unit is the independent process pair, not the 50 calls or eight means. No per-call percentile claim is possible.

The endpoints, always in this order, are:

1. `remove-file`: remove a 128-byte regular file, verify its pathname is absent.
2. `remove-empty-directory`: remove a newly created empty directory, verify absence.
3. `move-existing-overwrite`: move a 128-byte source over a distinct, existing 96-byte destination with `{ overwrite: true }`; verify source absence, exact destination bytes and original source device/inode identity, then clean the destination.
4. `remove-recursive`: remove seven entries (tree root, two child directories, four 128-byte files), default filesystem order, maxEntries 7, maxDepth 2; verify complete tree absence. Linux/macOS must admit the actual mount-bounded primitive and execute it. Windows declares this unsupported endpoint as a fixed skip, never a timed failure or latency sample.

The fixture root must be empty after every call, and final cleanup must complete before a report is written. This yields 19,200 measured calls per endpoint/platform (76,800 POSIX; 57,600 Windows) plus 240 warmups per measured endpoint/platform. Public require-mode calls must actually load the expected installed addon: verify its independent build digest, direct and main-package resolution, matching package manifests, required functions, CJS cache entry and OS shared image. Distribution and addon hashes stay unchanged within and across processes. The measurement harness does not inject a native binding.

## Frozen inference and disposition

For each endpoint and each source pair, compute the arithmetic mean of all eight process sample means for A and B, then `d = log(meanB / meanA)`. Give every pair equal weight. For n=12 independent paired log ratios, compute their mean and sample standard deviation, then bounds `mean(d) ± 1.795884818703669 * sd(d)/sqrt(12)` (Student t, 11 degrees of freedom, one-sided 95% critical value). Exponentiate the bounds for reported ratios. This relies on the usual approximate independent, normal paired-log-error model; balanced order and A/A controls test drift/noise, but do not prove that assumption.

Source preservation requires the **one-sided 95% upper ratio ≤1.05 for every measured endpoint**. This is an intersection-union claim: every endpoint must pass; do not pool unlike methods or offset one endpoint's failure with another's improvement. Failure to clear is not proof of regression.

For controls, apply the same computation to pseudo-B/pseudo-A. Require the central **90% t interval entirely within [1/1.05, 1.05]** for every measured endpoint. This is the pair of one-sided 95% equivalence tests, symmetric in log space; a 5% multiplicative swing in either orientation is disallowed. Twelve control pairs replaced an initially considered four *before any measurement*: equal counts avoid a much less precise control gate for the same 5% margin.

Only if all source and control endpoints clear is the campaign `qualified`. If controls clear and a source endpoint's one-sided 95% **lower** ratio exceeds 1.05, the `material-regression` label flags pointwise evidence for that specific workload; this exploratory flag has no familywise 95% control across endpoints/platforms and cannot support a project-wide regression claim. Otherwise report `inconclusive`, including when controls do not clear. Preserve all bounds and pair ratios regardless of disposition. Four POSIX or three Windows endpoints must clear on **all three platforms** before claiming this campaign establishes performance preservation. A control failure never subtracts a source regression or licenses reruns.

## Invocation

The small driver serializes all processes and writes the full schedule, copied expected-artifact documents and packet/Node hashes to a fresh output directory before launching anything. Configuration example (absolute paths; no shell interpolation inside the JSON):

```json
{
  "node": "/absolute/node24",
  "A": { "consumer": "/absolute/installed-baseline", "expected": "/absolute/baseline-expected.json" },
  "B": { "consumer": "/absolute/installed-pr770", "expected": "/absolute/candidate-expected.json" }
}
```

Each expected JSON uses the already qualified probe's `packageVersion`, `nativePackage`, and independently built `nativeSha256` fields. Use `python -I` so Python environment flags cannot alter execution. The driver rejects inherited Node preload/instrumentation paths or forced openat2 disablement and disables the Node compile cache for these new processes.

```sh
python3 -I /absolute/packet/campaign.py run /absolute/platform-config.json /absolute/fresh-campaign-output
python3 -I /absolute/packet/campaign.py analyze /absolute/fresh-campaign-output
```

On Windows the same standard-library driver accepts `python -I C:\absolute\packet\campaign.py run C:\absolute\platform-config.json C:\absolute\fresh-campaign-output` (or the verified interpreter's absolute executable path). JSON path strings may use forward slashes, such as `C:/task/consumer-A`, to avoid backslash escaping. The config uses the exact same `node`, `A.consumer`, `A.expected`, `B.consumer`, and `B.expected` keys; `node` points to the already verified Node 24 `node.exe`. No shell is used for child Node processes, so spaces in absolute paths are preserved.

The first command runs the frozen schedule once and writes `analysis.json` after all 48 successful processes. It retains each process stdout/stderr and JSON report. A process timeout is 600 seconds; timeout/nonzero exit records a terminal failure and stops, without retry. The second command only recomputes analysis from retained reports; it never reruns timing. `measure.mjs` may also be invoked directly as `node measure.mjs EXPECTED_JSON NEW_REPORT_JSON` from an installed consumer, but campaign qualification requires the complete predefined schedule and analysis gates. Packet files are immutable once the parent records their final reviewed hashes and starts the campaign.
