"""Own the workload group, wait for nested owners, then collect settled files."""
import hashlib
import json
import os
from pathlib import Path
import sys
import bounded
from settlement_control import install, joined

if not __debug__:
    raise RuntimeError("process qualification requires Python assertion checks")
work, transport = map(Path, sys.argv[1:])
assert str(work).startswith("/tmp/fs-safe-root-sync-local-") and work.is_dir()
assert transport.is_absolute()
packet = Path(__file__).resolve().parent.parent
pins = json.loads((packet / "pins.json").read_text())
manifest = json.loads((packet / "packet-manifest.json").read_text())
assert pins["ready"] is True, "parent dispatch authorization is required"
assert {key: pins[key] for key in ("branch", "commits", "trees")} == manifest["sourcePins"]
for name, digest in manifest["files"].items():
    assert hashlib.sha256((packet / name).read_bytes()).hexdigest() == digest, name
evidence = work / "evidence"
evidence.mkdir()
control = evidence / "control"
install()
failure = None
try:
    # Nested owners settle in at most 3s TERM + 3s KILL + 1s wait. This
    # outer owner grants 30s before escalation and is the sole 120m deadline.
    bounded.run(control, "workload", ["node", str(packet / "harness/run.mjs"), str(work), str(transport)],
                120 * 60, cwd=transport, env=os.environ.copy(), required=False, settle_seconds=30)
except BaseException as error:
    failure = repr(error)

receipt_path = control / "workload.exit.json"
receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {}
settlement_errors = []
if not joined(receipt):
    settlement_errors.append({"owner": "workload", "receipt": receipt})
for request in sorted((evidence / "processes").glob("*.request.json")):
    exit_path = request.with_name(request.name.replace(".request.json", ".exit.json"))
    step_receipt = json.loads(exit_path.read_text()) if exit_path.is_file() else {}
    if not joined(step_receipt):
        settlement_errors.append({"owner": request.stem, "receipt": step_receipt})
bounded.save(control / "settlement.json", {"failure": failure, "allProcessGroupsSettled": not settlement_errors,
                                          "settlementErrors": settlement_errors})
if settlement_errors:
    print("FS_SAFE_PROCESS_SETTLEMENT=unproven; no archive collection; stop the owned lease", flush=True)
    sys.exit(1)

# Collection starts only after the workload and every started step owner have
# joined their children and confirmed that their process groups disappeared.
archive = work / "results.tar.gz"
archive_failure = None
try:
    bounded.run(control, "archive", ["tar", "-czf", str(archive), "-C", str(work), "evidence"],
                60, cwd=work, env=os.environ.copy(), required=True)
except BaseException as error:
    archive_failure = repr(error)
if archive_failure:
    print(f"FS_SAFE_ARCHIVE_FAILURE={archive_failure}; settled evidence directory remains at {evidence}", flush=True)
    sys.exit(1)
print(f"FS_SAFE_PROOF_ARTIFACT={archive}", flush=True)
sys.exit(0 if failure is None and receipt.get("exitCode") == 0 else 1)
