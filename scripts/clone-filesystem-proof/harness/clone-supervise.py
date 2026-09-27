"""Clone coordinator: reviewed process ownership, all-volume cleanup, archive."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import bounded
from settlement_control import install, joined

if not __debug__:
    raise RuntimeError('process qualification requires Python assertion checks')
work, transport = map(Path, sys.argv[1:])
assert work.is_absolute() and str(work).startswith('/tmp/fs-safe-clone-admission-')
assert work.is_dir() and work.resolve() == work and not list(work.iterdir())
assert transport.is_absolute() and not transport.is_relative_to(work)
packet = Path(__file__).resolve().parent.parent
pins = json.loads((packet / 'pins.json').read_text())
manifest = json.loads((packet / 'packet-manifest.json').read_text())
assert pins['ready'] is True, 'parent dispatch authorization is required'
assert {key: pins[key] for key in ('branch', 'commits', 'trees')} == manifest['sourcePins']
for name, digest in manifest['files'].items():
    assert hashlib.sha256((packet / name).read_bytes()).hexdigest() == digest, name
evidence = work / 'evidence'; evidence.mkdir(mode=0o700)
control = evidence / 'control'; control.mkdir()
states = evidence / 'mount-states'; states.mkdir(mode=0o700)
fixtures = work / 'fixtures'; fixtures.mkdir(mode=0o700)
volumes = ('xfs', 'btrfs', 'xfs-no-reflink')
install()
phase = 'workload'
cancellations = []
reviewed_cancel = signal.getsignal(signal.SIGTERM)


def coordinator_cancel(signum, frame):
    cancellations.append({'signal': signum, 'phase': phase})
    if phase == 'workload':
        reviewed_cancel(signum, frame)
    else:
        # Product groups are being checked/cleaned. A late first signal records
        # cancellation without escaping cleanup; repeated signals are masked.
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)


for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, coordinator_cancel)


def mount_step(action, volume, cap):
    label = f'mount-{action}-{volume}'
    argv = ['python3', str(packet / 'harness/mount-owner.py'), action, '--volume', volume,
            '--work-dir', str(fixtures), '--state-file', str(states / f'{volume}.json')]
    # The reviewed owner directly owns this helper's process group. A signal
    # during prepare therefore cannot kill an intermediate owner before it joins
    # a separately grouped command. Cleanup retains the same per-volume bound.
    receipt = bounded.run(control, label, argv, cap, cwd=work, env=os.environ.copy(), required=False)
    return {'receipt': receipt, 'ok': joined(receipt) and receipt.get('exitCode') == 0
            and receipt.get('failure') is None}



failure = None
prepared = {}
try:
    try:
        for volume in volumes:
            prepared[volume] = mount_step('prepare', volume, 15)
            assert prepared[volume]['ok'], f'volume preparation failed: {volume}'
        # Sole workload deadline; nested owners retain their reviewed 3/3/1s
        # settlement while the outer owner allows 30s before escalation.
        bounded.run(control, 'workload', ['node', str(packet / 'harness/run.mjs'), str(work), str(transport)],
                    120 * 60, cwd=transport, env=os.environ.copy(), required=False, settle_seconds=30)
    finally:
        phase = 'settlement'
except BaseException as error:
    failure = repr(error)

settlement_errors = []
for directory in (control, evidence / 'processes'):
    for request in sorted(directory.glob('*.request.json')):
        exit_path = request.with_name(request.name.replace('.request.json', '.exit.json'))
        receipt = json.loads(exit_path.read_text()) if exit_path.is_file() else {}
        if not joined(receipt):
            settlement_errors.append({'owner': request.stem, 'receipt': receipt})
bounded.save(control / 'settlement.json', {'failure': failure, 'allProcessGroupsSettled': not settlement_errors,
                                         'settlementErrors': settlement_errors, 'cancellations': cancellations})
if settlement_errors:
    print('FS_SAFE_PROCESS_SETTLEMENT=unproven; no mount operations/archive; stop the owned lease', flush=True)
    sys.exit(1)

# Every product group is now joined. Late cancellation remains non-throwing;
# each volume gets its own 30s cap plus <=7s reviewed settlement.
cleanup = {}
for volume in volumes:
    try:
        outcome = mount_step('cleanup', volume, 30)
        state_file = states / f'{volume}.json'
        state = json.loads(state_file.read_text()) if state_file.is_file() else {}
        volume_cleanup = state.get('cleanup', {})
        outcome['mountReceipt'] = volume_cleanup
        outcome['ok'] = outcome['ok'] and volume_cleanup.get('ok') is True and volume_cleanup.get('mountAbsent') is True and volume_cleanup.get('loopsAbsent') is True and volume_cleanup.get('errors') == []
        cleanup[volume] = outcome
    except BaseException as error:
        cleanup[volume] = {'ok': False, 'failure': repr(error)}
all_clean = all(item['ok'] for item in cleanup.values()) and len(cleanup) == 3
bounded.save(control / 'mount-cleanup.json', {'allVolumesReleased': all_clean, 'volumes': cleanup})
if not all_clean:
    print('FS_SAFE_MOUNT_SETTLEMENT=unproven; no archive; stop the owned lease', flush=True)
    sys.exit(1)
summary_file = evidence / 'summary.json'
summary = json.loads(summary_file.read_text()) if summary_file.is_file() else {}
receipt_file = control / 'workload.exit.json'
receipt = json.loads(receipt_file.read_text()) if receipt_file.is_file() else {}
completed = failure is None and not cancellations and receipt.get('exitCode') == 0 and receipt.get('failure') is None and summary.get('execution') == 'completed'
all_gates = completed and summary.get('gates') == {'correctness': True, 'traces': True, 'provenance': True}
result = summary.get('performance', 'inconclusive') if all_gates else 'failed-or-inconclusive'
bounded.save(evidence / 'final-gates.json', {'outcome': result, 'allProcessGroupsSettled': True,
    'allVolumesReleased': True, 'productGatesPassed': all_gates, 'cancellations': cancellations, 'providerCleanup': 'parent-must-verify-terminal'})
# Only evidence is archived. Fixtures, retained image files, worktrees, and
# consumers live outside this path and cannot enter the collected tarball.
archive = work / 'results.tar.gz'
try:
    bounded.run(control, 'archive', ['tar', '-czf', str(archive), '-C', str(work), 'evidence'],
                60, cwd=work, env=os.environ.copy(), required=True)
except BaseException as error:
    print(f'FS_SAFE_ARCHIVE_FAILURE={error!r}; settled evidence remains at {evidence}', flush=True)
    sys.exit(1)
print(f'FS_SAFE_PROOF_ARTIFACT={archive}', flush=True)
sys.exit(0 if all_gates else 1)
