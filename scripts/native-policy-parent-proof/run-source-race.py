"""Run the identical parent-swap regression with the existing Linux process owner."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import uuid

packet = Path(__file__).resolve().parent
workspace, work = (Path(value).resolve() for value in sys.argv[1:])
sys.path.insert(0, str(packet / 'harness'))
import bounded
from settlement_control import install, joined

install()
phase = 'workload'
cancellations = []
reviewed_cancel = signal.getsignal(signal.SIGTERM)


def coordinator_cancel(signum, frame):
    cancellations.append({'signal': signum, 'phase': phase})
    if phase == 'validation':
        if failure is not None:
            raise failure
        if cleanup_failure is not None:
            raise cleanup_failure
    if phase != 'cleanup':
        reviewed_cancel(signum, frame)


for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, coordinator_cancel)

assert sys.platform == 'linux'
manifest = json.loads((packet / 'packet-manifest.json').read_text())
for name, digest in manifest['files'].items():
    assert hashlib.sha256((packet / name).read_bytes()).hexdigest() == digest, name
contract = json.loads((packet / 'race-regression-contract.json').read_text())
protocol = json.loads((packet / 'protocol.json').read_text())
processes = work / 'evidence/processes'
evidence = work / 'evidence/race-regression'
attempt = uuid.uuid4().hex
helper = packet / 'run-race-regression.py'
pnpm = shutil.which('pnpm')
assert pnpm
env = {**os.environ, 'FS_SAFE_NATIVE_MODE': 'require', 'FS_SAFE_TEST_SERIAL': '1'}
nodes = {'22': os.environ['NODE22'], '24': shutil.which('node')}
assert all(nodes.values())
failure = None
cleanup_failure = None
try:
    try:
        bounded.run(processes, 'race-prepare', [sys.executable, str(helper), 'prepare',
                    str(workspace / 'A'), str(workspace / 'B'), str(evidence), attempt],
                    protocol['bounds']['raceHelperSeconds'])
        for major, node in nodes.items():
            runtime_env = {**env, 'PATH': str(Path(node).parent) + os.pathsep + env['PATH']}
            bounded.run(processes, f'race-node{major}-version', [node, '--version'], 30, env=runtime_env)
            version = (processes / f'race-node{major}-version.stdout.log').read_text().strip()
            assert version == ('v22.23.2' if major == '22' else 'v24.21.0')
            for role in ('A', 'B'):
                bounded.run(processes, f'race-{role}-node{major}', [pnpm, 'test', contract['test']['path'],
                            '--maxWorkers=1', '--retry=0', '--reporter=json',
                            '--outputFile', str(evidence / f'source-race-{role}-node{major}.json')],
                            protocol['bounds']['raceTestSeconds'], cwd=workspace / role, env=runtime_env)
    except BaseException as error:
        failure = error
    finally:
        phase = 'cleanup'
except BaseException as error:
    if failure is None:
        failure = error
    phase = 'cleanup'
try:
    requests = list(processes.glob('race-*.request.json'))
    assert requests
    for request in requests:
        receipt = request.with_name(request.name.replace('.request.json', '.exit.json'))
        assert joined(json.loads(receipt.read_text())), request.name
    bounded.run(processes, 'race-cleanup', [sys.executable, str(helper), 'cleanup',
                str(workspace / 'A'), str(workspace / 'B'), str(evidence), attempt],
                protocol['bounds']['raceHelperSeconds'])
except BaseException as error:
    cleanup_failure = error
phase = 'validation'
bounded.save(work / 'evidence/race-settlement.json', {
    'failure': None if failure is None else repr(failure),
    'cleanupFailure': None if cleanup_failure is None else repr(cleanup_failure),
    'cancellations': cancellations,
})
if failure is not None:
    if cleanup_failure is not None:
        print(f'race cleanup also failed: {cleanup_failure!r}', file=sys.stderr)
    raise failure
if cleanup_failure is not None:
    raise cleanup_failure
if cancellations:
    raise InterruptedError('source-race qualification cancelled after joined cleanup')
for major in nodes:
    for role in ('A', 'B'):
        report = json.loads((evidence / f'source-race-{role}-node{major}.json').read_text())
        cases = [case for file in report['testResults'] for case in file['assertionResults']]
        assert report['success'] is True and len(cases) == 1
        assert report['numTotalTests'] == report['numPassedTests'] == 1
        assert report['numPendingTests'] == report['numFailedTests'] == 0
        assert cases[0]['status'] == 'passed' and cases[0]['fullName'] == contract['test']['name']
for name in ('prepared', 'cleanup'):
    receipt = json.loads((evidence / f'{name}.json').read_text())
    assert receipt['state'] == 'complete' and receipt['attemptToken'] == attempt
assert all(receipt[key] is True for key in ('overlayRemoved', 'overlayAbsent', 'cleanSources'))
print('Identical real-native parent-swap regression passed in both clean source arms.')
