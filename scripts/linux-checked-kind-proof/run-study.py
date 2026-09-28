"""Run public qualification, exact syscall comparisons and two fixed timing cohorts."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError('qualification requires assertions')
packet = Path(__file__).resolve().parent
workspace, work = map(lambda value: Path(value).resolve(), sys.argv[1:])
pins = json.loads((packet / 'pins.json').read_text())
protocol = json.loads((packet / 'protocol.json').read_text())
assert pins['ready'] is True and protocol['ready'] is True
assert sys.platform == 'linux' and os.geteuid() != 0
manifest = json.loads((packet / 'packet-manifest.json').read_text())
evidence = work / 'evidence'; processes = evidence / 'processes'
assert json.loads((evidence / 'preparation.json').read_text())['state'] == 'complete'
assert json.loads((evidence / 'prepared.json').read_text())['pins'] == pins
conditional = json.loads((evidence / 'conditional-native.json').read_text())
assert conditional['pins'] == pins
assert conditional['state'] == 'complete' and conditional['resourceSettled'] is True
assert conditional['processesJoinedBeforeCleanup'] is True and not conditional['cleanupErrors']
conditional_tests = json.loads((packet / 'qualification.json').read_text())['rustConditionalTests']
binary_manifest_path = evidence / 'native-test-binaries.json'
binary_manifest = json.loads(binary_manifest_path.read_text())
assert binary_manifest['pins'] == pins
assert conditional['binaryManifestSha256'] == hashlib.sha256(binary_manifest_path.read_bytes()).hexdigest()
assert len(conditional['rows']) == 6
assert {(row['role'], row['case'], row['test']) for row in conditional['rows']} == {
    (role, case, test) for role in ('A', 'B') for case, test in conditional_tests.items()}
for row in conditional['rows']:
    assert row['executed'] is True and row['fixtureEmpty'] is True
    assert row['source'] == pins[row['role']]
    assert row['binarySha256'] == binary_manifest['arms'][row['role']]['binarySha256']
paths = json.loads((evidence / 'runtime-paths.json').read_text())
tools = json.loads((evidence / 'tools.json').read_text())
build = json.loads((evidence / 'deny-wrapper-build.json').read_text())
expected = {role: json.loads((evidence / f'expected-{role}.json').read_text()) for role in ('A', 'B')}
assert expected['A']['nativeSha256'] != expected['B']['nativeSha256']
for request in processes.glob('*.request.json'):
    receipt = json.loads(request.with_name(request.name.replace('.request.json', '.exit.json')).read_text())
    assert receipt['localProcessSettled'] is True and not receipt['cleanupErrors']
sys.path.insert(0, str(packet / 'harness'))
import bounded
from settlement_control import install
install()
private = work / 'private-fixtures'; private.mkdir(mode=0o700)
traces = evidence / 'syscalls'; traces.mkdir()
legs = evidence / 'legs'; legs.mkdir()
qualifications = evidence / 'qualification'; qualifications.mkdir()
summary = {'state': 'incomplete', 'startedAt': time.time(), 'steps': [], 'qualifiedProcesses': 0, 'tracedCalls': 0, 'timingLegs': 0}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_summary():
    temporary = evidence / 'study.next'
    temporary.write_text(json.dumps(summary, indent=2) + '\n')
    temporary.replace(evidence / 'study.json')


def verify_packet():
    for name, digest in manifest['files'].items():
        assert sha(packet / name) == digest, name


def verify_sources():
    for role in ('A', 'B'):
        source = workspace / role
        for expr, expected_value in (('HEAD', pins[role]['commit']), ('HEAD^{tree}', pins[role]['tree'])):
            actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', expr], text=True, timeout=30).strip()
            assert actual == expected_value
        assert not subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain'], text=True, timeout=30).strip()
    for major, tool in (('22', 'node22'), ('24', 'node')):
        assert sha(paths[major]) == tools[tool]['sha256']
    assert paths['denialWrapper'] == build['binaryPath']
    assert sha(build['binaryPath']) == build['binarySha256']
    assert sha(packet / 'harness/deny-openat2.c') == build['sourceSha256']


def step(label, cap, command, env=None):
    verify_packet()
    try:
        bounded.run(processes, label, list(map(str, command)), cap, cwd=str(work), env=env)
    finally:
        receipt = json.loads((processes / f'{label}.exit.json').read_text())
        summary['steps'].append({'label': label, 'receipt': receipt})
        save_summary()
        assert receipt['localProcessSettled'] is True and not receipt['cleanupErrors'], label


def launch(mechanism, node, args):
    command = [node, *args]
    if mechanism in ('ENOSYS', 'EPERM'):
        command = [build['binaryPath'], mechanism, *command]
    else:
        assert mechanism == 'openat2'
    return command


try:
    save_summary(); verify_packet(); verify_sources()
    consumers = {}
    for role in ('A', 'B'):
        consumer = work / f'consumer-{role}'
        env = json.loads((consumer / 'environment.json').read_text())
        assert env['FS_SAFE_TEST_NO_OPENAT2'] == '0'
        env.update(FS_SAFE_PROOF_DENY_WRAPPER=build['binaryPath'],
                   FS_SAFE_PROOF_DENY_WRAPPER_SHA256=build['binarySha256'],
                   FS_SAFE_PROOF_DENY_BUILD_RECEIPT=str(evidence / 'deny-wrapper-build.json'))
        consumers[role] = (consumer, env)
    for major in protocol['qualification']['nodeMajors']:
        for mechanism in protocol['qualification']['mechanisms']:
            outcomes = []
            for role in ('A', 'B'):
                consumer, env = consumers[role]
                output = qualifications / f'node{major}-{mechanism}-{role}.json'
                step(f'qualify-node{major}-{mechanism}-{role}', protocol['bounds']['qualificationSeconds'],
                     launch(mechanism, paths[str(major)], [packet / 'harness/qualify.mjs', consumer, private, mechanism, str(major), output]), env)
                report = json.loads(output.read_text())
                assert report['state'] == 'complete' and report['cleanup'] is True
                assert report['mechanism'] == mechanism and report['nodeVersion'] == protocol['nodeVersions'][str(major)]
                assert report['nodeMajor'] == major and report['fallbackHook'] == '0'
                assert report['source'] == {**pins[role], 'dirty': False} and report['role'] == role
                assert report['native']['sha256'] == expected[role]['nativeSha256'] and report['native']['configuredMode'] == 'require'
                assert [row['id'] for row in report['rows']] == protocol['qualification']['rowIds']
                assert all(row['passed'] is True for row in report['rows'])
                outcomes.append(report['rows']); summary['qualifiedProcesses'] += 1
            assert outcomes[0] == outcomes[1]
    assert summary['qualifiedProcesses'] == 12 and not list(private.iterdir())
    for major in protocol['syscalls']['nodeMajors']:
        for row_id in protocol['syscalls']['rows']:
            row = next(value for value in protocol['rows'] if value['id'] == row_id)
            pair = []
            for role in ('A', 'B'):
                consumer, env = consumers[role]
                prefix = traces / f'node{major}-{row_id}-{role}'
                trace, captured, proof = (Path(str(prefix) + suffix) for suffix in ('.trace', '.manifest.json', '.proof.json'))
                child = launch(row['mechanism'], paths[str(major)], [packet / 'harness/syscall-probe.mjs', consumer, private, row_id, str(major), captured, proof])
                step(f'trace-node{major}-{row_id}-{role}', protocol['bounds']['traceSeconds'],
                     [sys.executable, packet / 'harness/trace-launch.py', trace, *child], env)
                pair.extend((trace, captured, proof)); summary['tracedCalls'] += 1
            output = traces / f'node{major}-{row_id}-comparison.json'
            step(f'compare-node{major}-{row_id}', protocol['bounds']['traceComparisonSeconds'],
                 [sys.executable, packet / 'harness/compare-syscalls.py', *pair, output], consumers['A'][1])
            report = json.loads(output.read_text())
            assert report['ok'] is True and report['status'] == 'pass'
            assert report['comparison']['componentFstatDelta'] == row['expectedComponentFstatDelta']
    assert summary['tracedCalls'] == 32 and not list(private.iterdir())
    for cohort in protocol['timing']['cohorts']:
        directory = legs / cohort['id']; directory.mkdir()
        for index, plan in enumerate(protocol['timing']['schedule']):
            consumer, env = consumers[plan['role']]
            output = directory / f'leg-{index + 1:02d}.json'
            step(f"{cohort['id']}-leg-{index + 1:02d}", protocol['bounds']['legSeconds'],
                 launch(cohort['mechanism'], paths['24'], [packet / 'harness/benchmark-leg.mjs', consumer, private, cohort['id'], str(index), output]), env)
            summary['timingLegs'] += 1
    assert summary['timingLegs'] == 64 and not list(private.iterdir())
    verify_sources()
    for role in ('A', 'B'):
        consumer, env = consumers[role]
        step(f'verify-{role}', 60, [paths['24'], packet / 'verify-installed.mjs', consumer, workspace / role, evidence / f'expected-{role}.json'], env)
    step('assessment', protocol['bounds']['assessmentSeconds'],
         [sys.executable, packet / 'harness/assess.py', legs, evidence, evidence / 'assessment.json'], consumers['A'][1])
    assessment = json.loads((evidence / 'assessment.json').read_text())
    assert assessment['validInput'] is True
    summary['performanceOutcome'] = assessment['performanceOutcome']
    assert assessment['performanceOutcome'] == 'pass'
    assert assessment['completedLegs'] == 64 and assessment['measuredCalls'] == 8000
    verify_packet(); verify_sources()
    summary['state'] = 'complete'
except BaseException as error:
    summary['failure'] = repr(error)
    raise
finally:
    summary['finishedAt'] = time.time(); save_summary()
