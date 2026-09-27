"""Run the frozen pair serially after source/package qualification has settled."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError('qualification requires Python assertion checks')

packet = Path(__file__).resolve().parent
workspace, work = map(lambda value: Path(value).resolve(), sys.argv[1:])
protocol = json.loads((packet / 'protocol.json').read_text())
pins = json.loads((packet / 'pins.json').read_text())
manifest = json.loads((packet / 'packet-manifest.json').read_text())
assert pins['ready'] is True
evidence = work / 'evidence'
assert json.loads((evidence / 'prepared.json').read_text())['pins'] == pins
platform = 'win32' if os.name == 'nt' else 'linux'
node = shutil.which('node')
assert node
processes = evidence / 'processes'
processes.mkdir()
legs = evidence / 'legs'
legs.mkdir()
private = work / 'private-fixtures'
private.mkdir()
owner = packet / 'harness' / ('windows-step-owner.py' if platform == 'win32' else 'step-owner.py')
if platform == 'linux':
    sys.path.insert(0, str(packet / 'harness'))
    import bounded
    from settlement_control import install
    install()
cancelled = []
if platform == 'win32':
    def cancel(signum, _frame):
        if not cancelled:
            cancelled.append(signum)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGBREAK):
        signal.signal(sig, cancel)
summary = {'state': 'incomplete', 'platform': platform, 'steps': [], 'startedAt': time.time()}


def save_summary():
    target = evidence / 'study.json'
    temporary = target.with_suffix('.next')
    temporary.write_text(json.dumps(summary, indent=2) + '\n')
    temporary.replace(target)


def verify_packet():
    for name, expected in manifest['files'].items():
        assert hashlib.sha256((packet / name).read_bytes()).hexdigest() == expected, name


def verify_sources():
    for role in ('A', 'B'):
        source = workspace / role
        for expr, expected in (('HEAD', pins[role]['commit']), ('HEAD^{tree}', pins[role]['tree'])):
            actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', expr], text=True, timeout=30).strip()
            assert actual == expected
        dirty = subprocess.check_output(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=no'], text=True, timeout=30).strip()
        assert not dirty, role


def step(label, cap, command, env=None):
    verify_packet()
    assert not cancelled, 'study cancelled before dispatch'
    failure = None
    returncode = 0
    try:
        if platform == 'linux':
            bounded.run(processes, label, list(map(str, command)), cap, cwd=os.getcwd(), env=env)
        else:
            child = subprocess.Popen([sys.executable, str(owner), str(processes), label, str(cap), *map(str, command)],
                                     env=env, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            deadline = time.monotonic() + cap + 30
            forwarded = False
            try:
                while child.poll() is None:
                    if cancelled and not forwarded:
                        child.send_signal(signal.CTRL_BREAK_EVENT)
                        forwarded = True
                        deadline = min(deadline, time.monotonic() + 15)
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f'{label}: owner did not settle before watchdog')
                    time.sleep(0.05)
                returncode = child.wait()
            finally:
                if child.poll() is None:
                    # Failure containment only; missing settlement evidence cannot pass.
                    child.kill()
                    child.wait(timeout=5)
            if cancelled:
                raise InterruptedError('study cancelled')
    except BaseException as error:
        failure = error
    receipt_path = processes / f'{label}.exit.json'
    assert receipt_path.is_file(), f'missing process receipt: {label}'
    receipt = json.loads(receipt_path.read_text())
    assert receipt['localProcessSettled'] is True, label
    assert not receipt['cleanupErrors'], label
    summary['steps'].append({'label': label, 'returncode': returncode, 'receipt': receipt})
    save_summary()
    if failure is not None:
        raise failure
    assert returncode == 0, label


try:
    save_summary()
    verify_packet()
    verify_sources()
    consumers = {}
    for role in ('A', 'B'):
        consumer = work / f'consumer-{role}'
        env = json.loads((consumer / 'environment.json').read_text())
        consumers[role] = (consumer, env)
        step(f'qualify-{role}', protocol['bounds']['qualificationSeconds'],
             [node, packet / 'harness/qualify.mjs', consumer, private, evidence / f'qualification-{role}.json'], env)
        qualified = json.loads((evidence / f'qualification-{role}.json').read_text())
        assert qualified['state'] == 'complete' and qualified['cleanup'] is True
        assert qualified['source'] == {**pins[role], 'dirty': False}
        assert len(qualified['rows']) == (38 if platform == 'linux' else 34)
        assert len({row['id'] for row in qualified['rows']}) == len(qualified['rows'])
        assert all(row['passed'] is True for row in qualified['rows'])
    for index, leg in enumerate(protocol['timing']['schedule']):
        consumer, env = consumers[leg['role']]
        step(f'leg-{index + 1:02d}', protocol['bounds']['legSeconds'],
             [node, packet / 'harness/benchmark-leg.mjs', consumer, private, index, legs / f'leg-{index + 1:02d}.json'], env)
    verify_sources()
    assert not list(private.iterdir()), 'unsettled fixture directories'
    for role in ('A', 'B'):
        consumer, env = consumers[role]
        step(f'verify-{role}', 30,
             [node, packet / 'verify-installed.mjs', consumer, workspace / role, evidence / f'expected-{role}.json'], env)
    step('assessment', protocol['bounds']['assessmentSeconds'],
         [sys.executable, packet / 'harness/assess.py', platform, legs, evidence / 'assessment.json'])
    assessment = json.loads((evidence / 'assessment.json').read_text())
    assert assessment['validInput'] is True
    summary['performanceOutcome'] = assessment['performanceOutcome']
    assert assessment['performanceOutcome'] == 'pass', assessment['performanceOutcome']
    verify_packet()
    summary['state'] = 'complete'
except BaseException as error:
    summary['failure'] = repr(error)
    raise
finally:
    summary['finishedAt'] = time.time()
    save_summary()
