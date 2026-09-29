#!/usr/bin/env python3
"""Offline assessment of the frozen eight-cell study; never launches a process."""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys

PROTOCOL_HASH = "f4005736ad14612986b4f935937326b88e257ac5eb67da696d1c8fa3b485e7ba"
PREFIX = "Root/exact-identity-domain/"
SEMANTICS = "Complete awaited public call; walk fully consumed; fixture and output checks outside timer."
def sha(file): return hashlib.sha256(Path(file).read_bytes()).hexdigest()
def read(file): return json.loads(Path(file).read_text())

def journal(file):
    starts, elapsed, preflights, pending = [], [], [], None
    for line in Path(file).read_text().splitlines():
        if '"rootExactIdentityEvent"' not in line and '"rootExactIdentityPreflight"' not in line:
            continue
        item = json.loads(line)
        if item.get('rootExactIdentityPreflight'):
            preflights.append(item)
        elif item['rootExactIdentityEvent'] == 'start':
            assert pending is None
            pending = (item['sequence'], item['row']); starts.append(item)
        else:
            assert item['rootExactIdentityEvent'] == 'elapsed'
            assert pending == (item['sequence'], item['row'])
            assert type(item['milliseconds']) in (int, float) and math.isfinite(item['milliseconds']) and item['milliseconds'] >= 0
            pending = None; elapsed.append(item)
    return starts, elapsed, preflights, pending

def validate_report(plan, binding, record):
    arm, mode = record['schedule']['arm'], record['schedule']['mode']
    consumer = binding['consumers'][arm]
    report = read(record['report']); observed = report['metadata']
    assert report['schemaVersion'] == 1
    expected = {'harnessRevision': binding['harness']['commit'], 'harnessHash': binding['harness']['runnerHash'],
        'distHash': consumer['distSha256'], 'node': binding['runtime']['nodeVersion'], 'platform': 'linux', 'arch': 'x64',
        'mode': mode, 'native': mode == 'require', 'samples': 5,
        'nativeHash': consumer['nativeAddon']['sha256'] if mode == 'require' else None}
    for key, value in expected.items(): assert observed[key] == value, (key, observed.get(key), value)
    loads = observed['exactIdentityDlopen']
    assert set(loads) == {'attempts', 'outcomes'}
    assert loads['attempts'] == ([{'sequence': 1}] if mode == 'require' else [])
    outcomes = loads['outcomes']
    assert isinstance(outcomes, list) and len(outcomes) == (1 if mode == 'require' else 0)
    if outcomes:
        assert outcomes[0] == {'sequence': 1, 'succeeded': True,
            'sha256': consumer['nativeAddon']['sha256'], 'filename': Path(consumer['nativeAddon']['path']).name}
    starts, elapsed, preflights, pending = journal(record['stderr'])
    assert pending is None and len(preflights) == 1
    preflight = preflights[0]
    assert preflight['protocol'] == plan['study'] and preflight['mode'] == mode
    assert preflight['safeNumericIdentities'] is True and preflight['hooksAbsent'] is True
    assert preflight['bindingPresent'] is (mode == 'require')
    names = [PREFIX + name for name in plan['runner']['rowsByMode'][mode]]
    assert [row['name'] for row in report['results']] == names
    witnesses = preflight['routeWitnesses']
    assert [row['row'] for row in witnesses] == names
    for witness in witnesses:
        assert witness['mode'] == mode and witness['events']
        calls = sum(event['method'] == 'observeDirectory' for event in witness['events'])
        assert witness['nativeCalls'] == calls and (calls > 0) == (mode == 'require')
        for event in witness['events']:
            assert event['method'] in ('statSync', 'lstatSync', 'observeDirectory')
            assert isinstance(event['bigint'], bool) and isinstance(event['relative'], str)
        for row, method in [('root-construction', 'statSync'), ('root-assert-resolve', 'lstatSync')]:
            if witness['row'] == PREFIX + row:
                assert any(event == {'method': method, 'relative': '', 'bigint': True} for event in witness['events'])
    expected_calls = len(names) * 100
    assert len(starts) == len(elapsed) == expected_calls
    assert [item['sequence'] for item in starts] == list(range(1, expected_calls + 1))
    assert [item['sequence'] for item in elapsed] == list(range(1, expected_calls + 1))
    assert [item['row'] for item in starts] == [item['row'] for item in elapsed]
    for index, row in enumerate(report['results']):
        assert 'skipped' not in row and row['iterations'] == 20
        assert row['workloadSemantics'] == SEMANTICS
        assert row['workloadDetails'] == {'protocol': plan['study'], 'workload': row['name'][len(PREFIX):], 'nativeMode': mode}
        calls = elapsed[index * 100:(index + 1) * 100]
        assert all(item['row'] == row['name'] for item in calls)
        reconstructed = []
        for sample in range(5):
            total = 0.0
            for item in calls[sample * 20:(sample + 1) * 20]: total += item['milliseconds']
            reconstructed.append(total * 1000 / 20)
        assert reconstructed == row['samplesUs'] and all(math.isfinite(x) and x > 0 for x in reconstructed)
        assert row['medianUs'] == statistics.median(reconstructed)
        assert row['minUs'] == min(reconstructed) and row['maxUs'] == max(reconstructed)
    return report['results'], witnesses

def assess(plan, binding, records):
    assert len(records) == 192 and [r['schedule'] for r in records] == plan['schedule']
    grouped, signatures = {}, {}
    for record in records:
        assert sha(record['report']) == record['reportSha256'] and sha(record['stderr']) == record['stderrSha256']
        rows, witnesses = validate_report(plan, binding, record)
        item = record['schedule']
        for witness in witnesses:
            key = (item['mode'], witness['row'])
            if key not in signatures: signatures[key] = witness['events']
            assert signatures[key] == witness['events'], ('route witness drift', key)
        for row in rows:
            grouped.setdefault((item['mode'], row['name']), {}).setdefault(item['block'], {})[item['arm']] = row
    def bound(values, control=False):
        assert len(values) == 24
        mean, sd = statistics.mean(values), statistics.stdev(values)
        upper = math.exp((abs(mean) if control else mean) + 1.7138715277470473 * sd / math.sqrt(24))
        return {'ratio': math.exp(mean), 'upper': upper, 'meanLogRatio': mean, 'sampleLogSd': sd, 'accepted': upper <= 1.10}
    result = {'state': 'complete', 'decision': 'PASS', 'protocolSha256': PROTOCOL_HASH,
        'counts': plan['counts'], 'workloads': [], 'allSamplesRetained': True,
        'scope': plan['scope'], 'claim': 'Per-row sample-mean bounds; not individual tails or familywise confidence.'}
    for mode, names in plan['runner']['rowsByMode'].items():
        for name in names:
            key = (mode, PREFIX + name)
            source, baseline, candidate, blocks = [], [], [], []
            for block in range(1, 25):
                rows = grouped[key][block]; assert sorted(rows) == ['B0', 'B1', 'C0', 'C1']
                center = {arm: statistics.median(row['samplesUs']) for arm, row in rows.items()}
                source.append((math.log(center['C0']) + math.log(center['C1']) - math.log(center['B0']) - math.log(center['B1'])) / 2)
                baseline.append(math.log(center['B1']) - math.log(center['B0']))
                candidate.append(math.log(center['C1']) - math.log(center['C0']))
                blocks.append({'block': block, 'armMediansUs': center, 'samples': {arm: row['samplesUs'] for arm, row in rows.items()}})
            row = {'mode': mode, 'name': key[1], 'source': bound(source), 'baselineControl': bound(baseline, True),
                'candidateControl': bound(candidate, True), 'blocks': blocks}
            if not all(row[k]['accepted'] for k in ('source', 'baselineControl', 'candidateControl')): result['decision'] = 'HOLD'
            result['workloads'].append(row)
    return result

if __name__ == '__main__':
    assert __debug__ and len(sys.argv) == 5
    protocol_file, binding_file, receipt_file, output = map(Path, sys.argv[1:])
    assert sha(protocol_file) == PROTOCOL_HASH and not output.exists()
    plan, binding, receipt = read(protocol_file), read(binding_file), read(receipt_file)
    assert binding['launch'] is True and binding['study'] == plan['study']
    assert binding['protocolSha256'] == PROTOCOL_HASH
    assert receipt['state'] == 'executed' and receipt['bindingSha256'] == sha(binding_file)
    try:
        result = assess(plan, binding, receipt['reports'])
    except Exception as error:
        output.write_text(json.dumps({'state': 'incomplete', 'decision': 'HOLD', 'error': str(error),
            'protocolSha256': PROTOCOL_HASH, 'allRawFilesPreserved': True}, indent=2) + '\n')
        raise
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'state': result['state'], 'decision': result['decision'], 'cells': len(result['workloads'])}))
