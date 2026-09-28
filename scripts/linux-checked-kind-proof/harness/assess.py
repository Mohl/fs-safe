"""Assess the complete two-cohort study, without executing or pooling product runs.
CLI: python assess.py LEG_DIRECTORY EVIDENCE_DIRECTORY NEW_OUTPUT
"""
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def upper95(logs):
    state = 734
    bootstrap = []
    for _ in range(100000):
        draws = []
        for _ in range(8):
            state = (state ^ (state << 13)) & 0xffffffff
            state = (state ^ (state >> 17)) & 0xffffffff
            state = (state ^ (state << 5)) & 0xffffffff
            draws.append(logs[state >> 29])
        bootstrap.append(math.fsum(draws) / 8)
    bootstrap.sort()
    return math.exp(bootstrap[94999])


def main():
    if not __debug__:
        raise RuntimeError('assessment requires assertions')
    directory, evidence, output = map(Path, sys.argv[1:])
    packet = Path(__file__).resolve().parent.parent
    protocol_path = packet / 'protocol.json'
    protocol, pins = load(protocol_path), load(packet / 'pins.json')
    assert protocol['ready'] is True and pins['ready'] is True
    schedule = protocol['timing']['schedule']
    report = {'schema': 1, 'platform': 'linux', 'validInput': False,
              'performanceOutcome': 'inconclusive', 'overallOutcome': 'not-assessed',
              'externalGates': 'Source/package/correctness/process/mount/fixture gates are separate and all required.',
              'protocolSha256': sha(protocol_path), 'assessorSha256': sha(__file__),
              'threshold': 1.05, 'bootstrapSeed': 734, 'bootstrapResamples': 100000,
              'cells': [], 'inputs': [], 'errors': []}
    try:
        assert protocol['timing']['threshold'] == 1.05 and len(schedule) == 32
        assert protocol['sourcePins'] == {role: pins[role] for role in ('A', 'B')}
        expected = {role: load(evidence / f'expected-{role}.json') for role in ('A', 'B')}
        for role in ('A', 'B'):
            assert expected[role]['role'] == role and expected[role]['source'] == {**pins[role], 'dirty': False}
            assert expected[role]['pinsSha256'] == sha(packet / 'pins.json')
            assert expected[role]['protocolSha256'] == sha(protocol_path)
        assert expected['A']['nativeSha256'] != expected['B']['nativeSha256'], 'native builds are distinct for this Rust change'
        cohorts = protocol['timing']['cohorts']
        assert [cohort['id'] for cohort in cohorts] == ['fallback', 'kernel']
        assert len(list(directory.glob('*/leg-[0-9][0-9].json'))) == 64
        sample_count = call_count = warm_count = leg_count = 0
        seen = set()
        for cohort in cohorts:
            descriptors = [next(row for row in protocol['rows'] if row['id'] == row_id) for row_id in cohort['rows']]
            assert len(descriptors) == (4 if cohort['id'] == 'fallback' else 1)
            assert all(row['mechanism'] == cohort['mechanism'] for row in descriptors)
            medians = {}
            for index, plan in enumerate(schedule, 1):
                filename = directory / cohort['id'] / f'leg-{index:02d}.json'
                leg = load(filename); leg_count += 1
                report['inputs'].append({'name': str(filename.relative_to(directory)), 'sha256': sha(filename)})
                assert leg['state'] == 'complete' and leg['cleanup'] is True and leg['platform'] == 'linux'
                assert leg['cohort'] == cohort['id'] and leg['mechanism'] == cohort['mechanism']
                assert leg['nodeVersion'] == protocol['nodeVersions']['24'] and leg['nodeMajor'] == 24
                assert leg['fallbackHook'] == '0'
                for field in ('block', 'position', 'role', 'order', 'rowOrder'):
                    assert leg[field] == plan[field], (index, field)
                role = plan['role']
                assert leg['source'] == {**pins[role], 'dirty': False}
                assert leg['native']['configuredMode'] == 'require'
                assert leg['native']['nativePackage'] == protocol['nativePackage']
                assert leg['native']['sha256'] == expected[role]['nativeSha256'], 'wrong native arm'
                assert leg['native']['path'], 'loaded native path is required'
                ordered = list(reversed(descriptors)) if plan['rowOrder'] == 'reverse' else descriptors
                assert list(leg['rows']) == [row['id'] for row in ordered]
                for row in descriptors:
                    measured = leg['rows'][row['id']]
                    assert measured['descriptor'] == row
                    assert measured['warmups'] == 5 and measured['checkedUntimed'] == 1 and measured['callsPerSample'] == 10
                    warm_count += 6
                    raw_samples, means = measured['samples'], measured['sampleMeansUs']
                    assert len(raw_samples) == len(means) == 5
                    for raw, mean in zip(raw_samples, means):
                        assert len(raw) == 10 and all(positive(value) for value in raw) and positive(mean)
                        assert math.isclose(sum(raw) / 10, mean, rel_tol=1e-12, abs_tol=1e-12)
                        sample_count += 1; call_count += 10
                    medians[(plan['block'], plan['position'], row['id'])] = statistics.median(means)
            for row in descriptors:
                assert row['id'] not in seen; seen.add(row['id'])
                logs, strata, quartets = [], {'ABBA': [], 'BAAB': []}, []
                for block in range(1, 9):
                    order = 'ABBA' if block % 2 else 'BAAB'
                    arms = {'A': [], 'B': []}
                    for position, role in enumerate(order, 1):
                        arms[role].append(math.log(medians[(block, position, row['id'])]))
                    ratio_log = math.fsum(arms['B']) / 2 - math.fsum(arms['A']) / 2
                    logs.append(ratio_log); strata[order].append(ratio_log)
                    quartets.append({'block': block, 'order': order, 'ratio': math.exp(ratio_log)})
                paired = math.exp(math.fsum(logs) / 8)
                orders = {key: math.exp(math.fsum(values) / 4) for key, values in strata.items()}
                upper = upper95(logs)
                assert all(positive(value) for value in [paired, upper, *orders.values()])
                outcome = 'hold' if max(paired, *orders.values()) > 1.05 else 'inconclusive' if upper > 1.05 else 'pass'
                report['cells'].append({'id': row['id'], 'cohort': cohort['id'], 'pairedRatio': paired,
                    'orderRatios': orders, 'upper95': upper, 'outcome': outcome, 'quartets': quartets})
        assert len(seen) == 5 and leg_count == 64 and call_count == 8000 and warm_count == 960
        outcomes = [cell['outcome'] for cell in report['cells']]
        report.update(validInput=True, performanceOutcome='hold' if 'hold' in outcomes else 'inconclusive' if 'inconclusive' in outcomes else 'pass',
            completedLegs=leg_count, sampleMeans=sample_count, measuredCalls=call_count, warmupAndCheckedCalls=warm_count,
            nativeSha256={role: expected[role]['nativeSha256'] for role in ('A', 'B')},
            counts={kind: outcomes.count(kind) for kind in ('pass', 'hold', 'inconclusive')})
    except (AssertionError, KeyError, ValueError, TypeError, OSError, OverflowError) as error:
        report['errors'].append(f'{type(error).__name__}: {error}')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, allow_nan=False); stream.write('\n')
    return 0 if report['validInput'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
