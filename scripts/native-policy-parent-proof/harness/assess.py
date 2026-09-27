"""Assess one complete platform, without executing product or pooling old data.
CLI: python assess.py linux|win32 LEG_DIRECTORY OUTPUT
Exit zero means valid complete input; performance hold/inconclusive remain data.
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
    platform, directory, output = sys.argv[1:]
    directory, output = Path(directory), Path(output)
    protocol_path = Path(__file__).resolve().parent.parent / 'protocol.json'
    protocol = load(protocol_path)
    assert platform in ('linux', 'win32')
    descriptors = protocol['matrix'][platform]
    schedule = protocol['timing']['schedule']
    report = {'schema': 1, 'platform': platform, 'validInput': False,
              'performanceOutcome': 'inconclusive', 'overallOutcome': 'not-assessed',
              'externalGates': 'Parent must verify source/package/correctness/process/fixture gates.',
              'protocolSha256': sha(protocol_path), 'assessorSha256': sha(__file__),
              'threshold': 1.05, 'bootstrapSeed': 734, 'bootstrapResamples': 100000,
              'cells': [], 'inputs': [], 'errors': []}
    try:
        assert len(schedule) == 32 and len(list(directory.glob('leg-[0-9][0-9].json'))) == 32
        medians, native_hashes = {}, set()
        sample_count = call_count = 0
        for index, plan in enumerate(schedule, 1):
            filename = directory / f'leg-{index:02d}.json'
            leg = load(filename)
            report['inputs'].append({'name': filename.name, 'sha256': sha(filename)})
            assert leg['state'] == 'complete' and leg['cleanup'] is True and leg['platform'] == platform
            for field in ('block', 'position', 'role', 'order', 'rowOrder'):
                assert leg[field] == plan[field], (index, field)
            expected_source = protocol['sourcePins'][plan['role']]
            assert leg['source'] == {**expected_source, 'dirty': False}
            assert leg['native']['configuredMode'] == 'require'
            native_hashes.add(leg['native']['sha256'])
            ordered = list(reversed(descriptors)) if plan['rowOrder'] == 'reverse' else descriptors
            assert list(leg['rows']) == [row['id'] for row in ordered]
            for row in descriptors:
                measured = leg['rows'][row['id']]
                assert measured['descriptor'] == row
                assert measured['warmups'] == 5 and measured['checkedUntimed'] == 1 and measured['callsPerSample'] == 10
                raw_samples, means = measured['samples'], measured['sampleMeansUs']
                assert len(raw_samples) == len(means) == 5
                for raw, mean in zip(raw_samples, means):
                    assert len(raw) == 10 and all(positive(value) for value in raw) and positive(mean)
                    assert math.isclose(sum(raw) / 10, mean, rel_tol=1e-12, abs_tol=1e-12)
                    sample_count += 1
                    call_count += 10
                medians[(plan['block'], plan['position'], row['id'])] = statistics.median(means)
        assert len(native_hashes) == 1, 'both arms must use the same verified native bytes on a host'
        for row in descriptors:
            logs, strata, quartets = [], {'ABBA': [], 'BAAB': []}, []
            for block in range(1, 9):
                order = 'ABBA' if block % 2 else 'BAAB'
                arms = {'A': [], 'B': []}
                for position, role in enumerate(order, 1):
                    arms[role].append(math.log(medians[(block, position, row['id'])]))
                ratio_log = math.fsum(arms['B']) / 2 - math.fsum(arms['A']) / 2
                logs.append(ratio_log)
                strata[order].append(ratio_log)
                quartets.append({'block': block, 'order': order, 'ratio': math.exp(ratio_log)})
            paired = math.exp(math.fsum(logs) / 8)
            orders = {key: math.exp(math.fsum(values) / 4) for key, values in strata.items()}
            upper = upper95(logs)
            assert all(positive(value) for value in [paired, upper, *orders.values()])
            outcome = 'hold' if max(paired, *orders.values()) > 1.05 else 'inconclusive' if upper > 1.05 else 'pass'
            report['cells'].append({'id': row['id'], 'pairedRatio': paired, 'orderRatios': orders,
                                    'upper95': upper, 'outcome': outcome, 'quartets': quartets})
        outcomes = [cell['outcome'] for cell in report['cells']]
        report.update(validInput=True, performanceOutcome='hold' if 'hold' in outcomes else 'inconclusive' if 'inconclusive' in outcomes else 'pass',
                      completedLegs=32, sampleMeans=sample_count, measuredCalls=call_count,
                      commonNativeSha256=next(iter(native_hashes)), counts={kind: outcomes.count(kind) for kind in ('pass', 'hold', 'inconclusive')})
    except (AssertionError, KeyError, ValueError, TypeError, OSError, OverflowError) as error:
        report['errors'].append(f'{type(error).__name__}: {error}')
    with output.open('x', encoding='utf-8') as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write('\n')
    return 0 if report['validInput'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
