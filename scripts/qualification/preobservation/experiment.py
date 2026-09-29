#!/usr/bin/env python3
"""One baseline diagnostic; conditional, unchanged A/B campaign. No retries."""
import json
import math
import os
from pathlib import Path
import statistics
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, PACKET_HASHES, digest, read, require, reserve_budget, run, verify_packet, write

NAMES = ['remove-file', 'remove-empty-directory', 'move-existing-overwrite', 'remove-recursive']
T95_DF11 = 1.795884818703669


def parse_iostat(text, logical_cpus):
    rows = []
    header = None
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[-6:] == ['us', 'sy', 'id', '1m', '5m', '15m']:
            require(len(fields) >= 9 and fields[:-6] == ['KB/t', 'tps', 'MB/s'] * ((len(fields) - 6) // 3),
                    'unexpected iostat disk columns')
            require(header is None or header == fields, 'iostat header changed')
            header = fields
        elif fields[0] in ['cpu', 'load', 'disk0'] or fields[0].startswith('disk'):
            continue
        else:
            require(header is not None and len(fields) == len(header), 'unrecognized iostat row')
            values = [float(item) for item in fields]
            require(all(math.isfinite(item) and item >= 0 for item in values), 'invalid iostat value')
            cpu = values[-6:-3]
            require(all(item <= 100 for item in cpu) and abs(sum(cpu) - 100) <= 2, 'invalid CPU percentages')
            rows.append(dict(disk=[dict(kbPerTransfer=values[i], transfersPerSecond=values[i+1], mbPerSecond=values[i+2])
                                   for i in range(0, len(values) - 6, 3)],
                             cpuUser=cpu[0], cpuSystem=cpu[1], cpuIdle=cpu[2], loads=values[-3:],
                             loadPerCpu=values[-3] / logical_cpus))
    require(len(rows) == 7, 'require initial cumulative row and exactly six five-second intervals')
    return dict(cumulative=rows[0], intervals=rows[1:],
                passed=all(row['cpuIdle'] >= 75 and row['loadPerCpu'] <= 0.5 for row in rows[1:]))


def environmental_admission(output, logical_cpus, deadline):
    output.mkdir(exist_ok=False)
    run(output, 'processes', ['/bin/ps', '-axo', 'pid=,ppid=,pgid=,pcpu=,comm='], deadline=deadline)
    reserve_budget(deadline, 60 + 45)
    started = time.monotonic()
    time.sleep(60)
    write(output / 'quiet.json', dict(requestedSeconds=60, actualSeconds=time.monotonic() - started))
    raw = run(output, 'iostat', ['/usr/sbin/iostat', '-w', '5', '-c', '7'], timeout=45, deadline=deadline)
    parsed = parse_iostat(raw, logical_cpus)
    write(output / 'parsed.json', parsed)
    require(parsed['passed'], 'fixed environmental admission failed; no retry')


def calibration_schedule():
    jobs = []
    for pair in range(1, 13):
        for role in ('BA' if pair % 2 else 'AB'):
            jobs.append(dict(pair=pair, role=role, arm='A', file=f'{len(jobs)+1:02d}-control-{pair:02d}-{role}.json'))
    return jobs


def control_bound(logs):
    require(len(logs) == 12 and all(math.isfinite(value) for value in logs), '12 finite independent pair ratios required')
    mean = statistics.fmean(logs)
    half = T95_DF11 * statistics.stdev(logs) / math.sqrt(12)
    lower, upper = mean - half, mean + half
    return dict(pairCount=12, geometricRatio=math.exp(mean), lower95=math.exp(lower), upper95=math.exp(upper),
                pairRatios=[math.exp(value) for value in logs],
                passed=lower >= -math.log(1.05) and upper <= math.log(1.05))


def analyze_calibration(output):
    plan = read(output / 'plan.json')
    require(plan['jobs'] == calibration_schedule() and plan['packetHashes'] == PACKET_HASHES, 'diagnostic schedule/packet changed')
    require(not (output / 'failure.json').exists(), 'diagnostic process failure')
    expected = plan['expected']
    require(read(output / 'expected-A.json') == expected, 'baseline expectation changed')
    observations = {}
    identities = set()
    for job in plan['jobs']:
        result = read(output / job['file'])
        require(result['schema'] == 1 and result['campaign'] == 'pr770-preobservation-v1', 'wrong measurement protocol')
        require(result['mode'] == 'require' and result['cleanup'] == 'complete', 'require mode and cleanup required')
        require(result['node'] == 'v24.21.0' and result['nodeSha256'] == plan['nodeSha256'] and result['nodePath'] == plan['node'], 'runtime changed')
        require(result['platform'] == 'darwin' and result['arch'] == 'arm64', 'wrong platform')
        require(result['probeSha256'] == PACKET_HASHES['measure.mjs'] and result['packageVersion'] == expected['packageVersion'], 'harness/package changed')
        require(result['native']['sha256'] == expected['nativeSha256'] and result['native']['cache'] is True and result['native']['osImage'] is True,
                'baseline native identity invalid')
        require([row['name'] for row in result['rows']] == NAMES, 'wrong diagnostic endpoints')
        require((result['samples'], result['iterations'], result['warmups']) == (8, 50, 5), 'counts changed')
        identities.add((result['apiPath'], result['apiSha256'], result['distSha256'], result['native']['path'], result['cpu']))
        for row in result['rows']:
            require('skipped' not in row and (row['iterations'], row['warmups'], row['verifiedCalls']) == (50, 5, 405), 'unqualified endpoint')
            values = row['sampleMeansUs']
            require(len(values) == 8 and all(type(v) in [int, float] and math.isfinite(v) and v > 0 for v in values), 'invalid observations')
            observations[job['pair'], job['role'], row['name']] = statistics.fmean(values)
    require(len(identities) == 1, 'installed baseline or CPU changed during diagnostic')
    results = {name: control_bound([math.log(observations[pair, 'B', name] / observations[pair, 'A', name])
                                   for pair in range(1, 13)]) for name in NAMES}
    return dict(processes=24, controlsCleared=all(row['passed'] for row in results.values()), results=results,
                samplesExcluded=0, controlLimits=[1 / 1.05, 1.05], baselineIdentity=list(next(iter(identities))))


def verify_pins(evidence):
    verify_packet()
    for file, expected in read(evidence / 'artifact-pins.json').items():
        require(digest(file) == expected, 'admitted artifact changed: ' + file)


def calibrate(evidence, config, deadline):
    output = evidence / 'calibration'
    output.mkdir(exist_ok=False)
    expected = read(config['A']['expected'])
    write(output / 'expected-A.json', expected)
    plan = dict(jobs=calibration_schedule(), node=config['node'], nodeSha256=digest(config['node']),
                consumer=config['A']['consumer'], expected=expected, packetHashes=PACKET_HASHES)
    write(output / 'plan.json', plan)
    for job in plan['jobs']:
        try:
            verify_packet()
            require(digest(config['node']) == plan['nodeSha256'], 'Node changed')
            require(read(output / 'expected-A.json') == expected, 'baseline expectation changed')
            run(output, Path(job['file']).stem, [config['node'], HERE / 'frozen/measure.mjs', output / 'expected-A.json', output / job['file']],
                cwd=config['A']['consumer'], extra_env=dict(NODE_DISABLE_COMPILE_CACHE='1'), timeout=600, deadline=deadline)
        except Exception as error:
            write(output / 'failure.json', dict(job=job, error=str(error), disposition='inconclusive; no retry'))
            raise
    analysis = analyze_calibration(output)
    write(output / 'analysis.json', analysis)
    return analysis


def main(evidence):
    deadline = time.monotonic() + 3300
    write(evidence / 'resource-budget.json', dict(overallSeconds=3300, reserveForCleanupSeconds=10,
          rule='Reserve each complete command timeout before launch; never shorten a child timeout or retry.'))
    verify_pins(evidence)
    require(read(evidence / 'build-complete.json')['allCommandGroupsTerminal'] is True, 'functional commands not terminal')
    admission = read(evidence / 'admission.json')
    config = read(evidence / 'config.json')
    require(config['A']['consumer'] != config['B']['consumer'], 'separate A/B installations required')
    for name in ['NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'NODE_COMPILE_CACHE', 'FS_SAFE_TEST_NO_OPENAT2']:
        require(name not in os.environ, 'confounding environment: ' + name)
    environmental_admission(evidence / 'admission-calibration', admission['logicalCpus'], deadline)
    calibration = calibrate(evidence, config, deadline)
    verify_pins(evidence)
    require(calibration['controlsCleared'], 'baseline suitability failed; stage two was not launched')
    reserve_budget(deadline, 2700)
    environmental_admission(evidence / 'admission-qualification', admission['logicalCpus'], deadline)
    run(evidence, 'qualification', [sys.executable, '-I', HERE / 'stage2.py', 'run', evidence / 'config.json', evidence / 'qualification'], timeout=2700, deadline=deadline)
    verify_pins(evidence)
    analysis = read(evidence / 'qualification/analysis.json')
    for job in read(evidence / 'qualification/plan.json')['jobs']:
        result = read(evidence / 'qualification' / job['file'])
        require(result['node'] == 'v24.21.0' and result['platform'] == 'darwin' and result['arch'] == 'arm64', 'stage-two scope changed')
        if job['arm'] == 'A':
            identity = [result['apiPath'], result['apiSha256'], result['distSha256'], result['native']['path'], result['cpu']]
            require(identity == calibration['baselineIdentity'], 'baseline changed between stages')
    write(evidence / 'outcome.json', dict(calibration='qualified', qualification=analysis['disposition'],
          scope='Fresh rebuilt artifacts on the admitted macOS 15 arm64 image and four frozen workloads only.',
          previousSharedRunnerResult='inconclusive; unchanged'))
    require(analysis['disposition'] == 'qualified', 'stage two did not qualify; no further campaign')


if __name__ == '__main__':
    require(len(sys.argv) == 2, 'usage: experiment.py EVIDENCE_DIRECTORY')
    evidence = Path(sys.argv[1]).resolve()
    try:
        main(evidence)
    except Exception as error:
        outcome = read(evidence / 'outcome.json')['qualification'] if (evidence / 'outcome.json').exists() else 'inconclusive'
        write(evidence / 'experiment-failure.json', dict(error=str(error), disposition=outcome, retry=False))
        raise
