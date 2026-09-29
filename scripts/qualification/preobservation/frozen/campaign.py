#!/usr/bin/env python3
"""Fixed PR770 packet: python -I campaign.py run CONFIG NEW_DIR | analyze DIR."""
import hashlib, json, math, os, pathlib, statistics, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
NAMES = ['remove-file', 'remove-empty-directory', 'move-existing-overwrite', 'remove-recursive']
T95_DF11 = 1.795884818703669
MARGIN = math.log(1.05)

def require(value, message):
    if not value:
        raise ValueError(message)

def digest(file):
    return hashlib.sha256(pathlib.Path(file).read_bytes()).hexdigest()

def read(file):
    return json.loads(pathlib.Path(file).read_text())

def write(file, value):
    with pathlib.Path(file).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def schedule():
    jobs = []
    for pair in range(1, 13):
        for kind in ['source', 'control']:
            order = 'AB' if (pair % 2 == 1) == (kind == 'source') else 'BA'
            for role in order:
                arm = 'B' if kind == 'source' and role == 'B' else 'A'
                jobs.append(dict(pair=pair, kind=kind, role=role, arm=arm,
                                 file=f'{len(jobs)+1:02d}-{kind}-{pair:02d}-{role}.json'))
    return jobs

def run(config_file, output):
    config = read(config_file)
    output = pathlib.Path(output).resolve()
    node = str(pathlib.Path(config['node']).resolve(strict=True))
    consumers = {arm: str(pathlib.Path(config[arm]['consumer']).resolve(strict=True)) for arm in ['A', 'B']}
    expected = {arm: read(config[arm]['expected']) for arm in ['A', 'B']}
    require(consumers['A'] != consumers['B'], 'source arms need separate installed consumers')
    for name in ['NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'NODE_COMPILE_CACHE', 'FS_SAFE_TEST_NO_OPENAT2']:
        require(name not in os.environ, f'confounding environment variable {name} must be unset')
    hashes = {name: digest(HERE / name) for name in ['measure.mjs', 'campaign.py', 'PROTOCOL.md']}
    output.mkdir(parents=True, exist_ok=False)
    for arm in ['A', 'B']:
        write(output / f'expected-{arm}.json', expected[arm])
    plan = dict(schema=1, campaign='pr770-preobservation-v1', node=node, nodeSha256=digest(node),
                consumers=consumers, expected=expected, packetHashes=hashes, jobs=schedule())
    write(output / 'plan.json', plan)
    env = dict(os.environ, NODE_DISABLE_COMPILE_CACHE='1')
    for job in plan['jobs']:
        require(all(digest(HERE / name) == value for name, value in hashes.items()), 'packet changed')
        require(digest(node) == plan['nodeSha256'], 'Node changed')
        require(read(output / f"expected-{job['arm']}.json") == expected[job['arm']], 'expected artifact changed')
        stem = pathlib.Path(job['file']).stem
        command = [node, str(HERE / 'measure.mjs'), str(output / f"expected-{job['arm']}.json"), str(output / job['file'])]
        try:
            with (output / f'{stem}.stdout').open('xb') as out, (output / f'{stem}.stderr').open('xb') as err:
                result = subprocess.run(command, cwd=consumers[job['arm']], env=env,
                                        stdout=out, stderr=err, timeout=600, check=False)
            require(result.returncode == 0, f'{stem} exited {result.returncode}')
        except Exception as error:
            write(output / 'failure.json', dict(job=job, error=str(error), disposition='inconclusive; no retry'))
            raise
    write(output / 'analysis.json', analyze(output))

def analyze(directory):
    directory = pathlib.Path(directory).resolve()
    plan = read(directory / 'plan.json')
    require(plan['schema'] == 1 and plan['campaign'] == 'pr770-preobservation-v1', 'wrong campaign')
    require(plan['jobs'] == schedule(), 'schedule changed')
    require(not (directory / 'failure.json').exists(), 'campaign stopped or failed')
    require(all(digest(HERE / name) == value for name, value in plan['packetHashes'].items()), 'packet changed')
    observed = {}
    runtimes = set()
    identities = {'A': set(), 'B': set()}
    for job in plan['jobs']:
        result = read(directory / job['file'])
        expected = plan['expected'][job['arm']]
        require(read(directory / f"expected-{job['arm']}.json") == expected, 'expected artifact changed')
        require(result['schema'] == 1 and result['campaign'] == plan['campaign'], 'report protocol changed')
        require(result['mode'] == 'require' and result['cleanup'] == 'complete', 'mode/cleanup invalid')
        require(result['node'].startswith('v24.') and result['nodeSha256'] == plan['nodeSha256'], 'runtime changed')
        require(result['probeSha256'] == plan['packetHashes']['measure.mjs'], 'harness changed')
        require(result['packageVersion'] == expected['packageVersion'], 'package changed')
        require(result['native']['sha256'] == expected['nativeSha256'], 'wrong native binary')
        require(result['native']['cache'] is True and result['native']['osImage'] is True, 'addon not loaded')
        require([row['name'] for row in result['rows']] == NAMES, 'wrong or duplicate endpoints')
        require((result['samples'], result['iterations'], result['warmups']) == (8, 50, 5), 'counts changed')
        runtimes.add((result['node'], result['nodePath'], result['platform'], result['arch'], result['cpu']))
        identities[job['arm']].add((result['apiPath'], result['distSha256'], result['native']['path'], result['native']['sha256']))
        for row in result['rows']:
            key = (job['kind'], job['pair'], job['role'], row['name'])
            if result['platform'] == 'win32' and row['name'] == 'remove-recursive':
                require(row == dict(name='remove-recursive', skipped='documented unsupported Windows require-mode recursive removal'), 'Windows skip changed')
                continue
            require('skipped' not in row, 'unexpected skip')
            require((row['iterations'], row['warmups'], row['verifiedCalls']) == (50, 5, 405), 'row counts changed')
            values = row['sampleMeansUs']
            require(len(values) == 8 and all(isinstance(v, (int, float)) and math.isfinite(v) and v > 0 for v in values), 'invalid means')
            observed[key] = statistics.fmean(values)
    require(len(runtimes) == 1, 'platform/runtime changed across campaign')
    require(all(len(values) == 1 for values in identities.values()), 'installed artifact changed across campaign')
    platform = next(iter(runtimes))[2]
    names = NAMES[:3] if platform == 'win32' else NAMES
    results = {}
    for kind in ['source', 'control']:
        results[kind] = {}
        for name in names:
            logs = [math.log(observed[(kind, pair, 'B', name)] / observed[(kind, pair, 'A', name)]) for pair in range(1, 13)]
            mean = statistics.fmean(logs)
            half = T95_DF11 * statistics.stdev(logs) / math.sqrt(12)
            lower, upper = mean - half, mean + half
            passed = upper <= MARGIN if kind == 'source' else lower >= -MARGIN and upper <= MARGIN
            results[kind][name] = dict(pairCount=12, geometricRatio=math.exp(mean), lower95=math.exp(lower),
                                       upper95=math.exp(upper), pairRatios=[math.exp(v) for v in logs], passed=passed)
    controls = all(row['passed'] for row in results['control'].values())
    sources = all(row['passed'] for row in results['source'].values())
    regression = any(row['lower95'] > 1.05 for row in results['source'].values())
    disposition = 'qualified' if controls and sources else 'material-regression' if controls and regression else 'inconclusive'
    return dict(schema=1, campaign=plan['campaign'], platform=platform, processes=48, disposition=disposition,
                sourceCleared=sources, controlsCleared=controls, results=results,
                sourceLimit=1.05, controlLimits=[1 / 1.05, 1.05], samplesExcluded=0)

if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == 'run':
        run(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == 'analyze':
        print(json.dumps(analyze(sys.argv[2]), indent=2))
    else:
        raise SystemExit('usage: python -I campaign.py run CONFIG NEW_DIR | analyze DIR')
