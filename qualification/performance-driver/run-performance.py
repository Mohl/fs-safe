#!/usr/bin/env python3
"""Bounded remote performance owner: ACTIVATION_JSON NEW_OUTPUT. No retries/builds."""
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tarfile
import time

assert __debug__ and len(sys.argv) == 3
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
read = lambda file: json.loads(Path(file).read_text())
sha = lambda file: hashlib.sha256(Path(file).read_bytes()).hexdigest()
manifest = read(HERE / 'MANIFEST.json')
for name, digest in manifest['files'].items(): assert sha(HERE / name) == digest, name
frozen = read(HERE / 'source-bindings.json')
activation_file = Path(sys.argv[1]).resolve(strict=True); activation_sha = sha(activation_file)
active = read(activation_file)
assert active['schema'] == 1 and active['study'] == frozen['study']
assert active['launch'] is True and active['executionReady'] is True
assert active['driverManifestSha256'] == sha(HERE / 'MANIFEST.json')
assert sys.platform == 'linux' and platform.machine() == 'x86_64' and os.geteuid() != 0
for name, digest in frozen['helperSha256'].items(): assert sha(HERE / 'support' / name) == digest
sys.path.insert(0, str(HERE / 'support'))
import bounded
import settlement_control
settlement_control.install()
started = time.monotonic(); deadline = started + 2700
work = Path(sys.argv[2]).absolute()
assert work.parent.resolve() == work.parent and not os.path.lexists(work)
assert not any(work.is_relative_to(Path(active['sources'][role]['path'])) for role in ('A', 'B'))
os.umask(0o077); work.mkdir(mode=0o700)
for name in ('processes', 'reports', 'home', 'tmp'): (work / name).mkdir(mode=0o700)
with (work / 'activation.json').open('xb') as stream: stream.write(activation_file.read_bytes())
summary = {'schema': 1, 'study': frozen['study'], 'state': 'incomplete', 'decision': 'HOLD',
           'activationSha256': activation_sha, 'steps': [], 'reports': [], 'startedAt': bounded.now()}
node_env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'),
            'LANG': 'C.UTF-8', 'TZ': 'UTC', 'CI': 'true', 'NODE_ENV': 'production',
            'NODE_DISABLE_COMPILE_CACHE': '1', 'GIT_CONFIG_NOSYSTEM': '1',
            'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0'}
def check_deadline(): assert time.monotonic() < deadline, 'campaign deadline reached'
def write(file, value):
    with Path(file).open('x') as stream: json.dump(value, stream, indent=2); stream.write('\n')
def save():
    temporary = work / 'campaign.next'; temporary.write_text(json.dumps(summary, indent=2) + '\n')
    temporary.replace(work / 'campaign.json')
def referenced(entry):
    file = Path(entry['path']); assert file.is_absolute() and file.resolve(strict=True) == file
    assert sha(file) == entry['sha256'], str(file)
    return file

def inventory(root):
    result = {}
    for file in sorted(root.rglob('*')):
        check_deadline(); assert not file.is_symlink(), file
        if file.is_file(): result[str(file.relative_to(root))] = sha(file)
    return result

def step(label, argv, cap, cwd, env=None):
    check_deadline(); assert sha(activation_file) == activation_sha
    remaining = deadline - time.monotonic() - 8
    assert remaining > 0, 'no settlement budget remains'
    try:
        bounded.run(work / 'processes', label, list(map(str, argv)), min(cap, remaining), cwd=str(cwd), env=env or node_env)
    finally:
        file = work / 'processes' / (label + '.exit.json')
        if file.is_file():
            receipt = read(file); summary['steps'].append({'label': label, 'receipt': receipt}); save()
            assert settlement_control.joined(receipt) and receipt['failure'] is None and receipt['exitCode'] == 0, label
        else: raise RuntimeError('missing settlement receipt: ' + label)
    check_deadline()
    return (work / 'processes' / (label + '.stdout.log')).read_text().strip()

def check_checkout(label, entry, suffix):
    checkout = Path(entry['path']); assert checkout.resolve(strict=True) == checkout
    assert step(label + '-pin-' + suffix, ['git', '-C', checkout, 'rev-parse', 'HEAD', 'HEAD^{tree}'], 30, work).splitlines() == [entry['commit'], entry['tree']]
    assert not step(label + '-clean-' + suffix, ['git', '-C', checkout, 'status', '--porcelain'], 30, work)

def packed_inventory(entry):
    file = referenced(entry); assert file.stat().st_size < 128 * 1024 * 1024
    sri = 'sha512-' + base64.b64encode(hashlib.sha512(file.read_bytes()).digest()).decode()
    assert sri == entry['sha512']
    files, total = {}, 0
    with tarfile.open(file) as archive:
        for member in archive:
            check_deadline(); assert len(files) < 4096
            assert member.name.startswith('package/') and not member.issym() and not member.islnk()
            name = member.name[len('package/'):].rstrip('/')
            assert name and all(part not in ('', '.', '..') for part in name.split('/'))
            if member.isdir(): continue
            assert member.isfile() and name not in files
            total += member.size; assert total <= 512 * 1024 * 1024
            with archive.extractfile(member) as content: files[name] = hashlib.sha256(content.read()).hexdigest()
    assert 'package.json' in files
    return files

try:
    claim = Path(active['attemptClaimPath']); assert claim.is_absolute() and claim.parent.resolve() == claim.parent
    assert not claim.is_relative_to(work)
    protected = [entry['path'] for entry in active['sources'].values()] + [active['harness']['path'], active['performance']['path'], active['functional']['packetPath'], str(HERE)]
    assert all(not claim.is_relative_to(Path(root)) and not work.is_relative_to(Path(root)) for root in protected)
    write(claim, {'study': frozen['study'], 'activationSha256': activation_sha, 'output': str(work), 'startedAt': bounded.now()})
    summary['attemptClaimPath'] = str(claim); save()
    performance = Path(active['performance']['path']).resolve(strict=True)
    assert active['performance']['manifestSha256'] == frozen['performanceManifestSha256'] == sha(performance / 'MANIFEST.json')
    performance_manifest = read(performance / 'MANIFEST.json')
    for name, digest in performance_manifest['files'].items(): assert sha(performance / name) == digest
    plan = read(performance / 'performance-protocol.json')
    assert sha(performance / 'performance-protocol.json') == frozen['protocolSha256']
    assert plan['runner']['processes'] == len(plan['schedule']) == 192
    functional = Path(active['functional']['packetPath']).resolve(strict=True)
    assert sha(functional / 'MANIFEST.json') == active['functional']['packetManifestSha256']
    fm = read(functional / 'MANIFEST.json'); pins = read(functional / 'pins.json')
    assert fm['executionReady'] is True and pins['executionReady'] is True
    normalized = {**pins, 'executionReady': False}
    assert hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == frozen['functionalPinsNormalizedSha256']
    expected_files = {**frozen['functionalFiles'], 'pins.json': sha(functional / 'pins.json')}
    assert fm['files'] == expected_files
    for name, digest in expected_files.items(): assert sha(functional / name) == digest
    ready_file = referenced(active['functional']['readiness']); ready = read(ready_file)
    final_file = referenced(ready['functionalReceipt']); final = read(final_file)
    outer_file = referenced(active['functional']['outerSettlement']); outer = read(outer_file)
    acceptance_file = referenced(active['functional']['audit']); acceptance = read(acceptance_file)
    assert ready['study'] == frozen['study'] and ready['state'] == 'pending-independent-audit-and-declaration-inspection'
    assert ready['launch'] is False and ready['allProcessesJoined'] is True
    assert ready['source'] == pins['sources'] == frozen['sourcePins']
    assert final['state'] == 'complete' and final['allProcessesJoined'] is True and final['sourcePins'] == ready['source']
    assert final['publicSurface'] == ready['publicSurface'] and final['consumers'] == ready['consumers'] and final['runtimes'] == ready['runtimes']
    assert settlement_control.joined(outer) and outer['failure'] is None and outer['exitCode'] == 0
    assert final['steps'] and len([item for item in final['steps'] if item['label'] == 'regression-A']) == 1
    assert len([item for item in final['steps'] if item['label'] == 'candidate-full-check']) == 1
    for role in ('A', 'B'):
        regression = final['regression'][role]
        assert regression['failed'] == (sorted(pins['regression']['baselineExpectedFailures']) if role == 'A' else [])
        assert regression['passed'] == sorted(pins['regression']['baselineExpectedPasses' if role == 'A' else 'candidateExpectedPasses'])
    expected_lanes = {f'{role}-{runtime}-{mode}' for role in ('A', 'B') for runtime in ('node22', 'node24') for mode in ('off', 'require')}
    assert set(final['installed']) == expected_lanes
    for lane in final['installed'].values():
        assert lane['passed'] == len(pins['scenarios']) and sha(lane['report']) == lane['sha256']
    for item in final['steps']:
        expected = 1 if item['label'] == 'regression-A' else 0
        receipt = item['receipt']; assert item['expectedExit'] == expected
        assert settlement_control.joined(receipt) and receipt['failure'] is None and receipt['exitCode'] == expected
    assert acceptance['state'] == 'accepted' and acceptance['study'] == frozen['study'] and acceptance['source'] == ready['source']
    assert acceptance['readinessSha256'] == sha(ready_file) and acceptance['functionalReceiptSha256'] == sha(final_file)
    assert acceptance['outerSettlementSha256'] == sha(outer_file)
    review = acceptance['independentAudit']; referenced(review)
    assert review['result'] == 'PASS' and review['findings'] == [] and acceptance['acceptedBy'] and acceptance['acceptedAt']
    surface = ready['publicSurface']; assert surface['internalDeclarationInspectionAccepted'] is False
    for name in ('publicEntrypointsEqual', 'packageExportsEqual', 'snapshotAndStrictConsumerPassed'):
        assert surface[name] is acceptance['publicSurface'][name] is True
    declaration = acceptance['internalDeclarationInspection']
    assert declaration['accepted'] is True
    assert declaration['changes'] == surface['internalDeclarationChanges'] == pins['expectedInternalDeclarationChanges']
    assert declaration['evidence'] == surface['internalDeclarationEvidence'] == inventory(final_file.parent / 'internal-declarations')
    assert len(declaration['changes']) == 3 and len(declaration['evidence']) == 9
    assert set(declaration['evidence']) == {Path(name).name + suffix for name in declaration['changes'] for suffix in ('.A', '.B', '.patch')}
    assert surface['fullDistChanges'] == sorted(pins['expectedChangedJs'] + pins['expectedInternalDeclarationChanges'])
    boot_file = referenced(ready['bootstrapReceipt']); boot = read(boot_file)
    assert boot['state'] == 'complete' and boot['processesJoined'] and boot['source'] == {**pins['sources']['A'], 'dirty': False}
    runtime = ready['runtimes']['node24']; node = referenced(runtime)
    assert runtime['version'] == pins['nodeVersions']['node24'] == 'v24.21.0'
    assert boot['toolchains']['node24']['path'] == str(node) and boot['toolchains']['node24']['sha256'] == runtime['sha256']
    assert sha(boot_file.parent / 'environment.json') == boot['environmentSha256']
    node_env['PATH'] = str(node.parent) + os.pathsep + node_env['PATH']
    assert step('node-version', [node, '--version'], 30, work) == runtime['version']
    host = active['host']; allowed = sorted(os.sched_getaffinity(0))
    assert all(isinstance(host[key], str) and host[key] for key in ('provider', 'leaseId', 'instanceId'))
    assert allowed == host['allowedCpuMask'] and len(allowed) == os.cpu_count() == 16 and host['cpu'] == min(allowed)
    consumers = ready['consumers']; assert set(consumers) == {'B0', 'B1', 'C0', 'C1'}
    assert len({Path(entry['path']).parent for entry in consumers.values()}) == 1
    assert {Path(entry['path']).name for entry in consumers.values()} == set(consumers)
    artifact_cache = {}
    def verify_consumer(label, entry):
        role = 'A' if label.startswith('B') else 'B'
        assert entry['sourceRole'] == role and {key: entry['source' + key.title()] for key in ('commit', 'tree')} == pins['sources'][role]
        root = Path(entry['path']); package = Path(entry['packageRoot']); dist = Path(entry['dist'])
        assert root.resolve(strict=True) == root and package == root / 'node_modules/@openclaw/fs-safe' and dist == package / 'dist'
        for pathname in (root, package, dist, work):
            assert pathname.stat().st_dev == host['filesystemDevice'] and os.statvfs(pathname).f_bsize == host['filesystemBlockSize']
        expected = read(referenced(entry['inventory']))
        actual = {'dist/' + name: digest for name, digest in inventory(dist).items()}; actual['package.json'] = sha(package / 'package.json')
        assert actual == expected
        assert {name: digest for name, digest in actual.items() if name.endswith('.d.ts')} == surface['allDeclarationHashes'][role]
        lock = read(referenced(entry['lockfile']))['packages']
        for key, package_name in [('packageTarball', '@openclaw/fs-safe'), ('addonTarball', pins['nativePackage'])]:
            artifact = entry[key]; referenced(artifact)
            assert artifact['name'] == package_name
            if artifact['sha256'] not in artifact_cache: artifact_cache[artifact['sha256']] = packed_inventory(artifact)
            target = root / ('node_modules/' + package_name)
            assert inventory(target) == artifact_cache[artifact['sha256']]
            assert lock['node_modules/' + package_name]['integrity'] == artifact['sha512']
            assert lock['node_modules/' + package_name]['version'] == artifact['version']
            assert read(target / 'package.json')['version'] == artifact['version']
        native = entry['nativeAddon']; referenced(native)
        assert native['path'] == str(root / ('node_modules/' + pins['nativePackage'] + '/fs-safe-native.node'))
        assert native['sha256'] == final['nativeBuild']['binarySha256'] and native['packageName'] == pins['nativePackage']
        assert native['packageVersion'] == entry['addonTarball']['version']
        digest_input = '\n'.join(name + sha(dist / name) for name in sorted(file.name for file in dist.iterdir() if file.is_file() and file.suffix in ('.js', '.wasm')))
        assert hashlib.sha256(digest_input.encode()).hexdigest() == entry['distSha256']
        return {'root': actual, 'native': inventory(root / ('node_modules/' + pins['nativePackage'])), 'lockSha256': entry['lockfile']['sha256']}
    assert consumers['B0']['packageTarball'] == consumers['B1']['packageTarball'] and consumers['C0']['packageTarball'] == consumers['C1']['packageTarball']
    assert all(entry['addonTarball'] == final['nativeArtifact'] == consumers['B0']['addonTarball'] for entry in consumers.values())
    assert final['nativeBuild']['source'] == pins['sources']['A'] and final['nativeBuild']['commonInputs'] == pins['nativeCommonInputs']
    for role, entry in active['sources'].items():
        assert role in ('A', 'B') and {key: entry[key] for key in ('commit', 'tree')} == pins['sources'][role]
        check_checkout(role, entry, 'before')
        for name, digest in {**pins['productionSha256'][role], **pins['nativeCommonInputs']}.items(): assert sha(Path(entry['path']) / name) == digest
    before = {label: verify_consumer(label, entry) for label, entry in consumers.items()}; write(work / 'consumers-before.json', before)
    harness = active['harness']; harness_root = Path(harness['path']); check_checkout('harness', harness, 'before')
    hf = performance / 'harness-files.json'; assert sha(hf) == harness['inventorySha256']
    harness_files = read(hf)
    def verify_harness():
        for name, digest in harness_files.items(): assert sha(harness_root / name) == digest
        modules = sorted((harness_root / 'benchmarks').glob('*.mjs'))
        assert {str(file.relative_to(harness_root)) for file in modules} == {name for name in harness_files if name.startswith('benchmarks/') and name.endswith('.mjs')}
        value = hashlib.sha256()
        for file in modules: value.update(file.name.encode()); value.update(file.read_bytes())
        for name in ('package.json', 'pnpm-lock.yaml'): value.update((harness_root / name).read_bytes())
        assert value.hexdigest() == harness['runnerHash']
    verify_harness(); os.sched_setaffinity(0, {host['cpu']}); assert os.sched_getaffinity(0) == {host['cpu']}
    assessor_binding = {**active, 'protocolSha256': frozen['protocolSha256'], 'consumers': consumers,
        'runtime': {'nodePath': str(node), 'nodeVersion': runtime['version'], 'nodeSha256': runtime['sha256']}}
    binding_file = work / 'assessor-binding.json'; write(binding_file, assessor_binding)
    summary['acceptedEvidence'] = {'readinessSha256': sha(ready_file), 'functionalReceiptSha256': sha(final_file),
        'acceptanceSha256': sha(acceptance_file), 'independentAuditSha256': review['sha256'], 'outerSettlementSha256': sha(outer_file)}
    summary['host'] = host; summary['state'] = 'running'; save()
    for slot in plan['schedule']:
        check_deadline(); assert os.sched_getaffinity(0) == {host['cpu']}
        verify_harness(); assert sha(node) == runtime['sha256']
        entry = consumers[slot['arm']]; assert verify_consumer(slot['arm'], entry) == before[slot['arm']]
        report = work / 'reports' / slot['report']; label = f"slot-{slot['ordinal']:03}-{slot['arm']}-{slot['mode']}"
        step(label, [node, harness_root / 'benchmarks/runner.mjs', '--dist', entry['dist'], '--mode', slot['mode'],
            '--filter', plan['runner']['filter'], '--iterations', '20', '--samples', '5', '--warmup', '10', '--json', report], 180,
            harness_root, {**node_env, 'FS_SAFE_NATIVE_MODE': slot['mode']})
        assert verify_consumer(slot['arm'], entry) == before[slot['arm']]
        stderr = work / 'processes' / (label + '.stderr.log')
        summary['reports'].append({'schedule': slot, 'report': str(report), 'reportSha256': sha(report), 'stderr': str(stderr), 'stderrSha256': sha(stderr)})
        save()
    after = {label: verify_consumer(label, entry) for label, entry in consumers.items()}; assert after == before
    write(work / 'consumers-after.json', after); verify_harness(); assert sha(node) == runtime['sha256']
    for role, entry in active['sources'].items(): check_checkout(role, entry, 'after')
    check_checkout('harness', harness, 'after')
    assert sha(ready_file) == active['functional']['readiness']['sha256'] and sha(acceptance_file) == active['functional']['audit']['sha256']
    assert sha(final_file) == ready['functionalReceipt']['sha256'] and sha(outer_file) == active['functional']['outerSettlement']['sha256']
    assert len(summary['reports']) == 192 and [record['schedule'] for record in summary['reports']] == plan['schedule']
    assert sha(performance / 'MANIFEST.json') == frozen['performanceManifestSha256']
    for name, digest in performance_manifest['files'].items(): assert sha(performance / name) == digest
    for name, digest in expected_files.items(): assert sha(functional / name) == digest
    referenced(review); referenced(ready['bootstrapReceipt'])
    receipt_file = work / 'assessment-input.json'
    write(receipt_file, {'state': 'executed', 'bindingSha256': sha(binding_file), 'reports': summary['reports']})
    step('assessment', [sys.executable, '-I', performance / 'assess-performance.py', performance / 'performance-protocol.json',
        binding_file, receipt_file, work / 'assessment.json'], 120, work)
    result = read(work / 'assessment.json'); assert result['state'] == 'complete' and result['decision'] in ('PASS', 'HOLD')
    summary.update(state='complete', decision=result['decision'], assessmentSha256=sha(work / 'assessment.json'), allProcessesJoined=True)
except BaseException as error:
    summary['state'] = 'incomplete'; summary['decision'] = 'HOLD'
    summary['failure'] = repr(error); raise
finally:
    summary['finishedAt'] = bounded.now(); summary['elapsedSeconds'] = time.monotonic() - started; save()
