#!/usr/bin/env python3
"""Remote functional proof only: CLEAN_A CLEAN_B NEW_OUTPUT. Never invokes timing."""
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import tarfile

assert __debug__ and len(sys.argv) == 4
assert sys.platform == 'linux' and platform.machine() == 'x86_64' and os.geteuid() != 0
assert os.cpu_count() == len(os.sched_getaffinity(0)) == 16
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
read = lambda file: json.loads(Path(file).read_text())
sha = lambda file: hashlib.sha256(Path(file).read_bytes()).hexdigest()
pins = read(HERE / 'pins.json'); manifest = read(HERE / 'MANIFEST.json')
assert pins['executionReady'] is True and manifest['executionReady'] is True
assert pins['study'] == 'root-exact-identity-domain-v2'
for name, digest in manifest['files'].items(): assert sha(HERE / name) == digest, name
sources = {role: Path(value).resolve(strict=True) for role, value in zip(('A', 'B'), sys.argv[1:3])}
work = Path(sys.argv[3]).absolute()
assert work.parent.resolve() == work.parent and not os.path.lexists(work)
assert all(not work.is_relative_to(source) for source in sources.values())
sys.path.insert(0, str(HERE / 'bootstrap/harness'))
import bounded
import settlement_control
settlement_control.install()
work.mkdir(mode=0o700)
for name in ('evidence', 'home', 'tmp', 'tool-bin', 'cargo-home', 'consumers'): (work / name).mkdir(mode=0o700)
evidence = work / 'evidence'; processes = evidence / 'processes'
summary = {'schema': 1, 'study': pins['study'], 'state': 'incomplete', 'qualificationReady': False,
           'sourcePins': pins['sources'], 'steps': [], 'installed': {}, 'startedAt': bounded.now()}
env = {'PATH': os.environ['PATH'], 'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'),
       'LANG': 'C.UTF-8', 'CI': 'true', 'NODE_DISABLE_COMPILE_CACHE': '1',
       'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_TERMINAL_PROMPT': '0',
       'COREPACK_HOME': str(work / 'corepack-home'), 'COREPACK_ENABLE_DOWNLOAD_PROMPT': '0',
       'COREPACK_DEFAULT_TO_LATEST': '0', 'npm_config_update_notifier': 'false'}
assert all(Path(part).is_absolute() for part in env['PATH'].split(os.pathsep))
def write(file, value):
    with Path(file).open('x') as stream: json.dump(value, stream, indent=2); stream.write('\n')
def save():
    temporary = evidence / 'functional.next'; temporary.write_text(json.dumps(summary, indent=2) + '\n')
    temporary.replace(evidence / 'functional.json')
def step(label, argv, cap, cwd=work, child_env=None, expected_exit=0):
    for name, digest in manifest['files'].items(): assert sha(HERE / name) == digest, name
    try:
        bounded.run(processes, label, list(map(str, argv)), cap, cwd=str(cwd), env=child_env or env,
                    required=expected_exit == 0)
    finally:
        file = processes / (label + '.exit.json')
        if file.is_file():
            receipt = read(file); summary['steps'].append({'label': label, 'expectedExit': expected_exit, 'receipt': receipt}); save()
            assert settlement_control.joined(receipt) and receipt['failure'] is None, label
            assert receipt['exitCode'] == expected_exit, label
        else: raise RuntimeError('missing settlement receipt: ' + label)
    return (processes / (label + '.stdout.log')).read_text().strip()
def check_source(role, suffix):
    source = sources[role]; pin = pins['sources'][role]
    assert step(role + '-pin-' + suffix, ['git', '-C', source, 'rev-parse', 'HEAD', 'HEAD^{tree}'], 30).splitlines() == [pin['commit'], pin['tree']]
    assert not step(role + '-clean-' + suffix, ['git', '-C', source, 'status', '--porcelain'], 30)
    for name, digest in pins['productionSha256'][role].items(): assert sha(source / name) == digest
def inventory(root):
    result = {}
    for file in sorted(root.rglob('*')):
        assert not file.is_symlink(), file
        if file.is_file(): result[str(file.relative_to(root))] = sha(file)
    return result
def artifact(file, name, version):
    return {'path': str(file), 'name': name, 'version': version, 'sha256': sha(file),
            'sha512': 'sha512-' + base64.b64encode(hashlib.sha512(file.read_bytes()).digest()).decode()}
def assert_consumer(entry):
    package = Path(entry['packageRoot']); assert package.resolve() == package
    assert sha(entry['inventory']['path']) == entry['inventory']['sha256']
    expected = read(entry['inventory']['path'])
    actual = {'dist/' + name: digest for name, digest in inventory(package / 'dist').items()}
    actual['package.json'] = sha(package / 'package.json'); assert actual == expected
    assert sha(entry['lockfile']['path']) == entry['lockfile']['sha256']
    locked = read(entry['lockfile']['path'])['packages']
    for name, key in [('@openclaw/fs-safe', 'packageTarball'), (pins['nativePackage'], 'addonTarball')]:
        assert locked['node_modules/' + name]['integrity'] == entry[key]['sha512']
        assert locked['node_modules/' + name]['version'] == entry[key]['version']
        assert sha(entry[key]['path']) == entry[key]['sha256']
    assert sha(entry['nativeAddon']['path']) == entry['nativeAddon']['sha256']
    return {'inventorySha256': entry['inventory']['sha256'], 'lockSha256': entry['lockfile']['sha256'], 'nativeSha256': entry['nativeAddon']['sha256']}

try:
    for role in ('A', 'B'): check_source(role, 'initial')
    for role in ('A', 'B'):
        for name, digest in pins['nativeCommonInputs'].items(): assert sha(sources[role] / name) == digest, name
        for name, digest in pins['commonSuites'].items(): assert sha(sources[role] / name) == digest, name
    regression = pins['regression']; assert sha(sources['B'] / regression['path']) == regression['sha256']
    assert not (sources['A'] / regression['path']).exists()
    step('bootstrap', [sys.executable, '-I', HERE / 'bootstrap/bootstrap-toolchains.py', '--prepare-only', sources['A'], work / 'bootstrap'], 1800)
    boot = read(work / 'bootstrap/bootstrap.json'); assert boot['state'] == 'complete' and boot['processesJoined']
    assert boot['source'] == {**pins['sources']['A'], 'dirty': False}
    assert sha(work / 'bootstrap/environment.json') == boot['environmentSha256']
    env.update(read(work / 'bootstrap/environment.json')); env['CARGO_HOME'] = str(work / 'cargo-home')
    runtimes = {key: {'path': value['path'], 'sha256': value['sha256'], 'version': pins['nodeVersions'][key]}
                for key, value in boot['toolchains'].items() if key in ('node22', 'node24')}
    assert set(runtimes) == {'node22', 'node24'}
    for key, value in runtimes.items():
        assert sha(value['path']) == value['sha256']; assert step(key + '-version', [value['path'], '--version'], 30) == value['version']
    node = Path(runtimes['node24']['path']); npm = node.parent.parent / 'lib/node_modules/npm/bin/npm-cli.js'
    assert npm.is_file(); env['PATH'] = str(node.parent) + os.pathsep + env['PATH']
    corepack = shutil.which('corepack', path=env['PATH']); assert corepack
    step('corepack-enable', [corepack, 'enable', '--install-directory', work / 'tool-bin', 'pnpm'], 60)
    step('corepack-pin', [corepack, 'prepare', pins['packageManager'], '--activate'], 180)
    env['PATH'] = str(work / 'tool-bin') + os.pathsep + env['PATH']; pnpm = work / 'tool-bin/pnpm'
    assert 'pnpm@' + step('pnpm-version', [pnpm, '--version'], 30) == pins['packageManager']
    for role, source in sources.items(): step('install-' + role, [pnpm, 'install', '--frozen-lockfile'], 600, cwd=source)
    native_env = {**env, 'CARGO_TARGET_DIR': str(work / 'native-target')}
    step('native-build-common', [pnpm, 'native:build'], 1200, cwd=sources['A'], child_env=native_env)
    binary_relative = 'native/fs-safe-native.linux-x64-gnu.node'; package_binary = 'packages/linux-x64-gnu/fs-safe-native.node'
    binary = sources['A'] / binary_relative; native_sha = sha(binary)
    assert sha(sources['A'] / package_binary) == native_sha
    for name, digest in pins['nativeCommonInputs'].items():
        assert sha(sources['A'] / name) == sha(sources['B'] / name) == digest, name
    for name in (binary_relative, package_binary):
        destination = sources['B'] / name; assert not destination.exists(); shutil.copyfile(binary, destination); assert sha(destination) == native_sha
    summary['nativeBuild'] = {'source': pins['sources']['A'], 'commonInputs': pins['nativeCommonInputs'],
        'binarySha256': native_sha, 'stagedIntoB': [binary_relative, package_binary],
        'reason': 'All native/Cargo/build inputs match; one fresh binary keeps native code identical across JS comparisons.'}
    save()
    step('candidate-full-check', [pnpm, 'check'], 2700, cwd=sources['B'], child_env={**env, 'FS_SAFE_TEST_SERIAL': '1', 'CARGO_TARGET_DIR': str(work / 'wasm-B')})
    common_reports = {}
    for role, source in sources.items():
        output = evidence / ('focused-' + role + '.json')
        step('focused-' + role, [pnpm, 'test', *pins['commonSuites'], '--maxWorkers=1', '--retry=0', '--reporter=json', '--outputFile', output], 600,
             cwd=source, child_env={**env, 'FS_SAFE_NATIVE_MODE': 'off'})
        report = read(output); assert report['success'] and len(report['testResults']) == len(pins['commonSuites'])
        cases = [case for suite in report['testResults'] for case in suite['assertionResults']]
        assert cases and all(case['status'] == 'passed' for case in cases)
        common_reports[role] = sorted(case['fullName'] for case in cases)
    assert common_reports['A'] == common_reports['B']; summary['focusedCaseNames'] = common_reports['A']
    baseline_tests = work / 'baseline-test-overlay'
    step('baseline-overlay-checkout', ['git', '-C', sources['A'], 'worktree', 'add', '--detach', baseline_tests, pins['sources']['A']['commit']], 90)
    overlay = baseline_tests / regression['path']; assert not overlay.exists(); overlay.write_bytes((sources['B'] / regression['path']).read_bytes())
    step('baseline-overlay-dependencies', [pnpm, 'install', '--frozen-lockfile'], 600, cwd=baseline_tests)
    assert step('baseline-overlay-status', ['git', '-C', baseline_tests, 'status', '--porcelain'], 30) == '?? ' + regression['path']
    summary['regression'] = {}
    for role, source, expected_exit in [('A', baseline_tests, 1), ('B', sources['B'], 0)]:
        assert sha(source / regression['path']) == regression['sha256']
        output = evidence / ('regression-' + role + '.json')
        step('regression-' + role, [pnpm, 'test', regression['path'], '--maxWorkers=1', '--retry=0', '--reporter=json', '--outputFile', output], 300,
             cwd=source, child_env={**env, 'FS_SAFE_NATIVE_MODE': 'off'}, expected_exit=expected_exit)
        report = read(output); cases = [case for suite in report['testResults'] for case in suite['assertionResults']]
        assert len(report['testResults']) == 1 and len(cases) == 12
        failed = sorted(case['title'] for case in cases if case['status'] == 'failed'); passed = sorted(case['title'] for case in cases if case['status'] == 'passed')
        assert len(failed) + len(passed) == 12
        assert failed == (sorted(regression['baselineExpectedFailures']) if role == 'A' else [])
        assert passed == sorted(regression['baselineExpectedPasses' if role == 'A' else 'candidateExpectedPasses'])
        summary['regression'][role] = {'passed': passed, 'failed': failed, 'expectedExit': expected_exit, 'reportSha256': sha(output)}
    assert sha(overlay) == regression['sha256']; overlay.unlink()
    assert not step('baseline-overlay-final', ['git', '-C', baseline_tests, 'status', '--porcelain'], 30)
    def isolated(label, source, directory):
        script = "import{pathToFileURL}from'node:url';const{isolatedConsumerEnv}=await import(pathToFileURL(process.argv[1]));console.log(JSON.stringify(isolatedConsumerEnv(process.argv[2])));"
        return read_json_output(step(label, [node, '--input-type=module', '-e', script, source / 'scripts/consumer-install-smoke.mjs', directory], 30))
    def read_json_output(value): return json.loads(value)
    artifacts = {}; distributions = {}; exports = {}
    for role, source in sources.items():
        check_source(role, 'before-package')
        step('build-' + role, [pnpm, 'build'], 900, cwd=source, child_env={**env, 'CARGO_TARGET_DIR': str(work / ('wasm-' + role))})
        destination = work / ('packages-' + role); destination.mkdir()
        step('pack-' + role, [node, npm, 'pack', '--json', '--ignore-scripts', '--pack-destination', destination], 180,
             cwd=source, child_env=isolated('pack-env-' + role, source, destination / 'config'))
        tarball, = destination.glob('*.tgz'); pkg = read(source / 'package.json')
        artifacts[role] = artifact(tarball, pkg['name'], pkg['version']); exports[role] = pkg['exports']
        distributions[role] = {'dist/' + name: digest for name, digest in inventory(source / 'dist').items()}
        with tarfile.open(tarball) as archive: assert json.load(archive.extractfile('package/package.json')) == pkg
    native_dir = work / 'native-package'; native_dir.mkdir()
    step('pack-native', [node, npm, 'pack', '--json', '--ignore-scripts', '--pack-destination', native_dir], 180,
         cwd=sources['A'] / 'packages/linux-x64-gnu', child_env=isolated('native-pack-env', sources['A'], native_dir / 'config'))
    native_tar, = native_dir.glob('*.tgz'); native_package = read(sources['A'] / 'packages/linux-x64-gnu/package.json')
    native_artifact = artifact(native_tar, pins['nativePackage'], native_package['version'])
    assert exports['A'] == exports['B']
    dist_changes = sorted(name for name in set(distributions['A']) | set(distributions['B'])
                          if distributions['A'].get(name) != distributions['B'].get(name))
    distribution_evidence = evidence / 'distribution-difference.json'
    write(distribution_evidence, {'changedFiles': dist_changes, 'inventories': distributions})
    summary['distributionDifference'] = {'path': str(distribution_evidence), 'sha256': sha(distribution_evidence)}
    save()
    assert dist_changes == sorted(pins['expectedChangedJs'] + pins['expectedInternalDeclarationChanges']), dist_changes
    declarations = {role: {name: digest for name, digest in values.items() if name.endswith('.d.ts')} for role, values in distributions.items()}
    assert set(declarations['A']) == set(declarations['B'])
    declaration_changes = sorted(name for name in declarations['A'] if declarations['A'][name] != declarations['B'][name])
    assert declaration_changes == pins['expectedInternalDeclarationChanges']
    declaration_dir = evidence / 'internal-declarations'; declaration_dir.mkdir()
    for name in declaration_changes:
        before = (sources['A'] / name).read_text(); after = (sources['B'] / name).read_text()
        (declaration_dir / (Path(name).name + '.A')).write_text(before); (declaration_dir / (Path(name).name + '.B')).write_text(after)
        (declaration_dir / (Path(name).name + '.patch')).write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='A/' + name, tofile='B/' + name)))
    public_paths = [target['types'] for target in exports['A'].values() if isinstance(target, dict) and 'types' in target]
    assert public_paths and all(distributions['A'][name.removeprefix('./')] == distributions['B'][name.removeprefix('./')] for name in public_paths)
    summary['publicSurface'] = {'publicEntrypointsEqual': True, 'packageExportsEqual': True,
        'internalDeclarationChanges': declaration_changes, 'internalDeclarationInspectionAccepted': False,
        'internalDeclarationEvidence': inventory(declaration_dir), 'allDeclarationHashes': declarations,
        'fullDistChanges': dist_changes}
    consumers = {}
    for label, role in [('B0', 'A'), ('B1', 'A'), ('C0', 'B'), ('C1', 'B')]:
        consumer = work / 'consumers' / label; consumer.mkdir(mode=0o700); write(consumer / 'package.json', {'private': True, 'type': 'module'})
        step('consumer-install-' + label, [node, npm, 'install', '--ignore-scripts', '--omit=optional', '--offline', '--no-audit', '--no-fund', artifacts[role]['path'], native_artifact['path']], 180,
             cwd=consumer, child_env=isolated('consumer-env-' + label, sources[role], consumer / 'config'))
        package = consumer / 'node_modules/@openclaw/fs-safe'; dist = package / 'dist'
        native_installed = consumer / ('node_modules/' + pins['nativePackage'] + '/fs-safe-native.node')
        assert native_installed.resolve() == native_installed and sha(native_installed) == native_sha
        files = dict(distributions[role]); files['package.json'] = sha(sources[role] / 'package.json')
        inv = consumer / 'inventory.json'; write(inv, files)
        digest_input = '\n'.join(name + sha(dist / name) for name in sorted(file.name for file in dist.iterdir() if file.is_file() and file.suffix in ('.js', '.wasm')))
        entry = {'path': str(consumer), 'packageRoot': str(package), 'dist': str(dist), 'distSha256': hashlib.sha256(digest_input.encode()).hexdigest(),
            'sourceRole': role, 'sourceCommit': pins['sources'][role]['commit'], 'sourceTree': pins['sources'][role]['tree'],
            'packageTarball': artifacts[role], 'addonTarball': native_artifact,
            'nativeAddon': {'path': str(native_installed), 'sha256': native_sha, 'packageName': pins['nativePackage'], 'packageVersion': native_package['version']},
            'inventory': {'path': str(inv), 'sha256': sha(inv)}, 'lockfile': {'path': str(consumer / 'package-lock.json'), 'sha256': sha(consumer / 'package-lock.json')},
            'runtimes': runtimes, 'scenarioNames': pins['scenarios'], 'probeSha256': sha(HERE / 'installed-proof.mjs')}
        write(consumer / 'expected.json', entry); assert_consumer(entry); consumers[label] = entry
    summary['consumers'] = consumers; summary['runtimes'] = runtimes; summary['nativeArtifact'] = native_artifact
    public_reports = {}
    for label, role in [('B0', 'A'), ('C0', 'B')]:
        project = work / ('types-' + role); output = evidence / ('public-' + role + '.json')
        report = json.loads(step('public-api-' + role, [node, HERE / 'installed-public-api.mjs', sources[role], consumers[label]['path'], project, output], 180))
        assert report == read(output) and report['snapshotPassed'] and report['privateSubpathsDenied']
        command = report['typecheck']['command']; assert Path(command[0]).resolve() == node.resolve()
        for key in ('compiler', 'configuration', 'probe'): assert sha(report['typecheck'][key]) == report['typecheck'][key + 'Sha256']
        step('consumer-typecheck-' + role, command, 180, cwd=project); public_reports[role] = report['actual']
    assert public_reports['A'] == public_reports['B']; summary['publicSurface']['snapshotAndStrictConsumerPassed'] = True
    for runtime_key, runtime in runtimes.items():
        for label, role in [('B0', 'A'), ('C0', 'B')]:
            for mode in ('off', 'require'):
                lane = role + '-' + runtime_key + '-' + mode; output = evidence / ('installed-' + lane + '.json'); entry = consumers[label]
                report = json.loads(step('installed-' + lane, [runtime['path'], HERE / 'installed-proof.mjs', entry['path'], Path(entry['path']) / 'expected.json', mode, runtime_key, output], 180,
                    cwd=Path(entry['path']), child_env={**env, 'NODE_ENV': 'test', 'FS_SAFE_NATIVE_MODE': mode}))
                assert report == read(output) and report['complete'] and report['fixtureRemoved'] and report['loaderRestored']
                assert report['mode'] == mode and report['runtime'] == runtime
                assert [row['name'] for row in report['scenarios']] == pins['scenarios']
                assert all(row['passed'] and row['hooksRestored'] and row['fdBefore'] == row['fdAfter'] for row in report['scenarios'])
                assert report['fdBefore'] == report['fdAfter']
                assert report['nativeLoads'] == ([{'path': entry['nativeAddon']['path'], 'sha256': native_sha}] if mode == 'require' else [])
                attempts = report['nativeLoadAttempts']
                assert len(attempts) == (1 if mode == 'require' else 0)
                assert all(item['succeeded'] is True and item['path'] == entry['nativeAddon']['path'] for item in attempts)
                assert report['nativePreflight']['attempts'] == (1 if mode == 'require' else 0)
                assert report['nativePreflight']['loads'] == (1 if mode == 'require' else 0)
                assert report['nativePreflight']['observeDirectoryCalls'] > 0 if mode == 'require' else report['observeDirectoryCalls'] == 0
                summary['installed'][lane] = {'passed': len(report['scenarios']), 'report': str(output), 'sha256': sha(output)}
    summary['finalConsumers'] = {label: assert_consumer(entry) for label, entry in consumers.items()}
    for role in ('A', 'B'):
        check_source(role, 'final')
        for name, digest in pins['nativeCommonInputs'].items(): assert sha(sources[role] / name) == digest
    for runtime in runtimes.values(): assert sha(runtime['path']) == runtime['sha256']
    assert all(settlement_control.joined(item['receipt']) and item['receipt']['exitCode'] == item['expectedExit'] for item in summary['steps'])
    summary.update(state='complete', allProcessesJoined=True, completedAt=bounded.now(),
        disposition='Functional execution complete; parent must inspect three internal declaration diffs and independent evidence before performance readiness.')
    write(evidence / 'functional-final.json', summary)
    write(work / 'readiness-candidate.json', {'schema': 1, 'study': pins['study'], 'state': 'pending-independent-audit-and-declaration-inspection',
        'launch': False, 'source': pins['sources'], 'runtimes': runtimes, 'consumers': consumers,
        'functionalReceipt': {'path': str(evidence / 'functional-final.json'), 'sha256': sha(evidence / 'functional-final.json')},
        'bootstrapReceipt': {'path': str(work / 'bootstrap/bootstrap.json'), 'sha256': sha(work / 'bootstrap/bootstrap.json')},
        'publicSurface': summary['publicSurface'], 'allProcessesJoined': True})
except BaseException as error:
    summary['failure'] = repr(error); raise
finally:
    summary['finishedAt'] = bounded.now(); save()
