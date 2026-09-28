"""Prepare independent source/native/package arms; remote execution only after review."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if not __debug__:
    raise RuntimeError('qualification requires assertions')
packet = Path(__file__).resolve().parent
workspace, work, bootstrap = map(lambda value: Path(value).resolve(), sys.argv[1:])
pins = json.loads((packet / 'pins.json').read_text())
protocol = json.loads((packet / 'protocol.json').read_text())
assert pins['ready'] is True and protocol['ready'] is True
assert sys.platform == 'linux' and os.geteuid() != 0, 'prepare as a nonroot Linux user; conditional tests have a separate root owner'
assert protocol['sourcePins'] == {role: pins[role] for role in ('A', 'B')}
manifest = json.loads((packet / 'packet-manifest.json').read_text())
bootstrap_receipt = json.loads((bootstrap / 'bootstrap.json').read_text())
assert bootstrap_receipt['state'] == 'complete' and bootstrap_receipt['prepareOnly'] is True
assert bootstrap_receipt['processesJoined'] is True
assert bootstrap_receipt['source'] in [{**pins[role], 'dirty': False} for role in ('A', 'B')]
assert hashlib.sha256((bootstrap / 'environment.json').read_bytes()).hexdigest() == bootstrap_receipt['environmentSha256']
bootstrap_environment = json.loads((bootstrap / 'environment.json').read_text())
assert set(bootstrap_environment) == {'PATH', 'NODE22', 'CC_wasm32_unknown_unknown', 'AR_wasm32_unknown_unknown', 'FS_SAFE_PROOF_BOOTSTRAP_JSON'}
assert Path(bootstrap_environment['FS_SAFE_PROOF_BOOTSTRAP_JSON']).resolve() == bootstrap / 'bootstrap.json'
work.mkdir(mode=0o700)
evidence = work / 'evidence'; evidence.mkdir()
processes = evidence / 'processes'; processes.mkdir()
sys.path.insert(0, str(packet / 'harness'))
import bounded
from settlement_control import install
install()
summary = {'state': 'incomplete', 'startedAt': time.time(), 'steps': [], 'sourcePins': protocol['sourcePins']}


def save(path, value):
    temporary = path.with_suffix('.next')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_packet():
    for name, expected in manifest['files'].items():
        assert sha(packet / name) == expected, name


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True, timeout=30).strip()


def verify_sources():
    for role in ('A', 'B'):
        source = workspace / role
        assert git(source, 'rev-parse', 'HEAD') == pins[role]['commit']
        assert git(source, 'rev-parse', 'HEAD^{tree}') == pins[role]['tree']
        assert not git(source, 'status', '--porcelain'), role
        pkg = json.loads((source / 'package.json').read_text())
        assert pkg['version'] == protocol['packageVersion'] and pkg['packageManager'] == protocol['packageManager']


def step(label, command, cap, env, cwd=None):
    verify_packet()
    try:
        bounded.run(processes, label, list(map(str, command)), cap, cwd=str(cwd or work), env=env)
    finally:
        receipt = json.loads((processes / f'{label}.exit.json').read_text())
        summary['steps'].append({'label': label, 'receipt': receipt})
        save(evidence / 'preparation.json', summary)
        assert receipt['localProcessSettled'] is True and not receipt['cleanupErrors'], label


try:
    verify_packet(); verify_sources()
    # Do not forward auth, registry, proxy, NODE_OPTIONS or arbitrary FS_SAFE hooks.
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL', 'RUSTUP_HOME', 'CARGO_HOME') if key in os.environ}
    env.update(bootstrap_environment)
    env.update(CI='true', NODE_DISABLE_COMPILE_CACHE='1', FS_SAFE_TEST_NO_OPENAT2='0')
    retained_bootstrap = evidence / 'toolchain-bootstrap'
    shutil.copytree(bootstrap / 'evidence', retained_bootstrap)
    shutil.copyfile(bootstrap / 'bootstrap.json', retained_bootstrap / 'bootstrap.json')
    shutil.copyfile(bootstrap / 'environment.json', retained_bootstrap / 'environment.json')
    toolchains = bootstrap_receipt['toolchains']
    for item in (toolchains['node22'], toolchains['node24'], toolchains['rust']['compiler'], toolchains['rust']['cargo'], toolchains['llvm']['compiler'], toolchains['llvm']['archiver']):
        assert sha(item['path']) == item['sha256'], item['path']
    assert toolchains['rust']['version'] == '1.98.1'
    assert toolchains['rust']['compiler']['sha256'] == toolchains['rust']['originalCompiler']['sha256']
    assert toolchains['rust']['cargo']['sha256'] == toolchains['rust']['originalCargo']['sha256']
    assert toolchains['rust']['wasm']['libcore']
    for item in toolchains['rust']['wasm']['libcore']:
        assert sha(item['path']) == item['sha256']
    tools = {name: shutil.which(name, path=env.get('PATH')) for name in ('node', 'pnpm', 'cargo', 'rustc', 'cc', 'strace', 'git', 'tar', 'python3')}
    assert all(tools.values()), tools
    tools['node'] = str(Path(tools['node']).resolve())
    node22 = Path(env['NODE22']).resolve(); assert node22.is_file()
    tools['node22'] = str(node22)
    tool_receipts = {name: {'path': str(Path(value).resolve()), 'sha256': sha(Path(value).resolve())} for name, value in tools.items()}
    save(evidence / 'tools.json', tool_receipts)
    for major, node in ((22, tools['node22']), (24, tools['node'])):
        step(f'node{major}-version', [node, '--version'], 30, env)
        assert (processes / f'node{major}-version.stdout.log').read_text().strip() == protocol['nodeVersions'][str(major)]
    step('pnpm-version', [tools['pnpm'], '--version'], 30, env)
    assert 'pnpm@' + (processes / 'pnpm-version.stdout.log').read_text().strip() == protocol['packageManager']
    for name in ('cargo', 'rustc', 'cc', 'strace'):
        step(f'{name}-version', [tools[name], '--version'], 30, env)
    assert tools['node'] == toolchains['node24']['path']
    assert tools['node22'] == toolchains['node22']['path']
    assert str(Path(tools['rustc']).resolve()) == str(Path(toolchains['rust']['compiler']['path']).resolve())
    assert str(Path(tools['cargo']).resolve()) == str(Path(toolchains['rust']['cargo']['path']).resolve())
    save(evidence / 'bootstrap-binding.json', {'bootstrapSha256': sha(bootstrap / 'bootstrap.json'),
        'environmentSha256': bootstrap_receipt['environmentSha256'], 'toolchains': toolchains})
    denial = work / 'deny-openat2'
    source = packet / 'harness/deny-openat2.c'
    assert sha(source) == sha(workspace / 'A/test/fixtures/deny-openat2.c') == sha(workspace / 'B/test/fixtures/deny-openat2.c')
    compile_command = [tools['cc'], str(source), '-o', str(denial)]
    step('compile-deny-wrapper', compile_command, 60, env)
    save(evidence / 'deny-wrapper-build.json', {'sourcePath': str(source), 'sourceSha256': sha(source),
        'binaryPath': str(denial), 'binarySha256': sha(denial), 'compilerPath': tools['cc'],
        'compilerSha256': tool_receipts['cc']['sha256'], 'command': compile_command, 'processLabel': 'compile-deny-wrapper'})
    qualification = json.loads((packet / 'qualification.json').read_text())
    test_binaries = {'schemaVersion': 1, 'pins': pins, 'arms': {}}
    for role in ('A', 'B'):
        source = workspace / role
        build = work / f'build-{role}'; build.mkdir()
        temporary = build / 'tmp'; temporary.mkdir()
        target = build / 'cargo'
        build_env = {**env, 'CARGO_TARGET_DIR': str(target), 'TMPDIR': str(temporary),
            'FS_SAFE_EXPECTED_SOURCE_COMMIT': pins[role]['commit']}
        # Empty npm config files prevent inherited account configuration during builds.
        for setting in ('userconfig', 'globalconfig'):
            config = build / f'{setting}.npmrc'; config.touch()
            build_env[f'npm_config_{setting}'] = str(config)
        step(f'install-{role}', [tools['pnpm'], 'install', '--frozen-lockfile'], protocol['bounds']['installSeconds'], build_env, source)
        step(f'build-{role}', [tools['pnpm'], 'build'], protocol['bounds']['buildSeconds'], build_env, source)
        step(f'native-build-{role}', [tools['pnpm'], 'native:build'], protocol['bounds']['buildSeconds'], build_env, source)
        binary = source / 'native/fs-safe-native.linux-x64-gnu.node'
        assert binary.is_file() and binary.stat().st_size > 0
        assert sha(binary) == sha(source / 'packages/linux-x64-gnu/fs-safe-native.node')
        save(evidence / f'native-build-{role}.json', {'role': role, 'source': {**pins[role], 'dirty': False},
            'separateNativeBuild': True, 'cargoTargetDir': str(target), 'nativeSha256': sha(binary),
            'nativeSourceSha256': sha(source / 'native/src/linux_open.rs'), 'toolReceiptsSha256': sha(evidence / 'tools.json')})
        step(f'native-tests-{role}', [tools['pnpm'], 'native:test', '--locked'], protocol['bounds']['nativeTestsSeconds'], build_env, source)
        # Machine compiler-artifact receipts bind the exact test binary used by the separate root owner.
        step(f'native-test-manifest-{role}', [tools['cargo'], 'test', '-p', 'fs-safe-native', '--lib', '--no-run', '--message-format=json', '--locked'], protocol['bounds']['nativeTestsSeconds'], build_env, source)
        messages = processes / f'native-test-manifest-{role}.stdout.log'
        artifacts = [json.loads(line) for line in messages.read_text().splitlines() if line.strip()]
        artifacts = [row for row in artifacts if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'fs_safe_native' and row.get('profile', {}).get('test') is True and row.get('executable')]
        assert len(artifacts) == 1
        native_test = Path(artifacts[0]['executable']).resolve(); assert native_test.is_relative_to(target) and native_test.is_file()
        test_binaries['arms'][role] = {'cargoMessages': str(messages), 'cargoMessagesSha256': sha(messages),
            'cargoTargetDir': str(target), 'binary': str(native_test), 'binarySha256': sha(native_test)}
        for mechanism, hook in (('normal', '0'), ('hook', '1')):
            source_env = {**build_env, 'FS_SAFE_NATIVE_MODE': 'require', 'FS_SAFE_TEST_NO_OPENAT2': hook}
            step(f'source-{role}-{mechanism}', [tools['pnpm'], 'test', *qualification['sourceTests'], '--maxWorkers=1', '--retry=0', '--reporter=json', '--outputFile', evidence / f'source-{role}-{mechanism}.json'], protocol['bounds']['sourceTestsSeconds'], source_env, source)
        for mechanism in ('ENOSYS', 'EPERM'):
            step(f'seccomp-source-{role}-{mechanism.lower()}', [denial, mechanism, tools['node'], source / 'test/fixtures/linux-openat2-fallback.mjs', binary], 120, {**build_env, 'FS_SAFE_NATIVE_MODE': 'require'}, source)
        step(f'seccomp-parity-{role}', [tools['pnpm'], 'test', 'test/linux-openat2-parity.test.ts', '--maxWorkers=1', '--retry=0', '--reporter=json', '--outputFile', evidence / f'seccomp-parity-{role}.json'], protocol['bounds']['sourceTestsSeconds'], {**build_env, 'FS_SAFE_NATIVE_MODE': 'require', 'FS_SAFE_TEST_OPENAT2_FILTER': str(denial)}, source)
        step(f'full-check-{role}', [tools['pnpm'], 'check'], protocol['bounds']['fullCheckSeconds'], build_env, source)
        step(f'package-{role}', [tools['pnpm'], 'package:smoke', '--output', work / f'packages-{role}'], protocol['bounds']['packageSeconds'], build_env, source)
        verify_sources()
    save(evidence / 'native-test-binaries.json', test_binaries)
    step('source-test-assessment', [sys.executable, packet / 'check-source-tests.py', work], 60, env)
    step('prepare-consumers', [tools['node'], packet / 'prepare-consumers.mjs', workspace, work], 480, env)
    save(evidence / 'runtime-paths.json', {'22': tools['node22'], '24': tools['node'], 'denialWrapper': str(denial)})
    verify_packet(); verify_sources()
    summary['state'] = 'complete'; summary['next'] = 'separate-root-conditional-owner-then-run-study'
except BaseException as error:
    summary['failure'] = repr(error)
    raise
finally:
    summary['finishedAt'] = time.time()
    save(evidence / 'preparation.json', summary)
