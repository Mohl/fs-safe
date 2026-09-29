#!/usr/bin/env python3
"""Admit the pinned runner, build both sources, and retain the complete proof."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import HERE, SOURCES, digest, pin_files, read, require, run, verify_packet, write

EVIDENCE = Path(os.environ['EVIDENCE_ROOT']).resolve()
WORKSPACE = Path(os.environ['GITHUB_WORKSPACE']).resolve()


def source_receipt(source, expected, output, label):
    head = run(output, label + '-head', ['git', 'rev-parse', 'HEAD'], cwd=source).strip()
    require(head == expected, 'source HEAD mismatch')
    require(not run(output, label + '-status', ['git', 'status', '--porcelain', '--untracked-files=no'], cwd=source).strip(),
            'tracked source changes')
    tree = run(output, label + '-tree', ['git', 'rev-parse', 'HEAD^{tree}'], cwd=source).strip()
    manifest = run(output, label + '-files', ['git', 'ls-tree', '-rz', 'HEAD'], cwd=source)
    files = {}
    for entry in manifest.rstrip('\0').split('\0'):
        metadata, relative = entry.split('\t', 1)
        mode, kind, blob = metadata.split()
        file = source / relative
        require(kind == 'blob' and mode in ['100644', '100755', '120000'], 'unsupported source entry')
        require(file.is_symlink() == (mode == '120000'), 'source file kind changed')
        payload = os.readlink(file).encode() if file.is_symlink() else file.read_bytes()
        observed = hashlib.sha1(f'blob {len(payload)}\0'.encode() + payload).hexdigest()
        require(observed == blob, 'source bytes differ from Git blob: ' + relative)
        if mode != '120000':
            require(bool(file.stat().st_mode & 0o111) == (mode == '100755'), 'source executable mode changed')
        files[relative] = dict(mode=mode, blob=blob, sha256=hashlib.sha256(payload).hexdigest())
    write(output / (label + '-source.json'), dict(head=head, tree=tree, files=files))
    return dict(head=head, tree=tree, trackedFileCount=len(files))


def admit():
    EVIDENCE.mkdir(exist_ok=False)
    verify_packet()
    expected = os.environ['EXPECTED_HARNESS_SHA']
    require(re.fullmatch('[0-9a-f]{40}', expected), 'expected carrier must be an exact commit')
    require(expected == os.environ['WORKFLOW_SHA'], 'dispatch must execute the reviewed workflow commit')
    require(os.environ['GITHUB_RUN_ATTEMPT'] == '1', 'reruns are not part of this one-shot procedure')
    require(os.environ.get('ImageVersion') and os.environ.get('ImageOS'), 'runner image metadata required')
    harness = source_receipt(WORKSPACE / 'harness', expected, EVIDENCE, 'carrier')
    require(run(EVIDENCE, 'architecture', ['uname', '-m']).strip() == 'arm64', 'arm64 runner required')
    version = run(EVIDENCE, 'os-version', ['sw_vers', '-productVersion']).strip()
    require(version.split('.')[0] == '15', 'macOS 15 required')
    run(EVIDENCE, 'os-build', ['sw_vers'])
    cpus = int(run(EVIDENCE, 'logical-cpus', ['sysctl', '-n', 'hw.logicalcpu']).strip())
    require(cpus > 0 and os.getuid() != 0, 'non-root runner and logical CPU count required')
    run(EVIDENCE, 'cpu-model', ['sysctl', '-n', 'machdep.cpu.brand_string'])
    fixture = Path(os.environ['RUNNER_TEMP']) / 'preobservation-fixtures'
    fixture.mkdir(exist_ok=False)
    disk = run(EVIDENCE, 'fixture-disk', ['/bin/df', '-k', fixture]).splitlines()[1].split()[0]
    require(disk.startswith('/dev/'), 'expected a local fixture volume')
    run(EVIDENCE, 'fixture-volume', ['/usr/sbin/diskutil', 'info', '-plist', disk])
    shutil.copytree(HERE, EVIDENCE / 'carrier-packet', ignore=shutil.ignore_patterns('__pycache__'))
    write(EVIDENCE / 'admission.json', dict(carrier=harness, platform='darwin', arch='arm64', osVersion=version,
          logicalCpus=cpus, fixtureDirectory=str(fixture), uid=os.getuid(), provider='github-actions',
          runId=os.environ['GITHUB_RUN_ID'], runAttempt=os.environ['GITHUB_RUN_ATTEMPT'],
          job=os.environ['GITHUB_JOB'], imageVersion=os.environ.get('ImageVersion'),
          runnerImage=os.environ.get('ImageOS'), packetHashes=pin_files(EVIDENCE / 'carrier-packet')))
    with Path(os.environ['GITHUB_ENV']).open('a') as stream:
        stream.write(f'TMPDIR={fixture}\n')


def check_integration(file):
    result = read(file)
    require(result['success'] is True and result['numFailedTests'] == 0, 'native integration failed')
    require(result['numTotalTests'] == 26 and result['numPassedTests'] == 25 and result['numPendingTests'] == 1,
            'native integration coverage changed')
    pending = [row['title'] for suite in result['testResults'] for row in suite['assertionResults'] if row['status'] != 'passed']
    require(pending == ['fails closed for unsupported Windows recursive directories'], 'unexpected native integration skip')


def snapshot_consumer(consumer, output, name):
    output.mkdir(parents=True, exist_ok=True)
    files = pin_files(consumer)
    write(output / (name + '-files.json'), files)
    with tarfile.open(output / (name + '.tar.gz'), 'x:gz') as archive:
        archive.add(consumer, arcname='consumer')
    return files


def build():
    verify_packet()
    admission = read(EVIDENCE / 'admission.json')
    require(Path(os.environ['TMPDIR']).resolve() == Path(admission['fixtureDirectory']), 'fixture volume changed')
    for name in ['NODE_OPTIONS', 'NODE_PATH', 'NODE_V8_COVERAGE', 'NODE_COMPILE_CACHE', 'FS_SAFE_TEST_NO_OPENAT2',
                 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_PROFILE_RELEASE_LTO', 'CARGO_PROFILE_RELEASE_OPT_LEVEL']:
        require(name not in os.environ, f'confounding environment variable {name}')
    node = Path(run(EVIDENCE, 'node-path', ['node', '-p', 'process.execPath']).strip()).resolve()
    node_info = json.loads(run(EVIDENCE, 'node-version', [node, '-p', 'JSON.stringify({version:process.version,arch:process.arch,platform:process.platform})']))
    require(node_info == dict(version='v24.21.0', arch='arm64', platform='darwin'), 'wrong Node runtime')
    require(run(EVIDENCE, 'pnpm-version', ['pnpm', '--version']).strip() == '12.4.2', 'wrong pnpm')
    pnpm = Path(shutil.which('pnpm')).resolve()
    write(EVIDENCE / 'pnpm-executable.json', dict(path=str(pnpm), sha256=digest(pnpm)))
    require(run(EVIDENCE, 'rust-version', ['rustc', '--version']).startswith('rustc 1.98.1 '), 'wrong Rust')
    for name in ['rustc', 'cargo']:
        executable = Path(run(EVIDENCE, name + '-path', ['rustup', 'which', name]).strip())
        write(EVIDENCE / (name + '-executable.json'), dict(path=str(executable), sha256=digest(executable)))
    run(EVIDENCE, 'clang-version', [os.environ['CC_wasm32_unknown_unknown'], '--version'])
    run(EVIDENCE, 'archiver-version', [os.environ['AR_wasm32_unknown_unknown'], '--version'])
    write(EVIDENCE / 'archive-tools.json', {name: dict(path=os.environ[name], sha256=digest(os.environ[name]))
          for name in ['CC_wasm32_unknown_unknown', 'AR_wasm32_unknown_unknown']})
    config = dict(node=str(node))
    pins = {str(node): digest(node)}
    for arm, (directory, commit) in SOURCES.items():
        output = EVIDENCE / arm
        output.mkdir()
        source = WORKSPACE / directory
        source_receipt(source, commit, output, 'before')
        run(output, 'source-archive', ['git', 'archive', '--format=tar.gz', '-o', output / 'source.tar.gz', 'HEAD'], cwd=source)
        env = dict(CARGO_TARGET_DIR=str(Path(os.environ['RUNNER_TEMP']) / ('cargo-' + arm)), NODE_DISABLE_COMPILE_CACHE='1')
        run(output, 'install', ['pnpm', 'install', '--frozen-lockfile'], cwd=source, extra_env=env, timeout=600)
        run(output, 'build', ['pnpm', 'build'], cwd=source, extra_env=env, timeout=900)
        run(output, 'native-build', ['pnpm', 'native:build'], cwd=source, extra_env=env, timeout=900)
        run(output, 'rust-tests', ['pnpm', 'native:test', '--locked'], cwd=source, extra_env=env, timeout=900)
        run(output, 'native-integration', ['pnpm', 'test', 'test/root-remove-native-integration.test.ts',
            'test/root-move-replace-native-integration.test.ts', '--reporter=json', '--outputFile=' + str(output / 'integration.json')],
            cwd=source, extra_env=dict(env, FS_SAFE_NATIVE_MODE='require'), timeout=600)
        check_integration(output / 'integration.json')
        run(output, 'package-smoke', ['pnpm', 'package:smoke'], cwd=source, extra_env=env, timeout=900)
        shutil.copytree(source / 'release-artifacts', output / 'packages')
        native_package = '@openclaw/fs-safe-darwin-arm64'
        binary = source / 'packages/darwin-arm64/fs-safe-native.node'
        shutil.copyfile(binary, output / 'fs-safe-native.node')
        version = read(source / 'package.json')['version']
        expected = dict(packageVersion=version, nativePackage=native_package, nativeSha256=digest(binary))
        expected_file = output / 'expected.json'
        write(expected_file, expected)
        manifest = {row['name']: row for row in read(output / 'packages/manifest.json')}
        tarballs = {name: output / 'packages' / manifest[name]['filename'] for name in ['@openclaw/fs-safe', native_package]}
        with tarfile.open(tarballs[native_package]) as archive:
            packed = archive.extractfile('package/fs-safe-native.node').read()
        require(hashlib.sha256(packed).hexdigest() == expected['nativeSha256'], 'packed addon differs from built addon')
        consumer = Path(os.environ['RUNNER_TEMP']) / ('preobservation-consumer-' + arm)
        consumer.mkdir(exist_ok=False)
        dependencies = {name: 'file:' + str(file) for name, file in tarballs.items()}
        write(consumer / 'package.json', dict(name='preobservation-consumer', version='1.0.0', private=True, dependencies=dependencies))
        (consumer / 'pnpm-workspace.yaml').write_text('overrides:\n  ' + json.dumps(native_package) + ': ' + json.dumps(dependencies[native_package]) + '\n')
        run(output, 'consumer-install', ['pnpm', 'install', '--ignore-scripts', '--no-frozen-lockfile'], cwd=consumer, extra_env=env, timeout=300)
        installed_files = snapshot_consumer(consumer, output, 'consumer')
        observed = json.loads(run(output, 'installed-probe', [node, HERE / 'installed-probe.mjs', expected_file], cwd=consumer,
                                  extra_env=dict(NODE_ENV='test', NODE_DISABLE_COMPILE_CACHE='1'), timeout=120))
        require(observed['result'] == 'PASS' and observed['cases'] == 8 and observed['skipped'] == 0 and
                observed['cleanup'] == 'complete' and observed['node'] == 'v24.21.0' and observed['platform'] == 'darwin' and
                observed['arch'] == 'arm64' and observed['nativeSha256'] == expected['nativeSha256'], 'installed proof not admitted')
        require(pin_files(consumer) == installed_files, 'installed consumer changed during qualification probe')
        for relative, hashed in installed_files.items():
            pins[str(consumer / relative)] = hashed
        for file in [binary, output / 'fs-safe-native.node', expected_file, *tarballs.values()]:
            pins[str(file)] = digest(file)
        source_receipt(source, commit, output, 'after')
        config[arm] = dict(consumer=str(consumer), expected=str(expected_file))
    for relative, hashed in pin_files(HERE).items():
        if '__pycache__' not in relative:
            pins[str(HERE / relative)] = hashed
    write(EVIDENCE / 'config.json', config)
    pins[str(EVIDENCE / 'config.json')] = digest(EVIDENCE / 'config.json')
    write(EVIDENCE / 'artifact-pins.json', pins)
    write(EVIDENCE / 'build-complete.json', dict(functionalQualification='passed', allCommandGroupsTerminal=True,
          scope='Fresh source builds; these are not the previous shared-runner binary bytes.', node=node_info))


def collect():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    for arm, (directory, _) in SOURCES.items():
        consumer = Path(os.environ['RUNNER_TEMP']) / ('preobservation-consumer-' + arm)
        if consumer.exists():
            snapshot_consumer(consumer, EVIDENCE / arm, 'consumer-final')
        packages = WORKSPACE / directory / 'release-artifacts'
        retained = EVIDENCE / arm / 'packages'
        if packages.exists() and not retained.exists():
            shutil.copytree(packages, retained)
        binary = WORKSPACE / directory / 'packages/darwin-arm64/fs-safe-native.node'
        if binary.exists():
            (EVIDENCE / arm).mkdir(exist_ok=True)
            shutil.copyfile(binary, EVIDENCE / arm / 'final-built-native.node')
    write(EVIDENCE / 'SHA256.json', pin_files(EVIDENCE))


if __name__ == '__main__':
    require(len(sys.argv) == 2 and sys.argv[1] in ['admit', 'build', 'collect'], 'usage: prepare.py admit|build|collect')
    try:
        globals()[sys.argv[1]]()
    except Exception as error:
        if EVIDENCE.exists():
            write(EVIDENCE / (sys.argv[1] + '-failure.json'), dict(error=str(error), disposition='inconclusive; no retry'))
        raise
