"""Own the three guarded Rust test bodies and a private nosymfollow mount.

Run directly as root inside `unshare --mount --propagation private`. Never put
this resource owner beneath an external timeout or bounded process-group owner.
Each child is bounded by the existing harness; this owner always joins children
before attempting normal, identity-checked unmount and private-fixture cleanup.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tempfile

if not __debug__:
    raise RuntimeError('qualification requires Python assertion checks')

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET / 'harness'))
import bounded
import settlement_control

TESTS = {
    'nonroot': 'linux_open::tests::preserves_search_permissions_and_directory_suffixes',
    'root': 'linux_open::tests::refuses_foreign_owned_links_in_sticky_shared_directories',
    'nosymfollow': 'linux_open::tests::respects_nosymfollow_mount',
}
IDENTITY_PREFIX = 'FS_SAFE_CONDITIONAL_IDENTITY='
UNPRIVILEGED_ID = 65534


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def identity(path):
    info = Path(path).lstat()
    assert stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), str(path)
    return {'dev': info.st_dev, 'ino': info.st_ino}


def decode_mount_field(value):
    return re.sub(r'\\(040|011|012|134)', lambda match: chr(int(match[1], 8)), value)


def parse_mountinfo(text):
    result = []
    for line in text.splitlines():
        left, right = line.split(' - ', 1)
        fields, filesystem = left.split(), right.split()
        assert len(fields) >= 6 and len(filesystem) == 3, line
        result.append({
            'id': int(fields[0]), 'parentId': int(fields[1]), 'device': fields[2],
            'root': decode_mount_field(fields[3]),
            'mountpoint': decode_mount_field(fields[4]),
            'options': fields[5].split(','), 'optional': fields[6:],
            'type': filesystem[0], 'source': decode_mount_field(filesystem[1]),
            'superOptions': filesystem[2].split(','), 'raw': line,
        })
    assert len({row['id'] for row in result}) == len(result), 'duplicate mount IDs'
    return result


def mount_table():
    return parse_mountinfo(Path('/proc/self/mountinfo').read_text())


def under(path, ancestor):
    return Path(path) == Path(ancestor) or Path(ancestor) in Path(path).parents


def private_containing_mount(table, path):
    ancestors = [row for row in table if under(path, row['mountpoint'])]
    assert ancestors, 'mountpoint has no containing filesystem'
    depth = max(len(Path(row['mountpoint']).parts) for row in ancestors)
    nearest = [row for row in ancestors if len(Path(row['mountpoint']).parts) == depth]
    assert len(nearest) == 1, 'ambiguous containing mount'
    assert not any(item.startswith('shared:') for item in nearest[0]['optional']), (
        'shared mount propagation: run directly through sudo -n unshare --mount '
        '--propagation private -- python3 run-conditional-native.py WORKSPACE WORK')
    return nearest[0]


def owned_mount(table, path, source, expected=None):
    matches = [row for row in table if row['mountpoint'] == str(path)]
    assert len(matches) <= 1, 'stacked mounts: ownership is ambiguous'
    if not matches:
        return None
    current = matches[0]
    assert current['source'] == source and current['type'] == 'tmpfs', 'foreign replacement mount'
    if expected is not None:
        assert current == expected, 'owned mount changed before cleanup'
    return current


def exact_test_output(output, test):
    assert len(re.findall(r'^running 1 test\s*$', output, re.M)) == 1, 'not exactly one test'
    assert len(re.findall(r'^test ' + re.escape(test) + r' \.\.\. ok\s*$', output, re.M)) == 1, test
    summaries = re.findall(r'^test result: (.+)$', output, re.M)
    assert len(summaries) == 1 and re.fullmatch(
        r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in .+',
        summaries[0]), 'missing exact successful libtest summary'


# This wrapper runs in the bounded child's process group and execs the binary;
# it does not create another supervisor. Its stdout attests the credentials and
# namespace that the same process retains across exec of the non-setid binary.
CHILD_LAUNCHER = r'''
import ctypes, hashlib, json, os, pathlib, platform, stat, sys
spec = json.loads(sys.argv[1])
uid, gid = spec['uid'], spec['gid']
os.setgroups([])
os.setresgid(gid, gid, gid)
os.setresuid(uid, uid, uid)
libc = ctypes.CDLL(None, use_errno=True)
assert libc.prctl(38, 1, 0, 0, 0) == 0, 'PR_SET_NO_NEW_PRIVS failed'
os.chdir(spec['temporary'])
os.umask(0o077)
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
uids, gids = ([int(value) for value in status[name].split()] for name in ('Uid', 'Gid'))
caps = {name: int(status[name].strip(), 16) for name in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb')}
assert uids == [uid] * 4 and gids == [gid] * 4 and os.getgroups() == [], 'credential drop mismatch'
assert status['NoNewPrivs'].strip() == '1'
if uid != 0:
    assert not any(caps.values()), 'nonroot test retains capabilities'
binary = pathlib.Path(spec['binary'])
info = binary.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
assert stat.S_IMODE(info.st_mode) == 0o555
assert 'security.capability' not in os.listxattr(binary), 'copied executable has file capabilities'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == spec['binarySha256']
namespace = os.readlink('/proc/self/ns/mnt')
assert namespace == spec['mountNamespace']
protected = pathlib.Path('/proc/sys/fs/protected_symlinks').read_text().strip()
assert protected == '1', 'kernel parity requires protected_symlinks=1'
mount = spec['mount']
if mount is not None:
    assert os.environ.get('FS_SAFE_TEST_NOSYMFOLLOW_ROOT') == mount['path']
    lines = [line for line in pathlib.Path('/proc/self/mountinfo').read_text().splitlines()
             if line.split(' ', 1)[0] == str(mount['record']['id'])]
    assert lines == [mount['record']['raw']], 'mount changed at test launch'
    mounted = pathlib.Path(mount['path']).lstat()
    assert {'dev': mounted.st_dev, 'ino': mounted.st_ino} == mount['identity']
    assert os.statvfs(mount['path']).f_flag & 0x2000, 'missing kernel ST_NOSYMFOLLOW'
else:
    assert 'FS_SAFE_TEST_NOSYMFOLLOW_ROOT' not in os.environ
assert 'FS_SAFE_TEST_NO_OPENAT2' not in os.environ
assert not any(name in os.environ for name in ('LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH'))
assert platform.machine() in ('x86_64', 'aarch64'), 'unrecognised openat2 syscall architecture'
class OpenHow(ctypes.Structure):
    _fields_ = [('flags', ctypes.c_uint64), ('mode', ctypes.c_uint64), ('resolve', ctypes.c_uint64)]
how = OpenHow(os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC, 0, 0x08 | 0x02)
libc.syscall.restype = ctypes.c_long
fd = libc.syscall(ctypes.c_long(437), ctypes.c_int(-100), ctypes.c_char_p(b'.'),
                  ctypes.byref(how), ctypes.c_size_t(ctypes.sizeof(how)))
assert fd >= 0, f'unfiltered openat2 preflight failed with errno {ctypes.get_errno()}'
os.close(fd)
print('FS_SAFE_CONDITIONAL_IDENTITY=' + json.dumps({
    'uids': uids, 'gids': gids, 'groups': os.getgroups(), 'capabilities': caps,
    'noNewPrivileges': True, 'protectedSymlinks': protected,
    'mountNamespace': namespace, 'mount': mount,
    'uidMap': pathlib.Path('/proc/self/uid_map').read_text(),
    'gidMap': pathlib.Path('/proc/self/gid_map').read_text(),
    'userNamespace': os.readlink('/proc/self/ns/user'),
    'seccomp': status['Seccomp'].strip(), 'openat2ProbeSucceeded': True,
    'binary': str(binary), 'binarySha256': spec['binarySha256'],
    'temporary': spec['temporary'], 'test': spec['test'],
}), flush=True)
os.execve(str(binary), [str(binary), '--exact', spec['test'], '--nocapture', '--test-threads=1'], dict(os.environ))
'''


def validate_identity(output, spec):
    records = [json.loads(line[len(IDENTITY_PREFIX):]) for line in output.splitlines()
               if line.startswith(IDENTITY_PREFIX)]
    assert len(records) == 1, 'missing or duplicate launch identity receipt'
    actual = records[0]
    for key in ('binary', 'binarySha256', 'temporary', 'test', 'mountNamespace', 'mount'):
        assert actual[key] == spec[key], key
    assert actual['uids'] == [spec['uid']] * 4 and actual['gids'] == [spec['gid']] * 4
    assert actual['groups'] == [] and actual['noNewPrivileges'] is True
    assert actual['protectedSymlinks'] == '1' and actual['openat2ProbeSucceeded'] is True
    assert set(actual['capabilities']) == {'CapInh', 'CapPrm', 'CapEff', 'CapAmb'}
    if spec['uid'] != 0:
        assert not any(actual['capabilities'].values()), 'privileged nonroot launch'
    return actual


def binary_from_messages(messages, source, target, binary):
    artifacts = []
    finished = []
    for line in messages.splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if value.get('reason') == 'build-finished':
            finished.append(value)
        if (value.get('reason') == 'compiler-artifact'
                and value.get('target', {}).get('name') == 'fs_safe_native'
                and value.get('profile', {}).get('test') is True
                and value.get('executable')):
            artifacts.append(value)
    assert len(finished) == 1 and finished[0]['success'] is True, 'Cargo build did not finish'
    assert len(artifacts) == 1, 'ambiguous native unit-test executable'
    artifact = artifacts[0]
    assert set(artifact['target']['kind']).intersection({'lib', 'cdylib'}), 'not native library tests'
    assert Path(artifact['target']['src_path']).resolve() == source / 'native/src/lib.rs'
    assert Path(artifact['manifest_path']).resolve() == source / 'native/Cargo.toml'
    assert Path(artifact['executable']).resolve() == binary and under(binary, target)
    return artifact


@contextlib.contextmanager
def defer_cancellation():
    # Record ownership before delivering a first cancellation; never discard it.
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, settlement_control.SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextlib.contextmanager
def shield_cleanup():
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, settlement_control.SIGNALS)
    try:
        previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in settlement_control.SIGNALS}
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
    try:
        yield
    finally:
        blocked = signal.pthread_sigmask(signal.SIG_BLOCK, settlement_control.SIGNALS)
        try:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, blocked)


class Owner:
    def __init__(self, workspace, work):
        self.workspace, self.work = workspace.resolve(), work.resolve()
        self.evidence = self.work / 'evidence'
        self.processes = self.evidence / 'processes'
        self.pins = json.loads((PACKET / 'pins.json').read_text())
        self.protocol = json.loads((PACKET / 'protocol.json').read_text())
        self.configuration = json.loads((PACKET / 'qualification.json').read_text())
        self.manifest = json.loads((PACKET / 'packet-manifest.json').read_text())
        self.destination = self.evidence / 'conditional-native.json'
        assert not self.destination.exists(), 'conditional proof already exists; do not overwrite'
        self.summary = {'schemaVersion': 1, 'state': 'incomplete', 'pins': self.pins,
                        'resourceSettled': False, 'rows': [], 'steps': [],
                        'cleanupErrors': [], 'startedAt': bounded.now()}
        self.scratch = None
        self.scratch_identity = None
        self.mountpoint = None
        self.covered_identity = None
        self.mounted_identity = None
        self.mount_record = None
        self.mount_source = None
        self.namespace = None
        self.mount_attempted = False
        self.cap = self.protocol['bounds']['conditionalSeconds']
        assert isinstance(self.cap, (int, float)) and 0 < self.cap <= 600

    def save(self):
        temporary = self.destination.with_suffix('.next')
        temporary.write_text(json.dumps(self.summary, indent=2) + '\n')
        temporary.replace(self.destination)

    def verify_packet(self):
        for name, expected in self.manifest['files'].items():
            assert sha256(PACKET / name) == expected, name
        assert self.pins['ready'] is True and self.protocol['ready'] is True
        assert self.protocol['platform'] == 'linux'
        assert self.protocol['sourcePins'] == {role: self.pins[role] for role in ('A', 'B')}
        assert self.configuration['rustConditionalTests'] == TESTS

    def step(self, label, argv, *, cwd=None, env=None, verify=True):
        if verify:
            self.verify_packet()
        failure = None
        try:
            bounded.run(self.processes, label, list(map(str, argv)), self.cap, cwd=cwd, env=env)
        except BaseException as error:
            failure = error
        receipt_path = self.processes / (label + '.exit.json')
        if receipt_path.is_file():
            receipt = json.loads(receipt_path.read_text())
            self.summary['steps'].append({'label': label, 'receipt': receipt})
            self.save()
            assert settlement_control.joined(receipt), 'unsettled child: ' + label
        else:
            raise RuntimeError('missing process settlement receipt: ' + label) from failure
        if failure is not None:
            raise failure
        assert receipt['exitCode'] == 0, label
        return (self.processes / (label + '.stdout.log')).read_text()

    def source_binaries(self):
        manifest_path = self.evidence / 'native-test-binaries.json'
        manifest = json.loads(manifest_path.read_text())
        assert manifest['schemaVersion'] == 1 and manifest['pins'] == self.pins
        assert set(manifest['arms']) == {'A', 'B'}
        result, tests = {}, []
        for role in ('A', 'B'):
            source = self.workspace / role
            resolved = source.resolve()
            assert source == resolved, 'source symlink is not a pinned checkout'
            output = self.step('conditional-' + role + '-source',
                               ['git', '-c', 'safe.directory=' + str(source), '-C', source,
                                'rev-parse', 'HEAD', 'HEAD^{tree}'])
            assert output.splitlines() == [self.pins[role]['commit'], self.pins[role]['tree']]
            dirty = self.step('conditional-' + role + '-clean',
                              ['git', '-c', 'safe.directory=' + str(source), '-C', source,
                               'status', '--porcelain', '--untracked-files=no'])
            assert not dirty.strip(), 'dirty pinned source'
            code = (source / 'native/src/linux_open.rs').read_bytes()
            assert code.count(b'#[cfg(test)]\nmod tests {') == 1
            tests.append(code.split(b'#[cfg(test)]\nmod tests {', 1)[1])
            arm = manifest['arms'][role]
            target = (self.work / ('build-' + role) / 'cargo').resolve()
            assert Path(arm['cargoTargetDir']).resolve() == target
            messages = self.processes / ('native-test-manifest-' + role + '.stdout.log')
            assert Path(arm['cargoMessages']).resolve() == messages
            assert sha256(messages) == arm['cargoMessagesSha256']
            receipt = json.loads(messages.with_name(messages.name.replace('.stdout.log', '.exit.json')).read_text())
            assert settlement_control.joined(receipt) and receipt['exitCode'] == 0
            binary = Path(arm['binary']).resolve()
            assert sha256(binary) == arm['binarySha256']
            artifact = binary_from_messages(messages.read_text(), source, target, binary)
            info = binary.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_mode & 0o111
            result[role] = {'path': binary, 'sha256': arm['binarySha256'],
                            'cargoArtifact': artifact, 'source': self.pins[role]}
        assert tests[0] == tests[1], 'A/B conditional tests differ'
        self.summary['conditionalTestSourceSha256'] = hashlib.sha256(tests[0]).hexdigest()
        self.summary['binaryManifestSha256'] = sha256(manifest_path)
        return result

    def create_private(self, binaries):
        assert os.geteuid() == 0 and os.getresuid() == (0, 0, 0), 'root owner is required'
        self.namespace = os.readlink('/proc/self/ns/mnt')
        self.summary['mountNamespace'] = self.namespace
        with defer_cancellation():
            self.scratch = Path(tempfile.mkdtemp(prefix='fs-safe-conditional-', dir='/tmp'))
            self.scratch_identity = identity(self.scratch)
            self.summary['privateDirectory'] = {'path': str(self.scratch), 'identity': self.scratch_identity}
            os.chmod(self.scratch, 0o711)
        private_containing_mount(mount_table(), self.scratch)
        with defer_cancellation():
            mountpoint = self.scratch / 'nosymfollow'
            mountpoint.mkdir(mode=0o700)
            self.covered_identity = identity(mountpoint)
            self.mountpoint = mountpoint
            self.mount_source = 'fs-safe-conditional-' + self.scratch.name.removeprefix('fs-safe-conditional-')
            self.summary['mount'] = {'path': str(self.mountpoint), 'source': self.mount_source,
                                     'coveredIdentity': self.covered_identity, 'attempted': False}
        for role, info in binaries.items():
            copy = self.scratch / ('test-' + role)
            with copy.open('xb') as output, info['path'].open('rb') as original:
                shutil.copyfileobj(original, output)
            os.chmod(copy, 0o555)
            assert sha256(copy) == info['sha256']
            assert 'security.capability' not in os.listxattr(copy), 'new executable has file capabilities'
            info['copy'] = copy
        self.save()

    def attest_mount(self):
        assert os.readlink('/proc/self/ns/mnt') == self.namespace, 'mount namespace changed'
        assert identity(self.scratch) == self.scratch_identity
        current = owned_mount(mount_table(), self.mountpoint, self.mount_source, self.mount_record)
        assert current is not None, 'owned mount is missing'
        if self.mount_record is None:
            self.mount_record = current
            self.mounted_identity = identity(self.mountpoint)
            self.summary['mount'].update({'record': current, 'mountedIdentity': self.mounted_identity})
        assert identity(self.mountpoint) == self.mounted_identity
        return current

    def create_mount(self):
        assert not any(under(row['mountpoint'], self.mountpoint) for row in mount_table())
        assert identity(self.mountpoint) == self.covered_identity
        self.mount_attempted = True
        self.summary['mount']['attempted'] = True
        self.save()
        self.step('conditional-mount',
                  ['/usr/bin/mount', '-t', 'tmpfs', '-o', 'nosymfollow,nodev,nosuid,size=16M,mode=0700',
                   self.mount_source, self.mountpoint])
        current = self.attest_mount()
        assert {'nosymfollow', 'nodev', 'nosuid'}.issubset(set(current['options']))
        assert not any(item.startswith('shared:') for item in current['optional'])
        assert os.statvfs(self.mountpoint).f_flag & 0x2000, 'kernel did not enable nosymfollow'
        self.summary['mount']['nosymfollowFlagObserved'] = True
        self.save()

    def run_test(self, role, case, binary):
        uid = UNPRIVILEGED_ID if case == 'nonroot' else 0
        temporary = self.scratch / (role + '-' + case)
        temporary.mkdir(mode=0o700)
        os.chown(temporary, uid, uid)
        mount = None
        if case == 'nosymfollow':
            current = self.attest_mount()
            assert not list(self.mountpoint.iterdir()), 'mount fixture was not clean'
            mount = {'path': str(self.mountpoint), 'record': current, 'identity': self.mounted_identity}
        spec = {'uid': uid, 'gid': uid, 'binary': str(binary['copy']), 'binarySha256': binary['sha256'],
                'test': TESTS[case], 'temporary': str(temporary), 'mountNamespace': self.namespace,
                'mount': mount}
        environment = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8',
                       'HOME': str(temporary), 'TMPDIR': str(temporary), 'RUST_BACKTRACE': '1'}
        if mount:
            environment['FS_SAFE_TEST_NOSYMFOLLOW_ROOT'] = mount['path']
        row = {'role': role, 'case': case, 'test': spec['test'], 'executed': False,
               'source': binary['source'], 'binarySha256': binary['sha256']}
        self.summary['rows'].append(row)
        self.save()
        output = self.step('conditional-' + role + '-' + case,
                           [sys.executable, '-I', '-c', CHILD_LAUNCHER, json.dumps(spec)], env=environment,
                           cwd=self.scratch)
        launch = validate_identity(output, spec)
        exact_test_output(output, spec['test'])
        assert Path('/proc/sys/fs/protected_symlinks').read_text().strip() == '1'
        assert sha256(binary['copy']) == binary['sha256']
        assert not list(temporary.iterdir()), 'Rust test left its private fixture behind'
        if mount:
            self.attest_mount()
            assert not list(self.mountpoint.iterdir()), 'nosymfollow test left its fixture behind'
        row.update({'executed': True, 'launch': launch, 'fixtureEmpty': True,
                    'protectedSymlinksAfter': '1', 'kernelParityBranchExecuted': case == 'root'})
        self.save()

    def cleanup(self):
        # Do not unmount or remove fixtures beneath a child whose settlement
        # receipt is missing or failed, even when the owner caught its error.
        for request in self.processes.glob('conditional-*.request.json'):
            receipt_path = request.with_name(request.name.replace('.request.json', '.exit.json'))
            assert receipt_path.is_file(), 'child settlement receipt is missing: ' + request.name
            receipt = json.loads(receipt_path.read_text())
            assert settlement_control.joined(receipt) and isinstance(receipt.get('exitCode'), int), (
                'child did not provably join before cleanup: ' + request.name)
        self.summary['processesJoinedBeforeCleanup'] = True
        if self.scratch is None:
            self.summary['resourceSettled'] = True
            return
        assert os.readlink('/proc/self/ns/mnt') == self.namespace, 'cleanup namespace changed'
        assert identity(self.scratch) == self.scratch_identity, 'private directory replaced'
        if self.mountpoint is not None:
            current = owned_mount(mount_table(), self.mountpoint, self.mount_source, self.mount_record)
            if current is not None:
                # A mount command may succeed immediately before cancellation;
                # adopt only our unique source/type at the pre-owned pathname.
                if self.mount_record is None:
                    assert self.mount_attempted, 'unexpected mount before mount attempt'
                    self.attest_mount()
                    self.summary['mount']['adoptedForCleanupAfterInterruptedCommand'] = True
                self.attest_mount()
                self.step('conditional-unmount', ['/usr/bin/umount', '--', self.mountpoint], verify=False)
            table = mount_table()
            assert not any(under(row['mountpoint'], self.mountpoint) for row in table), 'mount remains'
            if self.mount_record:
                assert all(row['id'] != self.mount_record['id'] for row in table), 'owned mount ID remains'
            assert identity(self.mountpoint) == self.covered_identity, 'covered directory changed'
            self.summary['mount']['goneVerified'] = True
            self.summary['mount']['coveredIdentityAfter'] = identity(self.mountpoint)
            assert not list(self.mountpoint.iterdir()), 'covered directory unexpectedly contains files'
        assert not any(under(row['mountpoint'], self.scratch) for row in mount_table()), 'nested mount remains'
        shutil.rmtree(self.scratch)
        assert not os.path.lexists(self.scratch), 'private directory remains'
        self.summary['privateDirectory']['removedVerified'] = True
        self.summary['resourceSettled'] = True

    def run(self):
        error = None
        try:
            self.save()
            self.verify_packet()
            assert sys.platform == 'linux' and os.getresuid() == (0, 0, 0), (
                'run this owner directly as root in an unshared private mount namespace')
            assert self.processes.is_dir()
            assert json.loads((self.evidence / 'prepared.json').read_text())['pins'] == self.pins
            for request in self.processes.glob('*.request.json'):
                receipt = json.loads(request.with_name(request.name.replace('.request.json', '.exit.json')).read_text())
                assert settlement_control.joined(receipt), 'prior child did not settle'
            binaries = self.source_binaries()
            self.create_private(binaries)
            assert Path('/proc/sys/fs/protected_symlinks').read_text().strip() == '1', (
                'protected_symlinks=1 is required; no global sysctl is changed by this helper')
            for role in ('A', 'B'):
                for case in ('nonroot', 'root'):
                    self.run_test(role, case, binaries[role])
            self.create_mount()
            for role in ('A', 'B'):
                self.run_test(role, 'nosymfollow', binaries[role])
            for info in binaries.values():
                assert sha256(info['path']) == info['sha256'], 'original test binary changed'
            self.verify_packet()
        except BaseException as caught:
            error = caught
            self.summary['failure'] = repr(caught)
        finally:
            with shield_cleanup():
                try:
                    self.cleanup()
                except BaseException as cleanup_error:
                    self.summary['cleanupErrors'].append(repr(cleanup_error))
                    if error is None:
                        error = cleanup_error
                        self.summary['failure'] = repr(cleanup_error)
                rows = self.summary['rows']
                if (error is None and self.summary['resourceSettled'] is True
                        and len(rows) == 6 and all(row['executed'] is True for row in rows)):
                    self.summary['state'] = 'complete'
                self.summary['completedAt'] = bounded.now()
                self.save()
        if error is not None:
            raise error
        assert self.summary['state'] == 'complete'
        print(json.dumps({'state': 'complete', 'resourceSettled': True, 'executedRows': 6}))


def main():
    assert len(sys.argv) == 3, 'usage: run-conditional-native.py WORKSPACE WORK'
    settlement_control.install()
    Owner(Path(sys.argv[1]), Path(sys.argv[2])).run()


if __name__ == '__main__':
    main()
