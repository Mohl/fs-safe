"""Synthetic parser tests only: no fs-safe/native execution or Linux dependency."""
from copy import deepcopy
import hashlib
import contextlib
import io
import runpy
import subprocess
from unittest.mock import patch
import json
from pathlib import Path
import tempfile
import types
import unittest

PACKET = Path(__file__).resolve().parent.parent
SOURCE = PACKET / 'harness/compare-syscalls.py'
module = types.ModuleType('compare_syscalls')
module.__file__ = str(SOURCE)
exec(compile(SOURCE.read_text(), str(SOURCE), 'exec'), module.__dict__)
C = module
PINS = json.loads((PACKET / 'pins.json').read_text())
PROTOCOL = json.loads((PACKET / 'protocol.json').read_text())
PINS['ready'] = PROTOCOL['ready'] = True  # Only these in-memory synthetic fixtures.


def q(value):
    if isinstance(value, str):
        value = value.encode()
    return '"' + ''.join(chr(byte) if 32 <= byte < 127 and byte not in (34, 92) else '\\%03o' % byte for byte in value) + '"'


def fields(ino, kind='S_IFDIR', size=4096):
    return '{st_dev=makedev(0, 32), st_ino=%d, st_mode=%s|0700, st_nlink=1, st_uid=1000, st_gid=1000, st_size=%d, st_atime=1, st_mtime=1, st_ctime=1}' % (ino, kind, size)


def manifest(role, row, major=24):
    root = '/synthetic/fixture-' + role + '/root-0'
    outside = '/synthetic/fixture-' + role + '/outside-0'
    components = ['actual'] if row['alias'] else ['d' + str(index) for index in range(row['depth'])]
    parent = root + ('/' + '/'.join(components) if components else '')
    relative = 'alias/value' if row['alias'] else '/'.join(components + ['value'])
    result = dict(schema=1, role=role, row=row['id'], descriptor=row, mechanism=row['mechanism'], fallbackHook='0',
                  nodeVersion=PROTOCOL['nodeVersions'][str(major)], nodeMajor=major,
                  source={**PINS[role], 'dirty': False}, nativeSha256=('a' if role == 'A' else 'b') * 64,
                  rootPath=root, parentPath=parent, targetPath=parent + '/value', sentinelPath=outside + '/sentinel',
                  outsidePath=outside, primePath=root + '/prime-sentinel',
                  existingParentPaths=[root + '/' + '/'.join(components[:index]) for index in range(1, len(components) + 1)],
                  relative=relative, options={'mkdir': False, 'durable': False, 'mode': 384},
                  beginMarker='FS_SAFE_KIND_BEGIN ' + row['id'], endMarker='FS_SAFE_KIND_END ' + row['id'])
    if row['alias']:
        result.update(aliasPath=root + '/alias', aliasTarget='actual')
    consumer = '/work/consumer-' + role
    probe_argv = ['/packet/harness/syscall-probe.mjs', consumer, '/synthetic', row['id'], str(major),
                  '/evidence/node%d-%s-%s.manifest.json' % (major, row['id'], role),
                  '/evidence/node%d-%s-%s.proof.json' % (major, row['id'], role)]
    result.update(expectedPath=consumer + '/expected.json', expectedSha256='7' * 64,
                  expectedReceipt={'file': Path(probe_argv[-2]).name + '.expected.json', 'sha256': '7' * 64},
                  launch={'executable': '/usr/bin/node', 'argv': probe_argv},
                  nativePath=consumer + '/node_modules/@openclaw/fs-safe-linux-x64-gnu/fs-safe-native.node')
    return result


def expected(m):
    def artifact(name):
        return dict(name=name, version='0.21.2', sha256='1' * 64, integrity='sha512-' + 'a' * 86 + '==')
    return dict(role=m['role'], source=m['source'], nativeSha256=m['nativeSha256'], nativePackage='@openclaw/fs-safe-linux-x64-gnu',
                distFiles={'dist/root.js': '2' * 64}, rootTarball=artifact('@openclaw/fs-safe'),
                nativeTarball=artifact('@openclaw/fs-safe-linux-x64-gnu'))


def proof(m):
    row = m['descriptor']
    root_names = ['actual', 'alias', 'prime-sentinel'] if row['alias'] else ['d0', 'prime-sentinel'] if row['depth'] else ['prime-sentinel', 'value']
    result = {**m, 'ok': True, 'cleanup': True, 'phase': 'complete', 'outcome': dict(bytesHex=C.PAYLOAD.hex(), mode=384, nlink=1,
              sentinelHex=b'outside sentinel retained\n'.hex(), names=['value'] if row['depth'] else root_names,
              rootNames=root_names, relative=m['relative'])}
    if row['alias']:
        result['outcome']['aliasTarget'] = 'actual'
    return result


def launcher(m):
    wrapper = None
    command = ['/usr/bin/node', *m['launch']['argv']]
    if m['mechanism'] != 'openat2':
        command = ['/packet/deny-openat2', m['mechanism'], *command]
        receipt = dict(sourcePath='/packet/harness/deny-openat2.c', sourceSha256=hashlib.sha256((PACKET / 'harness/deny-openat2.c').read_bytes()).hexdigest(),
                       binaryPath='/packet/deny-openat2', binarySha256='8' * 64, compilerPath='/usr/bin/cc', compilerSha256='9' * 64,
                       command=['/usr/bin/cc', '/packet/harness/deny-openat2.c', '-o', '/packet/deny-openat2'], processLabel='compile-deny-wrapper')
        raw = json.dumps(receipt)
        wrapper = dict(buildReceipt=receipt, buildReceiptText=raw, buildReceiptSha256=hashlib.sha256(raw.encode()).hexdigest())
    return dict(schema=1, tracePath='/evidence/node%d-%s-%s.trace' % (m['nodeMajor'], m['row'], m['role']), command=command,
                runtime={'path': '/usr/bin/node', 'sha256': '0' * 64}, row=m['row'], nodeMajor=m['nodeMajor'], mechanism=m['mechanism'], fallbackHook='0',
                denialWrapper=wrapper, pinsSha256='3' * 64, protocolSha256='4' * 64)


def trace(m, stat_form='fstat'):
    """Deliberately synthetic trace; positive cases are parser controls, not proof."""
    row, root = m['descriptor'], m['rootPath']
    calls = []
    def add(value):
        calls.append(value)
    def fd(number, path):
        return '%d<%s>' % (number, path)
    def sample(number, path, ino, kind='S_IFDIR', size=4096):
        out = fields(ino, kind, size)
        if stat_form == 'fstat':
            return 'fstat(%s, %s) = 0' % (fd(number, path), out)
        if stat_form == 'newfstatat':
            return 'newfstatat(%s, "", %s, AT_EMPTY_PATH) = 0' % (fd(number, path), out)
        out = out.replace('st_dev=makedev(0, 32)', 'stx_dev_major=0, stx_dev_minor=32').replace('st_', 'stx_')
        return 'statx(%s, "", AT_EMPTY_PATH, STATX_BASIC_STATS, %s) = 0' % (fd(number, path), out)
    def named(pnum, ppath, name, ino, kind='S_IFDIR', size=4096):
        return 'newfstatat(%s, %s, %s, AT_SYMLINK_NOFOLLOW) = 0' % (fd(pnum, ppath), q(name), fields(ino, kind, size))
    launch = launcher(m)
    if row['mechanism'] != 'openat2':
        add('execve("/packet/deny-openat2", [%s], 0x1234 /* 4 vars */) = 0' % ', '.join(q(value) for value in launch['command']))
        add('prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0')
        add('prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, {len=4, filter=0x9876}) = 0')
    add('execve("/usr/bin/node", [%s], 0x1234 /* 4 vars */) = 0' % ', '.join(q(value) for value in ['/usr/bin/node', *m['launch']['argv']]))
    add('openat(AT_FDCWD</work>, %s, O_RDONLY|O_CLOEXEC) = 8<%s>' % (q(m['nativePath']), m['nativePath']))
    add('close(8<%s>) = 0' % m['nativePath'])
    probe = 'openat2(AT_FDCWD</work>, ".", {flags=O_RDONLY|O_CLOEXEC|O_PATH|O_DIRECTORY, resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS}, 24)'
    if row['mechanism'] == 'openat2':
        add(probe + ' = 9</work>'); add('close(9</work>) = 0')
    else:
        add(probe + ' = -1 ' + row['mechanism'] + (' (Function not implemented)' if row['mechanism'] == 'ENOSYS' else ' (Operation not permitted)'))
    begin = (m['beginMarker'] + '\n').encode()
    add('write(2</evidence/stderr>, %s, %d) = %d' % (q(begin), len(begin), len(begin)))
    add('openat(AT_FDCWD</work>, %s, O_RDONLY|O_DIRECTORY|O_CLOEXEC) = %s' % (q(root), fd(10, root)))
    add(sample(10, root, 1))
    opened = []
    if row['mechanism'] != 'openat2':
        targets = [(root + '/alias', 2, 'S_IFLNK', 6), (root + '/actual', 3, 'S_IFDIR', 4096)] if row['alias'] else [(path, index + 2, 'S_IFDIR', 4096) for index, path in enumerate(m['existingParentPaths'])]
        for index, (path, ino, kind, size) in enumerate(targets):
            number = 20 + index
            pnum, ppath = (10, root) if row['alias'] or index == 0 else (19 + index, targets[index - 1][0])
            name = path.rsplit('/', 1)[1]
            add('openat(%s, %s, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_PATH) = %s' % (fd(pnum, ppath), q(name), fd(number, path)))
            add(named(pnum, ppath, name, ino, kind, size)); add(sample(number, path, ino, kind, size))
            if m['role'] == 'A':
                add(sample(number, path, ino, kind, size))
            opened.append((number, path, ino, kind, size, pnum, ppath, name))
            if kind == 'S_IFLNK':
                add('fstatfs(%s, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=1000, f_bfree=50, f_bavail=40, f_files=1000, f_ffree=900, f_fsid={val=[1, 2]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_RELATIME}) = 0' % fd(number, path))
                add(sample(pnum, ppath, 1)); add('readlinkat(%s, "", "actual", 256) = 6' % fd(number, path))
        for number, path, ino, kind, size, pnum, ppath, name in opened:
            if kind == 'S_IFLNK':
                add('fstatfs(%s, {f_type=EXT2_SUPER_MAGIC, f_bsize=4096, f_blocks=1000, f_bfree=50, f_bavail=40, f_files=1000, f_ffree=900, f_fsid={val=[1, 2]}, f_namelen=255, f_frsize=4096, f_flags=ST_VALID|ST_RELATIME}) = 0' % fd(number, path))
                add(sample(pnum, ppath, 1))
            add(named(pnum, ppath, name, ino, kind, size)); add(sample(number, path, ino, kind, size))
            if kind == 'S_IFLNK':
                add('readlinkat(%s, "alias", "actual", 256) = 6' % fd(pnum, ppath))
                add(named(pnum, ppath, name, ino, kind, size)); add(sample(number, path, ino, kind, size))
    parent = m['parentPath']
    if row['depth'] == 0:
        add('fcntl(%s, F_DUPFD_CLOEXEC, 0) = %s' % (fd(10, root), fd(40, parent)))
        pino = 1
    elif row['mechanism'] == 'openat2':
        add('openat2(%s, %s, {flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC, resolve=RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS}, 24) = %s' % (fd(10, root), q('/'.join('d' + str(index) for index in range(row['depth']))), fd(40, parent)))
        pino = 9
    else:
        _, _, pino, _, _, pnum, ppath, name = opened[-1]
        add('openat(%s, %s, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC) = %s' % (fd(pnum, ppath), q(name), fd(40, parent)))
    add(sample(40, parent, pino))
    for number, path, *_ in reversed(opened):
        add('close(%s) = 0' % fd(number, path))
    stage_name = '.fs-safe-12345678-1234-4234-8234-123456789abc.tmp'
    stage = parent + '/' + stage_name
    add('openat(%s, %s, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600) = %s' % (fd(40, parent), q(stage_name), fd(50, stage)))
    add('write(%s, %s, 128) = 128' % (fd(50, stage), q(C.PAYLOAD)))
    add('fchmod(%s, 0600) = 0' % fd(50, stage))
    add(sample(50, stage, 100, 'S_IFREG', 128))
    add(named(40, parent, 'value', 101, 'S_IFREG', 23))
    add('renameat(%s, %s, %s, "value") = 0' % (fd(40, parent), q(stage_name), fd(40, parent)))
    add(sample(50, m['targetPath'], 100, 'S_IFREG', 128))
    add('close(%s) = 0' % fd(50, m['targetPath']))
    add('close(%s) = 0' % fd(40, parent))
    add('close(%s) = 0' % fd(10, root))
    end = (m['endMarker'] + '\n').encode()
    add('write(2</evidence/stderr>, %s, %d) = %d' % (q(end), len(end), len(end)))
    return ('\n'.join('123 1000.%06d %s' % (index, value) for index, value in enumerate(calls + ['+++ exited with 0 +++'])) + '\n').encode()


def inspect(role, row, major=24, mutation=None, stat_form='fstat'):
    m = manifest(role, row, major)
    p = proof(m)
    C.verify_manifest(m, p, role, PINS, PROTOCOL, expected(m))
    data = trace(m, stat_form)
    if mutation:
        data = mutation(data)
    arm = {}
    parsed = C.inspect_arm(data, m, p, arm, launcher(m))
    return arm, parsed


class SyntheticComparatorTests(unittest.TestCase):
    def test_all_rows_both_versions(self):
        for major in (22, 24):
            for row in PROTOCOL['rows']:
                with self.subTest(major=major, row=row['id']):
                    arms, parsed = {}, {}
                    for role in ('A', 'B'):
                        arms[role], parsed[role] = inspect(role, row, major)
                    result = C.compare(arms, parsed, row)
                    self.assertEqual(result['componentFstatDelta'], row['expectedComponentFstatDelta'])

    def test_descriptor_stat_spellings(self):
        row = PROTOCOL['rows'][0]
        for form in ('fstat', 'newfstatat', 'statx'):
            arms, parsed = {}, {}
            for role in ('A', 'B'):
                arms[role], parsed[role] = inspect(role, row, stat_form=form)
            self.assertEqual(C.compare(arms, parsed, row)['componentFstatDelta'], -1)

    def test_not_ready_is_rejected(self):
        for target in ('pins', 'protocol'):
            pins, protocol = deepcopy(PINS), deepcopy(PROTOCOL)
            (pins if target == 'pins' else protocol)['ready'] = False
            with self.assertRaises(C.EvidenceError):
                C.verify_protocol(pins, protocol)

    def test_wrong_mechanism_or_filter_is_rejected(self):
        row = PROTOCOL['rows'][0]
        for before, after in ((b'= -1 ENOSYS (Function not implemented)', b'= -1 EPERM (Operation not permitted)'),
                              (b'PR_SET_NO_NEW_PRIVS, 1', b'PR_SET_NO_NEW_PRIVS, 0'),
                              (b'len=4', b'len=3'),
                              (b'SECCOMP_MODE_FILTER', b'SECCOMP_MODE_STRICT'),
                              (b'PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = 0', b'PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) = -1 EPERM (Operation not permitted)'),
                              (b'0x1234 /* 4 vars */', b'["SECRET=not-real"]')):
            with self.subTest(after=after), self.assertRaises(C.EvidenceError):
                inspect('A', row, mutation=lambda data: data.replace(before, after))

    def test_initial_duplicate_must_be_exact_and_owned(self):
        row = PROTOCOL['rows'][0]
        def remove_second_sample(data):
            result, seen = [], 0
            for line in data.splitlines(keepends=True):
                if b'fstat(20<' in line:
                    seen += 1
                    if seen == 2:
                        continue
                result.append(line)
            return b''.join(result)
        def add_second_sample(data):
            lines = data.splitlines()
            for index, line in enumerate(lines):
                if b'fstat(20<' in line:
                    lines.insert(index + 1, line)
                    break
            # Renumber synthetic records, preserving raw calls but not timestamps.
            return b''.join(b'123 1000.%06d ' % index + line.split(b' ', 2)[2] + b'\n' for index, line in enumerate(lines))
        with self.assertRaisesRegex(C.EvidenceError, 'baseline missing exact second'):
            inspect('A', row, mutation=remove_second_sample)
        with self.assertRaisesRegex(C.EvidenceError, 'candidate retains an immediately repeated'):
            inspect('B', row, mutation=add_second_sample)
        def change_second_identity(data):
            result, seen = [], 0
            for line in data.splitlines(keepends=True):
                if b'fstat(20<' in line:
                    seen += 1
                    if seen == 2:
                        line = line.replace(b'st_ino=2,', b'st_ino=999,')
                result.append(line)
            return b''.join(result)
        with self.assertRaisesRegex(C.EvidenceError, 'component fresh fences disagree'):
            inspect('A', row, mutation=change_second_identity)

    def test_removed_named_fence_rejected(self):
        row = PROTOCOL['rows'][0]
        def mutation(data):
            lines = data.splitlines(keepends=True)
            seen = 0
            result = []
            for line in lines:
                if b'newfstatat(10<' in line and b'"d0"' in line:
                    seen += 1
                    if seen == 2:
                        continue
                result.append(line)
            return b''.join(result)
        with self.assertRaises(C.EvidenceError):
            inspect('B', row, mutation=mutation)

    def test_missing_owner_close_rejected(self):
        row = PROTOCOL['rows'][0]
        with self.assertRaises(C.EvidenceError):
            inspect('B', row, mutation=lambda data: b''.join(line for line in data.splitlines(keepends=True) if b'close(20<' not in line))

    def test_alias_safety_admission_and_target_reread_required(self):
        row = PROTOCOL['rows'][2]
        mutations = [lambda data: b''.join(line for line in data.splitlines(keepends=True) if b'fstatfs(' not in line),
                     lambda data: b''.join(line for line in data.splitlines(keepends=True) if b'readlinkat(10<' not in line),
                     lambda data: data.replace(b'"actual", 256) = 6', b'"escape", 256) = 6')]
        for mutation in mutations:
            with self.assertRaises(C.EvidenceError):
                inspect('B', row, mutation=mutation)

    def test_extra_event_cannot_be_hidden_by_expected_count(self):
        row = PROTOCOL['rows'][0]
        arms, parsed = {}, {}
        arms['A'], parsed['A'] = inspect('A', row)
        arms['B'], parsed['B'] = inspect('B', row, mutation=lambda data: data.replace(b'fchmod(', b'fsync(').replace(b', 0600) = 0', b') = 0'))
        with self.assertRaises(C.EvidenceError):
            C.compare(arms, parsed, row)

    def test_volatile_fstatfs_counts_only_are_normalized(self):
        row = PROTOCOL['rows'][2]
        arms, parsed = {}, {}
        arms['A'], parsed['A'] = inspect('A', row)
        arms['B'], parsed['B'] = inspect('B', row, mutation=lambda data: data.replace(b'f_bfree=50', b'f_bfree=49').replace(b'f_bavail=40', b'f_bavail=39').replace(b'f_ffree=900', b'f_ffree=899'))
        self.assertTrue(C.compare(arms, parsed, row)['otherwiseIdentical'])
        arms['B'], parsed['B'] = inspect('B', row, mutation=lambda data: data.replace(b'ST_VALID|ST_RELATIME', b'ST_VALID|ST_NOSYMFOLLOW'))
        with self.assertRaises(C.EvidenceError):
            C.compare(arms, parsed, row)

    def test_receipt_and_outcome_bindings(self):
        m = manifest('A', PROTOCOL['rows'][0])
        for key in ('nativeSha256', 'source', 'role'):
            receipt = expected(m); receipt[key] = None
            with self.assertRaises(C.EvidenceError):
                C.verify_manifest(m, proof(m), 'A', PINS, PROTOCOL, receipt)
        p = proof(m); p['outcome']['bytesHex'] = '00'
        with self.assertRaises(C.EvidenceError):
            C.verify_manifest(m, p, 'A', PINS, PROTOCOL, expected(m))

    def test_exact_launch_bindings(self):
        m = manifest('A', PROTOCOL['rows'][0])
        l = launcher(m)
        def check(value, manifest_value=m):
            C.verify_launch(value, manifest_value, PROTOCOL, '3' * 64, '4' * 64,
                            hashlib.sha256((PACKET / 'harness/deny-openat2.c').read_bytes()).hexdigest(),
                            Path(l['tracePath']), Path(m['launch']['argv'][-2]), Path(m['launch']['argv'][-1]))
        check(l)
        mutations = [lambda v: v['command'].__setitem__(4, '/wrong-consumer'),
                     lambda v: v['command'].__setitem__(0, '/other-wrapper'),
                     lambda v: v.__setitem__('pinsSha256', '0' * 64),
                     lambda v: v['denialWrapper'].__setitem__('buildReceiptSha256', '0' * 64),
                     lambda v: v.__setitem__('fallbackHook', '1')]
        for mutate in mutations:
            changed = deepcopy(l); mutate(changed)
            with self.assertRaises(C.EvidenceError):
                check(changed)
        altered = deepcopy(m); altered['expectedSha256'] = '0' * 64
        with self.assertRaises(C.EvidenceError):
            check(l, altered)

    def test_traced_invocation_and_native_path_must_match(self):
        row = PROTOCOL['rows'][0]
        for old, new in [(b'/work/consumer-A', b'/work/consumer-X'),
                         (b'/usr/bin/node', b'/wrong/node'),
                         (b'/packet/deny-openat2', b'/packet/other-wrapper'),
                         (b'/fs-safe-native.node', b'/foreign-native.node')]:
            with self.subTest(new=new), self.assertRaises(C.EvidenceError):
                inspect('A', row, mutation=lambda data: data.replace(old, new))

    def test_exec_retires_only_cloexec_owner(self):
        start = '123 1000.000000 openat(AT_FDCWD</work>, "/work/old", O_RDONLY|O_CLOEXEC) = 8</work/old>\n'
        executed = '123 1000.000001 execve("/usr/bin/node", ["node"], 0x1234 /* 0 vars */) = 0\n'
        reused = '123 1000.000002 openat(AT_FDCWD</work>, "/work/new", O_RDONLY|O_CLOEXEC) = 8</work/new>\n'
        ending = '123 1000.000003 close(8</work/new>) = 0\n123 1000.000004 +++ exited with 0 +++\n'
        records, _ = C.parse_trace((start + executed + reused + ending).encode())
        lives, _ = C.annotate_lifetimes(records, {'startLine': 10, 'endLine': 10, 'tid': '123'}, {'startLine': 20})
        self.assertEqual(lives[0]['closedByExecLine'], 2)
        records, _ = C.parse_trace((start.replace('|O_CLOEXEC', '').replace('/work/old', '/work/O_CLOEXEC-not-a-flag') + executed + reused + ending).encode())
        with self.assertRaises(C.EvidenceError):
            C.annotate_lifetimes(records, {'startLine': 10, 'endLine': 10, 'tid': '123'}, {'startLine': 20})

    def test_launcher_refuses_unready_packet_before_spawn(self):
        if json.loads((PACKET / 'pins.json').read_text())['ready'] or json.loads((PACKET / 'protocol.json').read_text())['ready']:
            self.skipTest('actual packet readiness changed; readiness is still tested in memory')
        with patch.object(subprocess, 'Popen') as spawned:
            with self.assertRaises(ValueError):
                runpy.run_path(str(PACKET / 'harness/trace-launch.py'), run_name='__main__')
            spawned.assert_not_called()

    def test_cli_sidecars_and_replay(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-comparator-', dir=PACKET / 'offline-tests') as directory:
            root = Path(directory); harness = root / 'harness'; harness.mkdir()
            (harness / 'compare-syscalls.py').write_bytes(SOURCE.read_bytes())
            (harness / 'deny-openat2.c').write_bytes((PACKET / 'harness/deny-openat2.c').read_bytes())
            pin_bytes, protocol_bytes = json.dumps(PINS).encode(), json.dumps(PROTOCOL).encode()
            (root / 'pins.json').write_bytes(pin_bytes); (root / 'protocol.json').write_bytes(protocol_bytes)
            args, manifest_paths = [], []
            for role in ('A', 'B'):
                m = manifest(role, PROTOCOL['rows'][2]); l = launcher(m)
                l['pinsSha256'] = hashlib.sha256(pin_bytes).hexdigest(); l['protocolSha256'] = hashlib.sha256(protocol_bytes).hexdigest()
                tpath = root / Path(l['tracePath']).name
                mpath, ppath = (root / Path(value).name for value in m['launch']['argv'][-2:])
                receipt_bytes = json.dumps(expected(m)).encode()
                digest = hashlib.sha256(receipt_bytes).hexdigest()
                m['expectedSha256'] = m['expectedReceipt']['sha256'] = digest
                (root / m['expectedReceipt']['file']).write_bytes(receipt_bytes)
                tpath.write_bytes(trace(m)); Path(str(tpath) + '.launch.json').write_text(json.dumps(l))
                mpath.write_text(json.dumps(m)); ppath.write_text(json.dumps(proof(m)))
                args.extend(map(str, (tpath, mpath, ppath))); manifest_paths.append(mpath)
            output = root / 'comparison.json'
            with patch.object(C, '__file__', str(harness / 'compare-syscalls.py')), patch.object(C.sys, 'argv', ['compare', *args, str(output)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(C.main(), 0)
            self.assertTrue(json.loads(output.read_text())['ok'])
            # One altered sidecar must fail before any trace comparison.
            m = json.loads(manifest_paths[0].read_text())
            (root / m['expectedReceipt']['file']).write_text('{}')
            output = root / 'rejected.json'
            with patch.object(C, '__file__', str(harness / 'compare-syscalls.py')), patch.object(C.sys, 'argv', ['compare', *args, str(output)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(C.main(), 1)
            result = json.loads(output.read_text())
            self.assertFalse(result['ok']); self.assertTrue(any('sidecar digest' in error['message'] for error in result['errors']))



if __name__ == '__main__':
    unittest.main(verbosity=2)
