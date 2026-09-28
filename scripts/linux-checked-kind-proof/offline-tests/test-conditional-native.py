"""Offline synthetic contract checks; never execute the privileged owner/child."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / 'run-conditional-native.py'
spec = importlib.util.spec_from_file_location('conditional_native', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def mount_record(path='/tmp/owned/mount', source='owned-source', mount_id=13, shared=False):
    optional = ' shared:7' if shared else ''
    return module.parse_mountinfo(
        f'{mount_id} 1 0:37 / {path} rw,nosuid,nodev,nosymfollow{optional} - tmpfs {source} rw,size=16384k\n')[0]


def valid_output(test):
    return f'\nrunning 1 test\ntest {test} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 19 filtered out; finished in 0.00s\n'


def identity_pair():
    spec = {'uid': 65534, 'gid': 65534, 'binary': '/tmp/private/test-A', 'binarySha256': 'a' * 64,
            'temporary': '/tmp/private/A-nonroot', 'test': module.TESTS['nonroot'],
            'mountNamespace': 'mnt:[123]', 'mount': None}
    receipt = {key: spec[key] for key in ('binary', 'binarySha256', 'temporary', 'test', 'mountNamespace', 'mount')}
    receipt.update({'uids': [65534] * 4, 'gids': [65534] * 4, 'groups': [],
                    'capabilities': {'CapInh': 0, 'CapPrm': 0, 'CapEff': 0, 'CapAmb': 0},
                    'noNewPrivileges': True, 'protectedSymlinks': '1', 'openat2ProbeSucceeded': True})
    return spec, receipt


class EvidenceContractTests(unittest.TestCase):
    def test_owner_and_inline_launcher_parse_without_execution(self):
        ast.parse(PATH.read_text())
        ast.parse(module.CHILD_LAUNCHER)

    def test_cleanup_handlers_are_installed_under_an_atomic_signal_mask(self):
        calls = []
        def mask(how, signals):
            calls.append(('mask', how))
            return set()
        def handler(sig, value):
            calls.append(('handler', sig))
            return 'old-handler'
        with patch.object(module.signal, 'pthread_sigmask', side_effect=mask), \
                patch.object(module.signal, 'signal', side_effect=handler):
            with module.shield_cleanup():
                calls.append(('body', None))
        expected = [('mask', module.signal.SIG_BLOCK)]
        expected += [('handler', sig) for sig in module.settlement_control.SIGNALS]
        expected += [('mask', module.signal.SIG_SETMASK), ('body', None), ('mask', module.signal.SIG_BLOCK)]
        expected += [('handler', sig) for sig in module.settlement_control.SIGNALS]
        expected += [('mask', module.signal.SIG_SETMASK)]
        self.assertEqual(calls, expected)

    def test_mount_parser_preserves_escape_and_mount_identity(self):
        row = mount_record('/tmp/owned\\040mount')
        self.assertEqual(row['mountpoint'], '/tmp/owned mount')
        self.assertEqual(row['id'], 13)
        self.assertEqual(row['type'], 'tmpfs')
        self.assertIn('nosymfollow', row['options'])
        with self.assertRaises(AssertionError):
            module.parse_mountinfo(row['raw'] + '\n' + row['raw'])

    def test_shared_parent_and_stacked_mounts_block(self):
        shared = mount_record('/tmp', shared=True)
        with self.assertRaisesRegex(AssertionError, 'shared mount propagation'):
            module.private_containing_mount([shared], '/tmp/owned')
        one = mount_record()
        with self.assertRaisesRegex(AssertionError, 'stacked mounts'):
            module.owned_mount([one, {**one, 'id': 15}], '/tmp/owned/mount', 'owned-source')

    def test_replacement_or_mutated_mount_is_not_owned(self):
        expected = mount_record()
        with self.assertRaisesRegex(AssertionError, 'foreign replacement'):
            module.owned_mount([mount_record(source='other')], Path('/tmp/owned/mount'), 'owned-source', expected)
        changed = {**expected, 'id': 42}
        with self.assertRaisesRegex(AssertionError, 'changed'):
            module.owned_mount([changed], Path('/tmp/owned/mount'), 'owned-source', expected)

    def test_exact_success_only(self):
        test = module.TESTS['root']
        module.exact_test_output(valid_output(test), test)
        alternatives = [valid_output(test).replace('running 1 test', 'running 0 tests'),
                        valid_output(test).replace('1 passed', '0 passed'),
                        valid_output(test).replace('0 ignored', '1 ignored'),
                        valid_output(test).replace(test, module.TESTS['nonroot']),
                        valid_output(test) + valid_output(test)]
        for output in alternatives:
            with self.subTest(output=output), self.assertRaises(AssertionError):
                module.exact_test_output(output, test)

    def test_launch_evidence_rejects_vacuous_permission_case(self):
        expected, receipt = identity_pair()
        output = module.IDENTITY_PREFIX + json.dumps(receipt)
        self.assertEqual(module.validate_identity(output, expected), receipt)
        bad_rows = [dict(receipt, uids=[0, 0, 0, 0]),
                    dict(receipt, uids=[65534, 65534, 65534, 0]),
                    dict(receipt, groups=[0]), dict(receipt, noNewPrivileges=False),
                    dict(receipt, protectedSymlinks='0'), dict(receipt, openat2ProbeSucceeded=False),
                    dict(receipt, capabilities={**receipt['capabilities'], 'CapEff': 2}),
                    dict(receipt, capabilities={**receipt['capabilities'], 'CapInh': 2}),
                    dict(receipt, mountNamespace='mnt:[other]')]
        for wrong in bad_rows:
            with self.subTest(receipt=wrong), self.assertRaises(AssertionError):
                module.validate_identity(module.IDENTITY_PREFIX + json.dumps(wrong), expected)
        with self.assertRaises(AssertionError):
            module.validate_identity(output + '\n' + output, expected)

    def test_launch_evidence_requires_exact_mount(self):
        expected, receipt = identity_pair()
        expected.update({'uid': 0, 'gid': 0, 'test': module.TESTS['nosymfollow'],
                         'mount': {'path': '/tmp/owned/mount', 'record': mount_record(), 'identity': {'dev': 7, 'ino': 2}}})
        receipt.update({'uids': [0] * 4, 'gids': [0] * 4, 'test': expected['test'], 'mount': expected['mount']})
        module.validate_identity(module.IDENTITY_PREFIX + json.dumps(receipt), expected)
        for altered in (None, {**expected['mount'], 'path': '/tmp/other'},
                        {**expected['mount'], 'record': mount_record(source='other')}):
            wrong = {**receipt, 'mount': altered}
            with self.subTest(mount=altered), self.assertRaises(AssertionError):
                module.validate_identity(module.IDENTITY_PREFIX + json.dumps(wrong), expected)

    def test_cargo_provenance_accepts_cdylib_and_rejects_other_source(self):
        source, target = Path('/source/A'), Path('/work/build-A/cargo')
        binary = target / 'debug/deps/fs_safe_native-abc'
        artifact = {'reason': 'compiler-artifact', 'target': {'name': 'fs_safe_native', 'kind': ['cdylib'],
                    'src_path': str(source / 'native/src/lib.rs')}, 'profile': {'test': True},
                    'manifest_path': str(source / 'native/Cargo.toml'), 'executable': str(binary)}
        finished = {'reason': 'build-finished', 'success': True}
        messages = '\n'.join(map(json.dumps, (artifact, finished)))
        self.assertEqual(module.binary_from_messages(messages, source, target, binary), artifact)
        invalids = [[artifact, artifact, finished], [artifact, {'reason': 'build-finished', 'success': False}],
                    [{**artifact, 'executable': '/another/binary'}, finished],
                    [{**artifact, 'target': {**artifact['target'], 'src_path': '/other/native/src/lib.rs'}}, finished],
                    [{**artifact, 'profile': {'test': False}}, finished]]
        for rows in invalids:
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                module.binary_from_messages('\n'.join(map(json.dumps, rows)), source, target, binary)


class MountCleanupTests(unittest.TestCase):
    def fixture(self, directory, *, attempted=True, recorded=True):
        owner = module.Owner.__new__(module.Owner)
        owner.processes = Path(directory) / 'processes'
        owner.processes.mkdir()
        owner.scratch = Path(directory) / 'private'
        owner.scratch.mkdir()
        owner.mountpoint = owner.scratch / 'mount'
        owner.mountpoint.mkdir()
        owner.scratch_identity = module.identity(owner.scratch)
        owner.covered_identity = module.identity(owner.mountpoint)
        owner.mounted_identity = dict(owner.covered_identity)
        owner.mount_source = 'owned-source'
        owner.mount_attempted = attempted
        row = mount_record(str(owner.mountpoint))
        owner.mount_record = row if recorded else None
        owner.namespace = 'mnt:[test]'
        owner.summary = {'resourceSettled': False, 'mount': {}, 'privateDirectory': {}}
        owner.save = Mock()
        return owner, row

    def test_success_unmount_is_exact_normal_and_packet_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            table = [row]
            calls = []
            def step(label, argv, **kwargs):
                calls.append((label, argv, kwargs))
                table.clear()
            owner.step = step
            with patch.object(module, 'mount_table', side_effect=lambda: list(table)), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace):
                owner.cleanup()
            self.assertEqual(calls, [('conditional-unmount', ['/usr/bin/umount', '--', owner.mountpoint], {'verify': False})])
            self.assertTrue(owner.summary['resourceSettled'])
            self.assertTrue(owner.summary['mount']['goneVerified'])
            self.assertFalse(owner.scratch.exists())

    def test_interrupted_successful_mount_is_owned_and_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory, recorded=False)
            table = [row]
            owner.step = Mock(side_effect=lambda *_args, **_kwargs: table.clear())
            with patch.object(module, 'mount_table', side_effect=lambda: list(table)), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace):
                owner.cleanup()
            self.assertTrue(owner.summary['resourceSettled'])
            self.assertTrue(owner.summary['mount']['adoptedForCleanupAfterInterruptedCommand'])
            self.assertEqual(owner.mount_record, row)

    def test_failed_unmount_blocks_resource_settlement_and_preserves_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            owner.step = Mock(side_effect=RuntimeError('umount busy'))
            with patch.object(module, 'mount_table', return_value=[row]), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace), \
                    self.assertRaisesRegex(RuntimeError, 'umount busy'):
                owner.cleanup()
            self.assertFalse(owner.summary['resourceSettled'])
            self.assertTrue(owner.scratch.exists())
            self.assertNotIn('goneVerified', owner.summary['mount'])

    def test_replacement_mount_is_never_unmounted(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            owner.step = Mock()
            replacement = {**row, 'source': 'unrelated'}
            with patch.object(module, 'mount_table', return_value=[replacement]), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace), \
                    self.assertRaisesRegex(AssertionError, 'foreign replacement'):
                owner.cleanup()
            owner.step.assert_not_called()
            self.assertFalse(owner.summary['resourceSettled'])
            self.assertTrue(owner.scratch.exists())

    def test_remaining_mount_after_success_receipt_is_not_settled(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            owner.step = Mock()
            with patch.object(module, 'mount_table', return_value=[row]), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace), \
                    self.assertRaisesRegex(AssertionError, 'mount remains'):
                owner.cleanup()
            self.assertFalse(owner.summary['resourceSettled'])
            self.assertTrue(owner.scratch.exists())

    def test_changed_namespace_blocks_unmount(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            owner.step = Mock()
            with patch.object(module.os, 'readlink', return_value='mnt:[other]'), \
                    self.assertRaisesRegex(AssertionError, 'namespace changed'):
                owner.cleanup()
            owner.step.assert_not_called()
            self.assertFalse(owner.summary['resourceSettled'])

    def test_unsettled_child_blocks_all_cleanup(self):
        for absent in (False, True):
            with self.subTest(absent=absent), tempfile.TemporaryDirectory() as directory:
                owner, row = self.fixture(directory)
                (owner.processes / 'conditional-A-nonroot.request.json').write_text('{}')
                if not absent:
                    (owner.processes / 'conditional-A-nonroot.exit.json').write_text(json.dumps({
                        'localProcessSettled': False, 'cleanupErrors': ['group remained']}))
                owner.step = Mock()
                with patch.object(module, 'mount_table', return_value=[row]), \
                        patch.object(module.os, 'readlink', return_value=owner.namespace), \
                        self.assertRaises(AssertionError):
                    owner.cleanup()
                owner.step.assert_not_called()
                self.assertFalse(owner.summary['resourceSettled'])
                self.assertTrue(owner.scratch.exists())

    def test_ambiguous_spawn_receipt_blocks_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, row = self.fixture(directory)
            (owner.processes / 'conditional-A-nonroot.request.json').write_text('{}')
            (owner.processes / 'conditional-A-nonroot.exit.json').write_text(json.dumps({
                'exitCode': None, 'failure': "InterruptedError('received signal 15')",
                'localProcessSettled': True, 'cleanupErrors': []}))
            owner.step = Mock()
            with patch.object(module, 'mount_table', return_value=[row]), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace), \
                    self.assertRaisesRegex(AssertionError, 'provably join'):
                owner.cleanup()
            owner.step.assert_not_called()
            self.assertFalse(owner.summary['resourceSettled'])
            self.assertTrue(owner.scratch.exists())

    def test_first_cancellation_is_deferred_through_each_acquisition(self):
        for acquisition in (1, 2):
            with self.subTest(acquisition=acquisition), tempfile.TemporaryDirectory() as directory:
                owner = module.Owner.__new__(module.Owner)
                owner.processes = Path(directory) / 'processes'
                owner.processes.mkdir()
                owner.summary = {'resourceSettled': False}
                owner.scratch = owner.mountpoint = owner.mount_record = None
                owner.mount_attempted = False
                owner.save = Mock()
                private = Path(directory) / 'private'
                private.mkdir()
                calls = []
                def mask(how, signals):
                    calls.append((how, signals))
                    if len(calls) == 2 * acquisition:
                        raise InterruptedError('deferred first cancellation')
                    return set()
                with patch.object(module.os, 'geteuid', return_value=0), \
                        patch.object(module.os, 'getresuid', return_value=(0, 0, 0), create=True), \
                        patch.object(module.os, 'readlink', return_value='mnt:[test]'), \
                        patch.object(module.tempfile, 'mkdtemp', return_value=str(private)), \
                        patch.object(module, 'mount_table', return_value=[mount_record('/')]), \
                        patch.object(module.signal, 'pthread_sigmask', side_effect=mask), \
                        self.assertRaisesRegex(InterruptedError, 'deferred first cancellation'):
                    owner.create_private({})
                self.assertEqual(calls[-1][0], module.signal.SIG_SETMASK)
                self.assertEqual(owner.scratch_identity, module.identity(private))
                if acquisition == 2:
                    self.assertEqual(owner.covered_identity, module.identity(private / 'nosymfollow'))
                with patch.object(module.os, 'readlink', return_value='mnt:[test]'), \
                        patch.object(module, 'mount_table', return_value=[]):
                    owner.cleanup()
                self.assertTrue(owner.summary['resourceSettled'])
                self.assertFalse(private.exists())

    def test_mount_failure_without_resource_can_settle(self):
        with tempfile.TemporaryDirectory() as directory:
            owner, _row = self.fixture(directory, recorded=False)
            owner.step = Mock()
            with patch.object(module, 'mount_table', return_value=[]), \
                    patch.object(module.os, 'readlink', return_value=owner.namespace):
                owner.cleanup()
            owner.step.assert_not_called()
            self.assertTrue(owner.summary['resourceSettled'])
            self.assertFalse(owner.scratch.exists())


if __name__ == '__main__':
    unittest.main()
