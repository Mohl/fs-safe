"""Synthetic archives and manifests only; never download or execute toolchains."""
import ast
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'bootstrap-toolchains.py'
spec = importlib.util.spec_from_file_location('bootstrap', PATH)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TOP = 'node-v24.21.0-linux-x64'


def archive(root, members):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w') as stream:
        for name, kind, data in members:
            item = tarfile.TarInfo(name)
            item.mode = 0o755 if kind == 'executable' else 0o644
            if kind in ('file', 'executable'):
                item.size = len(data)
                stream.addfile(item, io.BytesIO(data))
            elif kind == 'directory':
                item.type = tarfile.DIRTYPE
                stream.addfile(item)
            elif kind in ('symlink', 'hardlink'):
                item.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
                item.linkname = data
                stream.addfile(item)
            elif kind == 'fifo':
                item.type = tarfile.FIFOTYPE
                stream.addfile(item)
    path = root / 'archive.tar.xz'
    path.write_bytes(lzma.compress(raw.getvalue()))
    return path


class ArchiveTests(unittest.TestCase):
    def test_source_parses_without_execution(self):
        ast.parse(PATH.read_text())

    def test_node_contained_links_and_executable_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = archive(root, [(TOP + '/bin/node', 'executable', b'node-fixture'),
                                    (TOP + '/lib/npm/index.js', 'file', b'javascript'),
                                    (TOP + '/bin/npm', 'symlink', '../lib/npm/index.js')])
            result = module.safe_extract(source, root / 'out', TOP)
            self.assertEqual(result['members'], 3)
            self.assertEqual((root / 'out' / TOP / 'bin/node').read_bytes(), b'node-fixture')
            self.assertEqual((root / 'out' / TOP / 'bin/npm').read_bytes(), b'javascript')
            self.assertTrue((root / 'out' / TOP / 'bin/node').stat().st_mode & 0o111)

    def test_archive_paths_links_duplicates_and_specials_rejected(self):
        alternatives = [
            [(TOP + '/../escape', 'file', b'bad')],
            [('/absolute', 'file', b'bad')],
            [('other/bin/node', 'file', b'bad')],
            [(TOP + '/bin/npm', 'symlink', '../../../outside')],
            [(TOP + '/bin/npm', 'symlink', '/outside')],
            [(TOP + '/bin/node', 'file', b'a'), (TOP + '/bin/node', 'file', b'b')],
            [(TOP + '/pipe', 'fifo', b'')],
            [(TOP + '/bin', 'symlink', 'lib'), (TOP + '/bin/node', 'file', b'bad')],
            [(TOP + '/bin/node', 'file', b'bad'), (TOP + '/bin', 'symlink', 'lib')],
            [(TOP + '/one', 'symlink', 'two'), (TOP + '/two', 'symlink', 'one')],
            [(TOP + '/one', 'hardlink', 'elsewhere/file')],
        ]
        for members in alternatives:
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                source = archive(root, members)
                with self.assertRaises((AssertionError, RuntimeError, OSError)):
                    module.safe_extract(source, root / 'out', TOP)
                self.assertFalse((root / 'escape').exists())
                self.assertFalse((root / 'outside').exists())

    def test_payload_and_member_bounds(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = archive(root, [(TOP + '/one', 'file', b'123'), (TOP + '/two', 'file', b'45')])
            with self.assertRaisesRegex(AssertionError, 'expanded archive limit'):
                module.safe_extract(source, root / 'bytes', TOP, max_bytes=4)
            with self.assertRaisesRegex(AssertionError, 'excess archive entries'):
                module.safe_extract(source, root / 'members', TOP, max_members=1)

    def test_decoder_caps_output_and_rejects_truncation_and_extra_stream(self):
        data = lzma.compress(b'a' * 1000)
        with self.assertRaisesRegex(AssertionError, 'decoded archive byte limit'):
            io.BufferedReader(module.LimitedXZ(io.BytesIO(data), 900)).read()
        for wrong in (data[:-5], data + lzma.compress(b'more')):
            with self.subTest(wrong=len(wrong)), self.assertRaises((AssertionError, lzma.LZMAError)):
                io.BufferedReader(module.LimitedXZ(io.BytesIO(wrong), 5000)).read()

    def test_pax_metadata_cap_applies_before_parsing(self):
        entry = module.LimitedTarInfo('pax')
        entry.size = module.CHUNK + 1
        with self.assertRaisesRegex(AssertionError, 'PAX metadata'):
            entry._proc_pax(None)
        entry.size = 8193
        with self.assertRaisesRegex(AssertionError, 'GNU pathname'):
            entry._proc_gnulong(None)

    def test_copy_is_independent_and_rewrites_internal_absolute_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'original'
            (source / 'bin').mkdir(parents=True)
            compiler = source / 'bin/rustc'
            compiler.write_bytes(b'compiler-fixture')
            compiler.chmod(0o755)
            (source / 'bin/compiler').symlink_to(compiler)
            result = module.copy_tree(source, root / 'private')
            copied = root / 'private/bin/rustc'
            self.assertNotEqual(compiler.stat().st_ino, copied.stat().st_ino)
            self.assertEqual(module.digest(compiler), module.digest(copied))
            self.assertEqual((root / 'private/bin/compiler').resolve(), copied.resolve())
            self.assertEqual(result['inventorySha256'], module.inventory_digest(module.tree_inventory(source)))
            copied.write_bytes(b'changed-private-copy')
            self.assertEqual(compiler.read_bytes(), b'compiler-fixture')

    def test_copy_rejects_external_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.mkdir()
            (root / 'external').write_bytes(b'outside')
            (source / 'link').symlink_to(root / 'external')
            with self.assertRaisesRegex(AssertionError, 'leaves private-copy scope'):
                module.copy_tree(source, root / 'copy')


class ManifestTests(unittest.TestCase):
    def test_checksum_binds_exact_filename_once(self):
        expected = 'a' * 64
        self.assertEqual(module.checksum_for(expected + '  archive.tar.xz\n', 'archive.tar.xz'), expected)
        for text in (expected + '  other.tar.xz\n', (expected + '  archive.tar.xz\n') * 2, 'invalid\n'):
            with self.subTest(text=text), self.assertRaises(AssertionError):
                module.checksum_for(text, 'archive.tar.xz')

    def test_official_tls_origin_only(self):
        module.validate_url('https://nodejs.org/dist/v24.21.0/a', 'nodejs.org')
        for value in ('http://nodejs.org/a', 'https://evil.test/a', 'https://u:p@nodejs.org/a',
                      'https://nodejs.org:8443/a', 'https://nodejs.org/a?token=secret'):
            with self.subTest(value=value), self.assertRaises(AssertionError):
                module.validate_url(value, 'nodejs.org')

    def test_official_channel_binds_compiler_target_url_and_hash(self):
        version = '1.98.1 (48a229cea 2026-09-01)'
        normal = {'version': version, 'available': True,
                  'url': 'https://static.rust-lang.org/dist/2026-09-03/rust-std-1.98.1-wasm32-unknown-unknown.tar.xz',
                  'hash': 'c' * 64}
        variations = [normal, {**normal, 'version': '1.98.0 (other 2026-08-01)'},
                      {**normal, 'available': False}, {**normal, 'url': 'https://evil.test/archive.xz'},
                      {**normal, 'url': normal['url'].replace('2026-09-03', '2026-08-01')},
                      {**normal, 'hash': 'bad'}]
        for index, values in enumerate(variations):
            with self.subTest(values=values), tempfile.TemporaryDirectory() as temp:
                text = '\n'.join(['manifest-version = "2"', 'date = "2026-09-03"',
                    '[pkg.rustc]', 'version = ' + json.dumps(values['version']),
                    '[pkg.rust-std]', 'version = ' + json.dumps(values['version']),
                    '[pkg.rust-std.target.wasm32-unknown-unknown]',
                    'available = ' + str(values['available']).lower(),
                    'xz_url = ' + json.dumps(values['url']), 'xz_hash = ' + json.dumps(values['hash'])])
                owner = module.Bootstrap.__new__(module.Bootstrap)
                owner.evidence = Path(temp)
                owner.report = {}
                def fake_worker(label, operation, request):
                    self.assertEqual(operation, 'download')
                    data = text.encode()
                    if label.endswith('checksum'):
                        data = (hashlib.sha256(data).hexdigest() + '  channel-rust-1.98.1.toml\n').encode()
                    destination = Path(request['destination'])
                    destination.write_bytes(data)
                    return {'sha256': hashlib.sha256(data).hexdigest()}
                owner.worker = fake_worker
                if index == 0:
                    self.assertEqual(owner.rust_channel('rustc ' + version)['xz_hash'], values['hash'])
                else:
                    with self.assertRaises(AssertionError):
                        owner.rust_channel('rustc ' + version)

    def std_fixture(self, root, entry):
        component = 'rust-std-' + module.TARGET
        (root / 'rust-installer-version').write_text('3\n')
        (root / 'components').write_text(component + '\n')
        payload = root / component / 'lib/rustlib' / module.TARGET / 'lib'
        payload.mkdir(parents=True)
        (payload / 'libcore-fixture.rlib').write_bytes(b'core-fixture')
        (root / component / 'manifest.in').write_text(entry + '\n')
        return root / component, payload

    def test_std_file_and_directory_manifest_forms(self):
        for entry in ('dir:lib/rustlib/wasm32-unknown-unknown/lib',
                      'file:lib/rustlib/wasm32-unknown-unknown/lib/libcore-fixture.rlib'):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.std_fixture(root, entry)
                result = module.validate_std(root, 'rustc 1.98.1 (48a229cea 2026-09-01)')
                self.assertEqual(result['componentVersion'], '1.98.1 (48a229cea 2026-09-01)')
                (root / 'version').write_text('1.98.0 (other 2026-08-01)')
                with self.assertRaisesRegex(AssertionError, 'version mismatch'):
                    module.validate_std(root, 'rustc 1.98.1 (48a229cea 2026-09-01)')

    def test_std_rejects_unmanifested_and_outside_payload(self):
        for added in ('lib/rustlib/wasm32-unknown-unknown/lib/unlisted.rlib', 'outside/file', 'outside/manifest.in'):
            with self.subTest(added=added), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                component, _payload = self.std_fixture(root,
                    'file:lib/rustlib/wasm32-unknown-unknown/lib/libcore-fixture.rlib')
                extra = component / added
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text('unexpected')
                with self.assertRaises(AssertionError):
                    module.validate_std(root, 'rustc 1.98.1 (48a229cea 2026-09-01)')

    def test_std_rejects_manifest_type_mismatch_and_duplicate_destination(self):
        invalid = ('dir:lib/rustlib/wasm32-unknown-unknown/lib/libcore-fixture.rlib',
                   'file:lib/rustlib/wasm32-unknown-unknown/lib',
                   'dir:lib/rustlib/wasm32-unknown-unknown/lib\ndir:lib/rustlib/wasm32-unknown-unknown/lib',
                   'file:../../escape')
        for entry in invalid:
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                self.std_fixture(root, entry)
                with self.assertRaises(AssertionError):
                    module.validate_std(root, 'rustc 1.98.1 (48a229cea 2026-09-01)')


if __name__ == '__main__':
    unittest.main()
