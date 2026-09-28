"""Prepare private, recorded toolchains; never build or test the product.

The explicit --prepare-only mode permits an unready qualification packet. This
owner reuses bounded.py for every child, including archive and copy workers.
Only checksum-verified Node/Rust data is extracted; downloaded installers are
never executed. The pinned first-party LLVM setup action is reused unchanged.
"""
import argparse
import hashlib
import json
import io
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import ssl
import stat
import sys
import tarfile
import tomllib
import urllib.parse
import urllib.request

if not __debug__:
    raise RuntimeError('bootstrap requires assertion checks')

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(PACKET / 'harness'))
import bounded
import settlement_control

RUST_VERSION = '1.98.1'
RUST_SYSROOT = Path('/opt/crabbox/toolchains/rust') / RUST_VERSION
TARGET = 'wasm32-unknown-unknown'
MAX_MEMBERS = 100_000
MAX_EXPANDED = 4 * 1024 ** 3
MAX_FILE = 1024 ** 3
CHUNK = 1024 ** 2
INSTALLER_FILES = ('install.mjs', 'download.mjs', 'action.yml')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            value.update(chunk)
    return value.hexdigest()


def write_json(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def clean_member_name(value):
    assert '\x00' not in value and '\\' not in value and '\n' not in value and '\r' not in value
    while value.startswith('./'):
        value = value[2:]
    value = value.rstrip('/')
    parts = value.split('/')
    assert len(value) <= 4096 and len(parts) <= 64, 'archive pathname limit'
    assert value and all(part not in ('', '.', '..') for part in parts), 'unsafe archive pathname'
    assert not value.startswith('/'), 'absolute archive pathname'
    return PurePosixPath(value)


def contained_member(value, top):
    result = clean_member_name(value)
    assert result.parts[0] == top, 'unexpected archive root'
    return result


def relative_link_target(member, link, top, hard=False):
    assert link and not link.startswith('/') and not any(c in link for c in ('\x00', '\\', '\n', '\r'))
    if hard:
        target = contained_member(link, top)
    else:
        target = PurePosixPath(posixpath.normpath(str(member.parent / link)))
        assert target.parts and target.parts[0] == top and '..' not in target.parts, 'escaping symlink'
    return target


class LimitedXZ(io.RawIOBase):
    def __init__(self, source, limit):
        self.source, self.limit, self.total = source, limit, 0
        self.decoder = lzma.LZMADecompressor(memlimit=256 * 1024 ** 2)
        self.pending = b''

    def readable(self):
        return True

    def readinto(self, output):
        while not self.pending and not self.decoder.eof:
            compressed = self.source.read(64 * 1024) if self.decoder.needs_input else b''
            assert compressed or not self.decoder.needs_input, 'truncated XZ archive'
            self.pending = self.decoder.decompress(compressed, max_length=CHUNK)
            self.total += len(self.pending)
            assert self.total <= self.limit, 'decoded archive byte limit'
            if self.decoder.eof:
                assert not self.decoder.unused_data and not self.source.read(1), 'concatenated/trailing XZ data'
        count = min(len(output), len(self.pending))
        output[:count] = self.pending[:count]
        self.pending = self.pending[count:]
        return count


class LimitedTarInfo(tarfile.TarInfo):
    def _proc_pax(self, archive):
        assert self.size <= CHUNK, 'PAX metadata size limit'
        return super()._proc_pax(archive)

    def _proc_gnulong(self, archive):
        assert self.size <= 8192, 'GNU pathname metadata size limit'
        return super()._proc_gnulong(archive)


def safe_extract(archive, destination, top, *, max_bytes=MAX_EXPANDED, max_members=MAX_MEMBERS):
    archive, destination = Path(archive), Path(destination).resolve()
    destination.mkdir()
    seen, links = {}, []
    total = 0
    assert archive.stat().st_size <= 256 * CHUNK, 'compressed archive byte limit'
    with archive.open('rb') as compressed, io.BufferedReader(LimitedXZ(compressed, max_bytes + 128 * CHUNK)) as decoded, tarfile.open(fileobj=decoded, mode='r|', tarinfo=LimitedTarInfo) as stream:
        for entry in stream:
            relative = contained_member(entry.name, top)
            name = str(relative)
            assert name not in seen and len(seen) < max_members, 'duplicate or excess archive entries'
            assert not (entry.mode & 0o7000) and not entry.issparse(), 'privileged or sparse archive member'
            for parent in relative.parents:
                assert seen.get(str(parent)) not in ('symlink', 'hardlink'), 'entry beneath archive link'
            output = destination / name
            assert output.parent.resolve().is_relative_to(destination.resolve())
            if entry.isdir():
                seen[name] = 'directory'
                output.mkdir(parents=True, exist_ok=True)
                assert output.is_dir() and not output.is_symlink()
                os.chmod(output, 0o755)
            elif entry.isreg():
                seen[name] = 'file'
                assert 0 <= entry.size <= MAX_FILE and total + entry.size <= max_bytes, 'expanded archive limit'
                total += entry.size
                output.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(entry) as source, output.open('xb') as target:
                    remaining = entry.size
                    while remaining:
                        chunk = source.read(min(CHUNK, remaining))
                        assert chunk, 'truncated archive file'
                        target.write(chunk)
                        remaining -= len(chunk)
                    assert not source.read(1), 'archive file exceeds declared size'
                os.chmod(output, 0o755 if entry.mode & 0o111 else 0o644)
            elif entry.issym() or entry.islnk():
                seen[name] = 'hardlink' if entry.islnk() else 'symlink'
                target = relative_link_target(relative, entry.linkname, top, hard=entry.islnk())
                assert not any(old != name and PurePosixPath(name) in PurePosixPath(old).parents for old in seen), 'link covers an existing entry'
                links.append((output, target, entry.linkname, entry.islnk()))
            else:
                raise AssertionError('unsupported archive member type: ' + name)
        while decoded.read(CHUNK):
            pass
    for hard in (True, False):
        for output, target, lexical, is_hard in links:
            if is_hard != hard:
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            target_path = destination / str(target)
            if hard:
                assert target_path.is_file() and not target_path.is_symlink(), 'unresolved hardlink'
                os.link(target_path, output)
            else:
                output.symlink_to(lexical)
    for output, _target, _lexical, _hard in links:
        assert output.resolve(strict=True).is_relative_to(destination / top), 'link resolution escapes archive root'
    assert (destination / top).is_dir() and not (destination / top).is_symlink()
    return {'archiveSha256': digest(archive), 'root': str(destination / top),
            'members': len(seen), 'regularBytes': total, 'links': len(links)}


def tree_inventory(root):
    root = Path(root).resolve(strict=True)
    result, total = {}, 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            assert len(result) < MAX_MEMBERS and not (info.st_mode & 0o6000), 'unsupported source tree'
            if stat.S_ISLNK(info.st_mode):
                target = path.resolve(strict=True)
                assert target.is_relative_to(root), 'source symlink leaves private-copy scope'
                result[relative] = {'type': 'symlink', 'target': target.relative_to(root).as_posix()}
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = {'type': 'directory'}
            else:
                assert stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE, 'unsupported source file'
                total += info.st_size
                assert total <= MAX_EXPANDED, 'source tree size limit'
                result[relative] = {'type': 'file', 'size': info.st_size, 'sha256': digest(path),
                                    'executable': bool(info.st_mode & 0o111)}
    return result


def inventory_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def copy_tree(source, destination):
    source, destination = Path(source).resolve(strict=True), Path(destination).resolve()
    before = tree_inventory(source)
    destination.mkdir()
    for name, item in before.items():
        target = destination / name
        if item['type'] == 'directory':
            target.mkdir(parents=True, exist_ok=True)
        elif item['type'] == 'file':
            target.parent.mkdir(parents=True, exist_ok=True)
            with (source / name).open('rb') as original, target.open('xb') as copied:
                shutil.copyfileobj(original, copied, CHUNK)
            os.chmod(target, 0o755 if item['executable'] else 0o644)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(os.path.relpath(destination / item['target'], target.parent))
    assert tree_inventory(source) == before, 'source changed during private copy'
    assert tree_inventory(destination) == before, 'private copy differs'
    return {'source': str(source), 'destination': str(destination), 'entries': len(before),
            'inventorySha256': inventory_digest(before)}


def checksum_for(text, filename):
    matches = []
    for line in text.splitlines():
        parsed = re.fullmatch(r'([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)', line)
        assert parsed, 'malformed official checksum manifest'
        if parsed[2] == filename:
            matches.append(parsed[1].lower())
    assert len(matches) == 1, 'missing or duplicate checksum for selected archive'
    return matches[0]


def validate_url(value, host):
    parsed = urllib.parse.urlsplit(value)
    assert parsed.scheme == 'https' and parsed.hostname == host and parsed.port in (None, 443)
    assert parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment


def download(url, destination, limit):
    host = urllib.parse.urlsplit(url).hostname
    assert host in ('nodejs.org', 'static.rust-lang.org')
    validate_url(url, host)
    class OfficialRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, response, code, message, headers, newurl):
            validate_url(newurl, host)
            return super().redirect_request(request, response, code, message, headers, newurl)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), OfficialRedirect(),
                                         urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={'User-Agent': 'fs-safe-toolchain-proof', 'Accept-Encoding': 'identity'})
    size = 0
    with opener.open(request, timeout=30) as response:
        validate_url(response.geturl(), host)
        assert response.status == 200
        length = response.headers.get('Content-Length')
        if length is not None:
            assert 0 <= int(length) <= limit, 'download exceeds declared byte limit'
        with Path(destination).open('xb') as output:
            while True:
                chunk = response.read(min(CHUNK, limit - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                assert size <= limit, 'download exceeded byte limit'
                output.write(chunk)
        if length is not None:
            assert size == int(length), 'short official download'
    return {'url': url, 'path': str(destination), 'bytes': size, 'sha256': digest(destination)}


def validate_std(distribution, compiler, commit_hash=None):
    distribution = Path(distribution)
    component = 'rust-std-' + TARGET
    assert (distribution / 'rust-installer-version').read_text().strip() == '3'
    assert (distribution / 'components').read_text().splitlines() == [component]
    version = compiler.removeprefix('rustc ')
    if (distribution / 'version').exists():
        assert (distribution / 'version').read_text().strip() in (RUST_VERSION, version), 'standard-library/compiler version mismatch'
    if (distribution / 'git-commit-hash').exists():
        assert commit_hash and (distribution / 'git-commit-hash').read_text().strip() == commit_hash, 'standard-library/compiler commit mismatch'
    root = distribution / component
    target = root / 'lib/rustlib' / TARGET
    assert target.is_dir() and not target.is_symlink()
    entries = []
    for line in (root / 'manifest.in').read_text().splitlines():
        kind, separator, name = line.partition(':')
        assert separator and kind in ('file', 'dir'), 'unsupported Rust component manifest entry'
        relative = clean_member_name(name)
        assert relative == PurePosixPath('lib/rustlib') / TARGET or (PurePosixPath('lib/rustlib') / TARGET) in relative.parents
        payload = root / str(relative)
        assert payload.is_file() if kind == 'file' else payload.is_dir(), 'Rust component manifest entry has wrong type'
        entries.append((kind, relative))
    assert entries and len({str(path) for _kind, path in entries}) == len(entries)
    for path in root.rglob('*'):
        if path.is_file() and path != root / 'manifest.in':
            assert path.resolve().is_relative_to(target.resolve()), 'payload outside Rust target subtree'
    inventory = tree_inventory(target)
    for name, item in inventory.items():
        relative = PurePosixPath('lib/rustlib') / TARGET / name
        if item['type'] == 'directory':
            continue
        assert any((kind == 'file' and path == relative) or (kind == 'dir' and (path == relative or path in relative.parents))
                   for kind, path in entries), 'unmanifested Rust target payload'
    assert list((target / 'lib').glob('libcore-*.rlib')), 'wasm libcore is absent'
    return {'componentVersion': version, 'component': component, 'target': str(target),
            'inventorySha256': inventory_digest(inventory), 'manifestSha256': digest(root / 'manifest.in')}


def worker(operation, specification):
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024 ** 3, 3 * 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_EXPANDED, MAX_EXPANDED))
    if operation == 'download':
        result = download(specification['url'], specification['destination'], specification['limit'])
    elif operation == 'extract':
        assert digest(specification['archive']) == specification['sha256'], 'archive changed before extraction'
        result = safe_extract(specification['archive'], specification['destination'], specification['top'])
    elif operation == 'copy':
        result = copy_tree(specification['source'], specification['destination'])
    elif operation == 'install-std':
        result = validate_std(specification['distribution'], specification['compilerVersion'], specification['compilerCommitHash'])
        result['copy'] = copy_tree(result['target'], specification['destination'])
        assert result['copy']['inventorySha256'] == result['inventorySha256']
    else:
        raise AssertionError('unknown preparation worker')
    print(json.dumps(result))


class Bootstrap:
    def __init__(self, source, destination):
        assert os.geteuid() != 0, 'run toolchain preparation as the unprivileged proof owner'
        self.source = source.resolve(strict=True)
        self.root = destination.absolute()
        assert self.root.parent.resolve() == self.root.parent, 'bootstrap parent must be a real directory'
        assert not os.path.lexists(self.root), 'bootstrap directory must be unused'
        self.pins = json.loads((PACKET / 'pins.json').read_text())
        self.protocol = json.loads((PACKET / 'protocol.json').read_text())
        assert self.protocol['sourcePins'] == {role: self.pins[role] for role in ('A', 'B')}
        assert self.protocol['platform'] == 'linux' and self.protocol['arch'] == 'x64' and self.protocol['libc'] == 'glibc'
        assert self.protocol['nodeVersions'] == {'22': 'v22.23.2', '24': 'v24.21.0'}
        self.root.mkdir(mode=0o700)
        self.evidence = self.root / 'evidence'
        self.processes = self.evidence / 'processes'
        self.processes.mkdir(parents=True)
        self.downloads = self.root / 'downloads'
        self.downloads.mkdir()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.original_path = os.environ['PATH']
        assert all(Path(part).is_absolute() for part in self.original_path.split(os.pathsep)), 'untrusted relative PATH entry'
        self.env = {'PATH': self.original_path, 'HOME': str(self.home), 'LANG': 'C.UTF-8',
                    'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        self.cap = self.protocol['bounds']['bootstrapSeconds']
        assert isinstance(self.cap, int) and 0 < self.cap <= 1800
        self.report = {'schemaVersion': 1, 'state': 'incomplete', 'prepareOnly': True,
                       'readyAtPreparation': self.pins['ready'] is True and self.protocol['ready'] is True,
                       'pins': self.pins, 'startedAt': bounded.now(), 'processesJoined': False,
                       'implementationSha256': digest(__file__), 'archives': {}, 'toolchains': {}}
        self.request_labels = []

    def save(self):
        temporary = self.root / 'bootstrap.next'
        temporary.write_text(json.dumps(self.report, indent=2) + '\n')
        temporary.replace(self.root / 'bootstrap.json')

    def step(self, label, argv, *, cwd=None, env=None, cap=None):
        assert digest(__file__) == self.report['implementationSha256'], 'bootstrap implementation changed'
        self.request_labels.append(label)
        bounded.run(self.processes, label, list(map(str, argv)), cap or self.cap,
                    cwd=cwd or self.root, env=env or self.env)
        receipt = json.loads((self.processes / (label + '.exit.json')).read_text())
        assert settlement_control.joined(receipt) and receipt['exitCode'] == 0
        return (self.processes / (label + '.stdout.log')).read_text().strip()

    def worker(self, label, operation, value):
        return json.loads(self.step(label, [sys.executable, '-I', __file__, '--worker', operation, json.dumps(value)]))

    def source_check(self, suffix):
        values = self.step('source-pin-' + suffix, ['git', '-C', self.source, 'rev-parse', 'HEAD', 'HEAD^{tree}'], cap=30).splitlines()
        assert len(values) == 2
        pair = {'commit': values[0], 'tree': values[1]}
        assert pair in (self.pins['A'], self.pins['B']), 'source does not match either exact pin'
        dirty = self.step('source-clean-' + suffix, ['git', '-C', self.source, 'status', '--porcelain', '--untracked-files=no'], cap=30)
        assert not dirty, 'source has tracked changes'
        return {**pair, 'dirty': False}

    def acquire(self, label, url, manifest_url, filename, top, limit):
        manifest = self.evidence / (label + '-official-sha256.txt')
        metadata = self.worker(label + '-checksum-download', 'download',
                               {'url': manifest_url, 'destination': str(manifest), 'limit': CHUNK})
        expected = checksum_for(manifest.read_text(), filename)
        archive = self.downloads / filename
        downloaded = self.worker(label + '-archive-download', 'download',
                                 {'url': url, 'destination': str(archive), 'limit': limit})
        assert downloaded['sha256'] == expected and digest(archive) == expected, label + ' checksum mismatch'
        extracted = self.worker(label + '-extract', 'extract',
                                {'archive': str(archive), 'sha256': expected,
                                 'destination': str(self.root / (label + '-distribution')), 'top': top})
        self.report['archives'][label] = {'officialManifest': metadata, 'archive': downloaded,
                                          'expectedSha256': expected, 'extracted': extracted}
        self.save()
        return Path(extracted['root'])

    def tool(self, label, path, *, env=None, expected=None):
        path = Path(path).resolve(strict=True)
        assert path.is_file() and os.access(path, os.X_OK)
        before = digest(path)
        version = self.step(label + '-version', [path, '--version'], env=env, cap=30)
        if expected is not None:
            assert version == expected, label + ' version mismatch'
        assert digest(path) == before
        return {'path': str(path), 'sha256': before, 'version': version}

    def prepare_nodes(self):
        for major in ('22', '24'):
            version = self.protocol['nodeVersions'][major]
            top = 'node-' + version + '-linux-x64'
            filename = top + '.tar.xz'
            base = 'https://nodejs.org/dist/' + version + '/'
            directory = self.acquire('node' + major, base + filename, base + 'SHASUMS256.txt', filename, top, 128 * CHUNK)
            self.report['toolchains']['node' + major] = self.tool('node' + major, directory / 'bin/node', expected=version)
        node24 = Path(self.report['toolchains']['node24']['path'])
        self.env['PATH'] = str(node24.parent) + os.pathsep + self.original_path

    def rust_channel(self, compiler):
        filename = 'channel-rust-' + RUST_VERSION + '.toml'
        url = 'https://static.rust-lang.org/dist/' + filename
        manifest = self.evidence / filename
        checksum = self.evidence / (filename + '.sha256')
        checksum_proof = self.worker('rust-channel-checksum', 'download',
            {'url': url + '.sha256', 'destination': str(checksum), 'limit': CHUNK})
        proof = self.worker('rust-channel-manifest', 'download',
            {'url': url, 'destination': str(manifest), 'limit': 4 * CHUNK})
        assert proof['sha256'] == checksum_for(checksum.read_text(), filename)
        data = tomllib.loads(manifest.read_text())
        assert data['manifest-version'] == '2'
        version = compiler.removeprefix('rustc ')
        assert data['pkg']['rustc']['version'] == data['pkg']['rust-std']['version'] == version
        target = data['pkg']['rust-std']['target'][TARGET]
        assert target['available'] is True
        validate_url(target['xz_url'], 'static.rust-lang.org')
        filename = 'rust-std-' + RUST_VERSION + '-' + TARGET + '.tar.xz'
        assert urllib.parse.urlsplit(target['xz_url']).path in (
            '/dist/' + filename, '/dist/' + data['date'] + '/' + filename)
        assert re.fullmatch(r'[0-9a-f]{64}', target['xz_hash'])
        self.report['rustChannel'] = {'manifest': proof, 'checksum': checksum_proof,
                                     'version': version, 'date': data['date'], 'target': target}
        return target

    def prepare_rust(self):
        original_compiler = self.tool('original-rustc', RUST_SYSROOT / 'bin/rustc')
        original_cargo = self.tool('original-cargo', RUST_SYSROOT / 'bin/cargo')
        verbose = self.step('original-rustc-verbose', [original_compiler['path'], '--version', '--verbose'], cap=30)
        details = dict(line.split(': ', 1) for line in verbose.splitlines()[1:] if ': ' in line)
        assert details['host'] == 'x86_64-unknown-linux-gnu' and details['release'] == RUST_VERSION
        assert re.fullmatch(r'[0-9a-f]{40}', details['commit-hash'])
        original_compiler['verboseVersion'] = verbose
        original_compiler['commitHash'] = details['commit-hash']
        assert re.fullmatch(r'rustc 1\.98\.1 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)', original_compiler['version'])
        assert re.fullmatch(r'cargo 1\.98\.1 \([0-9a-f]+ \d{4}-\d{2}-\d{2}\)', original_cargo['version'])
        sysroot = self.step('original-rust-sysroot', [original_compiler['path'], '--print', 'sysroot'], cap=30)
        assert Path(sysroot).resolve() == RUST_SYSROOT
        private = self.root / 'rust'
        copied = self.worker('rust-private-copy', 'copy', {'source': str(RUST_SYSROOT), 'destination': str(private)})
        self.env['PATH'] = str(Path(self.report['toolchains']['node24']['path']).parent) + os.pathsep + str(private / 'bin') + os.pathsep + self.original_path
        compiler = self.tool('private-rustc', private / 'bin/rustc', expected=original_compiler['version'])
        cargo = self.tool('private-cargo', private / 'bin/cargo', expected=original_cargo['version'])
        assert compiler['sha256'] == original_compiler['sha256'] and cargo['sha256'] == original_cargo['sha256']
        assert self.step('private-rust-sysroot', [compiler['path'], '--print', 'sysroot'], cap=30) == str(private)
        top = 'rust-std-' + RUST_VERSION + '-' + TARGET
        filename = top + '.tar.xz'
        channel = self.rust_channel(compiler['version'])
        url = channel['xz_url']
        distribution = self.acquire('rust-std', url, url + '.sha256', filename, top, 256 * CHUNK)
        assert self.report['archives']['rust-std']['expectedSha256'] == channel['xz_hash']
        target = private / 'lib/rustlib' / TARGET
        installed = self.worker('rust-std-install-data', 'install-std',
                                {'distribution': str(distribution), 'compilerVersion': compiler['version'],
                                 'compilerCommitHash': details['commit-hash'], 'destination': str(target)})
        inventory_path = self.evidence / 'rust-wasm-component-inventory.json'
        write_json(inventory_path, tree_inventory(target))
        libdir = self.step('private-wasm-libdir', [compiler['path'], '--print', 'target-libdir', '--target', TARGET], cap=30)
        assert Path(libdir) == target / 'lib'
        core = sorted((target / 'lib').glob('libcore-*.rlib'))
        assert len(core) == 1 and core[0].is_file()
        assert inventory_digest(tree_inventory(RUST_SYSROOT)) == copied['inventorySha256'], 'global sysroot changed'
        private_before_target = tree_inventory(private)
        prefix = 'lib/rustlib/' + TARGET
        private_before_target = {key: value for key, value in private_before_target.items() if key != prefix and not key.startswith(prefix + '/')}
        assert inventory_digest(private_before_target) == copied['inventorySha256'], 'existing private sysroot changed'
        self.report['toolchains']['rust'] = {'version': RUST_VERSION, 'sysroot': str(private),
            'originalSysroot': str(RUST_SYSROOT), 'compiler': compiler, 'cargo': cargo,
            'originalCompiler': original_compiler, 'originalCargo': original_cargo,
            'sysrootCopy': copied, 'wasm': {'target': TARGET, 'path': str(target),
                'inventorySha256': installed['inventorySha256'], 'componentVersion': installed['componentVersion'],
                'manifestSha256': installed['manifestSha256'],
                'inventoryFile': str(inventory_path), 'inventoryFileSha256': digest(inventory_path),
                'libcore': [{'path': str(path), 'sha256': digest(path)} for path in core]}}
        self.save()

    def prepare_llvm(self):
        action = self.source / '.github/actions/setup-archive-llvm'
        receipts = {}
        for name in INSTALLER_FILES:
            path = action / name
            relative = path.relative_to(self.source).as_posix()
            blob = self.step('llvm-source-' + name.replace('.', '-'), ['git', '-C', self.source, 'rev-parse', self.report['source']['commit'] + ':' + relative], cap=30)
            actual = self.step('llvm-file-' + name.replace('.', '-'), ['git', '-C', self.source, 'hash-object', path], cap=30)
            assert actual == blob
            receipts[name] = {'path': str(path), 'gitBlob': blob, 'sha256': digest(path)}
        temporary = self.root / 'llvm'
        temporary.mkdir()
        output = self.root / 'llvm-environment.txt'
        output.touch(exist_ok=False)
        env = {**self.env, 'RUNNER_TEMP': str(temporary), 'GITHUB_ENV': str(output)}
        self.step('llvm-first-party-setup', [self.report['toolchains']['node24']['path'], action / 'install.mjs'], env=env)
        exported = {}
        for line in output.read_text().splitlines():
            key, separator, value = line.partition('=')
            assert separator and key in ('CC_wasm32_unknown_unknown', 'AR_wasm32_unknown_unknown') and key not in exported
            resolved = Path(value).resolve(strict=True)
            assert resolved.is_relative_to(temporary) and resolved.is_file()
            exported[key] = str(resolved)
        assert set(exported) == {'CC_wasm32_unknown_unknown', 'AR_wasm32_unknown_unknown'}
        compiler = self.tool('wasm-clang', exported['CC_wasm32_unknown_unknown'])
        archiver = self.tool('wasm-ar', exported['AR_wasm32_unknown_unknown'])
        for info in receipts.values():
            assert digest(info['path']) == info['sha256']
        self.report['sourceInstaller'] = {'source': self.report['source'], 'files': receipts,
                                         'environmentFileSha256': digest(output)}
        self.report['toolchains']['llvm'] = {'compiler': compiler, 'archiver': archiver}
        self.wasm_environment = exported

    def verify_final(self):
        rust = self.report['toolchains']['rust']
        for key in ('originalCompiler', 'originalCargo', 'compiler', 'cargo'):
            item = rust[key]
            assert digest(item['path']) == item['sha256'], 'compiler bytes changed'
            assert self.step('final-' + key, [item['path'], '--version'], cap=30) == item['version']
        assert self.step('final-private-sysroot', [rust['compiler']['path'], '--print', 'sysroot'], cap=30) == rust['sysroot']
        assert self.step('final-original-sysroot', [rust['originalCompiler']['path'], '--print', 'sysroot'], cap=30) == rust['originalSysroot']
        assert self.source_check('after') == self.report['source']
        for item in (self.report['toolchains']['node22'], self.report['toolchains']['node24'],
                     self.report['toolchains']['llvm']['compiler'], self.report['toolchains']['llvm']['archiver']):
            assert digest(item['path']) == item['sha256']
        assert shutil.which('cc', path=self.original_path) == shutil.which('cc', path=self.env['PATH']), 'host compiler routing changed'

    def join_receipts(self):
        for label in self.request_labels:
            receipt = json.loads((self.processes / (label + '.exit.json')).read_text())
            assert settlement_control.joined(receipt) and isinstance(receipt.get('exitCode'), int), 'ambiguous or unsettled bootstrap child'
        self.report['processesJoined'] = True

    def run(self):
        try:
            self.save()
            assert sys.platform == 'linux' and platform.machine() == 'x86_64' and platform.libc_ver()[0] == 'glibc'
            self.report['source'] = self.source_check('before')
            self.report['hostCompilerBefore'] = shutil.which('cc', path=self.original_path)
            self.prepare_nodes()
            self.prepare_rust()
            self.prepare_llvm()
            self.verify_final()
            self.join_receipts()
            environment = {'PATH': self.env['PATH'], 'NODE22': self.report['toolchains']['node22']['path'],
                           **self.wasm_environment, 'FS_SAFE_PROOF_BOOTSTRAP_JSON': str(self.root / 'bootstrap.json')}
            write_json(self.root / 'environment.json', environment)
            self.report['environmentSha256'] = digest(self.root / 'environment.json')
            self.report['state'] = 'complete'
        except BaseException as error:
            self.report['failure'] = repr(error)
            try:
                self.join_receipts()
            except BaseException as cleanup_error:
                self.report['settlementFailure'] = repr(cleanup_error)
            raise
        finally:
            self.report['completedAt'] = bounded.now()
            self.save()
        print(json.dumps({'state': 'complete', 'bootstrap': str(self.root / 'bootstrap.json')}))


def main():
    if len(sys.argv) == 4 and sys.argv[1] == '--worker':
        worker(sys.argv[2], json.loads(sys.argv[3]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepare-only', action='store_true', required=True)
    parser.add_argument('source', type=Path)
    parser.add_argument('bootstrap_dir', type=Path)
    args = parser.parse_args()
    settlement_control.install()
    Bootstrap(args.source, args.bootstrap_dir).run()


if __name__ == '__main__':
    main()
