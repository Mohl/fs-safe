// Installed-package adaptation of scripts/clone-xfs-proof.mjs. FIEMAP and
// independent edits are correctness evidence; this script records no timings.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi } from './installed.mjs';
import {
  identity, assertIdentity, createFixture, snapshot, assertSnapshot, removeOwned, tool,
} from './fixture.mjs';

const [consumer, mountArgument, mode, output, ...extra] = process.argv.slice(2);
assert(consumer && mountArgument && output && ['reflink', 'no-reflink'].includes(mode)
  && extra.length === 0, 'Usage: node xfs-proof.mjs CONSUMER MOUNT reflink|no-reflink OUTPUT');
assert.equal(process.platform, 'linux', 'XFS proof requires Linux');
const mount = await fs.realpath(mountArgument);
process.env.LC_ALL = 'C';
const result = { schema: 1, kind: 'installed-xfs-storage-proof', backend: 'xfs', mode,
  mount, results: [], extentEvidence: [], fixtures: [], ok: false, passed: false, cleanupComplete: false };
const fixedMtimeNs = 1700000000000000000n;
const files = new Map([
  ['payload', Buffer.alloc(1024 * 1024, 0x5a)],
  ['nested/unaligned', Buffer.from(Array.from({ length: 4097 }, (_, index) => (index % 251) + 1))],
  ['empty-file', Buffer.alloc(0)],
]);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

async function absent(filename) {
  await assert.rejects(fs.lstat(filename), { code: 'ENOENT' });
}

async function names(directory, expected) {
  assert.deepEqual((await fs.readdir(directory)).sort(), [...expected].sort());
}

async function extents(filename, label) {
  // filefrag -b1 reports FIEMAP offsets in bytes; -s requests FIEMAP_FLAG_SYNC.
  // https://github.com/tytso/e2fsprogs/blob/master/misc/filefrag.c
  // https://www.kernel.org/doc/html/latest/filesystems/fiemap.html
  const raw = await tool('filefrag', ['-b1', '-e', '-s', filename]);
  const mapped = [];
  for (const line of raw.split('\n')) {
    if (!/^\s*\d+:/.test(line)) continue;
    const match = /^\s*\d+:\s*(\d+)\.\.\s*(\d+):\s*(\d+)\.\.\s*(\d+):\s*(\d+):\s*(.*)$/.exec(line);
    assert(match, 'Unrecognized filefrag extent format');
    const [, logicalStart, logicalLast, physicalStart, physicalLast, length, flags] = match;
    const logical = BigInt(logicalStart);
    const physical = BigInt(physicalStart);
    const bytes = BigInt(length);
    assert(bytes > 0n);
    assert.equal(BigInt(logicalLast) + 1n - logical, bytes, 'Invalid logical extent length');
    assert.equal(BigInt(physicalLast) + 1n - physical, bytes, 'Invalid physical extent length');
    assert(!/unknown_loc|delalloc|unwritten|not_aligned|inline|encoded|hole/.test(flags),
      'Proof requires initialized, physically mapped file data');
    mapped.push({ logical, end: logical + bytes, physical, shared: /\bshared\b/.test(flags) });
  }
  assert(mapped.length > 0, 'No physical extents reported');
  result.extentEvidence.push({ filename, label, raw, extents: mapped.map(entry => ({
    logical: String(entry.logical), end: String(entry.end), physical: String(entry.physical),
    shared: entry.shared,
  })) });
  return mapped;
}

async function assertSharedData(source, destination, size, label) {
  const original = await extents(source, `${label}:source`);
  const copied = await extents(destination, `${label}:destination`);
  let sourceIndex = 0;
  let copyIndex = 0;
  let offset = 0n;
  const end = BigInt(size);
  while (offset < end) {
    const left = original[sourceIndex];
    const right = copied[copyIndex];
    assert(left && right, 'Extent maps do not cover the entire file');
    assert(left.logical <= offset && left.end > offset, 'Source extent map has a gap');
    assert(right.logical <= offset && right.end > offset, 'Copy extent map has a gap');
    assert(left.shared && right.shared, 'FIEMAP_EXTENT_SHARED is missing');
    assert.equal(left.physical + offset - left.logical, right.physical + offset - right.logical,
      'Source and copy data occupy different physical bytes');
    offset = left.end < right.end ? left.end : right.end;
    if (offset >= left.end) sourceIndex++;
    if (offset >= right.end) copyIndex++;
  }
  return size;
}

async function assertSeparateData(source, destination, size, label) {
  const original = await extents(source, `${label}:source`);
  const copied = await extents(destination, `${label}:destination`);
  let covered = 0n;
  for (const right of copied) {
    assert.equal(right.logical, covered, 'Byte-copy extent map has a gap');
    assert(!right.shared, 'Byte copy unexpectedly reports shared storage');
    covered = right.end;
    const rightEnd = right.physical + right.end - right.logical;
    for (const left of original) {
      const leftEnd = left.physical + left.end - left.logical;
      assert(rightEnd <= left.physical || leftEnd <= right.physical,
        'Byte copy overlaps the source physical storage');
    }
  }
  assert(covered >= BigInt(size), 'Byte-copy extent map does not cover the file');
  return size;
}

async function verify(directory, editedPayload = null) {
  await names(directory, ['empty-directory', 'empty-file', 'literal-link', 'nested', 'payload']);
  await names(path.join(directory, 'nested'), ['unaligned']);
  await names(path.join(directory, 'empty-directory'), []);
  for (const relative of ['', 'nested', 'empty-directory']) {
    const st = await fs.lstat(path.join(directory, relative), { bigint: true });
    assert(st.isDirectory() && !st.isSymbolicLink());
    assert.equal(st.mode & 0o777n, 0o750n);
    assert.equal(st.mtimeNs, fixedMtimeNs);
  }
  const link = path.join(directory, 'literal-link');
  const linkStat = await fs.lstat(link, { bigint: true });
  assert(linkStat.isSymbolicLink());
  assert.equal(await fs.readlink(link), 'nested/unaligned');
  for (const [name, originalBytes] of files) {
    const filename = path.join(directory, name);
    const st = await fs.lstat(filename, { bigint: true });
    const bytes = name === 'payload' && editedPayload ? editedPayload : originalBytes;
    assert(st.isFile() && !st.isSymbolicLink());
    assert.equal(st.nlink, 1n);
    assert.equal(st.size, BigInt(bytes.length));
    assert.equal(st.mode & 0o777n, name === 'payload' ? 0o751n : 0o640n);
    assert.equal(hash(await fs.readFile(filename)), hash(bytes), `SHA-256 mismatch for ${name}`);
    if (name === 'payload' && editedPayload) assert(st.mtimeNs > fixedMtimeNs);
    else assert.equal(st.mtimeNs, fixedMtimeNs);
  }
}

try {
  const api = await installedApi(consumer, 'require');
  const { copyTree, createCloneSource, probeTreeClone } = api;
  result.expected = api.expected;
  assert.equal(probeTreeClone(mount), 'xfs', 'Mount must have native XFS support');
  const owned = await createFixture(mount, 'fs-safe-xfs-proof-');
  result.fixtures.push({ path: owned.path, identity: owned.identity, removed: false });
  await names(owned.path, []);
  const source = path.join(owned.path, 'source');
  await createCloneSource(source);
  const sourceIdentity = await identity(source);
  await names(source, []);
  await fs.mkdir(path.join(source, 'nested'), { mode: 0o750 });
  await fs.mkdir(path.join(source, 'empty-directory'), { mode: 0o750 });
  for (const [name, bytes] of files) {
    await fs.writeFile(path.join(source, name), bytes, { flag: 'wx', mode: 0o640 });
    await fs.chmod(path.join(source, name), name === 'payload' ? 0o751 : 0o640);
    await fs.utimes(path.join(source, name), 1700000000, 1700000000);
  }
  await fs.symlink('nested/unaligned', path.join(source, 'literal-link'));
  await fs.lutimes(path.join(source, 'literal-link'), 1700000000, 1700000000);
  for (const relative of ['nested', 'empty-directory', '']) {
    await fs.chmod(path.join(source, relative), 0o750);
    await fs.utimes(path.join(source, relative), 1700000000, 1700000000);
  }
  await verify(source);
  await names(owned.path, ['source']);
  const sourceExpected = await snapshot(source);

  if (mode === 'no-reflink') {
    const rejected = path.join(owned.path, 'strict-unavailable');
    await assert.rejects(copyTree(source, rejected, { clone: 'always' }), { code: 'unsupported-platform' });
    await absent(rejected);
    await names(owned.path, ['source']);
    await assertIdentity(source, sourceIdentity);
    await verify(source);
    await assertSnapshot(source, sourceExpected);
    result.results.push({ policy: 'always', unsupported: true, destinationAbsent: true });
  }
  const cases = mode === 'reflink' ? [
    { label: 'always-one-worker', clone: 'always', concurrency: 1 },
    { label: 'always-default-workers', clone: 'always' },
    { label: 'auto', clone: 'auto' },
    { label: 'never', clone: 'never' },
  ] : [{ label: 'auto', clone: 'auto' }, { label: 'never', clone: 'never' }];
  for (const { label, ...options } of cases) {
    const destination = path.join(owned.path, label);
    await copyTree(source, destination, options);
    const destinationIdentity = await identity(destination);
    await names(owned.path, ['source', label]);
    await verify(destination);
    await assertSnapshot(destination, sourceExpected);
    let sharedBytes = 0;
    let separateBytes = 0;
    for (const [name, bytes] of files) {
      if (bytes.length === 0) continue;
      const [original, copied] = await Promise.all([
        fs.lstat(path.join(source, name), { bigint: true }),
        fs.lstat(path.join(destination, name), { bigint: true }),
      ]);
      assert.equal(original.dev, copied.dev, 'Extent comparison requires the same device');
      assert.notEqual(original.ino, copied.ino, 'Copy must have an independent inode');
      if (mode === 'reflink' && options.clone !== 'never') {
        sharedBytes += await assertSharedData(path.join(source, name), path.join(destination, name), bytes.length, label);
      } else {
        separateBytes += await assertSeparateData(path.join(source, name), path.join(destination, name), bytes.length, label);
      }
    }
    const edited = Buffer.alloc(4096, 0x31);
    const payload = path.join(destination, 'payload');
    const before = await fs.lstat(payload, { bigint: true });
    const handle = await fs.open(payload, 'r+');
    try {
      const write = await handle.write(edited, 0, edited.length, 0);
      assert.equal(write.bytesWritten, edited.length);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const after = await fs.lstat(payload, { bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    const expectedEdit = Buffer.from(files.get('payload'));
    edited.copy(expectedEdit);
    await assertIdentity(destination, destinationIdentity);
    await verify(destination, expectedEdit);
    await assertIdentity(source, sourceIdentity);
    await verify(source);
    await assertSnapshot(source, sourceExpected);
    await names(owned.path, ['source', label]);
    const destinationExpected = structuredClone(sourceExpected);
    Object.assign(destinationExpected.payload, { size: expectedEdit.length,
      sha256: hash(expectedEdit), mtimeNs: String(after.mtimeNs) });
    await assertSnapshot(destination, destinationExpected);
    await removeOwned(destination, destinationIdentity, 'xfs', destinationExpected);
    await absent(destination);
    await names(owned.path, ['source']);
    result.results.push({ policy: label, sharedBytes, separateBytes, hashesMatch: true,
      metadataPreserved: true, independentWrite: true, destinationRemoved: true });
  }
  await assertIdentity(source, sourceIdentity);
  await verify(source);
  await assertSnapshot(source, sourceExpected);
  await names(owned.path, ['source']);
  await removeOwned(source, sourceIdentity, 'xfs', sourceExpected);
  await absent(source);
  await names(owned.path, []);
  await removeOwned(owned.path, owned.identity, 'xfs', await snapshot(owned.path));
  await absent(owned.path);
  result.fixtures[0].removed = true;
  await api.verify();
  assert.equal(result.results.length, mode === 'reflink' ? 4 : 3);
  assert(result.fixtures.every(fixture => fixture.removed));
  result.cleanupComplete = true;
  result.ok = true;
  result.passed = true;
} catch (error) {
  result.error = { name: error?.name ?? typeof error, code: error?.code ?? null,
    message: String(error?.message ?? error), stack: error?.stack ?? null };
  result.cleanupPolicy = 'Unexpected or failed fixtures are retained; no recursive failure cleanup';
  process.exitCode = 1;
}
await fs.writeFile(output, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
console.log(JSON.stringify({ passed: result.passed, policies: result.results.length,
  mode, output, cleanupComplete: result.cleanupComplete }));
