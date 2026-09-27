import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi } from './installed.mjs';
import {
  identity, assertIdentity, createFixture, fillSmall, snapshot, assertSnapshot,
  removeOwned, reclaim,
} from './fixture.mjs';

const [consumer, mountArgument, filesystem, output, mode = 'require', ...extra] = process.argv.slice(2);
assert(consumer && mountArgument && output && extra.length === 0,
  'Usage: node behavior.mjs CONSUMER MOUNT xfs|btrfs OUTPUT [require|off]');
assert(['xfs', 'btrfs'].includes(filesystem));
assert(['require', 'off'].includes(mode));
assert.equal(process.platform, 'linux');

const mount = await fs.realpath(mountArgument);
const result = { schema: 1, kind: 'installed-clone-behavior', filesystem, mode,
  mount, checks: [], fixtures: [], ok: false, passed: false, cleanupComplete: false };
const fixedMtimeNs = 1700000000000000000n;
const files = Array.from({ length: 8 }, (_, index) => ({
  name: path.posix.join(['', 'nested', 'nested/deeper'][index % 3], `file-${index}`),
  bytes: Buffer.from(Array.from({ length: 4096 }, (_, offset) => (index * 17 + offset) % 251)),
}));
const dirs = ['', 'nested', 'nested/deeper', 'empty'];
const edit = Buffer.from('independent installed clone edit\n');

async function absent(filename) {
  await assert.rejects(fs.lstat(filename), { code: 'ENOENT' });
}

async function names(directory, expected) {
  assert.deepEqual((await fs.readdir(directory)).sort(), [...expected].sort(),
    `Unexpected entries in ${directory}`);
}

// These expectations come from the fixed fixture specification, not a snapshot
// of arbitrary output that could accidentally authorize deleting extra entries.
async function verifySmall(directory, edited = false) {
  for (const relative of dirs) {
    const expected = files.filter(file => path.posix.dirname(file.name) === (relative || '.'))
      .map(file => path.posix.basename(file.name));
    if (!relative) expected.push('nested', 'empty', 'empty-file', 'literal-link');
    if (relative === 'nested') expected.push('deeper');
    await names(path.join(directory, relative), expected);
    const st = await fs.lstat(path.join(directory, relative), { bigint: true });
    assert(st.isDirectory() && !st.isSymbolicLink());
    assert.equal(st.mode & 0o777n, 0o750n);
    assert.equal(st.mtimeNs, fixedMtimeNs);
  }
  for (const file of [...files, { name: 'empty-file', bytes: Buffer.alloc(0) }]) {
    const filename = path.join(directory, file.name);
    const st = await fs.lstat(filename, { bigint: true });
    const expected = edited && file.name === 'file-0' ? edit : file.bytes;
    assert(st.isFile() && !st.isSymbolicLink());
    assert.equal(st.nlink, 1n);
    assert.equal(st.mode & 0o777n, 0o640n);
    assert.equal(st.size, BigInt(expected.length));
    assert.deepEqual(await fs.readFile(filename), expected, `Wrong bytes: ${file.name}`);
    if (edited && file.name === 'file-0') assert(st.mtimeNs > fixedMtimeNs);
    else assert.equal(st.mtimeNs, fixedMtimeNs);
  }
  const link = path.join(directory, 'literal-link');
  const st = await fs.lstat(link, { bigint: true });
  assert(st.isSymbolicLink());
  assert.equal(await fs.readlink(link), 'nested/file-1');
}

async function check(name, action) {
  const details = await action();
  result.checks.push({ name, passed: true, ...details });
}

async function rejected(action, expectedCode) {
  let seen;
  await assert.rejects(action, error => {
    assert(error instanceof Error);
    if (expectedCode !== undefined) assert.equal(error.code, expectedCode);
    seen = { name: error.name, code: error.code ?? null, message: error.message };
    return true;
  });
  return seen;
}

async function removeVerified(directory, ownedIdentity, fsKind, expectedTree) {
  await assertIdentity(directory, ownedIdentity);
  await assertSnapshot(directory, expectedTree);
  await removeOwned(directory, ownedIdentity, fsKind, expectedTree);
  await absent(directory);
}

let api;
try {
  api = await installedApi(consumer, mode);
  const { copyTree, createCloneSource, probeTreeClone } = api;
  result.expected = api.expected;
  const owned = await createFixture(mount, 'fs-safe-clone-behavior-');
  result.fixtures.push({ path: owned.path, identity: owned.identity, removed: false });
  const source = path.join(owned.path, 'source');

  await check('probe-is-artifact-free', async () => {
    await names(owned.path, []);
    assert.equal(probeTreeClone(owned.path), mode === 'off' ? undefined : filesystem);
    await names(owned.path, []);
  });

  if (mode === 'require') {
    await check('create-clone-source', async () => {
      await createCloneSource(source);
      assert((await fs.lstat(source)).isDirectory());
      await names(source, []);
      await names(owned.path, ['source']);
    });
  } else {
    await check('native-off-create-source-unavailable', async () => {
      const error = await rejected(() => createCloneSource(source), 'helper-unavailable');
      await absent(source);
      await names(owned.path, []);
      return { error };
    });
    await fs.mkdir(source);
  }
  const sourceIdentity = await identity(source);
  const sourceExpected = await fillSmall(source);
  await verifySmall(source);
  await assertSnapshot(source, sourceExpected);
  const policies = mode === 'require' ? ['always', 'auto', 'never'] : ['auto', 'never'];

  if (mode === 'off') {
    await check('native-off-strict-copy-unavailable', async () => {
      const destination = path.join(owned.path, 'strict-unavailable');
      const error = await rejected(() => copyTree(source, destination, { clone: 'always' }),
        'helper-unavailable');
      await absent(destination);
      await names(owned.path, ['source']);
      await assertIdentity(source, sourceIdentity);
      await assertSnapshot(source, sourceExpected);
      return { error };
    });
  }

  for (const clone of policies) {
    const destination = path.join(owned.path, `copy-${clone}`);
    let destinationIdentity;
    let editedExpected;
    await check(`${clone}-contents-metadata-symlinks`, async () => {
      await copyTree(source, destination, { clone, concurrency: 1 });
      destinationIdentity = await identity(destination);
      await names(owned.path, ['source', `copy-${clone}`]);
      await verifySmall(source);
      await verifySmall(destination);
      await assertIdentity(source, sourceIdentity);
      await assertSnapshot(source, sourceExpected);
      await assertSnapshot(destination, sourceExpected);
      const [original, copied] = await Promise.all([
        fs.lstat(path.join(source, 'file-0'), { bigint: true }),
        fs.lstat(path.join(destination, 'file-0'), { bigint: true }),
      ]);
      assert(original.dev !== copied.dev || original.ino !== copied.ino,
        'Copied file must have an independent filesystem identity');
    });
    await check(`${clone}-independent-write`, async () => {
      const file = path.join(destination, 'file-0');
      const before = await fs.lstat(file, { bigint: true });
      await fs.writeFile(file, edit);
      const after = await fs.lstat(file, { bigint: true });
      assert(after.isFile() && !after.isSymbolicLink());
      assert.equal(after.dev, before.dev);
      assert.equal(after.ino, before.ino);
      await verifySmall(destination, true);
      await verifySmall(source);
      await assertSnapshot(source, sourceExpected);
      editedExpected = structuredClone(sourceExpected);
      Object.assign(editedExpected['file-0'], { size: edit.length,
        sha256: createHash('sha256').update(edit).digest('hex'), mtimeNs: String(after.mtimeNs) });
      await assertSnapshot(destination, editedExpected);
    });
    await check(`${clone}-existing-destination-rejected`, async () => {
      const copyError = await rejected(() => copyTree(source, destination, { clone }));
      const createError = mode === 'require'
        ? await rejected(() => createCloneSource(destination)) : null;
      await assertIdentity(destination, destinationIdentity);
      await verifySmall(destination, true);
      await assertSnapshot(destination, editedExpected);
      await assertIdentity(source, sourceIdentity);
      await assertSnapshot(source, sourceExpected);
      await names(owned.path, ['source', `copy-${clone}`]);
      return { copyError, createError };
    });
    await removeVerified(destination, destinationIdentity, filesystem, editedExpected);
    await names(owned.path, ['source']);
  }

  await check('preaborted-source-and-copy-preserve-reason', async () => {
    const destination = path.join(owned.path, 'preaborted');
    const reason = new Error('installed clone behavior preaborted');
    const signal = AbortSignal.abort(reason);
    for (const action of [
      () => createCloneSource(destination, { signal }),
      () => copyTree(source, destination, { clone: 'always', signal }),
    ]) {
      await assert.rejects(action, error => { assert.equal(error, reason); return true; });
      await absent(destination);
    }
    await names(owned.path, ['source']);
    await assertIdentity(source, sourceIdentity);
    await assertSnapshot(source, sourceExpected);
  });

  await check('self-and-descendant-rejected', async () => {
    const clone = mode === 'require' ? 'always' : 'never';
    const selfError = await rejected(() => copyTree(source, source, { clone }), 'invalid-path');
    const child = path.join(source, 'forbidden-child');
    const childError = await rejected(() => copyTree(source, child, { clone }), 'invalid-path');
    await absent(child);
    await assertIdentity(source, sourceIdentity);
    await verifySmall(source);
    await assertSnapshot(source, sourceExpected);
    await names(owned.path, ['source']);
    return { selfError, childError };
  });

  if (filesystem === 'btrfs' && mode === 'require') {
    await check('btrfs-ordinary-directory-refused', async () => {
      const ordinary = path.join(owned.path, 'ordinary');
      const destination = path.join(owned.path, 'ordinary-copy');
      await fs.mkdir(ordinary);
      const ordinaryIdentity = await identity(ordinary);
      const ordinaryExpected = await fillSmall(ordinary);
      await verifySmall(ordinary);
      const error = await rejected(() => copyTree(ordinary, destination, { clone: 'always' }));
      await absent(destination);
      await names(owned.path, ['source', 'ordinary']);
      await assertIdentity(ordinary, ordinaryIdentity);
      await verifySmall(ordinary);
      await assertSnapshot(ordinary, ordinaryExpected);
      await removeVerified(ordinary, ordinaryIdentity, filesystem, ordinaryExpected);
      await names(owned.path, ['source']);
      return { error };
    });
  }

  // Deliberately use the host /tmp, independently of a caller's TMPDIR override.
  const hostTemporary = await fs.realpath('/tmp');
  assert.equal(probeTreeClone(hostTemporary), undefined,
    'The declared unsupported host /tmp must actually be unsupported; no skip');
  const unsupported = await createFixture(hostTemporary, 'fs-safe-clone-unsupported-');
  const unsupportedRecord = { path: unsupported.path, identity: unsupported.identity, removed: false };
  result.fixtures.push(unsupportedRecord);
  const plain = path.join(unsupported.path, 'source');
  await fs.mkdir(plain);
  const plainIdentity = await identity(plain);
  const plainExpected = await fillSmall(plain);
  await verifySmall(plain);
  await check('host-tmp-strict-and-source-creation-unavailable', async () => {
    const destination = path.join(unsupported.path, 'unavailable');
    const code = mode === 'off' ? 'helper-unavailable' : 'unsupported-platform';
    const copyError = await rejected(() => copyTree(plain, destination, { clone: 'always' }), code);
    await absent(destination);
    const createError = await rejected(() => createCloneSource(destination), code);
    await absent(destination);
    await names(unsupported.path, ['source']);
    await assertIdentity(plain, plainIdentity);
    await assertSnapshot(plain, plainExpected);
    return { copyError, createError };
  });
  for (const clone of ['auto', 'never']) {
    await check(`host-tmp-${clone}-fallback`, async () => {
      const destination = path.join(unsupported.path, `copy-${clone}`);
      await copyTree(plain, destination, { clone, concurrency: 1 });
      const destinationIdentity = await identity(destination);
      await names(unsupported.path, ['source', `copy-${clone}`]);
      await verifySmall(destination);
      await assertSnapshot(destination, plainExpected);
      await assertIdentity(plain, plainIdentity);
      await assertSnapshot(plain, plainExpected);
      await removeVerified(destination, destinationIdentity, 'unsupported', plainExpected);
      await names(unsupported.path, ['source']);
    });
  }
  await verifySmall(plain);
  await removeVerified(plain, plainIdentity, 'unsupported', plainExpected);
  await names(unsupported.path, []);
  await removeVerified(unsupported.path, unsupported.identity, 'unsupported', await snapshot(unsupported.path));
  unsupportedRecord.removed = true;

  await names(owned.path, ['source']);
  await verifySmall(source);
  await removeVerified(source, sourceIdentity, filesystem, sourceExpected);
  await names(owned.path, []);
  await removeVerified(owned.path, owned.identity, filesystem, await snapshot(owned.path));
  result.fixtures[0].removed = true;
  await reclaim(mount, filesystem);
  await api.verify();
  assert.equal(result.checks.length, mode === 'off' ? 14 : filesystem === 'btrfs' ? 17 : 16);
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
console.log(JSON.stringify({ passed: result.passed, checks: result.checks.length,
  filesystem, mode, output, cleanupComplete: result.cleanupComplete }));
