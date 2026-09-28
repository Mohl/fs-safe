import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, save } from './installed.mjs';
import { privateWorkspace, rowFixture, names, identity, sameIdentity, absent, checkFile,
  linkIdentity, descriptorSnapshot, settledDescriptors, assertMechanism,
  payload, targetSentinel, outsideSentinel, primeSentinel, writeOptions } from './fixture.mjs';
const [consumer, base, mechanism, majorText, output, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0); assert(consumer && base && output);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const nodeMajor = Number(majorText); assert([22, 24].includes(nodeMajor));
assertMechanism(mechanism, nodeMajor, protocol);
const rowIds = ['nested-write-read', 'relative-alias-write', 'root-write-read', 'dot-parent-write',
  'missing-parent-create', 'missing-parent-mkdir-false', 'alias-mutation-reject', 'alias-canonical-deny',
  'create-collision', 'move-success', 'move-collision', 'escaping-parent-reject', 'traversal-reject',
  'hardlink-read-reject', 'bounded-cleanup', 'no-orphan-settlement'];
assert.deepEqual(protocol.qualification.rowIds, rowIds);
const api = await installedApi(consumer);
const receipt = { state: 'incomplete', platform: process.platform, mechanism, fallbackHook: '0',
  nodeVersion: process.version, nodeMajor, source: api.expected.source, role: api.expected.role, rows: [], cleanup: false };
save(output, receipt);
try {
  const workspace = await privateWorkspace(base), workspaceIdentity = await identity(workspace);
  function passed(id) {
    assert.equal(id, rowIds[receipt.rows.length]);
    receipt.rows.push({ id, passed: true }); save(output, receipt);
  }
  const writes = [
    { id: rowIds[0], depth: 8, alias: false }, { id: rowIds[1], depth: 0, alias: true },
    { id: rowIds[2], depth: 0, alias: false }, { id: rowIds[3], depth: 1, alias: false },
  ];
  for (const [index, row] of writes.entries()) {
    const fixture = await rowFixture(workspace, row, index, api); await fixture.prepare();
    if (row.id === 'dot-parent-write') await fixture.safe.write('d0/./value', payload, writeOptions);
    else await fixture.invoke();
    assert.deepEqual((await fixture.safe.read(path.relative(fixture.rootPath, fixture.targetPath))).buffer, payload);
    await fixture.verifyAndReset(); await fixture.close(); passed(row.id);
  }
  await names(workspace, []);
  const rootPath = path.join(workspace, 'cases'), outsidePath = path.join(workspace, 'outside-cases');
  await fs.mkdir(rootPath, { mode: 0o700 }); await fs.mkdir(outsidePath, { mode: 0o700 });
  const outsideIdentity = await identity(outsidePath), sentinelPath = path.join(outsidePath, 'sentinel');
  await fs.writeFile(sentinelPath, outsideSentinel, { flag: 'wx', mode: 0o600 });
  const sentinelIdentity = await identity(sentinelPath);
  const entries = new Map();
  async function remember(name, bytes) {
    const file = path.join(rootPath, name), st = await fs.lstat(file);
    if (st.isSymbolicLink()) entries.set(name, { kind: 'link', receipt: await linkIdentity(file) });
    else entries.set(name, { kind: st.isDirectory() ? 'directory' : 'file', receipt: await identity(file), mode: st.mode & 0o7777, bytes });
  }
  await remember('');
  for (const name of ['actual', 'incoming', 'incoming/deep', 'archive', 'archive/deep']) {
    await fs.mkdir(path.join(rootPath, name), { mode: 0o700 }); await remember(name);
  }
  await fs.symlink('actual', path.join(rootPath, 'alias')); await remember('alias');
  await fs.symlink(outsidePath, path.join(rootPath, 'escape')); await remember('escape');
  for (const [name, bytes] of [['actual/value', targetSentinel], ['incoming/deep/source', payload]]) {
    await fs.writeFile(path.join(rootPath, name), bytes, { flag: 'wx', mode: 0o600 }); await remember(name, bytes);
  }
  const safe = await api.root(rootPath);
  await safe.create('prime-sentinel', primeSentinel, writeOptions); await remember('prime-sentinel', primeSentinel);
  receipt.native = api.nativeState();
  const descriptors = descriptorSnapshot();
  async function checkTree() {
    await sameIdentity(workspace, workspaceIdentity); await names(workspace, ['cases', 'outside-cases']);
    await sameIdentity(outsidePath, outsideIdentity); await names(outsidePath, ['sentinel']);
    await checkFile(sentinelPath, outsideSentinel, sentinelIdentity);
    for (const [name, entry] of entries) {
      const file = path.join(rootPath, name);
      if (entry.kind === 'link') assert.deepEqual(await linkIdentity(file), entry.receipt);
      else if (entry.kind === 'file') await checkFile(file, entry.bytes, entry.receipt);
      else {
        await sameIdentity(file, entry.receipt); assert.equal((await fs.lstat(file)).mode & 0o7777, entry.mode);
        const children = [...entries.keys()].filter(child => child && (path.posix.dirname(child) === (name || '.'))).map(child => path.posix.basename(child));
        await names(file, children);
      }
    }
    settledDescriptors(descriptors);
  }
  async function check(id, action) { await action(); await checkTree(); passed(id); }
  await check('missing-parent-create', async () => {
    await safe.create('created/deep/value', payload, { ...writeOptions, mkdir: true });
    await remember('created'); await remember('created/deep'); await remember('created/deep/value', payload);
    assert.deepEqual((await safe.read('created/deep/value')).buffer, payload);
  });
  await check('missing-parent-mkdir-false', async () => {
    await assert.rejects(safe.write('alias/missing/value', payload, writeOptions), { code: 'not-found' });
    await absent(path.join(rootPath, 'actual/missing'));
  });
  await check('alias-mutation-reject', () => assert.rejects(
    safe.write('alias/value', payload, { ...writeOptions, mutationSymlinks: 'reject' }), { code: 'symlink' }));
  await check('alias-canonical-deny', () => assert.rejects(
    safe.write('alias/value', payload, { ...writeOptions, denyMutations: { prefixes: [path.join(rootPath, 'actual')] } }), { code: 'denied-path' }));
  await check('create-collision', () => assert.rejects(safe.create('actual/value', payload, writeOptions), { code: 'already-exists' }));
  await check('move-success', async () => {
    const source = entries.get('incoming/deep/source');
    await safe.move('incoming/deep/source', 'archive/deep/target');
    await absent(path.join(rootPath, 'incoming/deep/source'));
    entries.delete('incoming/deep/source'); entries.set('archive/deep/target', source);
  });
  await check('move-collision', async () => {
    await fs.writeFile(path.join(rootPath, 'incoming/deep/source'), targetSentinel, { flag: 'wx', mode: 0o600 });
    await remember('incoming/deep/source', targetSentinel);
    await assert.rejects(safe.move('incoming/deep/source', 'archive/deep/target'), { code: 'already-exists' });
  });
  await check('escaping-parent-reject', () => assert.rejects(safe.write('escape/value', payload, writeOptions), { code: 'path-alias' }));
  await check('traversal-reject', () => assert.rejects(safe.write('../outside-cases/sentinel', payload, writeOptions), { code: 'outside-workspace' }));
  await check('hardlink-read-reject', async () => {
    const linked = path.join(rootPath, 'hardlink');
    await fs.link(path.join(rootPath, 'actual/value'), linked);
    assert.equal((await fs.lstat(linked, { bigint: true })).nlink, 2n);
    await assert.rejects(safe.readText('hardlink', { hardlinks: 'reject' }), { code: 'hardlink' });
    await sameIdentity(linked, entries.get('actual/value').receipt);
    assert.deepEqual(await fs.readFile(linked), targetSentinel); await fs.unlink(linked); await absent(linked);
  });
  await check('bounded-cleanup', async () => {
    const options = { rootDir: rootPath, prefix: 'bounded-', cleanupSafety: 'require-bounded' };
    if (mechanism === 'openat2') {
      const temporary = await api.tempWorkspace(options);
      assert.equal(path.dirname(temporary.dir), rootPath); assert(path.basename(temporary.dir).startsWith('bounded-'));
      await temporary.write('value', payload); await names(temporary.dir, ['value']);
      await checkFile(temporary.path('value'), payload);
      assert.equal(await temporary.cleanup(), 'removed'); await absent(temporary.dir);
    } else await assert.rejects(api.tempWorkspace(options), { code: 'helper-unavailable' });
  });
  await checkTree(); passed('no-orphan-settlement');
  // Remove only the exact owned entries after identity/name verification; never recursive cleanup.
  for (const [name, entry] of [...entries].sort((a, b) => b[0].split('/').length - a[0].split('/').length || b[0].length - a[0].length)) {
    if (!name) continue;
    const file = path.join(rootPath, name);
    if (entry.kind === 'directory') { await sameIdentity(file, entry.receipt); await names(file, []); await fs.rmdir(file); }
    else if (entry.kind === 'link') { assert.deepEqual(await linkIdentity(file), entry.receipt); await fs.unlink(file); }
    else { await checkFile(file, entry.bytes, entry.receipt); await fs.unlink(file); }
    await absent(file);
  }
  await sameIdentity(rootPath, entries.get('').receipt); await names(rootPath, []); await fs.rmdir(rootPath);
  await checkFile(sentinelPath, outsideSentinel, sentinelIdentity); await fs.unlink(sentinelPath);
  await sameIdentity(outsidePath, outsideIdentity); await names(outsidePath, []); await fs.rmdir(outsidePath);
  await sameIdentity(workspace, workspaceIdentity); await names(workspace, []); await fs.rmdir(workspace); await absent(workspace);
  settledDescriptors(descriptors); api.verify(); assert.deepEqual(api.nativeState(), receipt.native);
  assert.deepEqual(receipt.rows.map(row => row.id), rowIds);
  receipt.cleanup = true; receipt.state = 'complete'; save(output, receipt);
} catch (error) {
  receipt.failure = { message: error?.message ?? String(error), stack: error?.stack, code: error?.code };
  save(output, receipt); throw error;
}
