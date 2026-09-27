// One selected public call; setup, addon loading, verification and cleanup are outside markers.
import assert from 'node:assert/strict';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, save } from './installed.mjs';

const [consumer, base, row, majorText, manifestOutput, proofOutput, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0);
assert(['affected', 'retained', 'no-policy'].includes(row));
assert.equal(process.platform, 'linux');
const nodeMajor = Number(majorText);
const versions = { 22: 'v22.23.2', 24: 'v24.21.0' };
assert.equal(process.version, versions[nodeMajor]);
assert(!fsSync.existsSync(manifestOutput) && !fsSync.existsSync(proofOutput), 'trace outputs must be new');
const api = await installedApi(consumer);
assert(['A', 'B'].includes(api.expected.role));
const rootPath = await fs.mkdtemp(path.join(await fs.realpath(base), 'fs-safe-captured-parent-'));
await fs.chmod(rootPath, 0o700);
const parentPath = path.join(rootPath, 'parent');
const targetPath = path.join(parentPath, 'value');
const sentinelPath = path.join(rootPath, 'outside-sentinel');
const bytes = Buffer.from('synthetic payload');
const sentinel = Buffer.from('outside sentinel retained\n');
await fs.mkdir(parentPath, { mode: 0o700 });
const safe = await api.root(rootPath);
// Creating the required outside sentinel through the unchanged no-policy public
// route loads the real addon and fully settles before the selected write.
await safe.create('outside-sentinel', sentinel, { mkdir: false, durable: false, mode: 0o600 });
async function identity(name) {
  const st = await fs.lstat(name, { bigint: true });
  assert(!st.isSymbolicLink());
  return { dev: String(st.dev), ino: String(st.ino), directory: st.isDirectory() };
}
const rootIdentity = await identity(rootPath), parentIdentity = await identity(parentPath), sentinelIdentity = await identity(sentinelPath);
const native = api.nativeState();
const relative = row === 'affected' ? './parent/value' : 'parent/value';
const options = { mkdir: false, durable: false, ...(row === 'no-policy' ? {} : { mutationSymlinks: 'reject' }) };
const beginMarker = `FS_SAFE_PARENT_BEGIN ${row}`, endMarker = `FS_SAFE_PARENT_END ${row}`;
const manifest = { schema: 1, row, role: api.expected.role, nodeVersion: process.version, nodeMajor,
  rootPath, parentPath, targetPath, sentinelPath, beginMarker, endMarker,
  source: api.expected.source, nativeSha256: native.sha256 };
save(manifestOutput, manifest);
const receipt = { ...manifest, ok: false, cleanup: false, phase: 'prepared' };
save(proofOutput, receipt);
try {
  assert.equal(fsSync.writeSync(2, `${beginMarker}\n`), Buffer.byteLength(`${beginMarker}\n`));
  await safe.write(relative, 'synthetic payload', options);
  assert.equal(fsSync.writeSync(2, `${endMarker}\n`), Buffer.byteLength(`${endMarker}\n`));
  receipt.phase = 'verification';
  assert.deepEqual(await identity(rootPath), rootIdentity);
  assert.deepEqual(await identity(parentPath), parentIdentity);
  assert.deepEqual(await identity(sentinelPath), sentinelIdentity);
  assert.deepEqual((await fs.readdir(rootPath)).sort(), ['outside-sentinel', 'parent']);
  const names = (await fs.readdir(parentPath)).sort(); assert.deepEqual(names, ['value']);
  const actual = await fs.readFile(targetPath); assert.deepEqual(actual, bytes);
  assert.deepEqual(await fs.readFile(sentinelPath), sentinel);
  const stat = await fs.lstat(targetPath, { bigint: true });
  assert(stat.isFile() && !stat.isSymbolicLink()); assert.equal(stat.nlink, 1n);
  assert.equal(stat.mode & 0o7777n, 0o600n);
  receipt.outcome = { bytesHex: actual.toString('hex'), mode: Number(stat.mode & 0o7777n), sentinelHex: sentinel.toString('hex'), names };
  const targetIdentity = await identity(targetPath);
  assert.deepEqual(await identity(targetPath), targetIdentity); await fs.unlink(targetPath);
  assert.deepEqual(await fs.readdir(parentPath), []);
  assert.deepEqual(await identity(parentPath), parentIdentity); await fs.rmdir(parentPath);
  assert.deepEqual(await identity(sentinelPath), sentinelIdentity); await fs.unlink(sentinelPath);
  assert.deepEqual(await fs.readdir(rootPath), []);
  assert.deepEqual(await identity(rootPath), rootIdentity); await fs.rmdir(rootPath);
  api.verify(); assert.equal(api.nativeState().sha256, native.sha256);
  receipt.ok = true; receipt.cleanup = true; receipt.phase = 'complete'; save(proofOutput, receipt);
} catch (error) {
  receipt.failure = { name: error?.name, code: error?.code, message: error?.message ?? String(error), stack: error?.stack };
  save(proofOutput, receipt); throw error;
}
