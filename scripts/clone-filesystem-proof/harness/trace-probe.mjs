import assert from 'node:assert/strict';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, writeJson } from './installed.mjs';
import { identity, assertIdentity, snapshot, assertSnapshot } from './fixture.mjs';

const [consumer, setupFile, resultOutput] = process.argv.slice(2);
const prepared = readJson(setupFile);
const { fixture, destination, source, operation, filesystem, role, mount } = prepared;
assert(['createCloneSource', 'copyTree-empty', 'copyTree-small-nested'].includes(operation));
const api = await installedApi(consumer, 'require');
assert.deepEqual(api.expected.source, prepared.sourcePins);
await assertIdentity(fixture.path, fixture.identity);
assert.equal(path.dirname(fixture.path), await fs.realpath(mount));
assert.equal(destination, path.join(fixture.path, 'output'));
await assert.rejects(fs.lstat(destination), { code: 'ENOENT' });
if (source) {
  assert.equal(source.path, path.join(fixture.path, 'source'));
  await assertIdentity(source.path, source.identity);
  await assertSnapshot(source.path, source.expected);
}
assert.deepEqual(await fs.readdir(fixture.path), source ? ['source'] : []);
fsSync.writeSync(1, 'FS_SAFE_CLONE_BEGIN\n');
if (operation === 'createCloneSource') await api.createCloneSource(destination);
else await api.copyTree(source.path, destination, { clone: 'always', concurrency: 1 });
fsSync.writeSync(1, 'FS_SAFE_CLONE_END\n');
const destinationReceipt = await identity(destination);
if (source) await assertSnapshot(destination, source.expected);
else assert.deepEqual(await fs.readdir(destination), []);
if (source) await assertSnapshot(source.path, source.expected);
assert.deepEqual((await fs.readdir(fixture.path)).sort(), source ? ['output', 'source'] : ['output']);
api.verify();
writeJson(resultOutput, { ok: true, operation, filesystem, role, cleanup: 'pending-separate-untraced-step',
  sourcePins: api.expected.source, mount, fixture,
  destination: { path: destination, identity: destinationReceipt, expected: source?.expected ?? await snapshot(destination) }, source });
