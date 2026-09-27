// Fixture preparation and privileged reclamation run outside strace.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, writeJson } from './installed.mjs';
import { createFixture, identity, fillSmall, snapshot, reclaim } from './fixture.mjs';

const [consumer, mountArgument, filesystem, operation, role, manifestOutput, setupOutput] = process.argv.slice(2);
assert(['createCloneSource', 'copyTree-empty', 'copyTree-small-nested'].includes(operation));
const api = await installedApi(consumer, 'require');
const mount = await fs.realpath(mountArgument);
assert.equal(api.probeTreeClone(mount), filesystem);
const fixture = await createFixture(mount, 'fs-safe-clone-trace-');
let source = null;
if (operation !== 'createCloneSource') {
  const filename = path.join(fixture.path, 'source');
  await api.createCloneSource(filename);
  assert.deepEqual(await fs.readdir(filename), []);
  const receipt = await identity(filename);
  const expected = operation === 'copyTree-small-nested' ? await fillSmall(filename) : await snapshot(filename);
  source = { path: filename, identity: receipt, expected };
}
await reclaim(mount, filesystem);
api.verify();
writeJson(manifestOutput, { operation, filesystem, role, parentPath: fixture.path,
  sourcePath: source?.path ?? null, beginMarker: 'FS_SAFE_CLONE_BEGIN', endMarker: 'FS_SAFE_CLONE_END' });
writeJson(setupOutput, { operation, filesystem, role, mount, fixture, source,
  sourcePins: api.expected.source, destination: path.join(fixture.path, 'output') });
