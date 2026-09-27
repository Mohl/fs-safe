import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { installedApi, readJson } from './installed.mjs';
import { createFixture, identity, assertIdentity, fillSmall, snapshot, assertSnapshot, removeOwned, reclaim } from './fixture.mjs';

const [consumer, mountArgument, filesystem, indexArgument, output] = process.argv.slice(2);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const leg = protocol.timing.schedule[Number(indexArgument)];
assert(leg && leg.filesystem === filesystem);
const mount = await fs.realpath(mountArgument);
const api = await installedApi(consumer, 'require');
assert.equal(api.probeTreeClone(mount), filesystem);
const progress = { state: 'incomplete', filesystem, block: leg.block, position: leg.position,
  role: leg.variant, rowOrder: leg.rowOrder, rows: {}, source: api.expected.source,
  nativeState: api.nativeState(), cleanup: [], phase: 'fixture-setup' };
function persist() {
  // Replacement is atomic so a killed later write cannot destroy prior samples.
  const next = `${output}.next`;
  fsSync.writeFileSync(next, `${JSON.stringify(progress, null, 2)}\n`, { mode: 0o600 });
  fsSync.renameSync(next, output);
}
persist();
try {
  const fixture = await createFixture(mount, 'fs-safe-clone-leg-');
  const sourceEmpty = path.join(fixture.path, 'source-empty');
  const sourceSmall = path.join(fixture.path, 'source-small');
  await api.createCloneSource(sourceEmpty);
  await api.createCloneSource(sourceSmall);
  const emptyReceipt = await identity(sourceEmpty), smallReceipt = await identity(sourceSmall);
  const emptySnapshot = await snapshot(sourceEmpty), smallSnapshot = await fillSmall(sourceSmall);
  const rows = progress.rows, cleanup = progress.cleanup;
  const order = protocol.timing.rows.map(row => row.id);
  if (leg.rowOrder === 'reverse') order.reverse();
  for (const row of order) {
    progress.phase = `${row}:qualification`;
    const destination = path.join(fixture.path, 'output');
    const source = row === 'copyTree-empty' ? sourceEmpty : sourceSmall;
    const expected = row === 'copyTree-empty' ? emptySnapshot : smallSnapshot;
    async function once(measured) {
      await assert.rejects(fs.lstat(destination), { code: 'ENOENT' });
      const start = measured ? performance.now() : undefined;
      if (row === 'createCloneSource') await api.createCloneSource(destination);
      else await api.copyTree(source, destination, { clone: 'always', concurrency: 1 });
      const callUs = measured ? (performance.now() - start) * 1000 : undefined;
      const owned = await identity(destination);
      if (row === 'createCloneSource') assert.deepEqual(await fs.readdir(destination), []);
      else await assertSnapshot(destination, expected);
      await removeOwned(destination, owned, filesystem);
      return callUs;
    }
    await reclaim(mount, filesystem);
    await once(false);
    for (let warmup = 0; warmup < 5; warmup++) await once(false);
    await reclaim(mount, filesystem);
    const samples = [], sampleMeansUs = [];
    rows[row] = { metric: 'callUs', sampleMeansUs, samples, warmups: 5, checkedUntimed: 1, callsPerSample: 30 };
    for (let sample = 0; sample < 5; sample++) {
      progress.phase = `${row}:sample-${sample + 1}`;
      const values = [];
      progress.partialSample = { row, sample, values };
      for (let iteration = 0; iteration < 30; iteration++) values.push(await once(true));
      assert(values.every(value => Number.isFinite(value) && value > 0));
      samples.push(values);
      sampleMeansUs.push(values.reduce((a, b) => a + b, 0) / values.length);
      delete progress.partialSample;
      persist();
      await reclaim(mount, filesystem);
    }
  }
  progress.phase = 'fixture-cleanup';
  await assertSnapshot(sourceEmpty, emptySnapshot);
  await assertSnapshot(sourceSmall, smallSnapshot);
  await assertIdentity(sourceEmpty, emptyReceipt);
  await assertIdentity(sourceSmall, smallReceipt);
  await removeOwned(sourceEmpty, emptyReceipt, filesystem, emptySnapshot);
  await removeOwned(sourceSmall, smallReceipt, filesystem, smallSnapshot);
  assert.deepEqual(await fs.readdir(fixture.path), []);
  await removeOwned(fixture.path, fixture.identity, filesystem);
  await reclaim(mount, filesystem);
  cleanup.push('expected-entries-and-identities-verified-before-removal');
  api.verify();
  progress.state = 'complete';
  progress.phase = 'completed';
  progress.nativeState = api.nativeState();
  persist();
} catch (error) {
  progress.failure = { message: error?.message ?? String(error), stack: error?.stack, code: error?.code };
  persist();
  throw error;
}
