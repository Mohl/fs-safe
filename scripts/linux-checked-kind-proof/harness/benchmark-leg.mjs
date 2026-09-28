import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, save } from './installed.mjs';
import { privateWorkspace, rowFixture, names, absent, assertMechanism } from './fixture.mjs';
const [consumer, base, cohortId, indexText, output, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0); assert(consumer && base && output);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const index = Number(indexText); assert(Number.isInteger(index) && index >= 0);
const plan = protocol.timing.schedule[index]; assert(plan);
const cohort = protocol.timing.cohorts.find(value => value.id === cohortId); assert(cohort);
assertMechanism(cohort.mechanism, 24, protocol);
const descriptors = cohort.rows.map(id => { const row = protocol.rows.find(value => value.id === id); assert(row); assert.equal(row.mechanism, cohort.mechanism); return row; });
assert(descriptors.length && new Set(cohort.rows).size === descriptors.length);
if (plan.rowOrder === 'reverse') descriptors.reverse(); else assert.equal(plan.rowOrder, 'forward');
const { samples, callsPerSample, warmups } = protocol.timing;
assert.equal(samples, 5); assert.equal(callsPerSample, 10); assert.equal(warmups, 5);
const api = await installedApi(consumer); assert.equal(api.expected.role, plan.role);
const receipt = { state: 'incomplete', platform: process.platform, ...plan, cohort: cohortId, mechanism: cohort.mechanism,
  nodeVersion: process.version, nodeMajor: 24, fallbackHook: '0', source: api.expected.source,
  rows: {}, cleanup: false, phase: 'setup' }; save(output, receipt);
try {
  const workspace = await privateWorkspace(base);
  for (const [rowIndex, row] of descriptors.entries()) {
    receipt.phase = `${row.id}:qualification`;
    const fixture = await rowFixture(workspace, row, rowIndex, api);
    receipt.native ??= fixture.native; assert.deepEqual(fixture.native, receipt.native);
    async function once(measured) {
      await fixture.prepare();
      const start = measured ? performance.now() : undefined;
      await fixture.invoke();
      const callUs = measured ? (performance.now() - start) * 1000 : undefined;
      await fixture.verifyAndReset();
      return callUs;
    }
    await once(false);
    for (let warmup = 0; warmup < warmups; warmup++) await once(false);
    const result = receipt.rows[row.id] = { descriptor: row, samples: [], sampleMeansUs: [], warmups, checkedUntimed: 1, callsPerSample };
    for (let sample = 0; sample < samples; sample++) {
      receipt.phase = `${row.id}:sample-${sample + 1}`;
      const raw = []; receipt.partialSample = { row: row.id, sample, values: raw };
      for (let iteration = 0; iteration < callsPerSample; iteration++) raw.push(await once(true));
      assert(raw.every(value => Number.isFinite(value) && value > 0));
      result.samples.push(raw); result.sampleMeansUs.push(raw.reduce((a, b) => a + b, 0) / callsPerSample);
      delete receipt.partialSample; save(output, receipt);
    }
    await fixture.close();
  }
  await names(workspace, []); await fs.rmdir(workspace); await absent(workspace);
  api.verify(); assert.deepEqual(api.nativeState(), receipt.native);
  receipt.cleanup = true; receipt.state = 'complete'; receipt.phase = 'completed'; save(output, receipt);
} catch (error) {
  receipt.failure = { message: error?.message ?? String(error), stack: error?.stack, code: error?.code };
  save(output, receipt); throw error;
}
