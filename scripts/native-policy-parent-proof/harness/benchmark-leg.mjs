import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, save } from './installed.mjs';
import { privateWorkspace, rowFixture, names } from './fixture.mjs';
const [consumer, base, indexText, output] = process.argv.slice(2);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const plan = protocol.timing.schedule[Number(indexText)]; assert(plan);
const descriptors = [...protocol.matrix[process.platform]]; assert(descriptors.length);
if (plan.rowOrder === 'reverse') descriptors.reverse();
const api = await installedApi(consumer);
assert.equal(api.expected.role, plan.role);
const receipt = { state: 'incomplete', platform: process.platform, ...plan, source: api.expected.source, rows: {}, cleanup: false, phase: 'setup' };
save(output, receipt);
try {
  const workspace = await privateWorkspace(base);
  for (const [index, row] of descriptors.entries()) {
    receipt.phase = `${row.id}:qualification`;
    const fixture = await rowFixture(workspace, row, index, api);
    async function once(measured) {
      await fixture.prepare();
      const start = measured ? performance.now() : undefined;
      await fixture.invoke();
      const callUs = measured ? (performance.now() - start) * 1000 : undefined;
      await fixture.verifyAndReset();
      return callUs;
    }
    await once(false);
    for (let warmup = 0; warmup < 5; warmup++) await once(false);
    const result = receipt.rows[row.id] = { descriptor: row, samples: [], sampleMeansUs: [], warmups: 5, checkedUntimed: 1, callsPerSample: 10 };
    for (let sample = 0; sample < 5; sample++) {
      receipt.phase = `${row.id}:sample-${sample + 1}`;
      const raw = []; receipt.partialSample = { row: row.id, sample, values: raw };
      for (let iteration = 0; iteration < 10; iteration++) raw.push(await once(true));
      assert(raw.every(value => Number.isFinite(value) && value > 0));
      result.samples.push(raw); result.sampleMeansUs.push(raw.reduce((a, b) => a + b, 0) / 10);
      delete receipt.partialSample; save(output, receipt);
    }
    await fixture.close();
  }
  await names(workspace, []); await fs.rmdir(workspace);
  api.verify(); receipt.native = api.nativeState(); receipt.cleanup = true; receipt.state = 'complete'; receipt.phase = 'completed'; save(output, receipt);
} catch (error) {
  receipt.failure = { message: error?.message ?? String(error), stack: error?.stack, code: error?.code };
  save(output, receipt); throw error;
}
