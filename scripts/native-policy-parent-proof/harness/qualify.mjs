import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, save } from './installed.mjs';
import { privateWorkspace, rowFixture, names } from './fixture.mjs';
const [consumer, base, output] = process.argv.slice(2);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const api = await installedApi(consumer);
const receipt = { state: 'incomplete', platform: process.platform, source: api.expected.source, rows: [], cleanup: false };
save(output, receipt);
try {
  const workspace = await privateWorkspace(base);
  let index = 0;
  async function check(row, kind = 'success') {
    const fixture = await rowFixture(workspace, row, index++, api);
    await fixture.prepare();
    if (kind === 'success') {
      await fixture.call(); await fixture.verifyAndReset();
    } else {
      const reason = new Error('caller refused before first mutation'); let callbackCalls = 0;
      const overrides = kind === 'mkdir-false' ? { mkdir: false }
        : kind === 'denied-first-parent' ? { denyMutations: { prefixes: [path.join(fixture.directory, 'd0')] } }
        : kind === 'authority-refusal' ? { assertBeforeMutation() { callbackCalls++; throw reason; } } : {};
      await assert.rejects(() => fixture.call(overrides), error => {
        assert(error instanceof Error);
        if (kind === 'authority-refusal') assert.equal(error, reason);
        if (kind === 'mkdir-false') assert.equal(error.code, 'not-found');
        if (kind === 'denied-first-parent') assert.equal(error.code, 'denied-path');
        if (kind === 'existing-target') assert.equal(error.code, 'already-exists');
        return true;
      });
      if (kind === 'authority-refusal') assert.equal(callbackCalls, 1);
      await fixture.verifyRejected();
    }
    await fixture.close(); receipt.rows.push({ id: row.id, kind, passed: true }); save(output, receipt);
  }
  for (const row of protocol.matrix[process.platform]) await check(row);
  for (const operation of ['write', 'create', 'copyIn', 'create-atomic']) {
    for (const layout of ['partial', 'all-missing']) await check({ id: `${operation}/${layout}/control`, operation, layout, policyPath: 'eligible', depth: 8, target: 'absent' });
    for (const kind of ['mkdir-false', 'denied-first-parent', 'authority-refusal']) {
      await check({ id: `${operation}/missing/${kind}`, operation, layout: 'all-missing', policyPath: 'eligible', depth: 3, target: 'absent' }, kind);
    }
  }
  for (const operation of ['create', 'create-atomic']) await check({ id: `${operation}/complete/collision`, operation,
    layout: 'complete', policyPath: 'eligible', depth: 3, target: 'existing' }, 'existing-target');
  await names(workspace, []); await fs.rmdir(workspace); api.verify();
  receipt.native = api.nativeState(); receipt.cleanup = true; receipt.state = 'complete'; save(output, receipt);
} catch (error) {
  receipt.failure = { message: error?.message ?? String(error), stack: error?.stack, code: error?.code };
  save(output, receipt); throw error;
}
