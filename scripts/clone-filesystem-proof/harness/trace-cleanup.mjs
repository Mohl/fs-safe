// Privileged Btrfs maintenance must run outside the unprivileged strace process.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { readJson, writeJson } from './installed.mjs';
import { assertIdentity, assertSnapshot, removeOwned, reclaim } from './fixture.mjs';

const [proofFile, output] = process.argv.slice(2);
const proof = readJson(proofFile);
assert.equal(proof.ok, true);
assert.equal(proof.cleanup, 'pending-separate-untraced-step');
const { fixture, destination, source, filesystem } = proof;
const mount = await fs.realpath(proof.mount);
assert.equal(path.dirname(fixture.path), mount);
assert(path.basename(fixture.path).startsWith('fs-safe-clone-trace-'));
await assertIdentity(fixture.path, fixture.identity);
assert.deepEqual((await fs.readdir(fixture.path)).sort(), source ? ['output', 'source'] : ['output']);
assert.equal(destination.path, path.join(fixture.path, 'output'));
if (source) assert.equal(source.path, path.join(fixture.path, 'source'));
for (const owned of [destination, source].filter(Boolean)) {
  await assertIdentity(owned.path, owned.identity);
  await assertSnapshot(owned.path, owned.expected);
  await removeOwned(owned.path, owned.identity, filesystem, owned.expected);
}
assert.deepEqual(await fs.readdir(fixture.path), []);
await removeOwned(fixture.path, fixture.identity, filesystem);
await reclaim(mount, filesystem);
writeJson(output, { ok: true, proofFile, operation: proof.operation, filesystem,
  role: proof.role, cleanup: 'expected-entries-and-identities-verified-before-removal' });
