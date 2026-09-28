// Exactly one public write is marked; package loading, priming, checks and cleanup stay outside it.
import assert from 'node:assert/strict';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { installedApi, readJson, hash, save } from './installed.mjs';
import { privateWorkspace, rowFixture, names, absent, assertMechanism } from './fixture.mjs';
const [consumer, base, rowId, majorText, manifestOutput, proofOutput, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0); assert(consumer && base && manifestOutput && proofOutput);
const protocol = readJson(path.resolve(import.meta.dirname, '../protocol.json'));
const descriptor = protocol.rows.find(row => row.id === rowId); assert(descriptor);
const nodeMajor = Number(majorText); assert([22, 24].includes(nodeMajor));
assertMechanism(descriptor.mechanism, nodeMajor, protocol);
const sidecar = `${manifestOutput}.expected.json`;
for (const file of [manifestOutput, proofOutput, sidecar]) assert(!fsSync.existsSync(file), 'trace outputs must be new');
const api = await installedApi(consumer);
const workspace = await privateWorkspace(base);
const fixture = await rowFixture(workspace, descriptor, 0, api);
await fixture.prepare();
const beginMarker = `FS_SAFE_KIND_BEGIN ${rowId}`, endMarker = `FS_SAFE_KIND_END ${rowId}`;
const { rootPath, parentPath, targetPath, sentinelPath, outsidePath, primePath, existingParentPaths, relative, options } = fixture;
fsSync.copyFileSync(api.expectedPath, sidecar, fsSync.constants.COPYFILE_EXCL);
fsSync.chmodSync(sidecar, 0o600); assert.equal(hash(sidecar), api.expectedSha256);
const manifest = { schema: 1, row: rowId, descriptor, role: api.expected.role, nodeVersion: process.version, nodeMajor,
  mechanism: descriptor.mechanism, fallbackHook: '0', source: api.expected.source, nativeSha256: fixture.native.sha256,
  nativePath: fixture.native.path, launch: { executable: process.execPath, argv: process.argv.slice(1) },
  expectedPath: api.expectedPath, expectedSha256: api.expectedSha256,
  expectedReceipt: { file: path.basename(sidecar), sha256: hash(sidecar) },
  rootPath, parentPath, targetPath, sentinelPath, outsidePath, primePath, existingParentPaths, relative, options,
  ...(descriptor.alias ? { aliasPath: fixture.aliasPath, aliasTarget: fixture.aliasTarget } : {}), beginMarker, endMarker };
save(manifestOutput, manifest);
const receipt = { ...manifest, ok: false, cleanup: false, phase: 'prepared' }; save(proofOutput, receipt);
try {
  assert.equal(fsSync.writeSync(2, `${beginMarker}\n`), Buffer.byteLength(`${beginMarker}\n`));
  await fixture.invoke();
  assert.equal(fsSync.writeSync(2, `${endMarker}\n`), Buffer.byteLength(`${endMarker}\n`));
  receipt.phase = 'verification'; receipt.outcome = await fixture.verifyAndReset();
  await fixture.close(); await names(workspace, []); await fs.rmdir(workspace); await absent(workspace);
  api.verify(); assert.deepEqual(api.nativeState(), fixture.native);
  receipt.ok = true; receipt.cleanup = true; receipt.phase = 'complete'; save(proofOutput, receipt);
} catch (error) {
  receipt.failure = { name: error?.name, code: error?.code, message: error?.message ?? String(error), stack: error?.stack };
  save(proofOutput, receipt); throw error;
}
