import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { installedApi, hash } from './harness/installed.mjs';
const [consumer, source, expectedSnapshot] = process.argv.slice(2);
assert.deepEqual(fs.readFileSync(path.join(consumer, 'expected.json')), fs.readFileSync(expectedSnapshot));
const api = await installedApi(consumer);
api.verify();
const dist = {};
function walk(relative) {
  for (const entry of fs.readdirSync(path.join(source, relative), { withFileTypes: true })) {
    const name = `${relative}/${entry.name}`;
    if (entry.isDirectory()) walk(name);
    else { assert(entry.isFile()); dist[name] = hash(path.join(source, name)); }
  }
}
walk('dist');
assert.deepEqual(dist, api.expected.distFiles);
const label = api.expected.nativePackage.replace('@openclaw/fs-safe-', '');
assert.equal(hash(path.join(source, 'packages', label, 'fs-safe-native.node')), api.expected.nativeSha256);
assert.equal(hash(path.join(source, 'native', `fs-safe-native.${label}.node`)), api.expected.nativeSha256);
console.log(JSON.stringify({ installedAndSourceVerified: true, source: api.expected.source }));
