// Bind each neutral consumer to its own separately built package artifacts.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, hash, save, installedApi } from './installed.mjs';
const [source, consumer, packaged, role, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0); assert(['A', 'B'].includes(role));
const packet = path.resolve(import.meta.dirname, '..');
const pins = readJson(path.join(packet, 'pins.json')), protocol = readJson(path.join(packet, 'protocol.json'));
assert(pins.ready === true && protocol.ready === true);
const git = (...args) => execFileSync('git', args, { cwd: source, encoding: 'utf8', timeout: 30_000 }).trim();
assert.equal(git('rev-parse', 'HEAD'), pins[role].commit); assert.equal(git('rev-parse', 'HEAD^{tree}'), pins[role].tree);
assert.equal(git('status', '--porcelain'), '');
assert.equal(process.platform, 'linux'); assert.equal(process.arch, 'x64');
const nativeLabel = 'linux-x64-gnu', nativePackage = protocol.nativePackage;
assert.equal(nativePackage, `@openclaw/fs-safe-${nativeLabel}`);
const manifest = readJson(path.join(packaged, 'manifest.json'));
function artifact(name) {
  const entry = manifest.find(value => value.name === name); assert(entry);
  assert.equal(entry.version, protocol.packageVersion); assert.equal(path.basename(entry.filename), entry.filename);
  const file = path.join(packaged, entry.filename);
  assert.equal(entry.integrity, `sha512-${createHash('sha512').update(fs.readFileSync(file)).digest('base64')}`);
  return { ...entry, sha256: hash(file) };
}
const distFiles = {};
function walk(relative) {
  for (const entry of fs.readdirSync(path.join(source, relative), { withFileTypes: true })) {
    const next = `${relative}/${entry.name}`;
    if (entry.isDirectory()) walk(next); else { assert(entry.isFile()); distFiles[next] = hash(path.join(source, next)); }
  }
}
walk('dist');
const nativeSha256 = hash(path.join(source, 'packages', nativeLabel, 'fs-safe-native.node'));
assert.equal(hash(path.join(source, 'native', `fs-safe-native.${nativeLabel}.node`)), nativeSha256);
const build = readJson(path.join(path.dirname(packaged), 'evidence', `native-build-${role}.json`));
assert.deepEqual(build.source, { ...pins[role], dirty: false }); assert.equal(build.nativeSha256, nativeSha256);
assert.equal(build.role, role); assert.equal(build.separateNativeBuild, true);
const expected = { role, source: { ...pins[role], dirty: false }, distFiles, nativePackage, nativeSha256,
  packageVersion: protocol.packageVersion, pinsSha256: hash(path.join(packet, 'pins.json')),
  protocolSha256: hash(path.join(packet, 'protocol.json')),
  nativeBuildReceiptSha256: hash(path.join(path.dirname(packaged), 'evidence', `native-build-${role}.json`)),
  rootTarball: artifact('@openclaw/fs-safe'), nativeTarball: artifact(nativePackage) };
assert(!fs.existsSync(path.join(consumer, 'expected.json'))); save(path.join(consumer, 'expected.json'), expected);
(await installedApi(consumer)).verify();
console.log(JSON.stringify({ role, source: expected.source, nativePackage, nativeSha256, distFiles: Object.keys(distFiles).length }));
