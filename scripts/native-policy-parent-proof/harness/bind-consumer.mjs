// Run remotely only after the real matching tarballs were installed in a neutral consumer.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { readJson, hash, save, installedApi } from './installed.mjs';
const [source, consumer, packaged, role] = process.argv.slice(2);
assert(['A', 'B'].includes(role));
const pins = readJson(path.resolve(import.meta.dirname, '../pins.json'));
const git = (...args) => execFileSync('git', args, { cwd: source, encoding: 'utf8' }).trim();
assert.equal(git('rev-parse', 'HEAD'), pins[role].commit); assert.equal(git('rev-parse', 'HEAD^{tree}'), pins[role].tree);
assert.equal(git('status', '--porcelain'), '');
const nativeLabel = process.platform === 'win32' ? 'win32-x64-msvc' : 'linux-x64-gnu';
assert(['win32', 'linux'].includes(process.platform) && process.arch === 'x64');
const nativePackage = `@openclaw/fs-safe-${nativeLabel}`;
const manifest = readJson(path.join(packaged, 'manifest.json'));
function artifact(name) {
  const entry = manifest.find(value => value.name === name); assert(entry);
  assert.equal(entry.version, '0.21.1');
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
const expected = { role, source: { ...pins[role], dirty: false }, distFiles, nativePackage,
  nativeSha256: hash(path.join(source, 'packages', nativeLabel, 'fs-safe-native.node')),
  rootTarball: artifact('@openclaw/fs-safe'), nativeTarball: artifact(nativePackage) };
assert(!fs.existsSync(path.join(consumer, 'expected.json')));
save(path.join(consumer, 'expected.json'), expected);
(await installedApi(consumer)).verify();
console.log(JSON.stringify({ role, source: expected.source, nativePackage, nativeSha256: expected.nativeSha256, distFiles: Object.keys(distFiles).length }));
