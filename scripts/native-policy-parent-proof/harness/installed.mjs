import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
export const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export function save(file, value) {
  const next = `${file}.next`;
  fs.writeFileSync(next, JSON.stringify(value, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(next, file);
}
export async function installedApi(consumer) {
  consumer = fs.realpathSync(consumer);
  const expected = readJson(path.join(consumer, 'expected.json'));
  const require = createRequire(path.join(consumer, 'package.json'));
  const root = path.dirname(require.resolve('@openclaw/fs-safe/package.json'));
  const binary = require.resolve(expected.nativePackage);
  function inside(file) {
    const relative = path.relative(path.join(consumer, 'node_modules'), fs.realpathSync(file));
    assert(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  }
  function verify() {
    inside(root); inside(binary);
    for (const [name, digest] of Object.entries(expected.distFiles)) {
      const file = path.join(root, name); inside(file); assert.equal(hash(file), digest, name);
    }
    assert.equal(hash(binary), expected.nativeSha256);
    const lock = readJson(path.join(consumer, 'package-lock.json'));
    for (const [name, artifact] of [['@openclaw/fs-safe', expected.rootTarball], [expected.nativePackage, expected.nativeTarball]]) {
      assert.equal(lock.packages[`node_modules/${name}`].version, artifact.version);
      assert.equal(lock.packages[`node_modules/${name}`].integrity, artifact.integrity);
    }
  }
  verify();
  const config = require.resolve('@openclaw/fs-safe/config'); inside(config);
  (await import(pathToFileURL(config))).configureFsSafeNative({ mode: 'require' });
  const entry = require.resolve('@openclaw/fs-safe/root'); inside(entry);
  const api = await import(pathToFileURL(entry));
  function nativeState() {
    const loaded = process.report.getReport().sharedObjects.filter(file => file.endsWith('.node'));
    const canonical = process.platform === 'win32' ? fs.realpathSync.native : fs.realpathSync;
    const expectedPath = canonical(binary);
    const loadedPaths = loaded.map(file => canonical(file));
    assert(loadedPaths.includes(expectedPath), `expected native addon was not loaded: ${JSON.stringify({ expectedPath, loadedPaths })}`);
    return { nativePackage: expected.nativePackage, sha256: hash(binary), configuredMode: 'require' };
  }
  return { root: api.root, expected, verify, nativeState };
}
