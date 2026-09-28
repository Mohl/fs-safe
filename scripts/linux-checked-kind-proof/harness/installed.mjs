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
  const pinsFile = path.resolve(import.meta.dirname, '../pins.json');
  const protocolFile = path.resolve(import.meta.dirname, '../protocol.json');
  const pins = readJson(pinsFile), protocol = readJson(protocolFile);
  assert.equal(pins.ready, true, 'source pins must be frozen before importing the product');
  assert.equal(protocol.ready, true, 'protocol must be frozen before importing the product');
  const pinsHash = hash(pinsFile), protocolHash = hash(protocolFile);
  consumer = fs.realpathSync(consumer);
  const expectedPath = path.join(consumer, 'expected.json');
  const expected = readJson(expectedPath), expectedSha256 = hash(expectedPath);
  assert(['A', 'B'].includes(expected.role));
  assert.equal(expected.source.commit, pins[expected.role].commit);
  assert.equal(expected.source.tree, pins[expected.role].tree);
  assert.equal(expected.source.dirty, false);
  assert.deepEqual(protocol.sourcePins[expected.role], pins[expected.role]);
  assert.equal(expected.rootTarball.version, protocol.packageVersion);
  assert.equal(expected.nativePackage, protocol.nativePackage);
  const require = createRequire(path.join(consumer, 'package.json'));
  const root = path.dirname(require.resolve('@openclaw/fs-safe/package.json'));
  const binary = require.resolve(expected.nativePackage);
  function inside(file) {
    const relative = path.relative(path.join(consumer, 'node_modules'), fs.realpathSync(file));
    assert(relative && relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  }
  function verify() {
    assert.equal(hash(pinsFile), pinsHash); assert.equal(hash(protocolFile), protocolHash);
    assert.equal(hash(expectedPath), expectedSha256);
    inside(root); inside(binary);
    assert.equal(readJson(path.join(root, 'package.json')).version, expected.rootTarball.version);
    assert.equal(expected.nativeTarball.version, expected.rootTarball.version);
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
  function checkedExport(subpath, relative) {
    const resolved = require.resolve(`@openclaw/fs-safe/${subpath}`); inside(resolved);
    assert.equal(fs.realpathSync(resolved), fs.realpathSync(path.join(root, relative)));
    assert.equal(hash(resolved), expected.distFiles[relative], `unverified public export: ${subpath}`);
    return resolved;
  }
  const config = checkedExport('config', 'dist/config.js');
  (await import(pathToFileURL(config))).configureFsSafeNative({ mode: 'require' });
  const entry = checkedExport('root', 'dist/root.js');
  const tempEntry = checkedExport('temp', 'dist/temp.js');
  const api = await import(pathToFileURL(entry));
  const temp = await import(pathToFileURL(tempEntry));
  function nativeState() {
    const loaded = process.report.getReport().sharedObjects.filter(file => file.endsWith('.node'));
    const canonical = process.platform === 'win32' ? fs.realpathSync.native : fs.realpathSync;
    const expectedPath = canonical(binary);
    const loadedPaths = loaded.map(file => canonical(file));
    assert(loadedPaths.includes(expectedPath), `expected native addon was not loaded: ${JSON.stringify({ expectedPath, loadedPaths })}`);
    return { nativePackage: expected.nativePackage, sha256: hash(binary), configuredMode: 'require', path: expectedPath };
  }
  return { root: api.root, tempWorkspace: temp.tempWorkspace, expected, expectedPath, expectedSha256, verify, nativeState };
}
