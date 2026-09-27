import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
export const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));
export const writeJson = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
export const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  return (sorted[Math.floor((sorted.length - 1) / 2)] + sorted[Math.floor(sorted.length / 2)]) / 2;
};

export async function installedApi(consumer, mode) {
  assert.ok(['off', 'require'].includes(mode));
  consumer = fs.realpathSync(consumer);
  const expected = readJson(path.join(consumer, 'expected.json'));
  const require = createRequire(path.join(consumer, 'package.json'));
  const packageRoot = path.dirname(require.resolve('@openclaw/fs-safe/package.json'));
  const inside = file => assert.ok(fs.realpathSync(file).startsWith(`${consumer}/node_modules/`));
  inside(packageRoot);
  const binary = require.resolve('@openclaw/fs-safe-linux-x64-gnu');
  inside(binary);
  function verify() {
    for (const [relative, digest] of Object.entries(expected.distFiles)) {
      const file = path.join(packageRoot, relative);
      inside(file);
      assert.equal(hash(file), digest, `installed bytes differ: ${relative}`);
    }
    assert.equal(hash(binary), expected.nativeSha256);
  }
  const lock = readJson(path.join(consumer, 'package-lock.json'));
  for (const [name, artifact] of [['@openclaw/fs-safe', expected.rootTarball], ['@openclaw/fs-safe-linux-x64-gnu', expected.nativeTarball]]) {
    const entry = lock.packages[`node_modules/${name}`];
    assert.equal(entry.version, artifact.version);
    assert.equal(entry.integrity, artifact.integrity);
  }
  verify();
  async function load(subpath, file) {
    const resolved = require.resolve(`@openclaw/fs-safe/${subpath}`);
    inside(resolved);
    assert.equal(fs.realpathSync(resolved), fs.realpathSync(path.join(packageRoot, 'dist', file)));
    return import(pathToFileURL(resolved));
  }
  const { configureFsSafeNative } = await load('config', 'config.js');
  configureFsSafeNative({ mode });
  const { createCloneSource, copyTree, probeTreeClone } = await load('copy', 'copy.js');
  const nativeState = () => ({
    configuredMode: mode,
    artifactSha256: hash(binary),
    loadedAddonFiles: process.report.getReport().sharedObjects.filter(file => file.endsWith('.node'))
      .map(file => ({ file: path.relative(consumer, fs.realpathSync(file)), sha256: hash(file) })),
    measurementClaim: 'Public async call timing only; configured mode and loaded addon are not native-backend timing claims',
  });
  return { createCloneSource, copyTree, probeTreeClone, expected, verify, nativeState };
}
