import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

assert.equal(process.platform, 'linux');
const checkout = process.cwd();
const base = fs.mkdtempSync(path.join(os.tmpdir(), 'root-open-baseline-'));
const revision = 'a386202bcbaf0229397df7dc37ddc673f8e2ef34';
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
git('init', '--quiet', base);
git('-C', base, 'fetch', '--quiet', '--depth', '1', 'https://github.com/openclaw/fs-safe.git', revision);
git('-C', base, 'checkout', '--quiet', '--detach', 'FETCH_HEAD');
assert.equal(git('-C', base, 'rev-parse', 'HEAD'), revision);
fs.symlinkSync(path.join(checkout, 'node_modules'), path.join(base, 'node_modules'), 'dir');
execFileSync('pnpm', ['exec', 'tsc', '-p', path.join(base, 'tsconfig.json')], { stdio: 'inherit' });
fs.copyFileSync(path.join(checkout, 'dist/archive-parser.wasm'), path.join(base, 'dist/archive-parser.wasm'));
const load = async directory => {
  const api = await import(pathToFileURL(path.join(directory, 'dist/root.js')));
  const config = await import(pathToFileURL(path.join(directory, 'dist/config.js')));
  config.configureFsSafeNative({ mode: 'auto' });
  return api.root;
};
const before = await load(base);
const after = await load(checkout);
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'root-open-control-'));
fs.writeFileSync(path.join(fixture, 'writable.txt'), 'inside');
const cases = { before: await before(fixture), control: await before(fixture), after: await after(fixture) };
const samples = { before: [], control: [], after: [] };
const measure = async (scope, iterations) => {
  let elapsed = 0;
  for (let i = 0; i < iterations; i++) {
    const started = performance.now();
    const opened = await scope.openWritable('writable.txt');
    elapsed += performance.now() - started;
    await opened.handle.close();
  }
  return elapsed * 1000 / iterations;
};
try {
  for (const scope of Object.values(cases)) await measure(scope, 500);
  for (let sample = 0; sample < 20; sample++) {
    const order = sample % 2 ? ['after', 'control', 'before'] : ['before', 'control', 'after'];
    for (const name of order) {
      samples[name].push(await measure(cases[name], 1000));
      console.log(JSON.stringify({ sample, name, microseconds: samples[name].at(-1) }));
    }
  }
  const binary = createRequire(path.join(checkout, 'package.json')).resolve('@openclaw/fs-safe-linux-x64-gnu');
  const result = { before: revision, after: git('rev-parse', 'HEAD'), mode: 'auto', method: 'Root.openWritable',
    warmup: 500, iterations: 1000, sampleCount: 20, node: process.version,
    nativeBinarySha256: createHash('sha256').update(fs.readFileSync(binary)).digest('hex'), samples };
  fs.mkdirSync('.artifacts', { recursive: true });
  fs.writeFileSync('.artifacts/auto-open-control.json', JSON.stringify(result, null, 2) + '\n');
} finally { fs.rmSync(fixture, { recursive: true, force: true }); }
