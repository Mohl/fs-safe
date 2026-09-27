import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';

const [workspace, work] = process.argv.slice(2).map(value => path.resolve(value));
const packet = import.meta.dirname;
const pins = JSON.parse(fs.readFileSync(path.join(packet, 'pins.json'), 'utf8'));
assert.equal(pins.ready, true);
assert.equal(process.version, 'v24.21.0');
assert.equal(process.arch, 'x64');
assert(['linux', 'win32'].includes(process.platform));
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
const git = (source, ...args) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8', timeout: 30_000 }).trim();
const npmCli = [
  path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
  path.join(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js'),
].find(file => fs.existsSync(file));
assert(npmCli, 'Node installation must provide npm-cli.js');
const evidence = path.join(work, 'evidence');
fs.mkdirSync(evidence, { recursive: true });
save(path.join(evidence, 'environment.json'), {
  node: process.version, nodeSha256: hash(process.execPath), platform: process.platform,
  arch: process.arch, cpuCount: os.cpus().length, availableParallelism: os.availableParallelism(),
  cpuModel: os.cpus()[0]?.model, kernel: os.release(), filesystem: fs.statfsSync(work),
});
const { isolatedConsumerEnv } = await import(pathToFileURL(path.join(workspace, 'A/scripts/consumer-install-smoke.mjs')));
const sources = {};
for (const role of ['A', 'B']) {
  const source = path.join(workspace, role);
  assert.equal(git(source, 'rev-parse', 'HEAD'), pins[role].commit);
  assert.equal(git(source, 'rev-parse', 'HEAD^{tree}'), pins[role].tree);
  assert.equal(git(source, 'status', '--porcelain', '--untracked-files=no'), '');
  const files = execFileSync('git', ['-C', source, 'ls-files', '-z'], { encoding: 'utf8', timeout: 30_000 }).split('\0').filter(Boolean);
  sources[role] = Object.fromEntries(files.map(name => [name, hash(path.join(source, name))]));
  const packages = path.join(work, `packages-${role}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(packages, 'manifest.json'), 'utf8'));
  const nativePackage = process.platform === 'win32' ? '@openclaw/fs-safe-win32-x64-msvc' : '@openclaw/fs-safe-linux-x64-gnu';
  const tarballs = ['@openclaw/fs-safe', nativePackage].map(name => {
    const item = manifest.find(entry => entry.name === name);
    assert(item && item.version === '0.21.1');
    assert.equal(path.basename(item.filename), item.filename);
    const filename = path.join(packages, item.filename);
    assert.equal(item.integrity, 'sha512-' + createHash('sha512').update(fs.readFileSync(filename)).digest('base64'));
    return filename;
  });
  const retained = path.join(evidence, `package-${role}`);
  fs.mkdirSync(retained);
  for (const file of [...tarballs, path.join(packages, 'consumer-proof.json'), path.join(packages, 'manifest.json')]) {
    fs.copyFileSync(file, path.join(retained, path.basename(file)));
  }
  const consumer = path.join(work, `consumer-${role}`);
  fs.mkdirSync(consumer);
  save(path.join(consumer, 'package.json'), { private: true, type: 'module' });
  const env = isolatedConsumerEnv(path.join(consumer, 'config'));
  execFileSync(process.execPath, [npmCli, 'install', '--ignore-scripts', '--omit=optional', '--offline', '--no-audit', '--no-fund', ...tarballs], {
    cwd: consumer, env, stdio: 'inherit', timeout: 180_000,
  });
  execFileSync(process.execPath, [path.join(packet, 'harness/bind-consumer.mjs'), source, consumer, packages, role], {
    env, stdio: 'inherit', timeout: 60_000,
  });
  save(path.join(consumer, 'environment.json'), env);
  fs.copyFileSync(path.join(consumer, 'expected.json'), path.join(evidence, `expected-${role}.json`));
  fs.copyFileSync(path.join(consumer, 'package-lock.json'), path.join(evidence, `consumer-${role}-package-lock.json`));
}
for (const [name, digest] of Object.entries(sources.A)) {
  if (/^(native\/|archive-core\/|archive-wasm\/|packages\/)/.test(name) || ['pnpm-lock.yaml', 'Cargo.lock', 'Cargo.toml', 'package.json'].includes(name)) {
    assert.equal(sources.B[name], digest, `shared native/build input: ${name}`);
  }
}
save(path.join(evidence, 'source-files.json'), sources);
save(path.join(evidence, 'prepared.json'), { complete: true, pins });
