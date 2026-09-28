import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { pathToFileURL } from 'node:url';

const [workspace, work, ...extra] = process.argv.slice(2).map(value => path.resolve(value));
assert.equal(extra.length, 0);
const packet = import.meta.dirname;
const pins = JSON.parse(fs.readFileSync(path.join(packet, 'pins.json'), 'utf8'));
const protocol = JSON.parse(fs.readFileSync(path.join(packet, 'protocol.json'), 'utf8'));
assert(pins.ready === true && protocol.ready === true);
assert.equal(process.version, protocol.nodeVersions['24']);
assert.equal(process.arch, 'x64'); assert.equal(process.platform, 'linux');
assert(process.report.getReport().header.glibcVersionRuntime, 'glibc is required');
const hash = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const save = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
const git = (source, ...args) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8', timeout: 30_000 }).trim();
const npmCli = [path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js'),
  path.join(path.dirname(process.execPath), '../lib/node_modules/npm/bin/npm-cli.js')].find(file => fs.existsSync(file));
assert(npmCli, 'Node installation must provide npm-cli.js');
const evidence = path.join(work, 'evidence');
assert(fs.statSync(evidence).isDirectory());
save(path.join(evidence, 'environment.json'), {
  node: process.version, nodeSha256: hash(process.execPath), platform: process.platform,
  arch: process.arch, cpuCount: os.cpus().length, availableParallelism: os.availableParallelism(),
  cpuModel: os.cpus()[0]?.model, kernel: os.release(), filesystem: fs.statfsSync(work),
  glibc: process.report.getReport().header.glibcVersionRuntime,
});
const { isolatedConsumerEnv } = await import(pathToFileURL(path.join(workspace, 'A/scripts/consumer-install-smoke.mjs')));
const sources = {}, expected = {};
for (const role of ['A', 'B']) {
  const source = path.join(workspace, role);
  assert.equal(git(source, 'rev-parse', 'HEAD'), pins[role].commit);
  assert.equal(git(source, 'rev-parse', 'HEAD^{tree}'), pins[role].tree);
  assert.equal(git(source, 'status', '--porcelain'), '');
  const files = execFileSync('git', ['-C', source, 'ls-files', '-z'], { encoding: 'utf8', timeout: 30_000 }).split('\0').filter(Boolean);
  sources[role] = Object.fromEntries(files.map(name => [name, hash(path.join(source, name))]));
  const rootPackage = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
  assert.equal(rootPackage.version, protocol.packageVersion); assert.equal(rootPackage.packageManager, protocol.packageManager);
  const packages = path.join(work, `packages-${role}`);
  const manifest = JSON.parse(fs.readFileSync(path.join(packages, 'manifest.json'), 'utf8'));
  const proof = JSON.parse(fs.readFileSync(path.join(packages, 'consumer-proof.json'), 'utf8'));
  assert.deepEqual(proof.source, { ...pins[role], dirty: false });
  assert.equal(proof.expectedSourceCommit, pins[role].commit);
  const tarballs = ['@openclaw/fs-safe', protocol.nativePackage].map(name => {
    const item = manifest.find(entry => entry.name === name);
    assert(item && item.version === protocol.packageVersion);
    assert.equal(path.basename(item.filename), item.filename);
    const filename = path.join(packages, item.filename);
    assert.equal(item.integrity, 'sha512-' + createHash('sha512').update(fs.readFileSync(filename)).digest('base64'));
    return filename;
  });
  const retained = path.join(evidence, `package-${role}`); fs.mkdirSync(retained);
  for (const file of [...tarballs, path.join(packages, 'consumer-proof.json'), path.join(packages, 'manifest.json')]) fs.copyFileSync(file, path.join(retained, path.basename(file)));
  const consumer = path.join(work, `consumer-${role}`); fs.mkdirSync(consumer, { mode: 0o700 });
  save(path.join(consumer, 'package.json'), { private: true, type: 'module' });
  const env = isolatedConsumerEnv(path.join(consumer, 'config'));
  env.FS_SAFE_TEST_NO_OPENAT2 = '0';
  execFileSync(process.execPath, [npmCli, 'install', '--ignore-scripts', '--omit=optional', '--offline', '--no-audit', '--no-fund', ...tarballs], {
    cwd: consumer, env, stdio: 'inherit', timeout: 180_000,
  });
  execFileSync(process.execPath, [path.join(packet, 'harness/bind-consumer.mjs'), source, consumer, packages, role], { env, stdio: 'inherit', timeout: 60_000 });
  save(path.join(consumer, 'environment.json'), env);
  expected[role] = JSON.parse(fs.readFileSync(path.join(consumer, 'expected.json'), 'utf8'));
  fs.copyFileSync(path.join(consumer, 'expected.json'), path.join(evidence, `expected-${role}.json`));
  fs.copyFileSync(path.join(consumer, 'package-lock.json'), path.join(evidence, `consumer-${role}-package-lock.json`));
}
const names = [...new Set([...Object.keys(sources.A), ...Object.keys(sources.B)])].sort();
const changed = names.filter(name => sources.A[name] !== sources.B[name]);
assert.deepEqual(changed, [...protocol.sourceChangedFiles].sort(), 'source pair contains undeclared changes');
assert.notEqual(expected.A.nativeSha256, expected.B.nativeSha256, 'native arms must be built separately from the changed Rust sources');
assert.deepEqual(expected.A.distFiles, expected.B.distFiles, 'this Rust-only optimization must leave the published JS/WASM/declarations unchanged');
save(path.join(evidence, 'source-files.json'), sources);
save(path.join(evidence, 'prepared.json'), { complete: true, pins, protocolSha256: hash(path.join(packet, 'protocol.json')),
  changedFiles: changed, nativeSha256: { A: expected.A.nativeSha256, B: expected.B.nativeSha256 }, conditionalQualification: 'pending-separate-root-owner' });
