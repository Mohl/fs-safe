import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { hash, installedApi, readJson, writeJson } from './installed.mjs';

const [work, transport] = process.argv.slice(2);
assert.ok(work.startsWith('/tmp/fs-safe-clone-admission-'));
assert.ok(path.isAbsolute(transport));
const packet = path.resolve(import.meta.dirname, '..');
const pins = readJson(path.join(packet, 'pins.json'));
const protocol = readJson(path.join(packet, 'protocol.json'));
const manifest = readJson(path.join(packet, 'packet-manifest.json'));
assert.equal(pins.ready, true, 'parent authorization is required before execution');
for (const value of [...Object.values(pins.commits), ...Object.values(pins.trees)]) assert.match(value, /^[0-9a-f]{40}$/);
assert.equal(pins.branch, 'codex/clone-filesystem-admission');
assert.deepEqual({ branch: pins.branch, commits: pins.commits, trees: pins.trees }, manifest.sourcePins,
  'only the execution gate may change after packet inspection');
function verifyPacket() {
  for (const [file, digest] of Object.entries(manifest.files)) assert.equal(hash(path.join(packet, file)), digest, file);
}
verifyPacket();
const evidence = path.join(work, 'evidence');
assert.deepEqual(fs.readdirSync(evidence).sort(), ['control', 'mount-states'], 'supervisor must own fresh evidence and prepared mount states');
fs.cpSync(packet, path.join(evidence, 'packet'), { recursive: true });
const summary = { started: new Date().toISOString(), sourcePins: pins, steps: [],
  nativeBuild: 'Independently built in exact A and B worktrees with separate CARGO_TARGET_DIRs; no native byte sharing.' };
const write = (name, value) => writeJson(path.join(evidence, name), value);
// Short local metadata probes inherit the outer workload group. They never
// create the independent groups used by asynchronously awaited product steps.
const git = (cwd, ...args) => execFileSync('git', args, { cwd, encoding: 'utf8', timeout: 20_000 }).trim();
const source = cwd => ({ commit: git(cwd, 'rev-parse', 'HEAD'), tree: git(cwd, 'rev-parse', 'HEAD^{tree}'),
  dirty: git(cwd, 'status', '--porcelain') !== '' });
let activeOwner;
let cancellation;
function checkCancellation() { if (cancellation) throw cancellation; }
for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(signal, () => {
  cancellation ??= new Error(`workload cancelled by ${signal}`);
  process.exitCode = 1;
  // This owner also receives group cancellation from the outer supervisor.
  // Its first signal masks repeats while the reviewed helper settles its child.
  if (activeOwner) activeOwner.kill('SIGTERM');
});
async function step(name, command, args, cwd, timeoutMs, env = process.env) {
  checkCancellation();
  console.log(`CRABBOX_PHASE:${name}`);
  const fd = fs.openSync(path.join(evidence, `${name}.log`), 'w');
  const entry = { name, command: [command, ...args], timeoutMs, started: new Date().toISOString() };
  summary.steps.push(entry);
  const processDirectory = path.join(evidence, 'processes');
  let spawnError;
  try {
    const child = spawn('python3', [path.join(import.meta.dirname, 'step-owner.py'), processDirectory,
      name, String(timeoutMs / 1000), command, ...args], {
      cwd, env, detached: false, stdio: ['ignore', fd, fd],
    });
    activeOwner = child;
    const outcome = await new Promise(resolve => {
      child.on('error', error => { spawnError = error; });
      child.on('close', (code, signal) => resolve({ code, signal }));
    });
    activeOwner = undefined;
    entry.ownerExitCode = outcome.code;
    entry.ownerSignal = outcome.signal;
    const receiptPath = path.join(processDirectory, `${name}.exit.json`);
    const receipt = fs.existsSync(receiptPath) ? readJson(receiptPath) : undefined;
    entry.settlement = receipt;
    if (spawnError) throw spawnError;
    assert.ok(receipt, `${name}: missing step-owner settlement receipt`);
    assert.equal(receipt.localProcessSettled, true, `${name}: child was not joined`);
    assert.deepEqual(receipt.cleanupErrors, [], `${name}: process group did not settle`);
    checkCancellation();
    assert.equal(outcome.code, 0, `${name}: step owner failed`);
    assert.equal(receipt.exitCode, 0, `${name}: command failed`);
    assert.equal(receipt.failure, null, `${name}: command timed out or was interrupted`);
    entry.exitCode = 0;
  } catch (error) {
    entry.failure = { message: error.message, code: error.code };
    throw error;
  } finally {
    // Reaching here requires the Python owner to have exited. Its receipt is
    // independently checked again by the outer supervisor before collection.
    fs.closeSync(fd);
    entry.finished = new Date().toISOString();
    write('summary.json', summary);
  }
}
function distHashes(cwd) {
  const files = {};
  function walk(relative) {
    for (const entry of fs.readdirSync(path.join(cwd, relative), { withFileTypes: true })) {
      const name = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(name); else files[name] = hash(path.join(cwd, name));
    }
  }
  walk('dist');
  return files;
}
function telemetry() {
  return { time: new Date().toISOString(), load: os.loadavg(), cpuCount: os.cpus().length,
    availableParallelism: os.availableParallelism(), procStat: fs.readFileSync('/proc/stat', 'utf8').split('\n')[0] };
}
async function idlePreflight() {
  console.log('CRABBOX_PHASE:idle-preflight');
  const observations = [];
  const readCpu = () => fs.readFileSync('/proc/stat', 'utf8').split('\n')[0].trim().split(/\s+/).slice(1, 9).map(Number);
  for (let attempt = 0; attempt < 24; attempt++) {
    const first = readCpu();
    await delay(1000);
    checkCancellation();
    const second = readCpu();
    const delta = second.map((value, index) => value - first[index]);
    const total = delta.reduce((sum, value) => sum + value, 0);
    assert.ok(total > 0);
    const cpuBusyPercent = 100 * (1 - (delta[3] + delta[4]) / total);
    const observation = { ...telemetry(), attempt: attempt + 1, cpuBusyPercent };
    observations.push(observation);
    write('idle-preflight.json', { observations, accepted: false });
    if (cpuBusyPercent < 5 && observation.load[0] < 0.5 * observation.availableParallelism) {
      write('idle-preflight.json', { observations, accepted: true });
      return;
    }
    if (attempt < 23) await delay(4000);
  }
  throw new Error('Host did not meet the fixed idle preflight within 24 bounded observations; no timing started');
}
try {
  assert.equal(process.platform, 'linux');
  assert.equal(process.arch, 'x64');
  assert.equal(process.version, 'v24.21.0');
  assert.equal(execFileSync('pnpm', ['--version'], { encoding: 'utf8', timeout: 20_000 }).trim(), '12.4.2');
  const initialTransport = source(transport);
  assert.deepEqual(initialTransport, { commit: pins.commits.B, tree: pins.trees.B, dirty: false });
  write('environment.json', { node: process.version, pnpm: '12.4.2', platform: process.platform,
    arch: process.arch, cpuCount: os.cpus().length, availableParallelism: os.availableParallelism(),
    cpuModel: os.cpus()[0]?.model, kernel: os.release(), filesystem: fs.statfsSync(work),
    transport: initialTransport, clang: process.env.CC_wasm32_unknown_unknown, ar: process.env.AR_wasm32_unknown_unknown });
  await step('tool-layout', 'bash', ['-c', 'command -v node; command -v pnpm; file -L "$(command -v node)" "$(command -v pnpm)"; rustc --version; cargo --version; df -h /tmp'], work, 20_000);
  await step('apt-update', 'sudo', ['-n', 'apt-get', 'update', '-qq'], work, 300_000);
  await step('apt-install', 'sudo', ['-n', 'apt-get', 'install', '-y', 'btrfs-progs', 'strace', 'xfsprogs', 'e2fsprogs', 'attr', 'acl'], work, 300_000);
  const toolInputs = {};
  for (const name of ['node', 'pnpm', 'rustc', 'cargo', 'strace', 'mkfs.xfs', 'mkfs.btrfs', 'btrfs', 'filefrag']) {
    const located = execFileSync('which', [name], { encoding: 'utf8', timeout: 20_000 }).trim();
    const realpath = fs.realpathSync(located);
    toolInputs[name] = { path: located, realpath, sha256: hash(realpath) };
  }
  for (const key of ['CC_wasm32_unknown_unknown', 'AR_wasm32_unknown_unknown']) {
    const filename = process.env[key];
    assert(filename && path.isAbsolute(filename));
    toolInputs[key] = { path: filename, realpath: fs.realpathSync(filename), sha256: hash(filename) };
  }
  write('tool-inputs.json', toolInputs);
  const mounts = Object.fromEntries(['xfs', 'btrfs', 'xfs-no-reflink'].map(id => [id, path.join(work, 'fixtures', id)]));
  for (const volume of Object.keys(mounts)) {
    await step(`mount-setup-${volume}`, 'python3', [path.join(import.meta.dirname, 'mount-owner.py'), 'setup', '--volume', volume,
      '--work-dir', path.join(work, 'fixtures'), '--state-file', path.join(evidence, 'mount-states', `${volume}.json`)], work, 120_000);
    assert.equal(readJson(path.join(evidence, 'mount-states', `${volume}.json`)).setup.ok, true);
    assert.deepEqual(fs.readdirSync(mounts[volume]), []);
  }
  const repository = path.join(work, 'repository');
  await step('clone', 'git', ['clone', '--depth=1', '--branch', pins.branch, '--no-checkout', 'https://github.com/openclaw/fs-safe.git', repository], work, 180_000);
  assert.equal(git(repository, 'rev-parse', 'HEAD'), pins.commits.B);
  await step('fetch-A', 'git', ['fetch', '--depth=1', '--no-tags', 'origin', pins.commits.A], repository, 180_000);
  for (const variant of ['A', 'B']) {
    await step(`checkout-${variant}`, 'git', ['worktree', 'add', '--detach', path.join(work, variant), pins.commits[variant]], repository, 60_000);
    assert.deepEqual(source(path.join(work, variant)), { commit: pins.commits[variant], tree: pins.trees[variant], dirty: false });
  }
  const A = path.join(work, 'A');
  const changedFiles = git(repository, 'diff', '--name-only', pins.commits.A, pins.commits.B).split('\n').filter(Boolean).sort();
  assert.deepEqual(changedFiles, ['CHANGELOG.md', 'native/src/clone_unix.rs']);
  const inputs = ['package.json', 'pnpm-lock.yaml', 'Cargo.toml', 'Cargo.lock', 'native/Cargo.toml', 'native/build.rs',
    'scripts/prepack-build.mjs', 'scripts/build-native.mjs', 'scripts/check-release-packages.mjs'];
  // Whole-tree diff above proves all other source/build inputs equal; pin every
  // tracked file plus build-tool entrypoints for the execution receipt.
  write('inputs.json', Object.fromEntries(['A', 'B'].map(variant => {
    const cwd = path.join(work, variant);
    return [variant, { source: source(cwd), treeListing: git(cwd, 'ls-tree', '-r', 'HEAD'),
      inputs: Object.fromEntries(inputs.filter(file => fs.existsSync(path.join(cwd, file))).map(file => [file, hash(path.join(cwd, file))])) }];
  })));
  const native = {}, consumers = {};
  for (const variant of ['A', 'B']) {
    const cwd = path.join(work, variant);
    const cargoTarget = path.join(work, `cargo-target-${variant}`);
    const buildEnv = { ...process.env, CARGO_TARGET_DIR: cargoTarget };
    await step(`install-${variant}`, 'pnpm', ['install', '--frozen-lockfile'], cwd, 600_000, buildEnv);
    await step(`build-${variant}`, 'pnpm', ['build'], cwd, 1_200_000, buildEnv);
    await step(`native-build-${variant}`, 'pnpm', ['native:build'], cwd, 1_200_000, buildEnv);
    const artifact = path.join(cwd, 'native/fs-safe-native.linux-x64-gnu.node');
    native[variant] = { sha256: hash(artifact), artifact, cargoTarget, source: source(cwd) };
    assert.equal(hash(path.join(cwd, 'packages/linux-x64-gnu/fs-safe-native.node')), native[variant].sha256);
  }
  write('native.json', { provenance: summary.nativeBuild, builds: native });
  const focused = [];
  const excludedMock = 'joins admitted native writes and retains their descriptors before rejecting cancellation';
  const commonSkips = [excludedMock,
    'rejects ReFS alternate streams without reporting a lossy clone as success',
    'reports APFS clone provenance and stops matching after an independent edit'];
  const skipTitles = {
    xfs: [...commonSkips, 'requires a Btrfs subvolume source instead of copying an ordinary directory'],
    btrfs: [...commonSkips,
      'removes a failed Linux reflink clone without altering its source and permits retry',
      'preserves Linux reflink extended attributes and ACLs on writable entries',
      'preserves Linux reflink extended attributes and ACLs on read-only files',
      'preserves Linux reflink extended attributes and ACLs on read-only directories',
      'preserves Linux reflink directory attributes when umask removes owner-write'],
  };
  for (const variant of ['A', 'B']) {
    for (const filesystem of ['xfs', 'btrfs']) {
      const file = path.join(evidence, `focused-${variant}-${filesystem}.json`);
      await step(`focused-${variant}-${filesystem}`, 'pnpm', ['test', 'test/clone.test.ts',
        '--testNamePattern', `^(?!.*${excludedMock}).*$`, '--reporter=json', '--outputFile', file],
      path.join(work, variant), 600_000, { ...process.env, TMPDIR: '/tmp', FS_SAFE_TEST_SERIAL: '1',
        FS_SAFE_NATIVE_MODE: 'require', FS_SAFE_CLONE_TEST_ROOT: mounts[filesystem] });
      const result = readJson(file);
      assert.equal(result.success, true);
      assert.equal(result.numFailedTests, 0);
      assert.equal(result.testResults.length, 1);
      const cases = result.testResults[0].assertionResults;
      const skipped = cases.filter(test => test.status !== 'passed');
      assert(skipped.every(test => test.status === 'skipped' || test.status === 'pending'));
      assert.deepEqual(skipped.map(test => test.title).sort(), skipTitles[filesystem].sort());
      assert(cases.filter(test => test.status === 'passed').length >= 10);
      const contract = cases.map(test => ({ title: test.title, status: test.status })).sort((a, b) => a.title.localeCompare(b.title));
      focused.push({ variant, filesystem, contract });
      if (variant === 'B') assert.deepEqual(contract, focused.find(row => row.variant === 'A' && row.filesystem === filesystem).contract);
      assert.deepEqual(fs.readdirSync(mounts[filesystem]), [], 'source tests must clean their fixture tree');
    }
    const descriptorOutput = path.join(evidence, `descriptors-${variant}.json`);
    await step(`descriptors-${variant}`, 'pnpm', ['test', 'test/native-unix-descriptor-admission.test.ts', '--reporter=json', '--outputFile', descriptorOutput],
      path.join(work, variant), 600_000, { ...process.env, FS_SAFE_NATIVE_MODE: 'require', FS_SAFE_TEST_SERIAL: '1' });
    const result = readJson(descriptorOutput);
    assert.equal(result.success, true);
    assert.equal(result.numPassedTests, 15);
    assert.equal(result.numPendingTests, 0);
    assert.equal(result.numFailedTests, 0);
  }
  write('focused-summary.json', focused);
  const { isolatedConsumerEnv } = await import(pathToFileURL(path.join(A, 'scripts/consumer-install-smoke.mjs')));
  for (const variant of ['A', 'B']) {
    const cwd = path.join(work, variant);
    const output = path.join(evidence, `package-${variant}`);
    await step(`package-smoke-${variant}`, 'pnpm', ['package:smoke', '--output', output], cwd, 1_200_000,
      { ...process.env, FS_SAFE_EXPECTED_SOURCE_COMMIT: pins.commits[variant], CARGO_TARGET_DIR: native[variant].cargoTarget });
    const packages = readJson(path.join(output, 'manifest.json'));
    const packed = name => {
      const artifact = packages.find(entry => entry.name === name);
      assert(artifact);
      const filename = path.join(output, artifact.filename);
      assert.equal(artifact.integrity, `sha512-${createHash('sha512').update(fs.readFileSync(filename)).digest('base64')}`);
      return { ...artifact, sha256: hash(filename) };
    };
    const rootTarball = packed('@openclaw/fs-safe'), nativeTarball = packed('@openclaw/fs-safe-linux-x64-gnu');
    const consumer = path.join(work, `consumer-${variant}`);
    fs.mkdirSync(consumer);
    writeJson(path.join(consumer, 'package.json'), { private: true, type: 'module' });
    const env = isolatedConsumerEnv(path.join(consumer, 'config'));
    await step(`consumer-install-${variant}`, 'npm', ['install', '--ignore-scripts', '--omit=optional', '--no-audit', '--no-fund', '--offline',
      path.join(output, rootTarball.filename), path.join(output, nativeTarball.filename)], consumer, 180_000, env);
    const expected = { variant, source: source(cwd), distFiles: distHashes(cwd), nativeSha256: native[variant].sha256, rootTarball, nativeTarball };
    writeJson(path.join(consumer, 'expected.json'), expected);
    write(`expected-${variant}.json`, expected);
    fs.copyFileSync(path.join(consumer, 'package-lock.json'), path.join(evidence, `consumer-${variant}-package-lock.json`));
    consumers[variant] = { consumer, env, expected };
  }
  assert.deepEqual(consumers.A.expected.distFiles, consumers.B.expected.distFiles);
  for (const variant of ['A', 'B']) {
    const { consumer, env } = consumers[variant];
    for (const filesystem of ['xfs', 'btrfs']) for (const mode of ['require', 'off']) {
      const output = path.join(evidence, `behavior-${variant}-${filesystem}-${mode}.json`);
      await step(`behavior-${variant}-${filesystem}-${mode}`, process.execPath,
        [path.join(import.meta.dirname, 'behavior.mjs'), consumer, mounts[filesystem], filesystem, output, mode], consumer, 180_000, env);
      assert.equal(readJson(output).ok, true);
    }
    for (const [volume, mode] of [['xfs', 'reflink'], ['xfs-no-reflink', 'no-reflink']]) {
      const output = path.join(evidence, `xfs-proof-${variant}-${mode}.json`);
      await step(`xfs-proof-${variant}-${mode}`, process.execPath,
        [path.join(import.meta.dirname, 'xfs-proof.mjs'), consumer, mounts[volume], mode, output], consumer, 180_000, env);
      assert.equal(readJson(output).ok, true);
    }
  }
  const traces = path.join(evidence, 'traces'); fs.mkdirSync(traces);
  for (const variant of ['A', 'B']) for (const filesystem of ['xfs', 'btrfs']) for (const row of protocol.timing.rows) {
    const { consumer, env } = consumers[variant];
    const label = `${variant}-${filesystem}-${row.id}`;
    const trace = path.join(traces, `${label}.strace`), traceManifest = path.join(traces, `${label}.manifest.json`);
    const proof = path.join(traces, `${label}.proof.json`), parsed = path.join(traces, `${label}.parsed.json`);
    const setup = path.join(traces, `${label}.setup.json`);
    await step(`trace-prepare-${label}`, process.execPath, [path.join(import.meta.dirname, 'trace-prepare.mjs'),
      consumer, mounts[filesystem], filesystem, row.id, variant, traceManifest, setup], consumer, 60_000, env);
    await step(`trace-${label}`, 'python3', [path.join(import.meta.dirname, 'trace-launch.py'), trace,
      process.execPath, path.join(import.meta.dirname, 'trace-probe.mjs'), consumer, setup, proof], consumer, 60_000, env);
    await step(`parse-${label}`, 'python3', [path.join(import.meta.dirname, 'parse-strace.py'), trace, traceManifest, parsed], work, 30_000);
    assert.equal(readJson(proof).ok, true);
    const cleanup = path.join(traces, `${label}.cleanup.json`);
    await step(`trace-cleanup-${label}`, process.execPath,
      [path.join(import.meta.dirname, 'trace-cleanup.mjs'), proof, cleanup], consumer, 60_000, env);
    assert.equal(readJson(cleanup).ok, true);
  }
  await idlePreflight();
  const benchmarks = path.join(evidence, 'benchmarks'); fs.mkdirSync(benchmarks);
  const legs = [];
  for (const [index, leg] of protocol.timing.schedule.entries()) {
    const { consumer, env } = consumers[leg.variant];
    const label = `leg-${String(index + 1).padStart(2, '0')}`, output = path.join(benchmarks, `${label}.json`);
    writeJson(path.join(benchmarks, `${label}-load-before.json`), telemetry());
    await step(label, process.execPath, [path.join(import.meta.dirname, 'benchmark-leg.mjs'), consumer,
      mounts[leg.filesystem], leg.filesystem, String(index), output], consumer, 120_000, env);
    writeJson(path.join(benchmarks, `${label}-load-after.json`), telemetry());
    const receipt = readJson(output);
    assert.equal(receipt.state, 'complete');
    assert.deepEqual(receipt.source, consumers[leg.variant].expected.source);
    assert.deepEqual(receipt.cleanup, ['expected-entries-and-identities-verified-before-removal']);
    assert.deepEqual(Object.keys(receipt.rows).sort(), protocol.timing.rows.map(row => row.id).sort());
    for (const row of Object.values(receipt.rows)) {
      assert.equal(row.samples.length, 5); assert.equal(row.sampleMeansUs.length, 5);
      assert.equal(row.warmups, 5); assert.equal(row.checkedUntimed, 1); assert.equal(row.callsPerSample, 30);
      for (const [sample, values] of row.samples.entries()) {
        assert.equal(values.length, 30); assert(values.every(value => Number.isFinite(value) && value > 0));
        assert.equal(row.sampleMeansUs[sample], values.reduce((sum, value) => sum + value, 0) / 30);
      }
    }
    legs.push({ filesystem: receipt.filesystem, block: receipt.block, position: receipt.position, role: receipt.role,
      rows: Object.fromEntries(Object.entries(receipt.rows).map(([name, row]) => [name, { sampleMeansUs: row.sampleMeansUs }])) });
  }
  const assessmentInput = path.join(evidence, 'assessment-input.json'); writeJson(assessmentInput, { legs });
  await step('assessment', 'python3', [path.join(import.meta.dirname, 'assess.py'), assessmentInput, path.join(evidence, 'assessment.json')], work, 60_000);
  summary.performance = readJson(path.join(evidence, 'assessment.json')).performanceOutcome;
  for (const variant of ['A', 'B']) {
    assert.deepEqual(source(path.join(work, variant)), { commit: pins.commits[variant], tree: pins.trees[variant], dirty: false });
    assert.deepEqual(distHashes(path.join(work, variant)), consumers[variant].expected.distFiles);
    assert.equal(hash(native[variant].artifact), native[variant].sha256);
    const api = await installedApi(consumers[variant].consumer, 'off'); api.verify();
  }
  for (const volume of Object.keys(mounts)) assert.deepEqual(fs.readdirSync(mounts[volume]), [], 'all owned fixtures must be absent');
  assert.deepEqual(source(transport), initialTransport);
  verifyPacket(); checkCancellation();
  summary.gates = { correctness: true, traces: true, provenance: true };
  summary.execution = 'completed';
  summary.result = `${summary.performance}-pending-mount-and-provider-cleanup`;
} catch (error) {
  summary.execution = 'stopped-on-first-failure'; summary.result = 'failed-or-inconclusive';
  summary.failure = { message: error.message, stack: error.stack, status: error.status, code: error.code };
  console.error(error.stack); process.exitCode = 1;
} finally {
  summary.finished = new Date().toISOString(); write('summary.json', summary);
  console.log(`FS_SAFE_PROOF_RESULT=${summary.result}`);
}
