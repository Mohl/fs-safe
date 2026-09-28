import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';

const output = path.resolve('.artifacts/required-root');
fs.mkdirSync(output, { recursive: true });
const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const lanes = process.platform === 'linux' ? ['openat2', 'fallback'] : [process.platform];
const summary = [];
const failClosed = process.argv.includes('--fail-closed');
if (failClosed) {
  const { configureFsSafeNative } = await import('../../dist/config.js');
  const { root } = await import('../../dist/root.js');
  configureFsSafeNative({ mode: 'require' });
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'required-recursive-unavailable-'));
  try {
    fs.mkdirSync(path.join(directory, 'tree'));
    fs.writeFileSync(path.join(directory, 'tree/value'), 'preserve');
    const scoped = await root(directory);
    await assert.rejects(scoped.remove('tree', { recursive: true }), { code: 'helper-unavailable' });
    assert.equal(fs.readFileSync(path.join(directory, 'tree/value'), 'utf8'), 'preserve');
    assert.deepEqual(fs.readdirSync(directory), ['tree']);
    const receipt = { event: 'recursive-fail-closed', head, platform: process.platform, passed: true };
    fs.writeFileSync(path.join(output, `recursive-fail-closed-${process.platform}.json`), JSON.stringify(receipt) + '\n');
    console.log(JSON.stringify(receipt));
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
} else {
  for (const lane of lanes) {
    const env = { ...process.env };
    delete env.FS_SAFE_TEST_NO_OPENAT2;
    if (lane === 'fallback') env.FS_SAFE_TEST_NO_OPENAT2 = '1';
    const recursive = lane !== 'fallback' && process.platform !== 'win32';
    if (!recursive) execFileSync(process.execPath, [import.meta.filename, '--fail-closed'], { env, stdio: 'inherit' });
    const operations = ['remove', ...(recursive ? ['removeTree'] : []), 'rename', 'mkdir', 'appendCreate'];
    const file = path.join(output, `${lane}.jsonl`);
    const log = fs.createWriteStream(path.join(output, `${lane}.log`), { flags: 'wx' });
    const child = spawn(process.execPath, ['scripts/root-race/run.mjs', '--mode=require',
      `--ops=${operations.join(',')}`, '--seeds=60', '--seconds=20', `--output=${file}`], { env });
    child.stdout.on('data', data => { process.stdout.write(data); log.write(data); });
    child.stderr.on('data', data => { process.stderr.write(data); log.write(data); });
    const result = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    await new Promise(resolve => log.end(resolve));
    assert.equal(result.code, 0, `${lane} strict campaign failed: ${JSON.stringify(result)}`);
    const rows = fs.readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    const configuration = rows[0];
    assert.equal(configuration.nativeLoaded, true);
    if (lane === 'openat2') assert.equal(configuration.nativeContainment, 'kernel-atomic');
    if (lane === 'fallback') assert.equal(configuration.nativeContainment, 'best-effort');
    const complete = rows.at(-1);
    assert.equal(complete.event, 'complete');
    assert.equal(complete.seeds, 60);
    assert.equal(complete.affectedSeeds, 0);
    assert.equal(complete.incompleteSeeds, 0);
    const seeds = rows.filter(row => row.event === 'seed');
    const successes = Object.fromEntries(operations.map(operation => [operation,
      seeds.reduce((sum, row) => sum + row.metrics[operation].success, 0)]));
    summary.push({ head, lane, platform: process.platform, seconds: 1200, operations,
      calls: seeds.reduce((sum, row) => sum + row.operations, 0), successes,
      outsideEffects: 0, deniedEffects: 0, recursive: recursive ? 'exercised' : 'asserted-fail-closed' });
    fs.writeFileSync(path.join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
  }
  console.log(JSON.stringify({ event: 'campaign-summary', summary }));
}
