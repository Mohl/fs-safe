import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';

assert.equal(process.platform, 'linux', 'This paired comparison is the Linux performance lane');
const root = process.cwd();
const output = path.join(root, '.artifacts/methods-final');
fs.mkdirSync(output, { recursive: true });
const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();
const run = (command, args) => {
  console.log(JSON.stringify({ command, args }));
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${command} failed`);
};
const revisions = {
  main: 'a386202bcbaf0229397df7dc37ddc673f8e2ef34',
  pre: 'b4d6d6f69b5773e84986134dd7aa81a58716a333',
  after: git('rev-parse', 'HEAD'),
};
const distributions = { after: path.join(root, 'dist') };
for (const name of ['main', 'pre']) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `root-methods-${name}-`));
  git('init', '--quiet', directory);
  git('-C', directory, 'fetch', '--quiet', '--depth', '1', 'https://github.com/openclaw/fs-safe.git', revisions[name]);
  git('-C', directory, 'checkout', '--quiet', '--detach', 'FETCH_HEAD');
  assert.equal(git('-C', directory, 'rev-parse', 'HEAD'), revisions[name]);
  fs.symlinkSync(path.join(root, 'node_modules'), path.join(directory, 'node_modules'), 'dir');
  run('pnpm', ['exec', 'tsc', '-p', path.join(directory, 'tsconfig.json')]);
  fs.copyFileSync(path.join(root, 'dist/archive-parser.wasm'), path.join(directory, 'dist/archive-parser.wasm'));
  distributions[name] = path.join(directory, 'dist');
}
fs.writeFileSync(path.join(output, 'sources.json'), JSON.stringify({ revisions,
  node: process.version, arch: process.arch, sameNativeBinding: 'all distributions share the same node_modules directory',
  sequence: 'A/A control followed by A/B/B/A, repeated twice; 100 iterations, 5 samples, 5 warmups per invocation',
}, null, 2) + '\n');

for (const { mode, before, label } of [
  { mode: 'require', before: 'main', label: 'require' },
  { mode: 'require', before: 'pre', label: 'require-prefusion' },
  { mode: 'auto', before: 'main', label: 'auto' },
]) {
  for (const operation of ['remove', 'mkdir', 'append', 'move', 'openWritable']) {
    const sequence = [before, before, before, 'after', 'after', before, before, 'after', 'after', before];
    for (const [index, name] of sequence.entries()) {
      run('pnpm', ['benchmark:methods', '--mode', mode, '--filter', `Root.${operation}`,
        '--dist', distributions[name], '--iterations', '100', '--samples', '5', '--warmup', '5',
        '--json', path.join(output, `${label}-${operation}-${index}-${name}.json`)]);
    }
  }
}
console.log(JSON.stringify({ event: 'paired-methods-complete', revisions }));
