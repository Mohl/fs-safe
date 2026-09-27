import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
export const payload = Buffer.from(Array.from({ length: 128 }, (_, index) => (index * 17 + 3) % 251));
const sentinel = Buffer.from('existing caller target\n');
async function command(executable, args) {
  const child = spawn(executable, args, { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '', stderr = '', error;
  child.stdout.on('data', value => { stdout += value; }); child.stderr.on('data', value => { stderr += value; });
  const code = await new Promise(resolve => { child.on('error', value => { error = value; }); child.on('close', resolve); });
  if (error) throw error;
  assert.equal(code, 0, `${executable}: ${stderr}`);
  return stdout;
}
export async function privateWorkspace(base) {
  const directory = await fs.mkdtemp(path.join(await fs.realpath(base), 'fs-safe-parent-owner-'));
  if (process.platform === 'win32') {
    const user = await command('whoami.exe', ['/user', '/fo', 'csv', '/nh']);
    const sid = user.match(/S-1-[0-9-]+/)?.[0]; assert(sid, 'Windows caller SID unavailable');
    await command('icacls.exe', [directory, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`]);
  } else await fs.chmod(directory, 0o700);
  return directory;
}
export async function identity(file) {
  const st = await fs.lstat(file, { bigint: true });
  assert(!st.isSymbolicLink());
  return { dev: String(st.dev), ino: String(st.ino), directory: st.isDirectory() };
}
export async function sameIdentity(file, expected) { assert.deepEqual(await identity(file), expected); }
export async function absent(file) { await assert.rejects(fs.lstat(file), { code: 'ENOENT' }); }
export async function names(directory, expected) { assert.deepEqual((await fs.readdir(directory)).sort(), [...expected].sort()); }
export async function rowFixture(workspace, row, index, api) {
  const directory = path.join(workspace, `row-${index}`); await fs.mkdir(directory, { mode: 0o700 });
  const receipt = await identity(directory), safe = await api.root(directory);
  const denied = path.join(directory, 'denied'); await fs.mkdir(denied, { mode: 0o700 });
  const deniedReceipt = await identity(denied);
  const components = Array.from({ length: row.depth }, (_, i) => `d${i}`);
  const canonical = components.join(path.sep) + path.sep + 'value';
  const relative = row.policyPath === 'raw-dot-deopt' ? `.${path.sep}${canonical}` : canonical;
  const target = path.join(directory, canonical), parent = path.dirname(target);
  const source = path.join(workspace, `source-${index}`); await fs.writeFile(source, payload, { flag: 'wx', mode: 0o600 });
  const sourceIdentity = await identity(source);
  const options = { durable: false, mkdir: true, mode: 0o600, mutationSymlinks: 'reject',
    renameIdentity: 'strict', denyMutations: { prefixes: [denied] } };
  const initialDepth = row.layout === 'complete' ? row.depth : row.layout === 'partial' ? Math.floor(row.depth / 2) : row.layout === 'missing' ? 1 : 0;
  if (initialDepth) await fs.mkdir(path.join(directory, ...components.slice(0, initialDepth)), { recursive: true, mode: 0o700 });
  const existingParents = new Map();
  for (let depth = 1; depth <= initialDepth; depth++) {
    const name = path.join(directory, ...components.slice(0, depth)); existingParents.set(name, await identity(name));
  }
  const invoke = row.operation === 'write' ? safe.write.bind(safe, relative, payload, options)
    : row.operation === 'copyIn' ? safe.copyIn.bind(safe, relative, source, { ...options, clone: 'never', sourceHardlinks: 'reject', overwrite: true })
    : safe.create.bind(safe, relative, payload, { ...options, atomic: row.operation === 'create-atomic' });
  let sentinelIdentity;
  async function inspectTree(leaf, depth = components.length) {
    await sameIdentity(directory, receipt);
    await sameIdentity(denied, deniedReceipt); await names(denied, []);
    let current = directory;
    for (const component of components.slice(0, depth)) {
      await names(current, current === directory ? ['denied', component] : [component]); current = path.join(current, component);
      assert((await fs.lstat(current)).isDirectory());
      if (existingParents.has(current)) await sameIdentity(current, existingParents.get(current));
    }
    await names(current, [...(current === directory ? ['denied'] : []), ...(leaf ? ['value'] : [])]);
  }
  async function prepare() {
    await inspectTree(false, initialDepth);
    await absent(target);
    sentinelIdentity = undefined;
    if (row.target === 'existing') {
      await fs.writeFile(target, sentinel, { flag: 'wx', mode: 0o600 });
      sentinelIdentity = await identity(target);
    }
  }
  function call(overrides) {
    if (!overrides) return invoke();
    const selected = { ...options, ...overrides };
    if (row.operation === 'write') return safe.write(relative, payload, selected);
    if (row.operation === 'copyIn') return safe.copyIn(relative, source, { ...selected, clone: 'never', sourceHardlinks: 'reject', overwrite: true });
    return safe.create(relative, payload, { ...selected, atomic: row.operation === 'create-atomic' });
  }
  async function verifyAndReset() {
    await inspectTree(true);
    const st = await fs.lstat(target, { bigint: true });
    assert(st.isFile() && !st.isSymbolicLink()); assert.equal(st.nlink, 1n);
    if (process.platform !== 'win32') assert.equal(st.mode & 0o777n, 0o600n);
    assert.deepEqual(await fs.readFile(target), payload);
    await sameIdentity(source, sourceIdentity); assert.deepEqual(await fs.readFile(source), payload);
    const leaf = await identity(target); await sameIdentity(target, leaf); await fs.unlink(target); await absent(target);
    if (initialDepth < components.length) {
      for (let depth = components.length; depth > initialDepth; depth--) {
        const name = path.join(directory, ...components.slice(0, depth)); await names(name, []); await fs.rmdir(name);
      }
      await inspectTree(false, initialDepth);
    } else await inspectTree(false);
  }
  async function verifyRejected() {
    await inspectTree(row.target === 'existing', initialDepth);
    await sameIdentity(source, sourceIdentity); assert.deepEqual(await fs.readFile(source), payload);
    if (row.target === 'existing') {
      assert(sentinelIdentity); await sameIdentity(target, sentinelIdentity);
      assert.deepEqual(await fs.readFile(target), sentinel);
      const leaf = await identity(target); await sameIdentity(target, leaf); await fs.unlink(target);
    } else await absent(target);
    await inspectTree(false, initialDepth);
  }
  async function close() {
    await sameIdentity(directory, receipt);
    if (initialDepth) {
      await inspectTree(false, initialDepth);
      for (let depth = initialDepth; depth > 0; depth--) await fs.rmdir(path.join(directory, ...components.slice(0, depth)));
    }
    await names(directory, ['denied']); await sameIdentity(denied, deniedReceipt); await names(denied, []); await fs.rmdir(denied);
    await names(directory, []); await fs.rmdir(directory);
    await sameIdentity(source, sourceIdentity); assert.deepEqual(await fs.readFile(source), payload); await fs.unlink(source);
  }
  return { directory, target, source, options, prepare, invoke, call, verifyAndReset, verifyRejected, close };
}
