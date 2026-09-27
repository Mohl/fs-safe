import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

export async function tool(command, args) {
  const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '', err = '', failure;
  child.stdout.on('data', data => { out += data; });
  child.stderr.on('data', data => { err += data; });
  const code = await new Promise(resolve => {
    child.on('error', error => { failure = error; });
    child.on('close', resolve);
  });
  if (failure) throw failure;
  assert.equal(code, 0, `${command}: ${err}`);
  return out;
}
export async function identity(filename) {
  const st = await fs.lstat(filename, { bigint: true });
  assert(st.isDirectory() && !st.isSymbolicLink(), 'owned fixture must be a real directory');
  return { path: await fs.realpath(filename), dev: String(st.dev), ino: String(st.ino) };
}
export async function assertIdentity(filename, expected) {
  assert.deepEqual(await identity(filename), expected, 'owned directory identity changed');
}
export async function createFixture(mount, prefix) {
  mount = await fs.realpath(mount);
  const filename = await fs.mkdtemp(path.join(mount, prefix));
  await fs.chmod(filename, 0o700);
  return { path: filename, identity: await identity(filename) };
}
export async function snapshot(root) {
  const entries = {};
  async function visit(relative) {
    const filename = path.join(root, relative);
    const st = await fs.lstat(filename, { bigint: true });
    const item = { mode: Number(st.mode & 0o7777n), uid: String(st.uid), gid: String(st.gid), mtimeNs: String(st.mtimeNs) };
    if (st.isSymbolicLink()) {
      // Portable copy promises literal links, not symlink timestamp preservation.
      delete item.mtimeNs;
      Object.assign(item, { kind: 'link', target: await fs.readlink(filename) });
    }
    else if (st.isDirectory()) item.kind = 'directory';
    else {
      assert(st.isFile(), 'unexpected special entry');
      assert.equal(st.nlink, 1n, 'unexpected hardlink');
      Object.assign(item, { kind: 'file', size: Number(st.size), sha256: createHash('sha256').update(await fs.readFile(filename)).digest('hex') });
    }
    entries[relative] = item;
    if (item.kind === 'directory') for (const name of (await fs.readdir(filename)).sort()) await visit(relative ? `${relative}/${name}` : name);
  }
  await visit('');
  return entries;
}
export async function assertSnapshot(filename, expected) {
  assert.deepEqual(await snapshot(filename), expected, 'fixture contents or metadata differ');
}
export async function fillSmall(source) {
  for (const name of ['nested', 'nested/deeper', 'empty']) await fs.mkdir(path.join(source, name), { mode: 0o750 });
  const files = [];
  for (let i = 0; i < 8; i++) {
    const name = `${['', 'nested/', 'nested/deeper/'][i % 3]}file-${i}`;
    const bytes = Buffer.from(Array.from({ length: 4096 }, (_, offset) => (i * 17 + offset) % 251));
    await fs.writeFile(path.join(source, name), bytes, { mode: 0o640 });
    files.push(name);
  }
  await fs.writeFile(path.join(source, 'empty-file'), '', { mode: 0o640 });
  await fs.symlink('nested/file-1', path.join(source, 'literal-link'));
  const instant = new Date(1700000000000);
  for (const name of [...files, 'empty-file']) {
    await fs.chmod(path.join(source, name), 0o640);
    await fs.utimes(path.join(source, name), instant, instant);
  }
  await fs.lutimes(path.join(source, 'literal-link'), instant, instant);
  for (const name of ['nested/deeper', 'nested', 'empty', '']) {
    await fs.chmod(path.join(source, name), 0o750);
    await fs.utimes(path.join(source, name), instant, instant);
  }
  return snapshot(source);
}
export async function removeOwned(filename, receipt, filesystem, expected) {
  await assertIdentity(filename, receipt);
  if (expected) await assertSnapshot(filename, expected);
  // A public Btrfs clone source/snapshot has inode 256; the helper never walks
  // into subvolumes recursively or treats a failed subvolume delete as rm.
  if (filesystem === 'btrfs' && receipt.ino === '256') await tool('sudo', ['-n', 'btrfs', 'subvolume', 'delete', '--', filename]);
  else await fs.rm(filename, { recursive: true, force: false });
  await assert.rejects(fs.lstat(filename), { code: 'ENOENT' });
}
export async function reclaim(mount, filesystem) {
  if (filesystem === 'btrfs') {
    await tool('sudo', ['-n', 'btrfs', 'filesystem', 'sync', mount]);
    await tool('sudo', ['-n', 'btrfs', 'subvolume', 'sync', mount]);
  }
}
