import assert from 'node:assert/strict';
import fsSync from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
export const payload = Buffer.from(Array.from({ length: 128 }, (_, index) => (index * 17 + 3) % 251));
export const targetSentinel = Buffer.from('existing caller target\n');
export const outsideSentinel = Buffer.from('outside sentinel retained\n');
export const primeSentinel = Buffer.from('native warmup sentinel\n');
export const writeOptions = Object.freeze({ mkdir: false, durable: false, mode: 0o600 });
export async function privateWorkspace(base) {
  assert.equal(process.platform, 'linux');
  const directory = await fs.mkdtemp(path.join(await fs.realpath(base), 'fs-safe-checked-kind-'));
  await fs.chmod(directory, 0o700);
  return directory;
}
export async function identity(file) {
  const st = await fs.lstat(file, { bigint: true });
  assert(!st.isSymbolicLink());
  return { dev: String(st.dev), ino: String(st.ino), directory: st.isDirectory() };
}
export async function sameIdentity(file, expected) { assert.deepEqual(await identity(file), expected, file); }
export async function absent(file) { await assert.rejects(fs.lstat(file), { code: 'ENOENT' }); }
export async function names(directory, expected) { assert.deepEqual((await fs.readdir(directory)).sort(), [...expected].sort(), directory); }
export async function checkFile(file, bytes, expected) {
  const st = await fs.lstat(file, { bigint: true });
  assert(st.isFile() && !st.isSymbolicLink(), file); assert.equal(st.nlink, 1n, file);
  assert.equal(st.mode & 0o7777n, 0o600n, file);
  if (expected) await sameIdentity(file, expected);
  assert.deepEqual(await fs.readFile(file), bytes, file);
}
export async function linkIdentity(file) {
  const st = await fs.lstat(file, { bigint: true });
  assert(st.isSymbolicLink(), file); assert.equal(st.nlink, 1n, file);
  return { dev: String(st.dev), ino: String(st.ino), target: await fs.readlink(file) };
}
export function descriptorSnapshot() {
  const result = {};
  for (const fd of fsSync.readdirSync('/proc/self/fd').sort((a, b) => Number(a) - Number(b))) {
    try { result[fd] = fsSync.readlinkSync(`/proc/self/fd/${fd}`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  return result;
}
export function settledDescriptors(expected) { assert.deepEqual(descriptorSnapshot(), expected, 'public call leaked or replaced a descriptor'); }
export function assertMechanism(mechanism, nodeMajor, protocol) {
  assert.equal(process.platform, 'linux');
  assert(['ENOSYS', 'EPERM', 'openat2'].includes(mechanism));
  assert.equal(process.env.FS_SAFE_TEST_NO_OPENAT2, '0', 'the environment fallback hook must be explicitly disabled');
  assert.equal(process.version, protocol.nodeVersions[String(nodeMajor)]);
}
export async function rowFixture(workspace, row, index, api) {
  assert([0, 1, 8].includes(row.depth));
  assert.equal(typeof row.alias, 'boolean');
  const directory = path.join(workspace, `row-${index}`);
  const outsidePath = path.join(workspace, `outside-${index}`);
  await fs.mkdir(directory, { mode: 0o700 }); await fs.mkdir(outsidePath, { mode: 0o700 });
  const rootReceipt = await identity(directory), outsideReceipt = await identity(outsidePath);
  const sentinelPath = path.join(outsidePath, 'sentinel');
  await fs.writeFile(sentinelPath, outsideSentinel, { flag: 'wx', mode: 0o600 });
  const sentinelReceipt = await identity(sentinelPath);
  const components = row.alias ? ['actual'] : Array.from({ length: row.depth }, (_, i) => `d${i}`);
  const existingParents = new Map();
  let current = directory;
  for (const component of components) {
    current = path.join(current, component); await fs.mkdir(current, { mode: 0o700 });
    existingParents.set(current, await identity(current));
  }
  const parentPath = current, targetPath = path.join(parentPath, 'value');
  const aliasPath = row.alias ? path.join(directory, 'alias') : undefined;
  if (aliasPath) await fs.symlink('actual', aliasPath);
  const aliasReceipt = aliasPath ? await linkIdentity(aliasPath) : undefined;
  const relative = [...(row.alias ? ['alias'] : components), 'value'].join('/');
  assert(!path.isAbsolute(relative));
  const safe = await api.root(directory);
  // Public root-level create warms the normal addon and capability path before measured calls.
  const primePath = path.join(directory, 'prime-sentinel');
  await safe.create('prime-sentinel', primeSentinel, writeOptions);
  const primeReceipt = await identity(primePath);
  await checkFile(primePath, primeSentinel, primeReceipt);
  const native = api.nativeState(), descriptors = descriptorSnapshot();
  let targetReceipt;
  async function inspectTree(hasTarget) {
    await sameIdentity(directory, rootReceipt);
    await sameIdentity(outsidePath, outsideReceipt); await names(outsidePath, ['sentinel']);
    await checkFile(sentinelPath, outsideSentinel, sentinelReceipt);
    await checkFile(primePath, primeSentinel, primeReceipt);
    if (aliasPath) assert.deepEqual(await linkIdentity(aliasPath), aliasReceipt);
    let selected = directory;
    for (const component of components) {
      await names(selected, selected === directory ? ['prime-sentinel', ...(row.alias ? ['alias'] : []), component] : [component]);
      selected = path.join(selected, component);
      await sameIdentity(selected, existingParents.get(selected));
      assert.equal((await fs.lstat(selected)).mode & 0o7777, 0o700);
    }
    await names(selected, [...(selected === directory ? ['prime-sentinel'] : []), ...(hasTarget ? ['value'] : [])]);
  }
  async function prepare() {
    await inspectTree(false); await absent(targetPath);
    await fs.writeFile(targetPath, targetSentinel, { flag: 'wx', mode: 0o600 });
    targetReceipt = await identity(targetPath); await checkFile(targetPath, targetSentinel, targetReceipt);
    settledDescriptors(descriptors);
  }
  function invoke() { return safe.write(relative, payload, writeOptions); }
  async function verify() {
    await inspectTree(true); await checkFile(targetPath, payload);
    settledDescriptors(descriptors);
    return { bytesHex: payload.toString('hex'), mode: 0o600, nlink: 1,
      sentinelHex: outsideSentinel.toString('hex'), names: (await fs.readdir(parentPath)).sort(),
      rootNames: (await fs.readdir(directory)).sort(), relative,
      ...(row.alias ? { aliasTarget: 'actual' } : {}) };
  }
  async function reset() {
    const published = await identity(targetPath); await sameIdentity(targetPath, published);
    await fs.unlink(targetPath); await absent(targetPath); targetReceipt = undefined;
    await inspectTree(false); settledDescriptors(descriptors);
  }
  async function verifyAndReset() { const outcome = await verify(); await reset(); return outcome; }
  async function verifyRejected() {
    assert(targetReceipt); await inspectTree(true); await checkFile(targetPath, targetSentinel, targetReceipt);
    settledDescriptors(descriptors); await reset();
  }
  async function close() {
    await inspectTree(false); settledDescriptors(descriptors);
    if (aliasPath) { assert.deepEqual(await linkIdentity(aliasPath), aliasReceipt); await fs.unlink(aliasPath); }
    for (const [name, expected] of [...existingParents].reverse()) {
      await sameIdentity(name, expected); await names(name, []); await fs.rmdir(name);
    }
    await checkFile(primePath, primeSentinel, primeReceipt); await fs.unlink(primePath);
    await names(directory, []); await sameIdentity(directory, rootReceipt); await fs.rmdir(directory); await absent(directory);
    await checkFile(sentinelPath, outsideSentinel, sentinelReceipt); await fs.unlink(sentinelPath);
    await names(outsidePath, []); await sameIdentity(outsidePath, outsideReceipt); await fs.rmdir(outsidePath); await absent(outsidePath);
    settledDescriptors(descriptors);
  }
  return { directory, rootPath: directory, parentPath, targetPath, sentinelPath, outsidePath, primePath,
    aliasPath, aliasTarget: row.alias ? 'actual' : undefined, existingParentPaths: [...existingParents.keys()],
    relative, safe, options: writeOptions, native, prepare, invoke, verify, reset, verifyAndReset, verifyRejected, close };
}
