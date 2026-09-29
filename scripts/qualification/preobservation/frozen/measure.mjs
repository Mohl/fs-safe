import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import sync from "node:fs";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";

assert.equal(process.argv.length, 4, "usage: node measure.mjs EXPECTED_JSON NEW_REPORT_JSON");
assert.match(process.version, /^v24\./u, "fixed campaign uses Node 24");
assert.ok(["linux", "darwin", "win32"].includes(process.platform));
assert.equal(process.env.FS_SAFE_TEST_NO_OPENAT2, undefined, "do not disable capability admission");
const expected = JSON.parse(await fs.readFile(process.argv[2], "utf8"));
const reportPath = path.resolve(process.argv[3]);
assert.equal(sync.existsSync(reportPath), false, "report must be fresh");
const canonical = (file) => sync.realpathSync.native(file);
const hash = (file) => createHash("sha256").update(sync.readFileSync(file)).digest("hex");
assert.match(expected.nativeSha256, /^[a-f0-9]{64}$/u);
const consumer = canonical(process.cwd());
const require = createRequire(path.join(consumer, "package.json"));
const manifestPath = canonical(require.resolve("@openclaw/fs-safe/package.json"));
const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
assert.equal(manifest.name, "@openclaw/fs-safe");
assert.equal(manifest.version, expected.packageVersion);
const rootRequire = createRequire(manifestPath);
const binary = canonical(rootRequire.resolve(expected.nativePackage));
assert.equal(binary, canonical(require.resolve(expected.nativePackage)));
assert.equal(path.extname(binary), ".node");
assert.equal(hash(binary), expected.nativeSha256);
const nativeManifest = JSON.parse(await fs.readFile(path.join(path.dirname(binary), "package.json"), "utf8"));
assert.equal(nativeManifest.name, expected.nativePackage);
assert.equal(nativeManifest.version, manifest.version);
for (const file of [manifestPath, binary]) {
  const rel = path.relative(path.join(consumer, "node_modules"), file);
  assert.ok(rel && rel !== ".." && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel));
}
const apiPath = canonical(require.resolve("@openclaw/fs-safe"));
const dist = path.join(path.dirname(manifestPath), "dist");
function distributionHash() {
  const entries = [];
  function visit(directory, prefix = "") {
    for (const item of sync.readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0)) {
      const relative = `${prefix}${item.name}`;
      if (item.isDirectory()) visit(path.join(directory, item.name), `${relative}/`);
      else { assert.equal(item.isFile(), true); entries.push(`${relative}:${hash(path.join(directory, item.name))}`); }
    }
  }
  visit(dist);
  return createHash("sha256").update(entries.join("\n")).digest("hex");
}
const distSha256 = distributionHash();
const { root, configureFsSafeNative } = await import(pathToFileURL(apiPath));
configureFsSafeNative({ mode: "require" });
const top = canonical(await fs.mkdtemp(path.join(os.tmpdir(), "fs-safe-pr770-timing-")));
const payload = Buffer.alloc(128, 0x61);
const oldPayload = Buffer.alloc(96, 0x62);
const absent = (file) => assert.rejects(fs.lstat(file), { code: "ENOENT" });
const rows = [];
let nativeIdentity;
try {
  const scoped = await root(top);
  const file = path.join(top, "file");
  const empty = path.join(top, "empty");
  const source = path.join(top, "source");
  const target = path.join(top, "target");
  const tree = path.join(top, "tree");
  let sourceIdentity;
  const cases = [
    { name: "remove-file", prepare: () => fs.writeFile(file, payload),
      run: () => scoped.remove("file"), verify: () => absent(file) },
    { name: "remove-empty-directory", prepare: () => fs.mkdir(empty),
      run: () => scoped.remove("empty"), verify: () => absent(empty) },
    { name: "move-existing-overwrite", async prepare() {
      await fs.writeFile(source, payload);
      await fs.writeFile(target, oldPayload);
      sourceIdentity = await fs.stat(source, { bigint: true });
      const old = await fs.stat(target, { bigint: true });
      assert.ok(old.ino !== sourceIdentity.ino || old.dev !== sourceIdentity.dev);
      assert.deepEqual(await fs.readFile(target), oldPayload);
    }, run: () => scoped.move("source", "target", { overwrite: true }), async verify() {
      await absent(source);
      assert.deepEqual(await fs.readFile(target), payload);
      const published = await fs.stat(target, { bigint: true });
      assert.equal(published.dev, sourceIdentity.dev);
      assert.equal(published.ino, sourceIdentity.ino);
      await fs.unlink(target);
      await absent(target);
    } },
  ];
  if (process.platform !== "win32") cases.push({ name: "remove-recursive", async prepare() {
    await fs.mkdir(tree);
    for (const dir of ["a", "b"]) {
      await fs.mkdir(path.join(tree, dir));
      for (const name of ["one", "two"]) await fs.writeFile(path.join(tree, dir, name), payload);
    }
  }, run: () => scoped.remove("tree", { recursive: true, maxEntries: 7, maxDepth: 2 }), verify: () => absent(tree) });
  async function call(c, measured) {
    await c.prepare();
    const start = measured ? performance.now() : 0;
    await c.run();
    const elapsed = measured ? performance.now() - start : 0;
    await c.verify();
    assert.deepEqual(await fs.readdir(top), []);
    if (measured) assert.ok(Number.isFinite(elapsed) && elapsed > 0);
    return elapsed;
  }
  for (const c of cases) for (let warmup = 0; warmup < 5; warmup++) await call(c, false);
  const loaded = Object.values(require.cache).find((entry) => entry?.filename.endsWith(".node") && canonical(entry.filename) === binary);
  assert.ok(loaded, "public require-mode calls must load the matching addon");
  const methods = ["rootRemovalStat", "rootRemovalUnlink", "renameReplaceWithIdentity", "closeOwnedFd"];
  if (process.platform !== "win32") methods.push("openRootRemovalDirectory", "ownedTreeRemovalAvailable");
  for (const method of methods) assert.equal(typeof loaded.exports[method], "function", method);
  assert.ok(process.report.getReport().sharedObjects.filter((file) => file.endsWith(".node")).some((file) => canonical(file) === binary));
  if (process.platform !== "win32") {
    const fd = sync.openSync(top, sync.constants.O_RDONLY | sync.constants.O_DIRECTORY);
    try { assert.equal(loaded.exports.ownedTreeRemovalAvailable(fd), true); }
    finally { sync.closeSync(fd); }
  }
  nativeIdentity = { path: binary, sha256: hash(binary), methods, cache: true, osImage: true };
  for (const c of cases) {
    const sampleMeansUs = [];
    for (let sample = 0; sample < 8; sample++) {
      let elapsed = 0;
      for (let iteration = 0; iteration < 50; iteration++) elapsed += await call(c, true);
      sampleMeansUs.push(elapsed * 1000 / 50);
    }
    rows.push({ name: c.name, sampleMeansUs, iterations: 50, warmups: 5, verifiedCalls: 405 });
  }
  if (process.platform === "win32") rows.push({ name: "remove-recursive", skipped: "documented unsupported Windows require-mode recursive removal" });
  assert.equal(hash(binary), expected.nativeSha256);
  assert.equal(distributionHash(), distSha256, "installed distribution changed during measurement");
  assert.deepEqual(await fs.readdir(top), []);
} finally {
  configureFsSafeNative({ mode: "auto" });
  await fs.rm(top, { recursive: true, force: true });
}
const report = { schema: 1, campaign: "pr770-preobservation-v1", node: process.version,
  nodePath: canonical(process.execPath), nodeSha256: hash(process.execPath), platform: process.platform,
  arch: process.arch, cpu: os.cpus()[0]?.model, mode: "require", packageVersion: manifest.version,
  apiPath, apiSha256: hash(apiPath), distSha256, probeSha256: hash(new URL(import.meta.url)),
  native: nativeIdentity, samples: 8, iterations: 50, warmups: 5, cleanup: "complete", rows };
await fs.writeFile(reportPath, `${JSON.stringify(report)}\n`, { flag: "wx" });
console.log(JSON.stringify({ result: "PASS", report: reportPath, measuredCases: process.platform === "win32" ? 3 : 4 }));
