import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fsSync from "node:fs";
import fs from "node:fs/promises";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

// Invoke with a fresh packed consumer as cwd; expected hashes come from the build.
assert.equal(process.argv.length, 3, "usage: node installed-preobservation-probe.mjs expected.json");
assert.equal(process.env.NODE_ENV, "test", "public race hooks require NODE_ENV=test");
assert.ok(["linux", "darwin", "win32"].includes(process.platform));
const expected = JSON.parse(await fs.readFile(path.resolve(process.argv[2]), "utf8"));
assert.match(expected.nativeSha256, /^[a-f0-9]{64}$/u);
assert.equal(typeof expected.packageVersion, "string");
const consumer = fsSync.realpathSync.native(process.cwd());
const require = createRequire(path.join(consumer, "package.json"));
const manifestPath = fsSync.realpathSync.native(require.resolve("@openclaw/fs-safe/package.json"));
const manifest = JSON.parse(await fs.readFile(manifestPath, "utf8"));
assert.equal(manifest.name, "@openclaw/fs-safe");
assert.equal(manifest.version, expected.packageVersion);
const rootRequire = createRequire(manifestPath);
const nativePattern = process.platform === "linux"
  ? new RegExp(`^@openclaw/fs-safe-linux-${process.arch}-(gnu|musl)$`, "u")
  : new RegExp(`^@openclaw/fs-safe-${process.platform}-${process.arch}${process.platform === "win32" ? "-msvc" : ""}$`, "u");
assert.match(expected.nativePackage, nativePattern);
const binary = fsSync.realpathSync.native(rootRequire.resolve(expected.nativePackage));
assert.equal(binary, fsSync.realpathSync.native(require.resolve(expected.nativePackage)), "both consumers must resolve the same addon");
const nativeManifest = JSON.parse(await fs.readFile(path.join(path.dirname(binary), "package.json"), "utf8"));
assert.equal(nativeManifest.name, expected.nativePackage);
assert.equal(nativeManifest.version, manifest.version);
const hash = (file) => createHash("sha256").update(fsSync.readFileSync(file)).digest("hex");
assert.equal(hash(binary), expected.nativeSha256);
assert.equal(path.extname(binary), ".node");
for (const file of [manifestPath, binary]) {
  const relative = path.relative(path.join(consumer, "node_modules"), file);
  assert.ok(relative && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative), "require a packed installation inside consumer/node_modules");
}
const apiPath = require.resolve("@openclaw/fs-safe");
const { configureFsSafeNative, root } = await import(pathToFileURL(apiPath));
const { __setFsSafeTestHooksForTest: setHooks } = await import(pathToFileURL(rootRequire.resolve("@openclaw/fs-safe/test-hooks")));
configureFsSafeNative({ mode: "require" });
const rows = [];
const absent = (file) => assert.rejects(fs.lstat(file), { code: "ENOENT" });
const top = fsSync.realpathSync.native(await fs.mkdtemp(path.join(os.tmpdir(), "fs-safe-preobservation-")));
const directory = path.join(top, "root");
const outside = path.join(top, "outside");
const linkType = process.platform === "win32" ? "junction" : "dir";
let binding;
try {
  await fs.mkdir(directory);
  await fs.mkdir(outside);
  await fs.writeFile(path.join(outside, "value"), "outside sentinel");
  const scoped = await root(directory);

  // A public require-mode removal must load the package; do not prime with require(binary).
  await fs.writeFile(path.join(directory, "file"), "remove me");
  await scoped.remove("file");
  await absent(path.join(directory, "file"));
  const loaded = Object.values(require.cache).filter((entry) => entry?.filename.endsWith(".node"));
  const match = loaded.find((entry) => fsSync.realpathSync.native(entry.filename) === binary);
  assert.ok(match, "public operation must load the expected .node into require.cache");
  binding = match.exports;
  const required = ["rootRemovalStat", "rootRemovalUnlink", "renameReplaceWithIdentity", "closeOwnedFd"];
  if (process.platform !== "win32") required.push("openRootRemovalDirectory", "ownedTreeRemovalAvailable");
  for (const name of required) assert.equal(typeof binding[name], "function", `missing native primitive ${name}`);
  // Same loader-image check as scripts/consumer-proof-metadata.mjs.
  const nativeImages = process.report.getReport().sharedObjects.filter((file) => file.endsWith(".node"));
  assert.ok(nativeImages.some((file) => fsSync.realpathSync.native(file) === binary), "expected addon must be loaded by the OS");
  rows.push("file-remove-and-native-admission");

  await fs.mkdir(path.join(directory, "empty"));
  await scoped.remove("empty");
  await absent(path.join(directory, "empty"));
  rows.push("empty-directory-remove");

  await fs.writeFile(path.join(directory, "source"), "new contents");
  await fs.writeFile(path.join(directory, "target"), "old contents");
  const sourceIdentity = await fs.stat(path.join(directory, "source"), { bigint: true });
  await scoped.move("source", "target", { overwrite: true });
  await absent(path.join(directory, "source"));
  assert.equal(await fs.readFile(path.join(directory, "target"), "utf8"), "new contents");
  const targetIdentity = await fs.stat(path.join(directory, "target"), { bigint: true });
  assert.equal(targetIdentity.dev, sourceIdentity.dev);
  assert.equal(targetIdentity.ino, sourceIdentity.ino);
  rows.push("overwrite-existing-file");

  await fs.mkdir(path.join(directory, "full"));
  await fs.writeFile(path.join(directory, "full/value"), "preserve");
  await assert.rejects(scoped.remove("full"), { code: "not-empty" });
  assert.equal(await fs.readFile(path.join(directory, "full/value"), "utf8"), "preserve");
  rows.push("nonempty-directory-refusal");

  await fs.symlink(outside, path.join(directory, "leaf-link"), linkType);
  await scoped.remove("leaf-link");
  await absent(path.join(directory, "leaf-link"));
  assert.equal(await fs.readFile(path.join(outside, "value"), "utf8"), "outside sentinel");
  rows.push("leaf-link-removal-preserves-outside");

  if (process.platform === "win32") {
    await assert.rejects(scoped.remove("full", { recursive: true }), { code: "helper-unavailable" });
    assert.equal(await fs.readFile(path.join(directory, "full/value"), "utf8"), "preserve");
    rows.push("windows-recursive-refusal");
  } else {
    const parentFd = fsSync.openSync(directory, fsSync.constants.O_RDONLY | fsSync.constants.O_DIRECTORY);
    try { assert.equal(binding.ownedTreeRemovalAvailable(parentFd), true, "POSIX qualification requires actual mount-bounded capability"); }
    finally { fsSync.closeSync(parentFd); }
    for (const order of ["filesystem", "sorted"]) {
      const rel = `tree-${order}`;
      await fs.mkdir(path.join(directory, rel, "nested"), { recursive: true });
      await fs.writeFile(path.join(directory, rel, "nested/value"), "inside");
      await fs.symlink(outside, path.join(directory, rel, "outside-link"), linkType);
      await scoped.remove(rel, { recursive: true, order, maxEntries: 4, maxDepth: 2 });
      await absent(path.join(directory, rel));
      assert.equal(await fs.readFile(path.join(outside, "value"), "utf8"), "outside sentinel");
      rows.push(`recursive-${order}-preserves-outside`);
    }
  }

  await fs.mkdir(path.join(directory, "parent"));
  await fs.writeFile(path.join(directory, "parent/value"), "held inside");
  let swaps = 0;
  setHooks({ beforeRootFallbackMutation: async (operation) => {
    if (operation !== "remove" || swaps !== 0) return;
    await fs.rename(path.join(directory, "parent"), path.join(directory, "held"));
    await fs.symlink(outside, path.join(directory, "parent"), linkType);
    swaps++;
  } });
  try {
    await assert.rejects(scoped.remove("parent/value"), (error) => /^(path-mismatch|path-alias)$/u.test(error?.code));
  } finally { setHooks(); }
  assert.equal(swaps, 1, "parent replacement hook must have completed");
  assert.equal(await fs.readFile(path.join(outside, "value"), "utf8"), "outside sentinel");
  assert.equal(await fs.readFile(path.join(directory, "held/value"), "utf8"), "held inside");
  rows.push("deterministic-remove-parent-swap");
  assert.equal(hash(binary), expected.nativeSha256, "installed addon must remain unchanged");
  assert.equal(rows.length, process.platform === "win32" ? 7 : 8);
} finally {
  setHooks();
  configureFsSafeNative({ mode: "auto" });
  await fs.rm(top, { recursive: true, force: true });
}
console.log(JSON.stringify({ result: "PASS", node: process.version, platform: process.platform,
  arch: process.arch, mode: "require", packageVersion: manifest.version, apiPath, nativePath: binary,
  nativeSha256: expected.nativeSha256, cases: rows.length, rows, skipped: 0, cleanup: "complete" }));
