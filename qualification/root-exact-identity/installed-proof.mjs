import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

const [consumer, expectedFile, mode, runtimeKey, output, ...extra] = process.argv.slice(2);
assert.equal(extra.length, 0);
assert(["off", "require"].includes(mode));
assert.equal(process.platform, "linux"); assert.equal(process.arch, "x64");
assert.equal(process.env.NODE_ENV, "test");
const hash = file => createHash("sha256").update(fs.readFileSync(file)).digest("hex");
const expected = JSON.parse(fs.readFileSync(expectedFile, "utf8"));
assert.equal(hash(new URL(import.meta.url)), expected.probeSha256);
assert.equal(fs.realpathSync(consumer), expected.path);
assert.equal(fs.realpathSync(process.execPath), expected.runtimes[runtimeKey].path);
assert.equal(process.version, expected.runtimes[runtimeKey].version);
assert.equal(hash(process.execPath), expected.runtimes[runtimeKey].sha256);
const require = createRequire(path.join(consumer, "package.json"));
const packageRoot = fs.realpathSync(path.dirname(require.resolve("@openclaw/fs-safe/package.json")));
assert.equal(packageRoot, expected.packageRoot);
const inventory = JSON.parse(fs.readFileSync(expected.inventory.path, "utf8"));
function verifyBytes() {
  assert.equal(hash(expected.inventory.path), expected.inventory.sha256);
  assert.equal(hash(expected.lockfile.path), expected.lockfile.sha256);
  for (const [name, digest] of Object.entries(inventory)) assert.equal(hash(path.join(packageRoot, name)), digest);
  assert.equal(hash(expected.nativeAddon.path), expected.nativeAddon.sha256);
}
verifyBytes();
const resolved = {};
for (const name of ["root", "config", "errors", "test-hooks"]) {
  resolved[name] = fs.realpathSync(require.resolve("@openclaw/fs-safe/" + name));
  assert.equal(resolved[name], path.join(packageRoot, "dist", name + ".js"));
}
const attempts = [], loads = []; let observeCalls = 0, restoreNative;
const originalDlopen = process.dlopen;
process.dlopen = function (module, filename, ...args) {
  const attempt = { filenameType: typeof filename, succeeded: false };
  attempts.push(attempt);
  assert.notEqual(mode, "off", "native mode off attempted an addon load");
  const nativePath = fs.realpathSync(String(filename));
  attempt.path = nativePath;
  assert.equal(nativePath, expected.nativeAddon.path);
  const nativeDigest = hash(nativePath);
  assert.equal(nativeDigest, expected.nativeAddon.sha256);
  const result = Reflect.apply(originalDlopen, this, [module, filename, ...args]);
  attempt.succeeded = true;
  loads.push({ path: nativePath, sha256: nativeDigest });
  const descriptor = Object.getOwnPropertyDescriptor(module.exports, "observeDirectory");
  assert.equal(typeof descriptor?.value, "function");
  const original = descriptor.value;
  Object.defineProperty(module.exports, "observeDirectory", { ...descriptor, value: function (...values) {
    observeCalls += 1; return Reflect.apply(original, this, values);
  } });
  restoreNative = () => Object.defineProperty(module.exports, "observeDirectory", descriptor);
  return result;
};
let fixture, hooks, config;
const report = { schema: 1, study: "root-exact-identity-domain-v2", sourceRole: expected.sourceRole,
  sourceCommit: expected.sourceCommit, sourceTree: expected.sourceTree, mode, runtimeKey,
  runtime: expected.runtimes[runtimeKey], expectedSha256: hash(expectedFile), publicResolution: resolved,
  packageTarball: expected.packageTarball, addonTarball: expected.addonTarball,
  inventorySha256: expected.inventory.sha256, lockSha256: expected.lockfile.sha256,
  scenarios: [], nativeLoadAttempts: attempts, nativeLoads: loads, complete: false };
const census = () => fs.readdirSync("/proc/self/fd").length;
try {
  const api = await import(pathToFileURL(resolved.root));
  config = await import(pathToFileURL(resolved.config));
  hooks = await import(pathToFileURL(resolved["test-hooks"]));
  config.configureFsSafeNative({ mode });
  fixture = fs.mkdtempSync(path.join(path.dirname(output), "installed-root-"));
  fs.chmodSync(fixture, 0o700);
  const prime = path.join(fixture, "prime"); fs.mkdirSync(prime); fs.writeFileSync(path.join(prime, "file"), "prime");
  const primedRoot = await api.root(prime);
  assert.equal((await primedRoot.stat("file")).size, 5);
  assert.equal(attempts.length, mode === "require" ? 1 : 0);
  assert.equal(loads.length, mode === "require" ? 1 : 0);
  assert(attempts.every(attempt => attempt.succeeded));
  assert(mode === "require" ? observeCalls > 0 : observeCalls === 0);
  report.nativePreflight = { attempts: attempts.length, loads: loads.length, observeDirectoryCalls: observeCalls };
  report.fdBefore = census();
  for (const name of expected.scenarioNames) {
    const base = path.join(fixture, name), rootPath = path.join(base, "root"), outside = path.join(base, "outside");
    fs.mkdirSync(path.join(rootPath, "nested"), { recursive: true }); fs.mkdirSync(outside);
    fs.writeFileSync(path.join(rootPath, "nested", "alpha"), "alpha");
    fs.writeFileSync(path.join(rootPath, "nested", "beta"), "beta");
    fs.writeFileSync(path.join(outside, "sentinel"), "outside unchanged");
    const capability = await api.root(rootPath);
    const before = census(), nativeBefore = observeCalls;
    const row = { name, passed: false };
    try {
      if (name === "construction-and-resolve") {
        assert.equal(capability.rootDir, rootPath); assert.equal(capability.rootReal, rootPath);
        assert.equal(await capability.resolve("nested/alpha"), path.join(rootPath, "nested", "alpha"));
      } else if (name === "ordinary-stat") {
        const stat = await capability.stat("nested/alpha");
        assert.equal(stat.isFile, true); assert.equal(stat.isSymbolicLink, false); assert.equal(stat.size, 5);
        assert.equal(typeof stat.dev, "number"); assert.equal(typeof stat.ino, "number");
      } else if (name === "ordinary-list") {
        assert.deepEqual((await capability.list("nested")).sort(), ["alpha", "beta"]);
        const entries = await capability.list("nested", { withFileTypes: true });
        assert.deepEqual(entries.map(entry => entry.name).sort(), ["alpha", "beta"]);
        assert(entries.every(entry => entry.isFile && !entry.isSymbolicLink));
      } else if (name === "walk-skip" || name === "walk-include") {
        fs.symlinkSync(outside, path.join(rootPath, "outside-link"));
        const entries = [];
        for await (const entry of capability.walk("", { symlinkPolicy: name === "walk-skip" ? "skip" : "include" })) entries.push(entry);
        assert.deepEqual(entries.map(entry => entry.relativePath).sort(), name === "walk-skip"
          ? ["nested", "nested/alpha", "nested/beta"] : ["nested", "nested/alpha", "nested/beta", "outside-link"]);
        if (name === "walk-include") assert.equal(entries.find(entry => entry.relativePath === "outside-link").kind, "symlink");
      } else if (name === "initial-stat-hook") {
        let called = 0; hooks.__setFsSafeTestHooksForTest({ beforeRootStatInitialObservation() { called += 1; } });
        assert.equal((await capability.stat("nested/alpha")).size, 5); assert.equal(called, 1);
      } else if (name === "in-root-alias") {
        fs.symlinkSync(path.join(rootPath, "nested"), path.join(rootPath, "alias"));
        assert.equal((await capability.stat("alias/alpha")).size, 5);
        assert.deepEqual((await capability.list("alias")).sort(), ["alpha", "beta"]);
      } else if (name === "root-replacement") {
        fs.renameSync(rootPath, path.join(base, "retained-root")); fs.mkdirSync(rootPath);
        fs.writeFileSync(path.join(rootPath, "replacement"), "replacement unchanged");
        for (const operation of [() => capability.resolve("."), () => capability.stat("."), () => capability.list(".")]) {
          await assert.rejects(operation(), { code: "path-mismatch" });
        }
        assert.equal(fs.readFileSync(path.join(base, "retained-root/nested/alpha"), "utf8"), "alpha");
        assert.equal(fs.readFileSync(path.join(rootPath, "replacement"), "utf8"), "replacement unchanged");
      } else if (name === "parent-redirection") {
        let called = 0;
        hooks.__setFsSafeTestHooksForTest({ beforeRootStatObservation() {
          called += 1; fs.renameSync(path.join(rootPath, "nested"), path.join(rootPath, "retained-parent"));
          fs.symlinkSync(outside, path.join(rootPath, "nested"));
        } });
        await assert.rejects(capability.stat("nested/alpha"), { code: "path-mismatch" }); assert.equal(called, 1);
      } else throw new Error("unknown fixed scenario: " + name);
      if (mode === "require" && ["ordinary-stat", "ordinary-list"].includes(name)) assert(observeCalls > nativeBefore);
      if (mode === "off") assert.equal(observeCalls, 0);
      assert.equal(fs.readFileSync(path.join(outside, "sentinel"), "utf8"), "outside unchanged");
      row.passed = true;
    } finally {
      hooks.__setFsSafeTestHooksForTest();
      row.fdBefore = before; row.fdAfter = census(); row.observeDirectoryCalls = observeCalls - nativeBefore;
      row.hooksRestored = hooks.getFsSafeTestHooks() === undefined; report.scenarios.push(row);
      assert.equal(row.fdAfter, before); assert(row.hooksRestored);
      fs.rmSync(base, { recursive: true, force: true });
    }
  }
  report.fdAfter = census(); assert.equal(report.fdAfter, report.fdBefore);
  assert.equal(attempts.length, mode === "require" ? 1 : 0);
  assert.equal(loads.length, mode === "require" ? 1 : 0);
  assert(attempts.every(attempt => attempt.succeeded));
  verifyBytes(); report.complete = true;
} catch (error) {
  report.failure = { name: error?.name, message: String(error?.message ?? error) }; process.exitCode = 1;
} finally {
  hooks?.__setFsSafeTestHooksForTest(); restoreNative?.(); process.dlopen = originalDlopen;
  if (fixture) fs.rmSync(fixture, { recursive: true, force: true });
  report.fixtureRemoved = !fixture || !fs.existsSync(fixture); report.loaderRestored = process.dlopen === originalDlopen;
  report.observeDirectoryCalls = observeCalls;
  fs.writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  console.log(JSON.stringify(report));
}
