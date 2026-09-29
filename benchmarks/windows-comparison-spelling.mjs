import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import Module, { createRequire } from "node:module";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const WINDOWS_COMPARISON_FILTER = "windows-comparison-spelling";
const STUDY = "windows-comparison-spelling-v1";
const PREFIX = `Root.readAbsolute/${WINDOWS_COMPARISON_FILTER}/`;
const ROWS = ["exact", "namespace", "case-fold", "namespace-case-fold", "case-sibling-reject", "adjacent-reject"];
const DIRECTORY_KEYS = ["tree", "ordinaryRoot", "adjacentRoot", "sensitiveParent", "sensitiveRoot", "sensitiveSibling"];
const FILE_KEYS = ["ordinaryRoot", "adjacentRoot", "sensitiveRoot", "sensitiveSibling"];
const PAYLOAD = "fs-safe Windows comparison payload\n";
const CONTENT = {
  ordinaryRoot: PAYLOAD,
  adjacentRoot: "fs-safe Windows adjacent sentinel\n",
  sensitiveRoot: PAYLOAD,
  sensitiveSibling: "fs-safe Windows case-sensitive sibling sentinel\n",
};
const SOURCES = {
  baseline: { commit: "a1b8c9c1f499924d22799e50ec9b9861b4b67b08", tree: "fbd58c12c921a0d4248d76bf108b4e2127220e46" },
  candidate: { commit: "3befe9363c9173aa5b85f585cfd322461030b248", tree: "06bbff93f4efbe40aa4435226e1559c4013fb3e0" },
};
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const fileHash = (name) => sha256(fs.readFileSync(name));
const filePath = (fixture, key) => `${fixture.directories[key].path}\\payload.txt`;
const identity = (stat) => ({ dev: stat.dev.toString(), ino: stat.ino.toString() });
const sameIdentity = (left, right) => left.dev === right.dev && left.ino === right.ino;
const namespace = (name) => `\\\\?\\${name}`;

function keys(value, expected, label) {
  assert(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `${label} fields`);
}

function canonicalPath(value) {
  assert.equal(typeof value, "string");
  assert.match(value, /^[A-Za-z]:\\[^/]+[^\\]$/u, "Expected an ordinary drive-absolute path");
  assert(!value.includes("\0"));
  assert.equal(path.win32.normalize(value), value);
  assert.equal(fs.realpathSync.native(value), value, "Fixture paths must retain canonical spelling");
  return value;
}

function assertSeparate(left, right) {
  const a = left.toLowerCase();
  const b = right.toLowerCase();
  assert(a !== b && !a.startsWith(`${b}\\`) && !b.startsWith(`${a}\\`), "Fixture/evidence/consumer paths overlap");
}

function checkIdentity(stat, expected) {
  for (const field of ["dev", "ino"]) {
    assert.match(expected[field], /^[1-9][0-9]*$/u, `Invalid expected ${field}`);
    assert.equal(typeof stat[field], "bigint");
    assert(stat[field] > 0n, `Unknown observed ${field}`);
    assert.equal(stat[field].toString(), expected[field]);
  }
}

function checkFixture(fixture) {
  const directories = fixture.directories;
  const observed = [];
  for (const key of DIRECTORY_KEYS) {
    const expected = directories[key];
    keys(expected, ["path", "dev", "ino"], `directory ${key}`);
    canonicalPath(expected.path);
    const stat = fs.lstatSync(expected.path, { bigint: true });
    assert(stat.isDirectory() && !stat.isSymbolicLink());
    checkIdentity(stat, expected);
    assert(!observed.some((prior) => sameIdentity(prior, expected)), "Fixture directories must be distinct objects");
    observed.push(expected);
    const children = key === "tree" ? ["Root", "Root-other", "sensitive"]
      : key === "sensitiveParent" ? ["Root", "root"] : ["payload.txt"];
    assert.deepEqual(fs.readdirSync(expected.path).sort(), children.sort());
  }
  const observedFiles = [];
  for (const key of FILE_KEYS) {
    const expected = fixture.files[key];
    keys(expected, ["dev", "ino", "sha256"], `file ${key}`);
    const name = filePath(fixture, key);
    canonicalPath(name);
    const stat = fs.lstatSync(name, { bigint: true });
    assert(stat.isFile() && !stat.isSymbolicLink());
    assert.equal(stat.nlink, 1n);
    checkIdentity(stat, expected);
    assert(!observedFiles.some((prior) => sameIdentity(prior, expected)), "Fixture files must be distinct objects");
    observedFiles.push(expected);
    assert.equal(stat.size, BigInt(Buffer.byteLength(CONTENT[key])));
    const bytes = fs.readFileSync(name);
    assert.deepEqual(bytes, Buffer.from(CONTENT[key]));
    assert.equal(sha256(bytes), expected.sha256);
  }
  const alias = `${directories.tree.path}\\root`;
  const aliasStat = fs.lstatSync(alias, { bigint: true });
  assert(aliasStat.isDirectory() && !aliasStat.isSymbolicLink());
  checkIdentity(aliasStat, directories.ordinaryRoot);
  const aliasFile = fs.lstatSync(`${alias}\\payload.txt`, { bigint: true });
  assert(aliasFile.isFile() && aliasFile.nlink === 1n);
  checkIdentity(aliasFile, fixture.files.ordinaryRoot);
  assert.deepEqual(fs.readFileSync(`${alias}\\payload.txt`), Buffer.from(PAYLOAD));
}

function readFixture(inputPath, dist, packageRoot) {
  canonicalPath(inputPath);
  const bytes = fs.readFileSync(inputPath);
  const fixture = JSON.parse(bytes);
  keys(fixture, ["schemaVersion", "study", "node", "directories", "files", "admission"], "fixture input");
  assert.equal(fixture.schemaVersion, 1);
  assert.equal(fixture.study, STUDY);
  keys(fixture.node, ["version", "platform", "arch", "executableSha256"], "fixture runtime");
  assert.equal(fixture.node.version, "v24.21.0");
  assert.equal(process.version, fixture.node.version);
  assert.equal(fixture.node.platform, "win32");
  assert.equal(process.platform, fixture.node.platform);
  assert.equal(fixture.node.arch, "x64");
  assert.equal(process.arch, fixture.node.arch);
  assert.match(fixture.node.executableSha256, /^[a-f0-9]{64}$/u);
  assert.equal(fileHash(process.execPath), fixture.node.executableSha256);
  keys(fixture.directories, DIRECTORY_KEYS, "directories");
  keys(fixture.files, FILE_KEYS, "files");
  keys(fixture.admission, ["receiptPath", "sha256"], "admission");
  const tree = fixture.directories.tree.path;
  const layout = {
    ordinaryRoot: `${tree}\\Root`, adjacentRoot: `${tree}\\Root-other`,
    sensitiveParent: `${tree}\\sensitive`, sensitiveRoot: `${tree}\\sensitive\\Root`,
    sensitiveSibling: `${tree}\\sensitive\\root`,
  };
  for (const [key, name] of Object.entries(layout)) assert.equal(fixture.directories[key].path, name);
  const installedRoot = path.dirname(dist);
  const scope = path.dirname(installedRoot);
  assert.equal(path.basename(dist), "dist");
  assert.equal(path.basename(installedRoot), "fs-safe");
  assert.equal(path.basename(scope), "@openclaw");
  assert.equal(path.basename(path.dirname(scope)), "node_modules", "Use an installed public package");
  const consumer = path.dirname(path.dirname(scope));
  canonicalPath(installedRoot);
  canonicalPath(dist);
  const entry = createRequire(pathToFileURL(`${consumer}\\package.json`)).resolve("@openclaw/fs-safe");
  assert.equal(fs.realpathSync.native(path.dirname(entry)), fs.realpathSync.native(dist));
  const installedManifest = JSON.parse(fs.readFileSync(`${installedRoot}\\package.json`, "utf8"));
  assert.equal(installedManifest.name, "@openclaw/fs-safe");
  const receiptPath = canonicalPath(fixture.admission.receiptPath);
  for (const evidence of [inputPath, receiptPath]) {
    assertSeparate(tree, evidence);
    assertSeparate(consumer, evidence);
    assertSeparate(packageRoot, evidence);
  }
  assertSeparate(tree, consumer);
  assertSeparate(tree, packageRoot);
  assert.match(fixture.admission.sha256, /^[a-f0-9]{64}$/u);
  const receiptBytes = fs.readFileSync(receiptPath);
  assert.equal(sha256(receiptBytes), fixture.admission.sha256);
  const receipt = JSON.parse(receiptBytes);
  for (const [key, expected] of Object.entries({
    schemaVersion: 1, study: STUDY, result: "pass", filesystem: "NTFS",
    privateWindowsAcl: true, ordinaryCaseSensitive: false, sensitiveCaseSensitive: true,
    node: fixture.node, directories: fixture.directories, files: fixture.files,
  })) assert.deepEqual(receipt[key], expected, `Admission receipt ${key}`);
  checkFixture(fixture);
  return { fixture, inputHash: sha256(bytes), installedRoot, installedManifest, consumer };
}

function observeAddonAttempts(attempts) {
  const descriptors = [[Module, "_load"], [process, "dlopen"]].map(([owner, name]) => [owner, name, Object.getOwnPropertyDescriptor(owner, name)]);
  assert.equal(Object.values(createRequire(import.meta.url).cache).filter((entry) => entry?.filename.endsWith(".node")).length, 0);
  for (const [owner, name, descriptor] of descriptors) {
    assert.equal(typeof descriptor?.value, "function");
    Object.defineProperty(owner, name, { ...descriptor, value: function (...args) {
      const request = name === "_load" ? args[0] : args[1];
      if (name === "dlopen" || (typeof request === "string" &&
        (/\.node$/u.test(request) || /^@openclaw\/fs-safe-(?:linux|darwin|win32)-/u.test(request)))) {
        attempts.push({ loader: name, request });
      }
      return Reflect.apply(descriptor.value, this, args);
    } });
  }
  return () => {
    for (const [owner, name, descriptor] of descriptors) Object.defineProperty(owner, name, descriptor);
  };
}

function errorShape(error) {
  return { name: error?.name, code: error?.code, cause: error?.cause === undefined ? "undefined" : "present" };
}

async function routeWitness(run, verify, expected, moduleURL, onObserved) {
  const raw = [];
  const descriptors = [[path.win32, "normalize"], [fs, "lstatSync"]].map(([owner, name]) => [owner, name, Object.getOwnPropertyDescriptor(owner, name)]);
  const escaped = moduleURL.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  const origin = new RegExp(`(?:^|[ (])${escaped}:\\d+:\\d+(?:\\)|$)`, "mu");
  let output;
  let rejected = false;
  try {
    for (const [owner, name, descriptor] of descriptors) {
      assert.equal(typeof descriptor?.value, "function");
      Object.defineProperty(owner, name, { ...descriptor, value: function (...args) {
        const stack = new Error().stack;
        const event = origin.test(stack ?? "") ? { operation: name, args, stack, threw: false } : undefined;
        try {
          const value = Reflect.apply(descriptor.value, this, args);
          if (event) event.value = value;
          return value;
        } catch (error) {
          if (event) { event.threw = true; event.error = error; }
          throw error;
        } finally {
          if (event) raw.push(event);
        }
      } });
    }
    try { output = await run(); } catch (error) { output = error; rejected = true; }
  } finally {
    for (const [owner, name, descriptor] of descriptors) Object.defineProperty(owner, name, descriptor);
  }
  for (const [owner, name, descriptor] of descriptors) {
    assert.deepEqual(Object.getOwnPropertyDescriptor(owner, name), descriptor, "Witness descriptor restoration failed");
  }
  const events = raw.map((event) => ({
    operation: event.operation, input: event.args[0], module: moduleURL,
    bigint: event.operation === "lstatSync" ? event.args[1]?.bigint === true : undefined,
    outcome: event.threw ? "throw" : "return",
    result: event.threw ? errorShape(event.error)
      : event.operation === "normalize" ? event.value
        : { ...identity(event.value), devType: typeof event.value.dev, inoType: typeof event.value.ino, directory: event.value.isDirectory(), symlink: event.value.isSymbolicLink() },
    stack: event.stack,
  }));
  const receipt = {
    module: moduleURL, input: expected.input, trustedRoot: expected.root,
    outcome: rejected ? errorShape(output) : {
      bytes: output?.buffer?.length,
      sha256: Buffer.isBuffer(output?.buffer) ? sha256(output.buffer) : undefined,
      realPath: output?.realPath,
    },
    descriptorsRestoredBeforeWarmup: true,
    events,
    signature: events.map(({ stack: _stack, module: _module, ...event }) => event),
  };
  onObserved(receipt);
  verify(output);
  assert.equal(rejected, expected.rejected);
  if (!expected.slow) assert.deepEqual(events, [], "Exact prefix unexpectedly entered slow comparison");
  else assert(events.some((event) => event.operation === "normalize" && event.input === expected.root && event.result === expected.root), "Missing real slow-comparison normalization");
  const observations = events.filter((event) => event.operation === "lstatSync");
  if (expected.identity) {
    assert(observations.length > 0, "Missing case-fold directory identity observation");
    for (const event of observations) {
      assert.equal(event.input, expected.prefix, "Candidate Root prefix spelling changed");
      assert.equal(event.outcome, "return");
      assert.equal(event.bigint, true);
      assert.equal(event.result.devType, "bigint");
      assert.equal(event.result.inoType, "bigint");
      assert.equal(event.result.directory, true);
      assert.equal(event.result.symlink, false);
      assert.deepEqual({ dev: event.result.dev, ino: event.result.ino }, identity(expected.identity));
    }
  } else assert.deepEqual(observations, [], "Unexpected boundary identity observation");
  return receipt;
}

export function prepareWindowsComparisonStudy({ args, dist, packageRoot, manifest, measuredSource }) {
  if (args.filter !== WINDOWS_COMPARISON_FILTER) {
    assert.equal(args["windows-comparison-fixture"], undefined, "Shared Windows fixture requires its exact filter");
    assert(!args.filter?.includes(WINDOWS_COMPARISON_FILTER), "Select the complete six-row Windows filter");
    return undefined;
  }
  assert.equal(args.mode, "off");
  assert.equal(args.iterations, 20);
  assert.equal(args.samples, 5);
  assert.equal(args.warmup, 10);
  assert.equal(process.platform, "win32");
  assert.equal(process.arch, "x64");
  assert.equal(process.version, "v24.21.0");
  assert.equal(typeof args.json, "string");
  assert.equal(typeof args["windows-comparison-fixture"], "string");
  const source = SOURCES[measuredSource?.sourceRole];
  assert(source, "Supply the existing complete measured-source argument set");
  assert.equal(measuredSource.sourceCommit, source.commit);
  assert.equal(measuredSource.sourceTree, source.tree);
  const inputPath = path.resolve(args["windows-comparison-fixture"]);
  const { fixture, inputHash, installedRoot, installedManifest, consumer } = readFixture(inputPath, dist, packageRoot);
  assert.deepEqual(installedManifest.exports, manifest.exports);
  const reportPath = path.resolve(args.json);
  const journalPath = `${reportPath}.journal.jsonl`;
  for (const output of [reportPath, journalPath]) {
    assert(!fs.existsSync(output), "Report and journal must be new files");
    assertSeparate(fixture.directories.tree.path, output);
    assertSeparate(consumer, output);
    assertSeparate(packageRoot, output);
    assert.notEqual(output.toLowerCase(), inputPath.toLowerCase());
    assert.notEqual(output.toLowerCase(), fixture.admission.receiptPath.toLowerCase());
    canonicalPath(path.dirname(output));
  }
  const moduleURL = pathToFileURL(fs.realpathSync.native(`${dist}\\root-boundary.js`)).href;
  const journalFd = fs.openSync(journalPath, "wx", 0o600);
  const attempts = [];
  const restoreLoaders = observeAddonAttempts(attempts);
  const records = new Map();
  let closed = false;
  let previousEnd = -Infinity;
  const metadata = {
    schemaVersion: 1, study: STUDY, fixtureInputSha256: inputHash,
    admissionReceiptSha256: fixture.admission.sha256, node: fixture.node,
    rootBoundaryModule: moduleURL, rootBoundarySha256: fileHash(`${dist}\\root-boundary.js`),
    installedPackageSha256: fileHash(`${installedRoot}\\package.json`),
    addonObservationScope: "before-public-package-imports-through-runner-cleanup",
    addonLoadAttempts: attempts, journalPath,
  };
  const append = (record) => {
    const line = `${JSON.stringify(record)}\n`;
    assert.equal(fs.writeSync(journalFd, line), Buffer.byteLength(line), "Incomplete journal write");
  };
  const row = (name) => {
    assert(ROWS.map((id) => `${PREFIX}${id}`).includes(name));
    if (!records.has(name)) records.set(name, { warmups: 0, checked: 0, witness: 0, calls: [], sums: Array(5).fill(0) });
    return records.get(name);
  };
  const finish = (result) => {
    if (closed) return;
    try { append({ type: "finish", result, addonLoadAttempts: attempts }); }
    finally {
      closed = true;
      restoreLoaders();
      fs.closeSync(journalFd);
      process.removeListener("exit", onExit);
    }
  };
  const onExit = (code) => finish(`incomplete-exit-${code}`);
  process.once("exit", onExit);
  append({ type: "start", metadata, measuredSource });
  return {
    metadata,
    async register({ api, register }) {
      const ordinary = await api.root(fixture.directories.ordinaryRoot.path);
      const sensitive = await api.root(fixture.directories.sensitiveRoot.path);
      for (const [root, expected] of [[ordinary, fixture.directories.ordinaryRoot], [sensitive, fixture.directories.sensitiveRoot]]) {
        assert.equal(root.rootDir, expected.path);
        assert.equal(root.rootReal, expected.path);
      }
      const ordinaryPath = fixture.directories.ordinaryRoot.path;
      const alternate = `${fixture.directories.tree.path}\\root`;
      const sensitivePath = fixture.directories.sensitiveRoot.path;
      const sibling = fixture.directories.sensitiveSibling.path;
      const cases = [
        { id: "exact", root: ordinaryPath, prefix: ordinaryPath, slow: false },
        { id: "namespace", root: ordinaryPath, prefix: namespace(ordinaryPath), slow: true },
        { id: "case-fold", root: ordinaryPath, prefix: alternate, slow: true, identity: fixture.directories.ordinaryRoot },
        { id: "namespace-case-fold", root: ordinaryPath, prefix: namespace(alternate), slow: true, identity: fixture.directories.ordinaryRoot },
        { id: "case-sibling-reject", root: sensitivePath, prefix: sibling, slow: true, identity: fixture.directories.sensitiveSibling, rejected: true },
        { id: "adjacent-reject", root: ordinaryPath, prefix: fixture.directories.adjacentRoot.path, slow: true, rejected: true },
      ];
      for (const description of cases) {
        const expected = { ...description, rejected: Boolean(description.rejected), input: `${description.prefix}\\payload.txt` };
        const name = `${PREFIX}${expected.id}`;
        const root = expected.root === sensitivePath ? sensitive : ordinary;
        const run = () => root.readAbsolute(expected.input);
        const verify = (output) => {
          if (expected.rejected) {
            assert(output instanceof api.FsSafeError);
            assert.equal(output.code, "outside-workspace");
            assert.equal(output.cause, undefined);
          } else {
            assert.deepEqual(output.buffer, Buffer.from(PAYLOAD));
            assert.equal(output.realPath, `${ordinaryPath}\\payload.txt`);
          }
        };
        register(name, run, {
          expectError: expected.rejected, verify, after: verify,
          workloadSemantics: "complete-public-Root.readAbsolute-shared-Windows-fixture",
          workloadDetails: { study: STUDY, row: expected.id, nativeMode: "off", fixtureInputSha256: inputHash },
          witness: async () => {
            checkFixture(fixture);
            const receipt = await routeWitness(run, verify, expected, moduleURL,
              (observed) => append({ type: "witness-observed", row: name, receipt: observed }));
            checkFixture(fixture);
            assert.equal(attempts.length, 0, "Native-off attempted an addon load");
            row(name).witness += 1;
            append({ type: "witness", row: name, receipt, addonLoadAttempts: attempts.length });
            return receipt;
          },
        });
      }
    },
    recordPhase(name, phase, index) {
      const record = row(name);
      if (phase === "warmup") { assert.equal(index, record.warmups); record.warmups += 1; }
      else { assert.equal(phase, "checked"); record.checked += 1; }
      append({ type: phase, row: name, index });
    },
    recordTiming({ name, sample, iteration, start, elapsed, failed }) {
      const record = row(name);
      append({ type: "call", row: name, sample, iteration, startMs: start, elapsedMs: elapsed, failed });
      assert(Number.isFinite(start) && Number.isFinite(elapsed) && elapsed >= 0);
      assert(start >= previousEnd, "Timed calls overlap or are out of order");
      previousEnd = start + elapsed;
      assert.equal(record.calls.length, sample * 20 + iteration);
      record.calls.push({ sample, iteration, failed });
      record.sums[sample] += elapsed;
    },
    recordSample(name, sample, elapsed, mean) {
      assert.equal(row(name).sums[sample], elapsed);
      assert.equal(mean, elapsed * 1000 / 20);
      append({ type: "sample", row: name, sample, elapsedMs: elapsed, meanUs: mean });
    },
    validate(report) {
      assert.deepEqual(report.results.map(({ name }) => name), ROWS.map((id) => `${PREFIX}${id}`));
      assert.equal(report.metadata.native, false);
      assert.equal(report.metadata.nativeHash, null);
      assert.equal(attempts.length, 0, "Native-off attempted an addon load");
      for (const result of report.results) {
        const record = row(result.name);
        assert.equal(result.skipped, undefined);
        assert.equal(result.iterations, 20);
        assert.equal(record.witness, 1);
        assert.equal(record.warmups, 10);
        assert.equal(record.checked, 1);
        assert.equal(record.calls.length, 100);
        assert(record.calls.every(({ failed }) => failed === false));
        assert.deepEqual(result.samplesUs, record.sums.map((sum) => sum * 1000 / 20));
        assert.equal(result.routeWitness.descriptorsRestoredBeforeWarmup, true);
      }
      checkFixture(fixture);
      assert.equal(fileHash(inputPath), inputHash);
      assert.equal(fileHash(fixture.admission.receiptPath), fixture.admission.sha256);
      append({ type: "validated", rows: 6, calls: 600, addonLoadAttempts: 0 });
    },
    complete() { assert.equal(attempts.length, 0); finish("complete"); },
  };
}
