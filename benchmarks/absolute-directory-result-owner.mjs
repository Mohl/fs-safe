// Registration only; use the existing method runner's before/run/after timing owner.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const ABSOLUTE_RESULT_PREFIX = "ensureAbsoluteDirectory/result-owner/";
export const ABSOLUTE_RESULT_ROWS = [
  "existing-depth1", "existing-depth8", "missing-depth1", "missing-depth8",
  "early-policy", "late-guard-policy", "ordinary-rejection",
].map(name => ABSOLUTE_RESULT_PREFIX + name);

export function registerAbsoluteDirectoryResultOwner({ api, workspace, register, onCleanup }) {
  assert.equal(process.platform, "linux", "This fixed study is Linux-only");
  const affinity = /^Cpus_allowed_list:\s*(.+)$/m.exec(fs.readFileSync("/proc/self/status", "utf8"))?.[1].trim();
  const fixtureStat = fs.statSync(workspace, { bigint: true });
  assert.equal(os.cpus().length, 16);
  assert.equal(affinity, process.env.FS_SAFE_ABSOLUTE_RESULT_CPU);
  assert.equal(fixtureStat.dev.toString(), process.env.FS_SAFE_ABSOLUTE_RESULT_DEVICE);
  assert.equal(Number(fixtureStat.mode) & 0o777, 0o700);
  assert.equal(workspace.length, Number(process.env.FS_SAFE_ABSOLUTE_RESULT_PATH_LENGTH));
  assert.equal(workspace.split(path.sep).length, Number(process.env.FS_SAFE_ABSOLUTE_RESULT_PATH_DEPTH));
  fs.writeSync(2, JSON.stringify({ absoluteResultPreflight: true, affinity, cpus: os.cpus().length,
    device: fixtureStat.dev.toString(), workspaceLength: workspace.length,
    workspaceDepth: workspace.split(path.sep).length, pid: process.pid, execPath: process.execPath }) + "\n");
  const base = fs.mkdtempSync(path.join(workspace, "absolute-result-"));
  const realLstat = fs.lstatSync;
  const identity = file => {
    const stat = realLstat(file, { bigint: true });
    assert(stat.isDirectory() && !stat.isSymbolicLink());
    return [stat.dev, stat.ino];
  };
  const baseIdentity = identity(base);
  onCleanup(() => {
    fs.lstatSync = realLstat;
    assert.deepEqual(identity(base), baseIdentity);
    fs.rmSync(base, { recursive: true, force: true });
  });
  const options = { scopeLabel: "result-owner study", mode: 0o700 };
  const registerRow = (suffix, run, fields) => register(ABSOLUTE_RESULT_PREFIX + suffix, run, {
    workloadSemantics: "Complete awaited public ensureAbsoluteDirectory; validation and reset are outside timing",
    workloadDetails: { protocol: "absolute-directory-result-owner-v1", workload: suffix, nativeMode: "off" },
    ...fields,
  });
  for (const state of ["existing", "missing"]) {
    for (const depth of [1, 8]) {
      const parent = path.join(base, `${state}-${depth}`);
      fs.mkdirSync(parent, { mode: 0o700 });
      const rootIdentity = identity(parent);
      const paths = Array.from({ length: depth }, (_, index) =>
        path.join(parent, ...Array.from({ length: index + 1 }, (_, i) => `level-${i}`)));
      const target = paths.at(-1);
      if (state === "existing") fs.mkdirSync(target, { recursive: true, mode: 0o700 });
      const expectedIdentities = state === "existing" ? paths.map(identity) : null;
      registerRow(`${state}-depth${depth}`, () => api.ensureAbsoluteDirectory(target, options), {
        before() {
          assert.deepEqual(identity(parent), rootIdentity);
          if (state === "existing") assert.deepEqual(paths.map(identity), expectedIdentities);
          else assert.equal(fs.existsSync(paths[0]), false);
        },
        after(result) {
          try {
            assert.deepEqual(result, { ok: true, path: target });
            assert.deepEqual(identity(parent), rootIdentity);
            for (const part of paths) {
              const stat = realLstat(part);
              assert(stat.isDirectory() && !stat.isSymbolicLink());
              assert.equal(Number(stat.mode) & 0o777, 0o700);
            }
            if (expectedIdentities) assert.deepEqual(paths.map(identity), expectedIdentities);
          } finally {
            if (state === "missing") fs.rmSync(paths[0], { recursive: true, force: true });
          }
          if (state === "missing") assert.equal(fs.existsSync(paths[0]), false);
        },
      });
    }
  }
  const policyFile = path.join(base, "policy-file");
  fs.writeFileSync(policyFile, "unchanged", { mode: 0o600 });
  const policyIdentity = realLstat(policyFile, { bigint: true });
  registerRow("early-policy", () => api.ensureAbsoluteDirectory(path.join(policyFile, "child"), options), {
    after(result) {
      assert.equal(result.ok, false);
      assert.equal(result.code, "not-file");
      assert(result.error instanceof api.FsSafeError);
      assert.equal(result.error.cause, undefined);
      const current = realLstat(policyFile, { bigint: true });
      assert.deepEqual([current.dev, current.ino], [policyIdentity.dev, policyIdentity.ino]);
      assert.equal(fs.readFileSync(policyFile, "utf8"), "unchanged");
    },
  });
  const lateTarget = path.join(base, "late-target");
  const lateSpare = path.join(base, "late-spare");
  const lateRetained = path.join(base, "late-retained");
  fs.mkdirSync(lateTarget, { mode: 0o700 });
  fs.mkdirSync(lateSpare, { mode: 0o700 });
  const targetIdentity = identity(lateTarget), spareIdentity = identity(lateSpare);
  let targetReads = 0;
  let movedOriginal = false;
  let movedSpare = false;
  registerRow("late-guard-policy", () => api.ensureAbsoluteDirectory(lateTarget, options), {
    before() {
      assert.equal(fs.lstatSync, realLstat);
      assert.deepEqual(identity(lateTarget), targetIdentity);
      assert.deepEqual(identity(lateSpare), spareIdentity);
      assert.equal(fs.existsSync(lateRetained), false);
      targetReads = 0; movedOriginal = false; movedSpare = false;
      // Prefix and acquisition inspect the real original directory. Swap exactly
      // when the final guard asks for it, then return its real replacement stat.
      fs.lstatSync = function (file, ...args) {
        if (String(file) === lateTarget && ++targetReads === 3) {
          fs.renameSync(lateTarget, lateRetained); movedOriginal = true;
          fs.renameSync(lateSpare, lateTarget); movedSpare = true;
        }
        return realLstat.call(this, file, ...args);
      };
    },
    after(result) {
      fs.lstatSync = realLstat;
      try {
        assert.equal(targetReads, 3);
        assert(movedOriginal && movedSpare);
        assert.equal(result.ok, false);
        assert.equal(result.code, "path-mismatch");
        assert(result.error instanceof api.FsSafeError);
        assert.deepEqual(identity(lateRetained), targetIdentity);
        assert.deepEqual(identity(lateTarget), spareIdentity);
      } finally {
        if (movedSpare) fs.renameSync(lateTarget, lateSpare);
        if (movedOriginal) fs.renameSync(lateRetained, lateTarget);
      }
      assert.deepEqual(identity(lateTarget), targetIdentity);
      assert.deepEqual(identity(lateSpare), spareIdentity);
      assert.equal(fs.existsSync(lateRetained), false);
    },
  });
  const denied = path.join(base, "denied");
  const refusal = Object.assign(new Error("synthetic operation denied"), { code: "EACCES" });
  let modeReads = 0;
  const refusalOptions = {
    scopeLabel: "result-owner study",
    get mode() { modeReads += 1; throw refusal; },
  };
  registerRow("ordinary-rejection", () => api.ensureAbsoluteDirectory(denied, refusalOptions), {
    expectError: true,
    before() { modeReads = 0; assert.equal(fs.existsSync(denied), false); },
    after(error) {
      assert.equal(error, refusal);
      assert.equal(modeReads, 1);
      assert.equal(fs.existsSync(denied), false);
    },
  });
}
