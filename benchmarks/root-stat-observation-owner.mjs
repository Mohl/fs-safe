// Registration only; the existing runner owns timing and invocation settlement.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const ROOT_STAT_OBSERVATION_PREFIX = "Root.stat/observation-owner/";
const routes = ["receipt", "fallback"];
const workloads = ["direct-file", "depth8-file", "admitted-missing", "admitted-changed"];
export const ROOT_STAT_OBSERVATION_ROWS = routes.flatMap(route =>
  workloads.map(workload => `${ROOT_STAT_OBSERVATION_PREFIX}${route}/${workload}`));

export async function registerRootStatObservationOwner({ api, workspace, register, onCleanup }) {
  assert.equal(process.platform, "linux", "This fixed study is Linux-only");
  assert.equal(process.env.NODE_ENV, "test");
  assert.equal(typeof api.__setFsSafeTestHooksForTest, "function");
  assert.equal(typeof api.getFsSafeTestHooks, "function");
  assert.equal(api.getFsSafeTestHooks(), undefined);
  const affinity = /^Cpus_allowed_list:\s*(.+)$/m.exec(fs.readFileSync("/proc/self/status", "utf8"))?.[1].trim();
  const fixtureStat = fs.statSync(workspace, { bigint: true });
  assert.equal(os.cpus().length, 16);
  assert.equal(affinity, process.env.FS_SAFE_ROOT_STAT_CPU);
  assert.equal(fixtureStat.dev.toString(), process.env.FS_SAFE_ROOT_STAT_DEVICE);
  assert.equal(Number(fixtureStat.mode) & 0o777, 0o700);
  assert.equal(workspace.length, Number(process.env.FS_SAFE_ROOT_STAT_PATH_LENGTH));
  assert.equal(workspace.split(path.sep).length, Number(process.env.FS_SAFE_ROOT_STAT_PATH_DEPTH));
  const base = fs.mkdtempSync(path.join(workspace, "root-stat-"));
  const realLstat = fs.lstatSync;
  const setHooks = api.__setFsSafeTestHooksForTest;
  const exact = file => realLstat(file, { bigint: true });
  const identity = file => {
    const stat = exact(file);
    assert(!stat.isSymbolicLink());
    assert(stat.dev >= 0n && stat.ino > 0n);
    assert(stat.dev <= BigInt(Number.MAX_SAFE_INTEGER) && stat.ino <= BigInt(Number.MAX_SAFE_INTEGER),
      "This receipt workload requires genuine safe numeric filesystem IDs");
    return [stat.dev, stat.ino];
  };
  const baseIdentity = identity(base);
  onCleanup(() => {
    setHooks();
    fs.lstatSync = realLstat;
    assert.deepEqual(identity(base), baseIdentity);
    fs.rmSync(base, { recursive: true, force: true });
  });
  const routeWitnesses = [];
  for (const route of routes) {
    for (const workload of workloads) {
      const suffix = `${route}/${workload}`;
      const directory = path.join(base, `${route}-${workload}`);
      fs.mkdirSync(directory, { mode: 0o700 });
      const directories = [directory];
      if (workload === "depth8-file") {
        for (let i = 0; i < 8; i++) {
          const child = path.join(directories.at(-1), `level-${i}`);
          fs.mkdirSync(child, { mode: 0o700 });
          directories.push(child);
        }
      }
      const target = path.join(directories.at(-1), "value");
      const relative = path.relative(directory, target);
      const retained = `${target}.retained`, spare = `${target}.spare`;
      const originalText = "original root stat payload";
      const replacementText = "replacement root stat payload";
      fs.writeFileSync(target, originalText, { mode: 0o600, flag: "wx" });
      fs.utimesSync(target, 1_700_000_000, 1_700_000_000);
      const changing = workload === "admitted-changed";
      const failing = workload === "admitted-missing" || changing;
      if (changing) fs.writeFileSync(spare, replacementText, { mode: 0o600, flag: "wx" });
      const originalIdentity = identity(target);
      const spareIdentity = changing ? identity(spare) : undefined;
      if (changing) assert.notDeepEqual(spareIdentity, originalIdentity);
      const directoryIdentities = directories.map(identity);
      const stat = exact(target);
      assert(stat.isFile() && stat.nlink === 1n);
      const expected = {
        dev: Number(stat.dev), gid: Number(stat.gid), ino: Number(stat.ino),
        isDirectory: false, isFile: true, isSymbolicLink: false,
        mode: Number(stat.mode), mtimeMs: 1_700_000_000_000,
        nlink: 1, size: Buffer.byteLength(originalText), uid: Number(stat.uid),
      };
      const capability = await api.root(directory);
      // Observe the real selected route once outside measurement. Stable receipt
      // samples below have no hooks or filesystem wrappers installed.
      let phase = "resolution", initialCalls = 0, finalCalls = 0;
      const events = [];
      const witnessHooks = {
        ...(route === "fallback" ? { beforeRootStatInitialObservation(file) {
          assert.equal(file, target); initialCalls += 1; phase = "initial";
          events.push({ event: "initial-hook" });
        } } : {}),
        beforeRootStatObservation(file) {
          assert.equal(file, target); finalCalls += 1; phase = "final";
          events.push({ event: "final-hook" });
        },
      };
      try {
        setHooks(witnessHooks);
        assert.equal(api.getFsSafeTestHooks(), witnessHooks);
        fs.lstatSync = function (file, ...args) {
          const observed = realLstat.call(this, file, ...args);
          if (String(file) === target) events.push({ event: "target-lstat", phase,
            bigint: args[0]?.bigint === true, dev: String(observed.dev), ino: String(observed.ino) });
          return observed;
        };
        assert.deepEqual(await capability.stat(relative), expected);
      } finally {
        fs.lstatSync = realLstat;
        setHooks();
      }
      assert.equal(initialCalls, route === "fallback" ? 1 : 0);
      assert.equal(finalCalls, 1);
      const finalReads = events.filter(event => event.event === "target-lstat" && event.phase === "final");
      assert.equal(finalReads.length, 1);
      assert.equal(finalReads[0].bigint, route === "fallback");
      assert.deepEqual([finalReads[0].dev, finalReads[0].ino], originalIdentity.map(String));
      const initialReads = events.filter(event => event.event === "target-lstat" && event.phase === "initial");
      if (route === "fallback") {
        assert.equal(initialReads.length, 1);
        assert.equal(initialReads[0].bigint, true);
      } else {
        assert.equal(initialReads.length, 0);
        const resolutionReads = events.filter(event => event.event === "target-lstat" && event.phase === "resolution");
        assert.equal(resolutionReads.length, 1);
        assert.equal(resolutionReads[0].bigint, false);
      }
      routeWitnesses.push({ row: ROOT_STAT_OBSERVATION_PREFIX + suffix, route, initialCalls, finalCalls, events });
      let movedOriginal = false, movedSpare = false;
      const hooks = route === "receipt" && !failing ? undefined : {
        ...(route === "fallback" ? { beforeRootStatInitialObservation() { initialCalls += 1; } } : {}),
        ...(failing ? { beforeRootStatObservation(file) {
          assert.equal(file, target); finalCalls += 1;
          assert.equal(finalCalls, 1);
          fs.renameSync(target, retained); movedOriginal = true;
          if (changing) { fs.renameSync(spare, target); movedSpare = true; }
        } } : {}),
      };
      register(ROOT_STAT_OBSERVATION_PREFIX + suffix, () => capability.stat(relative), {
        expectError: failing,
        workloadSemantics: "Complete awaited public Root.stat; forced-route hook and failure mutations are inside timing; checks and restoration are outside",
        workloadDetails: { protocol: "root-stat-observation-owner-v1", workload, route, nativeMode: "off" },
        before() {
          assert.equal(fs.lstatSync, realLstat);
          assert.equal(api.getFsSafeTestHooks(), undefined);
          assert.deepEqual(directories.map(identity), directoryIdentities);
          assert.deepEqual(identity(target), originalIdentity);
          assert.equal(fs.readFileSync(target, "utf8"), originalText);
          assert.equal(fs.existsSync(retained), false);
          if (changing) {
            assert.deepEqual(identity(spare), spareIdentity);
            assert.equal(fs.readFileSync(spare, "utf8"), replacementText);
          }
          initialCalls = 0; finalCalls = 0; movedOriginal = false; movedSpare = false;
          setHooks(hooks);
          assert.equal(api.getFsSafeTestHooks(), hooks);
        },
        after(result) {
          setHooks();
          try {
            assert.equal(initialCalls, route === "fallback" ? 1 : 0);
            assert.equal(finalCalls, failing ? 1 : 0);
            assert.deepEqual(directories.map(identity), directoryIdentities);
            if (failing) {
              assert(result instanceof api.FsSafeError);
              assert.equal(result.code, "path-mismatch");
              assert(movedOriginal);
              assert.deepEqual(identity(retained), originalIdentity);
              assert.equal(fs.readFileSync(retained, "utf8"), originalText);
              if (changing) {
                assert(movedSpare);
                assert.equal(result.cause, undefined);
                assert.deepEqual(identity(target), spareIdentity);
                assert.equal(fs.readFileSync(target, "utf8"), replacementText);
              } else {
                assert.equal(result.cause?.code, "ENOENT");
                assert.equal(fs.existsSync(target), false);
              }
            } else {
              assert.deepEqual(result, expected);
              assert.deepEqual(identity(target), originalIdentity);
              assert.equal(fs.readFileSync(target, "utf8"), originalText);
            }
          } finally {
            if (movedSpare) fs.renameSync(target, spare);
            if (movedOriginal) fs.renameSync(retained, target);
          }
          assert.deepEqual(identity(target), originalIdentity);
          if (changing) assert.deepEqual(identity(spare), spareIdentity);
          assert.equal(fs.existsSync(retained), false);
          assert.equal(api.getFsSafeTestHooks(), undefined);
        },
      });
    }
  }
  assert.equal(fs.lstatSync, realLstat);
  assert.equal(api.getFsSafeTestHooks(), undefined);
  fs.writeSync(2, JSON.stringify({ rootStatObservationPreflight: true, affinity, cpus: os.cpus().length,
    device: fixtureStat.dev.toString(), workspaceLength: workspace.length,
    workspaceDepth: workspace.split(path.sep).length, pid: process.pid, execPath: process.execPath,
    safeNumericIdentities: true, routeWitnesses }) + "\n");
}
