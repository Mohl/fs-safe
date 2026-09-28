import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { configureFsSafeNative } from "../src/native-config.js";
import { __loadBundledNativeForTest, __resetNativeLoaderForTest, __setNativeLoaderForTest, type NativeBinding } from "../src/native.js";
import { root } from "../src/root.js";
import { useRealTempDirs } from "./helpers/vitest.js";

let native: NativeBinding | undefined;
try { native = __loadBundledNativeForTest(); } catch { /* Native lanes build the binding. */ }
const { tempRoot } = useRealTempDirs();
afterEach(() => { vi.restoreAllMocks(); configureFsSafeNative({ mode: "auto" }); __resetNativeLoaderForTest(); });

describe.runIf(native?.removeStagedFile)("native Root creation", () => {
  it("preserves a replacement opened during a rejected FileHandle handoff", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-replacement-");
    const target = path.join(directory, "value");
    const realOpen = fs.open.bind(fs);
    let swapped = false;
    vi.spyOn(fs, "open").mockImplementation(async (...args) => {
      if (!swapped && String(args[0]) === target && fsSync.existsSync(target)) {
        fsSync.renameSync(target, path.join(directory, "created"));
        fsSync.writeFileSync(target, "replacement");
        swapped = true;
      }
      return await realOpen(...args);
    });
    const scoped = await root(directory);
    await expect(scoped.openWritable("value", { mkdir: false })).rejects.toMatchObject({ code: "path-mismatch" });
    expect(swapped).toBe(true);
    expect(await fs.readFile(target, "utf8")).toBe("replacement");
  });
  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)("creates below searchable writable parents without requesting directory reads", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-search-");
    const parent = path.join(directory, "parent");
    await fs.mkdir(parent);
    const scoped = await root(directory);
    await fs.chmod(parent, 0o300);
    await fs.chmod(directory, 0o300);
    try {
      await scoped.mkdir("parent/child");
      await scoped.append("parent/value", "inside", { durable: false });
    } finally { await fs.chmod(directory, 0o700); await fs.chmod(parent, 0o700); }
    expect(await fs.readFile(path.join(parent, "value"), "utf8")).toBe("inside");
  });

  it("closes both transferred resources when admission descriptor disposal fails", async () => {
    const directory = await tempRoot("fs-safe-native-create-close-");
    await fs.mkdir(path.join(directory, "parent"));
    const target = path.join(directory, "parent/value");
    const pending = new Set<number>();
    let injected = false;
    let handedOff: Awaited<ReturnType<typeof fs.open>> | undefined;
    const open = fs.open.bind(fs);
    vi.spyOn(fs, "open").mockImplementation(async (...args) => {
      const handle = await open(...args);
      if (String(args[0]) === target) handedOff = handle;
      return handle;
    });
    __setNativeLoaderForTest(() => ({ ...native!,
      openBeneath(...args) { const opened = native!.openBeneath(...args); pending.add(opened.fd); return opened; },
      closeOwnedFd(fd) {
        const directory = fsSync.fstatSync(fd).isDirectory();
        native!.closeOwnedFd(fd);
        pending.delete(fd);
        if (handedOff && directory && !injected) { injected = true; throw new Error("close failed"); }
      },
    }));
    configureFsSafeNative({ mode: "require" });
    const scoped = await root(directory);
    await expect(scoped.openWritable("parent/value", { mkdir: false })).rejects.toBeTruthy();
    expect(injected).toBe(true);
    expect(handedOff?.fd).toBe(-1);
    expect(pending.size).toBe(0);
    expect(await fs.readdir(path.dirname(target))).toEqual([]);
  });
  it.each((["mkdir", "append"] as const).flatMap(operation =>
    (["require", "auto"] as const).map(mode => ({ operation, mode })),
  ))("confines $operation in $mode when its parent pathname becomes a symlink at dispatch", async ({ operation, mode }) => {
    const directory = await tempRoot("fs-safe-native-create-");
    const outside = await tempRoot("fs-safe-native-create-outside-");
    await fs.mkdir(path.join(directory, "parent"));
    const scoped = await root(directory);
    let swapped = false;
    const swap = () => {
      if (swapped) return;
      fsSync.renameSync(path.join(directory, "parent"), path.join(directory, "held"));
      fsSync.symlinkSync(outside, path.join(directory, "parent"), process.platform === "win32" ? "junction" : "dir");
      swapped = true;
    };
    __setNativeLoaderForTest(() => ({ ...native!,
      mkdirChildBeneath(parent, name, mode) {
        if (operation === "mkdir") swap();
        return native!.mkdirChildBeneath!(parent, name, mode);
      },
      openBeneath(parent, name, flags) {
        if (operation === "append" && (flags & fsSync.constants.O_CREAT)) swap();
        return native!.openBeneath(parent, name, flags);
      },
    }));
    configureFsSafeNative({ mode });
    const result = operation === "mkdir" ? scoped.mkdir("parent/created") : scoped.append("parent/created", "inside", { durable: false });
    await expect(result).rejects.toBeTruthy();
    expect(swapped).toBe(true);
    expect(await fs.readdir(outside)).toEqual([]);
  });

  it("preserves FileHandle behavior and requested permissions for newly created files", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-handle-");
    const scoped = await root(directory);
    const opened = await scoped.openWritable("new/file", { writeMode: "append", mode: 0o640 });
    try {
      expect(opened.createdForWrite).toBe(true);
      await opened.handle.writeFile("first");
      await opened.handle.appendFile("second");
      const mode = (await opened.handle.stat()).mode;
      if (process.platform === "win32") expect(mode & 0o222).not.toBe(0);
      else expect(mode & 0o777).toBe(0o640 & ~process.umask());
    } finally { await opened.handle.close(); }
    expect(await fs.readFile(path.join(directory, "new/file"), "utf8")).toBe("firstsecond");
  });

  it("cleans an aborted empty append through the retained creation identity", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-abort-");
    const scoped = await root(directory);
    const reason = new Error("revoked");
    await expect(scoped.append("new", "data", { durable: false, assertBeforeMutation() {
      if (fsSync.existsSync(path.join(directory, "new"))) throw reason;
    } })).rejects.toBe(reason);
    expect(await fs.readdir(directory)).toEqual([]);
  });

  it.skipIf(process.platform === "win32")("fails closed under restrictive umask without widening creation permissions", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-umask-");
    const scoped = await root(directory);
    const previous = process.umask(0o777);
    try {
      await expect(scoped.append("required", "data", { mkdir: false, durable: false }))
        .rejects.toMatchObject({ code: "helper-unavailable" });
      expect(await fs.readdir(directory)).toEqual([]);
      configureFsSafeNative({ mode: "auto" });
      await scoped.append("compatible", "data", { mkdir: false, durable: false });
      expect((await fs.stat(path.join(directory, "compatible"))).mode & 0o777).toBe(0);
    } finally { process.umask(previous); }
  });

  it.skipIf(process.platform === "win32")("preserves restrictive creation modes through auto fallback and fails closed in require", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-mode-");
    const scoped = await root(directory);
    await expect(scoped.openWritable("required", { mkdir: false, mode: 0o400 }))
      .rejects.toMatchObject({ code: "helper-unavailable" });
    expect(await fs.readdir(directory)).toEqual([]);
    configureFsSafeNative({ mode: "auto" });
    const opened = await scoped.openWritable("compatible", { mkdir: false, mode: 0o400 });
    try { await opened.handle.writeFile("inside"); }
    finally { await opened.handle.close(); }
    expect((await fs.stat(path.join(directory, "compatible"))).mode & 0o777).toBe(0o400 & ~process.umask());
  });

  it("cleans its own empty file after the creation parent is renamed before append dispatch", async () => {
    __setNativeLoaderForTest(() => native!);
    configureFsSafeNative({ mode: "require" });
    const directory = await tempRoot("fs-safe-native-create-retained-");
    await fs.mkdir(path.join(directory, "parent"));
    const scoped = await root(directory);
    const reason = new Error("revoked after rename");
    await expect(scoped.append("parent/new", "data", { durable: false, assertBeforeMutation() {
      if (!fsSync.existsSync(path.join(directory, "parent/new"))) return;
      fsSync.renameSync(path.join(directory, "parent"), path.join(directory, "held"));
      fsSync.mkdirSync(path.join(directory, "parent"));
      fsSync.writeFileSync(path.join(directory, "parent/new"), "replacement");
      throw reason;
    } })).rejects.toBe(reason);
    expect(await fs.readdir(path.join(directory, "held"))).toEqual([]);
    expect(await fs.readFile(path.join(directory, "parent/new"), "utf8")).toBe("replacement");
  });
});
