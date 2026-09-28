import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { configureFsSafeNative, root } from "../src/index.js";
import { __loadBundledNativeForTest, __resetNativeLoaderForTest } from "../src/native.js";
import { useRealTempDirs } from "./helpers/vitest.js";

const { tempRoot } = useRealTempDirs();
let nativeAvailable = false;
try {
  __loadBundledNativeForTest();
  nativeAvailable = true;
} catch (error) {
  if (process.env.FS_SAFE_NATIVE_MODE === "require") throw error;
}
afterEach(() => {
  configureFsSafeNative({ mode: "auto" });
  __resetNativeLoaderForTest();
});

for (const mode of ["off", "require"] as const) {
  describe.skipIf(mode === "require" && !nativeAvailable)(`buffered leaf admission (native ${mode})`, () => {
    it.each(["write", "writeJson"] as const)("%s rejects final links without changing their in-root target", async method => {
      configureFsSafeNative({ mode });
      const directory = await tempRoot("fs-safe-buffered-link-");
      await fs.writeFile(path.join(directory, "target"), "original");
      await fs.symlink("target", path.join(directory, "link"), "file");
      await fs.symlink("absent", path.join(directory, "dangling"), "file");
      const safe = await root(directory, { durable: false });
      for (const name of ["link", "dangling"]) {
        await expect(safe[method](name, "replacement")).rejects.toMatchObject({
          name: "FsSafeError", code: "path-alias", category: "policy",
        });
        expect((await fs.lstat(path.join(directory, name))).isSymbolicLink()).toBe(true);
      }
      expect(await fs.readFile(path.join(directory, "target"), "utf8")).toBe("original");
      expect((await fs.readdir(directory)).sort()).toEqual(["dangling", "link", "target"]);
    });

    it.each(["create", "createJson"] as const)("%s classifies an existing directory as not-file", async method => {
      configureFsSafeNative({ mode });
      const directory = await tempRoot("fs-safe-buffered-directory-");
      await fs.mkdir(path.join(directory, "target"));
      const safe = await root(directory, { durable: false });
      await expect(safe[method]("target", "replacement")).rejects.toMatchObject({
        name: "FsSafeError", code: "not-file", category: "policy",
      });
      expect(await fs.readdir(path.join(directory, "target"))).toEqual([]);
      expect(await fs.readdir(directory)).toEqual(["target"]);
    });

    it.each(["write", "create"] as const)("%s retains hardlink rejection", async method => {
      configureFsSafeNative({ mode });
      const directory = await tempRoot("fs-safe-buffered-hardlink-");
      await fs.writeFile(path.join(directory, "target"), "original");
      await fs.link(path.join(directory, "target"), path.join(directory, "peer"));
      const safe = await root(directory, { durable: false });
      await expect(safe[method]("target", "replacement")).rejects.toMatchObject({
        code: "path-alias",
      });
      expect(await fs.readFile(path.join(directory, "peer"), "utf8")).toBe("original");
      expect((await fs.stat(path.join(directory, "target"))).nlink).toBe(2);
    });
  });
}
