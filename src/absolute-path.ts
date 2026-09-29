import fsSync from "node:fs";
import type { Stats } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import {
  assertAsyncDirectoryGuard,
  type AsyncDirectoryGuard,
  createAsyncDirectoryGuard,
} from "./directory-guard.js";
import { FsSafeError, type FsSafeErrorCode } from "./errors.js";
import { pathExists } from "./fs.js";
import { realpathSync } from "./realpath.js";
import { resolveRootPath } from "./root-path.js";
import {
  assertNoWindowsPathAlias,
  pathForWindowsFilesystem,
  resolvePathPreservingWindowsRoot,
} from "./windows-path-alias.js";

export type AbsolutePathSymlinkPolicy = "reject" | "follow";

function resolveSymlinkPolicy(policy: AbsolutePathSymlinkPolicy | undefined): AbsolutePathSymlinkPolicy {
  if (policy === undefined) return "reject";
  if (policy !== "reject" && policy !== "follow") {
    throw new TypeError(`invalid absolute path symlink policy: ${String(policy)}`);
  }
  return policy;
}

export type ResolvedAbsolutePath = {
  path: string;
  canonicalPath: string;
};

export type ResolvedWritableAbsolutePath = ResolvedAbsolutePath & {
  parentDir: string;
  parentExists: boolean;
};

export type EnsureAbsoluteDirectoryOptions = {
  scopeLabel?: string;
  mode?: number;
};

export type EnsureAbsoluteDirectoryResult =
  | { ok: true; path: string }
  | { ok: false; code: FsSafeErrorCode; error: FsSafeError };

type EnsureAbsoluteDirectoryFailure = Extract<EnsureAbsoluteDirectoryResult, { ok: false }>;

const classifiedDirectoryFailures = new WeakSet<object>();

function propagateDirectoryFailure(failure: EnsureAbsoluteDirectoryFailure): never {
  classifiedDirectoryFailures.add(failure);
  throw failure;
}

function ensureDirectoryFailure(
  code: FsSafeErrorCode,
  message: string,
  cause?: unknown,
): never {
  return propagateDirectoryFailure({
    ok: false,
    code,
    error: new FsSafeError(code, message, { cause }),
  });
}

async function assertPreparedDirectoryGuard(
  guard: AsyncDirectoryGuard,
  scopeLabel: string,
): Promise<void> {
  try {
    await assertAsyncDirectoryGuard(guard);
  } catch (err) {
    if (err instanceof FsSafeError) {
      return await directoryGuardFailure(err, guard.dir, scopeLabel);
    }
    throw err;
  }
}

async function createPreparedDirectoryGuard(
  dir: string,
  scopeLabel: string,
): Promise<AsyncDirectoryGuard> {
  try {
    return await createAsyncDirectoryGuard(dir);
  } catch (err) {
    if (err instanceof FsSafeError) {
      return await directoryGuardFailure(err, dir, scopeLabel);
    }
    throw err;
  }
}

function classifyDirectoryLookupError(
  err: unknown,
  scopeLabel: string,
): void {
  const code = (err as NodeJS.ErrnoException).code;
  if (code === "ENOENT") {
    return ensureDirectoryFailure(
      "not-found",
      `directory path must have a real existing ancestor within ${scopeLabel}`,
      err,
    );
  }
  if (code === "ENOTDIR") {
    return ensureDirectoryFailure(
      "not-file",
      `path must be a real directory within ${scopeLabel}`,
      err,
    );
  }
}

function classifyExistingDirectorySegment(
  stat: Stats,
  scopeLabel: string,
): void {
  if (stat.isSymbolicLink()) {
    return ensureDirectoryFailure(
      "symlink",
      `directory path traverses a symlink within ${scopeLabel}`,
    );
  }
  if (!stat.isDirectory()) {
    return ensureDirectoryFailure("not-file", `path must be a real directory within ${scopeLabel}`);
  }
}

async function directoryGuardFailure(
  err: FsSafeError,
  dir: string,
  scopeLabel: string,
): Promise<never> {
  if (err.code !== "not-file") {
    return propagateDirectoryFailure({ ok: false, code: err.code, error: err });
  }

  try {
    const stat = fsSync.lstatSync(pathForWindowsFilesystem(dir));
    classifyExistingDirectorySegment(stat, scopeLabel);
  } catch (lookupErr) {
    if (classifiedDirectoryFailures.has(lookupErr as object)) throw lookupErr;
    classifyDirectoryLookupError(lookupErr, scopeLabel);
    throw lookupErr;
  }
  return propagateDirectoryFailure({ ok: false, code: err.code, error: err });
}

async function resolveTrustedDirectoryPrefix(
  targetPath: string,
  scopeLabel: string,
): Promise<{ ancestorPath: string; missingSegments: string[] }> {
  const root = path.parse(targetPath).root;
  let current = root;
  let currentStat: Stats;
  try {
    currentStat = fsSync.lstatSync(pathForWindowsFilesystem(current));
  } catch (err) {
    classifyDirectoryLookupError(err, scopeLabel);
    throw err;
  }

  classifyExistingDirectorySegment(currentStat, scopeLabel);

  // Walk forward with lstat. Looking backward for the "nearest existing
  // ancestor" can cross an existing suffix through a symlinked parent before
  // this helper gets a chance to reject that parent.
  const segments = path.relative(root, targetPath).split(path.sep).filter(Boolean);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (!segment) {
      continue;
    }
    const next = path.join(current, segment);
    try {
      const nextStat = fsSync.lstatSync(pathForWindowsFilesystem(next));
      classifyExistingDirectorySegment(nextStat, scopeLabel);
      current = next;
      currentStat = nextStat;
    } catch (err) {
      if (classifiedDirectoryFailures.has(err as object)) throw err;
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") {
        return {
          ancestorPath: current,
          missingSegments: segments.slice(index),
        };
      }
      classifyDirectoryLookupError(err, scopeLabel);
      throw err;
    }
  }

  return { ancestorPath: current, missingSegments: [] };
}

export function assertAbsolutePathInput(filePath: string): string {
  if (!filePath) {
    throw new FsSafeError("invalid-path", "path is required");
  }
  if (filePath.includes("\0")) {
    throw new FsSafeError("invalid-path", "path must not contain NUL bytes");
  }
  assertNoWindowsPathAlias(filePath);
  if (!path.isAbsolute(filePath)) {
    throw new FsSafeError("invalid-path", "path must be absolute");
  }
  const normalized = path.normalize(filePath);
  assertNoWindowsPathAlias(normalized);
  return normalized;
}

export async function findExistingAncestor(filePath: string): Promise<string | null> {
  assertNoWindowsPathAlias(filePath);
  let current = resolvePathPreservingWindowsRoot(filePath);
  assertNoWindowsPathAlias(current);
  while (true) {
    try {
      fsSync.lstatSync(pathForWindowsFilesystem(current));
      return current;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    current = parent;
  }
}

export async function ensureAbsoluteDirectory(
  dirPath: string,
  options: EnsureAbsoluteDirectoryOptions = {},
): Promise<EnsureAbsoluteDirectoryResult> {
  const scopeLabel = options.scopeLabel ?? "directory";
  try {
    let targetPath: string;
    try {
      targetPath = assertAbsolutePathInput(dirPath);
    } catch (err) {
      if (err instanceof FsSafeError) {
        return { ok: false, code: err.code, error: err };
      }
      throw err;
    }

    const prefix = await resolveTrustedDirectoryPrefix(targetPath, scopeLabel);
    let current = prefix.ancestorPath;
    let currentGuard = await createPreparedDirectoryGuard(prefix.ancestorPath, scopeLabel);
    for (const segment of prefix.missingSegments) {
      current = path.join(current, segment);
      while (true) {
        await assertPreparedDirectoryGuard(currentGuard, scopeLabel);
        try {
          const stat = fsSync.lstatSync(current);
          if (stat.isSymbolicLink()) {
            return ensureDirectoryFailure(
              "symlink",
              `directory path traverses a symlink within ${scopeLabel}`,
            );
          }
          if (!stat.isDirectory()) {
            return ensureDirectoryFailure(
              "not-file",
              `path must be a real directory within ${scopeLabel}`,
            );
          }
          break;
        } catch (err) {
          if (classifiedDirectoryFailures.has(err as object)) throw err;
          if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
          }
          await assertPreparedDirectoryGuard(currentGuard, scopeLabel);
          try {
            await fs.mkdir(current, { mode: options.mode });
          } catch (mkdirErr) {
            if ((mkdirErr as NodeJS.ErrnoException).code === "EEXIST") {
              continue;
            }
            throw mkdirErr;
          }
        }
      }
      const nextGuard = await createPreparedDirectoryGuard(current, scopeLabel);
      await assertPreparedDirectoryGuard(currentGuard, scopeLabel);
      currentGuard = nextGuard;
    }

    await assertPreparedDirectoryGuard(currentGuard, scopeLabel);
    return { ok: true, path: targetPath };
  } catch (error) {
    // Weak identity checks do not inspect arbitrary thrown values or proxies.
    if (classifiedDirectoryFailures.delete(error as object)) {
      return error as EnsureAbsoluteDirectoryFailure;
    }
    throw error;
  }
}

export async function canonicalPathFromExistingAncestor(filePath: string): Promise<string> {
  assertNoWindowsPathAlias(filePath);
  const ancestor = await findExistingAncestor(filePath);
  if (!ancestor) {
    const resolved = resolvePathPreservingWindowsRoot(filePath);
    assertNoWindowsPathAlias(resolved);
    return resolved;
  }
  let canonicalAncestor = ancestor;
  let resolvedAncestor: string | undefined;
  try {
    resolvedAncestor = realpathSync.native(
      pathForWindowsFilesystem(ancestor),
    );
  } catch {
    // Keep lexical path when the existing ancestor cannot be canonicalized.
  }
  if (resolvedAncestor !== undefined) {
    assertNoWindowsPathAlias(resolvedAncestor);
    canonicalAncestor = resolvedAncestor;
  }
  const relative = path.relative(ancestor, filePath);
  const canonicalPath = relative ? path.join(canonicalAncestor, relative) : canonicalAncestor;
  assertNoWindowsPathAlias(canonicalPath);
  return canonicalPath;
}

export async function resolveAbsolutePathForRead(
  filePath: string,
  options: { symlinks?: AbsolutePathSymlinkPolicy } = {},
): Promise<ResolvedAbsolutePath> {
  const symlinks = resolveSymlinkPolicy(options.symlinks);
  const normalized = assertAbsolutePathInput(filePath);
  let canonicalPath: string;
  try {
    canonicalPath = realpathSync.native(
      pathForWindowsFilesystem(normalized),
    );
    assertNoWindowsPathAlias(canonicalPath);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new FsSafeError("not-found", "path not found", { cause: err });
    }
    throw err;
  }
  if (symlinks === "reject" && canonicalPath !== normalized) {
    throw new FsSafeError("symlink", "path traverses a symlink", { cause: { canonicalPath } });
  }
  return { path: normalized, canonicalPath };
}

export async function resolveAbsolutePathForWrite(
  filePath: string,
  options: { symlinks?: AbsolutePathSymlinkPolicy } = {},
): Promise<ResolvedWritableAbsolutePath> {
  const symlinks = resolveSymlinkPolicy(options.symlinks);
  const normalized = assertAbsolutePathInput(filePath);
  const parentDir = path.dirname(normalized);
  const parentExists = await pathExists(pathForWindowsFilesystem(parentDir));
  if (symlinks === "reject") {
    const filesystemRoot = path.parse(normalized).root;
    await resolveRootPath({
      absolutePath: normalized,
      rootPath: filesystemRoot,
      rootCanonicalPath: filesystemRoot,
      boundaryLabel: "absolute path",
      rejectSymlinks: true,
    });
  }
  const canonicalPath = await canonicalPathFromExistingAncestor(normalized);
  if (symlinks === "reject" && canonicalPath !== normalized) {
    throw new FsSafeError("symlink", "path traverses a symlink", {
      cause: { canonicalPath },
    });
  }
  return {
    path: normalized,
    canonicalPath,
    parentDir,
    parentExists,
  };
}
