import fs from "node:fs";
import path from "node:path";
import { FsSafeError } from "./errors.js";
import type {
  FileLockSyncAcquireOptions,
  FileLockSyncHandle,
} from "./file-lock-sync.js";
import { defaultSyncShouldReclaim, foreignSyncHeldLock } from "./file-lock-sync-admission.js";
import { getFsSafeLockConfig } from "./lock-config.js";
import type { Root } from "./root-impl.js";
import {
  isTransientLockFileDenial,
  sidecarLockStale,
  validateSidecarLockCompromiseCheckIntervalMs,
  validateSidecarLockRetryOptions,
  validateSidecarLockStaleMs,
  validateSidecarLockTimeoutMs,
} from "./sidecar-lock-policy.js";
import {
  serializeSidecarLockPayload,
  type SidecarLockSnapshot,
} from "./sidecar-lock-reclaim.js";
import { createSuppressedError } from "./suppressed-error.js";
import { SyncLockAcquisition } from "./file-lock-sync-acquisition.js";
import { assertSynchronousCallbackResult } from "./mutation-authority.js";
import { assertNoWindowsPathAlias } from "./windows-path-alias.js";
import {
  admitFileLockSyncRootPath,
  assertFileLockSyncRootPathsCurrent,
  captureFileLockSyncRootAuthority,
  normalizeFileLockSyncTargetWithRoot,
  type FileLockSyncRootPath,
} from "./file-lock-sync-root.js";
import {
  fileLockSyncRootSnapshotStillCurrent,
  type FileLockSyncRootDirectoryReceipt,
  type FileLockSyncRootFileReceipt,
  type FileLockSyncRootSnapshot,
} from "./file-lock-sync-root-io.js";
import {
  createFileLockSyncRootDirectory,
  createFileLockSyncRootFile,
  fileLockSyncRootGuardExists,
  fileLockSyncRootDirectoryReceiptStillCurrent,
  refreshFileLockSyncRootFileReceipt,
  removeFileLockSyncRootDirectory,
  removeFileLockSyncRootFile,
} from "./file-lock-sync-root-mutation.js";
import {
  createRootSyncHeldLockHandle,
  ensureRootSyncExitCleanupRegistered,
  getRootSyncHeldLocks,
  readRootSidecarSnapshotSync,
  verifyRootSyncHeldLock,
  type RootSyncHeldLock,
} from "./file-lock-sync-root-held.js";

class FileLockSyncRootArbitrationCollision extends FsSafeError {
  constructor() {
    super("path-mismatch", "file lock arbitration changed during local creation");
  }
}

function sameRootLockPath(left: FileLockSyncRootPath, right: FileLockSyncRootPath): boolean {
  return left.relativePath === right.relativePath && path.relative(left.path, right.path) === "";
}

export function cleanupCreatedRootSyncLock(
  lockRootPath: FileLockSyncRootPath,
  fd: number,
  receipt: FileLockSyncRootFileReceipt,
  timer?: NodeJS.Timeout,
): void {
  let timerCleanupFailed = false;
  let timerCleanupError: unknown;
  try {
    if (timer) clearInterval(timer);
  } catch (error) {
    timerCleanupFailed = true;
    timerCleanupError = error;
  }
  try {
    fs.closeSync(fd);
    if (!removeFileLockSyncRootFile(lockRootPath, receipt)) {
      throw new FsSafeError("path-mismatch", "created sidecar lock changed before cleanup");
    }
  } catch (fileCleanupError) {
    if (timerCleanupFailed) {
      throw createSuppressedError(
        timerCleanupError,
        fileCleanupError,
        "unpublished lock timer and file cleanup both failed",
      );
    }
    throw fileCleanupError;
  }
  if (timerCleanupFailed) throw timerCleanupError;
}

export function acquireFileLockSyncWithRoot<TPayload extends Record<string, unknown>>(
  targetPath: string,
  inputOptions: FileLockSyncAcquireOptions<TPayload>,
  lockRoot: Root,
): FileLockSyncHandle {
  // The public dispatcher already read lockRoot exactly once. Validate and
  // snapshot that genuine Root before any remaining option or retry getter can
  // mutate its defaults or retained policy inputs.
  const authority = captureFileLockSyncRootAuthority(lockRoot);
  // Capture every caller-owned option before validation. Retry accessors must
  // not be revisited by backoff or a callback that mutates the input options.
  const lockPathInput = inputOptions.lockPath;
  const staleMsInput = inputOptions.staleMs;
  const timeoutMsInput = inputOptions.timeoutMs;
  const retryInput = inputOptions.retry;
  const staleRecoveryInput = inputOptions.staleRecovery;
  const reentrantOwner = inputOptions.reentrantOwner;
  const payloadCallback = inputOptions.payload;
  const shouldReclaim = inputOptions.shouldReclaim;
  const shouldRemoveStaleLock = inputOptions.shouldRemoveStaleLock;
  const parsePayload = inputOptions.parsePayload;
  const onCompromised = inputOptions.onCompromised;
  const compromiseCheckIntervalMs = inputOptions.compromiseCheckIntervalMs;
  const retrySnapshot = retryInput === undefined ? undefined : Object.freeze({
    retries: retryInput.retries,
    factor: retryInput.factor,
    minTimeout: retryInput.minTimeout,
    maxTimeout: retryInput.maxTimeout,
    randomize: retryInput.randomize,
  });
  const defaults = getFsSafeLockConfig();
  const defaultRetry = defaults.retry;
  const retry = retrySnapshot ?? Object.freeze({
    retries: defaultRetry?.retries,
    factor: defaultRetry?.factor,
    minTimeout: defaultRetry?.minTimeout,
    maxTimeout: defaultRetry?.maxTimeout,
    randomize: defaultRetry?.randomize,
  });
  const timeoutMs = timeoutMsInput ?? defaults.timeoutMs;
  const staleMs = staleMsInput ?? defaults.staleMs ?? 30_000;
  const staleRecovery = staleRecoveryInput ?? defaults.staleRecovery;
  validateSidecarLockRetryOptions(retry);
  validateSidecarLockTimeoutMs(timeoutMs);
  validateSidecarLockStaleMs(staleMs);
  validateSidecarLockCompromiseCheckIntervalMs(compromiseCheckIntervalMs);
  ensureRootSyncExitCleanupRegistered();
  assertNoWindowsPathAlias(targetPath);
  if (lockPathInput !== undefined) assertNoWindowsPathAlias(lockPathInput);
  const resolvedTargetPath = path.resolve(targetPath);
  const normalizedTargetPath = normalizeFileLockSyncTargetWithRoot(authority, resolvedTargetPath);
  const requestedLockPath = path.resolve(lockPathInput ?? `${normalizedTargetPath}.lock`);
  const lockRootPath = admitFileLockSyncRootPath(authority, requestedLockPath);
  // A followed final alias and its admitted canonical spelling name the same
  // sidecar. Derive their arbitration guard from that shared admitted path,
  // then independently admit the derived mutation target under Root policy.
  const reclaimRootPath = admitFileLockSyncRootPath(authority, `${lockRootPath.path}.reclaim`);
  const guardedPaths = Object.freeze([lockRootPath, reclaimRootPath]);
  const lockPath = lockRootPath.path;
  const heldLocks = getRootSyncHeldLocks();
  const currentTargetHolder = () => heldLocks.get(normalizedTargetPath) ??
    foreignSyncHeldLock("root", normalizedTargetPath);
  const tryReuseCurrentRootSyncHeldLock = (): FileLockSyncHandle | undefined => {
    const held = heldLocks.get(normalizedTargetPath);
    const reusable = held && !foreignSyncHeldLock("root", normalizedTargetPath) &&
      reentrantOwner !== undefined &&
      held.reentrantOwner !== undefined &&
      reentrantOwner === held.reentrantOwner &&
      authority.adapter === held.rootAuthority.adapter &&
      sameRootLockPath(lockRootPath, held.rootPath) &&
      held.releaseState !== "released";
    if (!reusable) return undefined;
    if (!verifyRootSyncHeldLock(held)) {
      throw new FsSafeError("path-mismatch", "held sidecar lock changed before reentrant reuse");
    }
    // Verification can invoke a custom parser. Re-fetch the exact entry before
    // granting a reference, while retaining supported releasing/exit states.
    if (heldLocks.get(normalizedTargetPath) !== held ||
      held.releaseState === "released" || foreignSyncHeldLock("root", normalizedTargetPath)) {
      throw new FsSafeError("path-mismatch", "held sidecar lock changed during reentrant reuse");
    }
    held.refCount += 1;
    held.revision += 1;
    return createRootSyncHeldLockHandle(held);
  };
  if (heldLocks.has(normalizedTargetPath) && !foreignSyncHeldLock("root", normalizedTargetPath)) {
    assertFileLockSyncRootPathsCurrent(guardedPaths);
    const initiallyReusable = tryReuseCurrentRootSyncHeldLock();
    if (initiallyReusable) return initiallyReusable;
  }

  const acquisition = new SyncLockAcquisition(
    lockPath, normalizedTargetPath, retry, timeoutMs,
  );
  let ownedReclaimGuard: FileLockSyncRootDirectoryReceipt | undefined;
  let reclaimCleanupAttempted = false;
  const reuseCurrentHeld = (): FileLockSyncHandle | undefined =>
    ownedReclaimGuard ? undefined : tryReuseCurrentRootSyncHeldLock();
  const releaseReclaimGuard = (): void => {
    const receipt = ownedReclaimGuard;
    if (!receipt) return;
    reclaimCleanupAttempted = true;
    if (!removeFileLockSyncRootDirectory(reclaimRootPath, receipt)) {
      throw new FsSafeError("path-mismatch", "owned sidecar reclaim guard changed before release");
    }
    ownedReclaimGuard = undefined;
    reclaimCleanupAttempted = false;
  };
  const assertOwnedReclaimGuardCurrent = (): void => {
    const receipt = ownedReclaimGuard;
    if (!receipt || !fileLockSyncRootDirectoryReceiptStillCurrent(reclaimRootPath, receipt)) {
      throw new FsSafeError("path-mismatch", "owned sidecar reclaim guard changed during acquisition");
    }
  };
  try {
    while (true) {
      acquisition.reserve();
      acquisition.assert();
      assertFileLockSyncRootPathsCurrent(guardedPaths);
      acquisition.assert();
      if (ownedReclaimGuard) assertOwnedReclaimGuardCurrent();
      if (!ownedReclaimGuard && fileLockSyncRootGuardExists(reclaimRootPath)) {
        acquisition.waitForRetry();
        continue;
      }
      if (currentTargetHolder() !== undefined) {
        const reused = reuseCurrentHeld();
        if (reused) return reused;
      }
      const payload = Reflect.apply(payloadCallback, inputOptions, []);
      acquisition.assert();
      const { raw, ownershipToken } = serializeSidecarLockPayload(payload);
      acquisition.assert();
      if (ownedReclaimGuard) assertOwnedReclaimGuardCurrent();
      if (currentTargetHolder() !== undefined) {
        const reused = reuseCurrentHeld();
        if (reused) return reused;
        acquisition.waitForRetry();
        continue;
      }
      let fd: number | undefined;
      let rootReceipt: FileLockSyncRootFileReceipt | undefined;
      let unpublishedTimer: NodeJS.Timeout | undefined;
      let lockFileCreateOpenFailure: { error: unknown } | undefined;
      try {
        const created = createFileLockSyncRootFile(lockRootPath, {
          assertBeforeOpen: () => {
            acquisition.assert();
            if (ownedReclaimGuard) assertOwnedReclaimGuardCurrent();
            if (currentTargetHolder() !== undefined) throw new FileLockSyncRootArbitrationCollision();
          },
          onOpenFailure: (error) => {
            lockFileCreateOpenFailure = { error };
          },
        });
        fd = created.fd;
        rootReceipt = created.receipt;
        fs.writeFileSync(fd, raw, "utf8");
        fs.fsyncSync(fd);
        const snapshot: SidecarLockSnapshot = {
          raw,
          payload,
          ownershipToken,
        };
        if (ownedReclaimGuard) releaseReclaimGuard();
        rootReceipt = refreshFileLockSyncRootFileReceipt(lockRootPath, rootReceipt);
        const createdHeld: RootSyncHeldLock = {
          fd,
          lockPath,
          normalizedTargetPath,
          parsePayload,
          refCount: 1,
          reentrantOwner,
          releaseState: "active",
          revision: 0,
          rootAuthority: authority,
          rootPath: lockRootPath,
          rootReceipt,
          snapshot,
        };
        const returnedHandle = createRootSyncHeldLockHandle(createdHeld);
        acquisition.monitor(createdHeld, returnedHandle, onCompromised,
          compromiseCheckIntervalMs, inputOptions,
          (timer) => { unpublishedTimer = timer; });
        if (currentTargetHolder() !== undefined) {
          throw new FileLockSyncRootArbitrationCollision();
        }
        acquisition.assert();
        heldLocks.set(normalizedTargetPath, createdHeld);
        fd = undefined;
        unpublishedTimer = undefined;
        return returnedHandle;
      } catch (error) {
        if (fd !== undefined && rootReceipt) {
          const cleanupFd = fd;
          const cleanupReceipt = rootReceipt;
          const cleanupTimer = unpublishedTimer;
          fd = undefined;
          rootReceipt = undefined;
          unpublishedTimer = undefined;
          try {
            cleanupCreatedRootSyncLock(lockRootPath, cleanupFd, cleanupReceipt, cleanupTimer);
          } catch (cleanupError) {
            throw createSuppressedError(
              error,
              cleanupError,
              "file lock acquisition and Root cleanup both failed",
            );
          }
        }
        if (error instanceof FileLockSyncRootArbitrationCollision) {
          const reused = reuseCurrentHeld();
          if (reused) return reused;
          acquisition.waitForRetry();
          continue;
        }
        const fromLockFileOpen = lockFileCreateOpenFailure !== undefined &&
          lockFileCreateOpenFailure.error === error;
        if (fromLockFileOpen && acquisition.retryDenial(error)) continue;
        if (!fromLockFileOpen || (error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        if (ownedReclaimGuard) {
          releaseReclaimGuard();
          const reused = reuseCurrentHeld();
          if (reused) return reused;
          acquisition.waitForRetry();
          continue;
        }
        if (currentTargetHolder() !== undefined) {
          const reused = reuseCurrentHeld();
          if (reused) return reused;
          acquisition.waitForRetry();
          continue;
        }
        let lockFileOpenDenied = false;
        let current: FileLockSyncRootSnapshot | null;
        try {
          current = readRootSidecarSnapshotSync(
            lockRootPath,
            parsePayload,
            (openError) => {
              lockFileOpenDenied = isTransientLockFileDenial(openError, lockPath);
            },
          );
        } catch (readError) {
          if (lockFileOpenDenied && acquisition.retryDenial(readError)) continue;
          throw readError;
        }
        if (currentTargetHolder() !== undefined) {
          const reused = reuseCurrentHeld();
          if (reused) return reused;
          acquisition.waitForRetry();
          continue;
        }
        acquisition.assert();
        if (!current) {
          acquisition.waitForRetry();
          continue;
        }
        const snapshot = current.snapshot;
        const nowMs = Date.now();
        let reclaim: boolean;
        if (shouldReclaim) {
          reclaim = Reflect.apply(shouldReclaim, inputOptions, [{
            lockPath,
            normalizedTargetPath,
            payload: snapshot.payload,
            staleMs,
            nowMs,
            heldByThisProcess: false,
          }]);
          assertSynchronousCallbackResult(reclaim, "shouldReclaim");
          acquisition.assert();
          if (!fileLockSyncRootSnapshotStillCurrent(lockRootPath, current)) {
            throw new FsSafeError("path-mismatch", "sidecar changed during reclaim policy callback");
          }
        } else {
          reclaim = defaultSyncShouldReclaim(snapshot, staleMs, nowMs);
        }
        if (reclaim) {
          if (
            staleRecovery === "remove-if-unchanged" &&
            snapshot.raw !== undefined &&
            shouldRemoveStaleLock
          ) {
            const guard = createFileLockSyncRootDirectory(reclaimRootPath);
            if (!guard) {
              acquisition.waitForRetry();
              continue;
            }
            ownedReclaimGuard = guard;
            reclaimCleanupAttempted = false;
            const approved = Reflect.apply(shouldRemoveStaleLock, inputOptions, [{
              lockPath,
              normalizedTargetPath,
              raw: snapshot.raw,
              payload: snapshot.payload,
            }]);
            assertSynchronousCallbackResult(approved, "shouldRemoveStaleLock");
            acquisition.assert();
            assertOwnedReclaimGuardCurrent();
            if (approved) {
              const removed = removeFileLockSyncRootFile(
                lockRootPath,
                current.receipt,
                snapshot,
                () => {
                  acquisition.assert();
                  assertOwnedReclaimGuardCurrent();
                  if (currentTargetHolder() !== undefined) throw new FileLockSyncRootArbitrationCollision();
                },
              );
              if (!removed) {
                throw new FsSafeError("path-mismatch", "stale sidecar changed before removal");
              }
              continue;
            }
            if (!fileLockSyncRootSnapshotStillCurrent(lockRootPath, current)) {
              throw new FsSafeError(
                "path-mismatch",
                "sidecar changed during stale-removal policy callback",
              );
            }
            releaseReclaimGuard();
          }
          throw sidecarLockStale(lockPath, normalizedTargetPath);
        }
        acquisition.waitForRetry();
      }
    }
  } catch (error) {
    if (ownedReclaimGuard && !reclaimCleanupAttempted) {
      try {
        releaseReclaimGuard();
      } catch (cleanupError) {
        throw createSuppressedError(
          error,
          cleanupError,
          "file lock acquisition and reclaim cleanup both failed",
        );
      }
    }
    throw error;
  } finally {
    acquisition.release();
  }
}
