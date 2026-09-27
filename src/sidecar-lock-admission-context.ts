import { AsyncLocalStorage } from "node:async_hooks";

type AdmissionIdentity = {
  active: boolean;
  admissions: Map<string, object>;
  normalizedTargetPath: string;
  token: object;
};

type SidecarAdmissionAncestry = readonly AdmissionIdentity[];

type SidecarAdmissionScope = AdmissionIdentity & {
  ancestry: SidecarAdmissionAncestry;
};

const EMPTY_ANCESTRY: SidecarAdmissionAncestry = Object.freeze([]);
const GLOBAL_CONTEXT_KEY = Symbol.for("fsSafe.sidecarLockAdmissionAsyncContext");

function admissionContext(): AsyncLocalStorage<SidecarAdmissionScope> {
  const shared = globalThis as typeof globalThis & {
    [GLOBAL_CONTEXT_KEY]?: AsyncLocalStorage<SidecarAdmissionScope>;
  };
  return shared[GLOBAL_CONTEXT_KEY] ??=
    new AsyncLocalStorage<SidecarAdmissionScope>();
}

/** Capture active ancestry now; later lifecycle changes cannot reclassify this call. */
export function captureSidecarAdmissionAncestry(): SidecarAdmissionAncestry {
  const current = admissionContext().getStore();
  if (!current) return EMPTY_ANCESTRY;
  const active = current.ancestry.filter((entry) => entry.active);
  if (current.active) active.push(current);
  return active.length === 0 ? EMPTY_ANCESTRY : active;
}

export function ancestryHasSidecarAdmission(
  ancestry: SidecarAdmissionAncestry,
  admissions: Map<string, object>,
  normalizedTargetPath: string,
): boolean {
  return ancestry.some((entry) =>
    entry.admissions === admissions && entry.normalizedTargetPath === normalizedTargetPath);
}

export function createSidecarAdmissionController(
  ancestry: SidecarAdmissionAncestry,
  admissions: Map<string, object>,
  normalizedTargetPath: string,
) {
  let scope: SidecarAdmissionScope | undefined;
  const hasToken = (): boolean =>
    scope !== undefined && admissions.get(normalizedTargetPath) === scope.token;
  return {
    get owns(): boolean { return scope !== undefined; },
    hasToken,
    release(): void {
      if (scope) scope.active = false;
      if (hasToken()) admissions.delete(normalizedTargetPath);
      scope = undefined;
    },
    reserve(): void {
      const token = {};
      scope = { active: false, admissions, ancestry, normalizedTargetPath, token };
      admissions.set(normalizedTargetPath, token);
      scope.active = true;
    },
    run<T>(callback: () => T): T {
      return scope?.active ? admissionContext().run(scope, callback) : callback();
    },
  };
}
