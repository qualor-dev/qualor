import type {
  FixClaimItem,
  FixFailureCode,
  FixFamily,
  FixLockfile,
  FixTarget,
  NoFixReason,
} from '@qualor/shared/fix';
import type { Logger } from '../log';
import type { ToolRunner } from './runner';

/**
 * What an adapter (one per family, Tasks 13–16) works in: the scratch copy of HEAD, its tracked
 * files (repository-relative, `/`-separated), the job's tool runner (bounded by `deadline`), the
 * time the fix must be done by (ms since the epoch) and the job's log (scrubbed of secrets).
 */
export interface FixWorkspace {
  root: string;
  files: readonly string[];
  run: ToolRunner;
  deadline: number;
  log: Logger;
}

/** The versions of the package one lockfile (for Maven a `pom.xml`) resolves. */
export interface InstalledAt {
  lockfile: string;
  versions: string[];
}

/**
 * The fix to make (§6.5 step 2, B3): one target per vulnerable installed version and lockfile, the
 * greatest target and the installed version it raises (R30), the vulnerabilities no version fixes,
 * and whether a target leaves its release line.
 */
export interface FixPlan {
  targets: FixTarget[];
  greatest: string;
  installed: string;
  unfixable: string[];
  majorJump: boolean;
}

/** Why an adapter stopped: a failure (`failed`) or no version to move to (`no_fix`). */
export type FixStop =
  | { kind: 'failure'; code: FixFailureCode; message: string }
  | { kind: 'no_fix'; reason: NoFixReason; message: string };

/** What `apply` changed: each lockfile (or `pom.xml`) and how the package is pinned in it (R6). */
export interface AppliedFix {
  lockfiles: FixLockfile[];
}

/** One family's package managers (B7): where the package is installed, the edit, its check. */
export interface FixAdapter {
  readonly family: FixFamily;
  /** Every lockfile (or `pom.xml`) of the workspace that resolves the package, with its versions. */
  installed(ws: FixWorkspace, packageName: string): Promise<InstalledAt[]>;
  /** Edits the manifests and regenerates the lockfiles of the family in the workspace. */
  apply(ws: FixWorkspace, fix: FixClaimItem, plan: FixPlan): Promise<AppliedFix | FixStop>;
  /** Re-reads what `apply` made; null when every vulnerable resolution reached its target. */
  verify?(ws: FixWorkspace, fix: FixClaimItem, plan: FixPlan): Promise<FixStop | null>;
}
