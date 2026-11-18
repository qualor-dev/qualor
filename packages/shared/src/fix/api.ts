/**
 * Fix MRs (0.16, spec §6.5–§6.7, R4–R8, R16): the claim and result bodies the CLI's `qualor fix`
 * sends and the claim answer the server gives, shared so both sides read one shape.
 */
import { z } from 'zod';
import { FIX_FAILURE_CODES, FIX_FAMILIES, FIX_LIMITS, NO_FIX_REASONS } from './families';

/** R16: the result route's body limit (32 MiB of files is 43 MiB of base64, plus the JSON). */
export const FIX_RESULT_BODY_LIMIT = 48 * 1024 * 1024;
/** R6: a lockfile names at most this many packages that pin it, for the MR text. */
export const FIX_MAX_DEPENDENTS = 5;
/** The zod bound on files per upload; the fixed limit (50) is checked in code (R16). */
const FILES_SCHEMA_MAX = 1000;
/** Ruling F9: a failure message the CLI sends; the server keeps the scrubbed last 2 KiB. */
const FAILURE_MESSAGE_MAX = 8192;

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Text the database stores as sent: no U+0000, no lone UTF-16 surrogate. */
const storable = (min: number, max: number) =>
  z
    .string()
    .min(min)
    .max(max)
    .refine((s) => !s.includes('\u0000') && !LONE_SURROGATE.test(s), {
      message: 'Must not contain NUL characters or a lone surrogate',
    });

const sha = z
  .string()
  .regex(/^[0-9a-f]{40}$/)
  .meta({ description: 'A full commit sha, lower case' });

/** A vulnerability's severity, as the Vulnerabilities tab has it. */
export const FIX_SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;

/** R4, ruling F12: one claim call; `revision` is optional and the server only logs it. */
export const fixClaimBodySchema = z.strictObject({
  families: z
    .array(z.enum(FIX_FAMILIES))
    .min(1)
    .max(FIX_FAMILIES.length)
    .meta({ description: 'The families whose package managers the job can serve completely' }),
  max: z
    .number()
    .int()
    .min(1)
    .max(FIX_LIMITS.claimMax)
    .default(FIX_LIMITS.claimMax)
    .meta({ description: 'Fixes to hand out at most; the CLI claims one per call (R4)' }),
  branch: z
    .string()
    .min(1)
    .max(255)
    .meta({ description: "The checked-out branch; anything but the project's main branch is 409" }),
  revision: sha
    .optional()
    .meta({ description: 'The checked-out commit; recorded in the log only (ruling F12)' }),
});
export type FixClaimBody = z.infer<typeof fixClaimBodySchema>;

/** R5: one vulnerability of a claimed fix's package on the main branch. */
export const fixClaimVulnerabilitySchema = z.object({
  id: z.string(),
  severity: z.enum(FIX_SEVERITIES),
  title: z.string().nullable(),
  url: z.string().nullable(),
  /** The installed versions it affects. */
  installedVersions: z.array(z.string()),
  /** Trivy's fixed versions, split and trimmed; empty when there is none. */
  fixedVersions: z.array(z.string()),
});

/** spec §6.5, R5: a claimed fix, `preparing` with a 30-minute lease. */
export const fixClaimItemSchema = z.object({
  id: z.uuid(),
  generation: z.number().int(),
  /** The lease: only its hash is stored, so it is shown this once. */
  leaseToken: z.string(),
  family: z.enum(FIX_FAMILIES),
  packageName: z.string(),
  installedVersions: z.array(z.string()),
  vulnerabilities: z.array(fixClaimVulnerabilitySchema),
  mainBranch: z.string(),
  /** B4: a target a person declined; the CLI answers `noFix` `declined` when it would choose it. */
  declinedTarget: z.string().nullable(),
});
export type FixClaimItem = z.infer<typeof fixClaimItemSchema>;

/** R4: why a claim hands out nothing on a project the job cannot serve now (the job exits 0). */
export const FIX_CLAIM_REASONS = [
  'disabled',
  'not_allowed',
  'not_bound',
  'monitoring_off',
] as const;
export type FixClaimReason = (typeof FIX_CLAIM_REASONS)[number];

export const fixClaimAnswerSchema = z.object({
  items: z.array(fixClaimItemSchema),
  /** Null when the project's fixes can be claimed (the list may still be empty). */
  reason: z.enum(FIX_CLAIM_REASONS).nullable(),
});
export type FixClaimAnswer = z.infer<typeof fixClaimAnswerSchema>;

/** R6: a lockfile (for Maven an edited `pom.xml`) the fix changed, for the MR text. */
export const fixLockfileSchema = z.strictObject({
  path: storable(1, 1024),
  relation: z.enum(['direct', 'transitive']),
  /** The pin of a transitive fix (`overrides`, `resolutions`, `dependencyManagement`, …). */
  mechanism: storable(1, 64).nullable(),
  /** Packages that bring the pinned one (at most 5), for "remove the pin when …". */
  dependents: z.array(storable(1, 512)).max(FIX_MAX_DEPENDENTS),
});
export type FixLockfile = z.infer<typeof fixLockfileSchema>;

/** B3: one vulnerable installed version, its target and the lockfile (or `pom.xml`) it is in. */
export const fixResultTargetSchema = z.strictObject({
  installed: storable(1, 256),
  target: storable(1, 256),
  lockfile: storable(1, 1024),
});

/** A changed file: its path (checked in code, R16) and its new content in base64. */
export const fixResultFileSchema = z.strictObject({
  path: z.string(),
  content: z
    .string()
    .regex(/^[A-Za-z0-9+/]*={0,2}$/)
    .refine((s) => s.length % 4 === 0, { message: 'Must be base64' })
    .meta({ description: 'The whole new file, base64 (RFC 4648 §4, padded)' }),
});

const lease = {
  generation: z.number().int().min(1).max(32_767),
  leaseToken: z.string().min(1).max(128),
};

/** spec §6.5 step 6, R6: the files of a prepared fix. */
export const fixUploadSchema = z.strictObject({
  ...lease,
  baseSha: sha.meta({ description: "The main branch's head the job prepared the fix on" }),
  installedVersion: storable(1, 256).meta({
    description: 'The installed version whose target is the greatest (R30)',
  }),
  targetVersion: storable(1, 256).meta({ description: 'The greatest target (R30)' }),
  targets: z.array(fixResultTargetSchema).max(FILES_SCHEMA_MAX),
  files: z.array(fixResultFileSchema).min(1).max(FILES_SCHEMA_MAX),
  lockfiles: z.array(fixLockfileSchema).max(FILES_SCHEMA_MAX),
  /** Ids of the vulnerabilities no version fixes, listed in the MR. */
  unfixable: z.array(storable(1, 128)).max(FILES_SCHEMA_MAX),
});

/** spec §6.5: the job could not prepare the fix. */
export const fixFailureSchema = z.strictObject({
  ...lease,
  failure: z.strictObject({
    code: z.enum(FIX_FAILURE_CODES),
    message: z.string().max(FAILURE_MESSAGE_MAX),
  }),
});

/** spec §6.5, B3, B4: no version fixes the package (or the target was declined). */
export const fixNoFixSchema = z.strictObject({
  ...lease,
  noFix: z.strictObject({
    reason: z.enum(NO_FIX_REASONS),
    message: z.string().max(FIX_LIMITS.messageBytes),
  }),
});

/** R4, R6: the job hands a claim back (its time ran out) without trying it. */
export const fixReleasedSchema = z.strictObject({
  ...lease,
  released: z.literal(true),
});

/** R6: the four forms of `PUT /fixes/{id}/result`, each with the claim's generation and lease. */
export const fixResultBodySchema = z.union([
  fixUploadSchema,
  fixFailureSchema,
  fixNoFixSchema,
  fixReleasedSchema,
]);
export type FixResultBody = z.infer<typeof fixResultBodySchema>;
export type FixUpload = z.infer<typeof fixUploadSchema>;
