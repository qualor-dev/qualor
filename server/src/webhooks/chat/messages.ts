import { SEVERITIES, type Severity } from '@qualor/shared';
import { z } from 'zod';
import type { GateStatus } from '../../db/schema';
import type { DeliveryEvent } from '../deliveries';

export const MAX_FAILED_CONDITIONS = 5;
export const MAX_DIGEST_ROWS = 20;
export const MAX_TOP_ISSUES = 3;
export const MAX_EXPLOITED_ROWS = 10;
export const MAX_EXPLOITED_PROJECTS = 20;
export const MAX_VULNERABILITY_PROJECTS = 10;
export const MAX_TARGET_NAMES = 5;

const gateStatus = z.enum(['passed', 'failed', 'error', 'none']);
const count = z.number().int().min(0);
const name = z.string().max(500);
const severityCounts = z.strictObject(
  Object.fromEntries(SEVERITIES.map((s) => [s, count])) as Record<Severity, typeof count>,
);

/** 6G spec §4: a main-branch gate change, as the ingestion or the re-evaluation saw it (R5). */
const gateMessage = z.strictObject({
  type: z.literal('gate'),
  event: z.enum(['gate.failed', 'gate.recovered']),
  cause: z.enum(['analysis', 'reevaluation']),
  project: z.strictObject({ id: z.uuid(), key: name, name }),
  branch: z.strictObject({ id: z.uuid(), name }),
  analysisId: z.uuid(),
  revision: z.string().max(64).nullable(),
  at: z.iso.datetime(),
  gate: z.strictObject({ name: name.nullable(), status: gateStatus }),
  /** The failed conditions, at most MAX_FAILED_CONDITIONS; `failedCount` is all of them. */
  failed: z
    .array(
      z.strictObject({
        metric: z.string().max(100),
        operator: z.enum(['gt', 'lt']),
        threshold: z.number(),
        value: z.number().nullable(),
      }),
    )
    .max(MAX_FAILED_CONDITIONS),
  failedCount: count,
  newIssues: z.strictObject({
    security: count.nullable(),
    reliability: count.nullable(),
    maintainability: count.nullable(),
  }),
});

const digestRow = z.strictObject({
  projectId: z.uuid(),
  name,
  gate: z.enum(['passed', 'failed', 'error', 'none', 'never']),
  newSecurity: count,
  newBySeverity: severityCounts,
  openSecurity: count,
});

const topIssue = z.strictObject({
  id: z.uuid(),
  projectId: z.uuid(),
  projectName: name,
  severity: z.enum(SEVERITIES),
  ruleName: name,
  message: z.string().max(4000),
  path: z.string().max(4000).nullable(),
  line: z.number().int().nullable(),
});

const vulnerabilitySeverity = z.enum(['critical', 'high', 'medium', 'low', 'unknown']);
export type VulnerabilitySeverity = z.infer<typeof vulnerabilitySeverity>;

/** One exploited (CISA KEV) vulnerability of one package, as the `exploited` message lists it. */
const exploitedRow = z.strictObject({
  vulnerabilityId: z.string().max(200),
  severity: vulnerabilitySeverity,
  title: z.string().max(2000).nullable(),
  packageName: z.string().max(500),
  installedVersions: z.array(z.string().max(200)).max(50),
  fixedVersion: z.string().max(200).nullable(),
  /** `YYYY-MM-DD`. */
  kevDateAdded: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  targets: z.array(name).max(200),
});

/** 0.15 plan 6 C5: the new exploited vulnerabilities of one job run, posted at once. */
const exploitedMessage = z
  .strictObject({
    type: z.literal('exploited'),
    projects: z
      .array(
        z.strictObject({
          id: z.uuid(),
          key: name,
          name,
          rows: z.array(exploitedRow).max(MAX_EXPLOITED_ROWS),
          more: count,
        }),
      )
      .max(MAX_EXPLOITED_PROJECTS),
    moreProjects: count,
  })
  .refine((m) => m.projects.reduce((n, p) => n + p.rows.length, 0) <= MAX_EXPLOITED_ROWS, {
    message: `at most ${MAX_EXPLOITED_ROWS} rows in all`,
  });

/** 0.15 plan 6 C6: the digest's new High and Critical vulnerabilities; absent without the licence. */
const digestVulnerabilities = z.strictObject({
  critical: count,
  high: count,
  /** Null without `vuln.priority`. */
  exploited: count.nullable(),
  projects: z
    .array(
      z.strictObject({
        projectId: z.uuid(),
        name,
        critical: count,
        high: count,
        exploited: count.nullable(),
        targets: z.array(name).max(MAX_TARGET_NAMES),
        moreTargets: count,
      }),
    )
    .max(MAX_VULNERABILITY_PROJECTS),
  moreProjects: count,
});

/** 6G spec §4: the weekly security digest of one webhook's scope. */
const digestMessage = z.strictObject({
  type: z.literal('digest'),
  week: z.string().regex(/^\d{4}-W\d{2}$/),
  since: z.iso.datetime(),
  until: z.iso.datetime(),
  timezone: z.string().max(64),
  scope: z.strictObject({
    organization: z.strictObject({ id: z.uuid(), name }),
    project: z.strictObject({ id: z.uuid(), name }).nullable(),
  }),
  totals: z.strictObject({
    projects: count,
    failing: count,
    newSecurity: count,
    openSecurity: count,
    newBySeverity: severityCounts,
  }),
  rows: z.array(digestRow).max(MAX_DIGEST_ROWS),
  moreProjects: count,
  quietProjects: count,
  top: z.array(topIssue).max(MAX_TOP_ISSUES),
  /** Optional: a digest queued before 0.15, or without `vuln.alerts`, has none. */
  vulnerabilities: digestVulnerabilities.optional(),
});

/** R2: the message of `POST /webhooks/:id/test`. */
const testMessage = z.strictObject({
  type: z.literal('test'),
  organization: z.strictObject({ id: z.uuid(), name }),
  project: z.strictObject({ id: z.uuid(), name }).nullable(),
});

export const chatMessageSchema = z.discriminatedUnion('type', [
  gateMessage,
  digestMessage,
  exploitedMessage,
  testMessage,
]);
export type ChatGateMessage = z.infer<typeof gateMessage>;
export type ChatDigestMessage = z.infer<typeof digestMessage>;
export type ChatExploitedMessage = z.infer<typeof exploitedMessage>;
export type ExploitedRow = z.infer<typeof exploitedRow>;
export type DigestVulnerabilities = z.infer<typeof digestVulnerabilities>;
export type ChatTestMessage = z.infer<typeof testMessage>;
export type ChatMessage = z.infer<typeof chatMessageSchema>;
export type DigestRow = z.infer<typeof digestRow>;
export type DigestTopIssue = z.infer<typeof topIssue>;
export type DigestGate = DigestRow['gate'];
export type { GateStatus };

const TYPE_OF: Record<string, ChatMessage['type']> = {
  'gate.failed': 'gate',
  'gate.recovered': 'gate',
  'digest.weekly': 'digest',
  'vulnerabilities.exploited': 'exploited',
  'chat.test': 'test',
};

/** The stored payload as a message of its delivery's event, or null (R5: fail, never throw). */
export function parseChatMessage(event: DeliveryEvent, payload: unknown): ChatMessage | null {
  const parsed = chatMessageSchema.safeParse(payload);
  if (!parsed.success || TYPE_OF[event] !== parsed.data.type) return null;
  if (parsed.data.type === 'gate' && parsed.data.event !== event) return null;
  return parsed.data;
}
