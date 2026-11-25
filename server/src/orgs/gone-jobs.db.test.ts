import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { trivyArchive } from '@qualor/shared/test/trivy-archive';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { testConfig } from '../../test/config';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedFix } from '../../test/fixes';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { bootstrap } from '../auth/bootstrap';
import { BOARDS_QUEUE, enqueueBoardsCreate, scheduleBoardsSync } from '../boards/jobs';
import { boardsHandlers } from '../boards/run';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db } from '../db/client';
import {
  analyses,
  branches,
  jiraConnections,
  jobs,
  llmRequests,
  projectBoardsSettings,
  projectFixSettings,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  users,
  webhookSubscriptions,
} from '../db/schema';
import { FIX_QUEUE, enqueueFixJob, scheduleFixSync } from '../fixes/jobs';
import { fixHandlers } from '../fixes/run';
import { GATE_QUEUE, enqueueReevaluations, gateHandlers } from '../gates/reevaluate';
import { jobHandlers } from '../ingest/handlers';
import { ANALYSIS_QUEUE, createQueuedAnalysis } from '../ingest/service';
import { enqueueJiraCreate, JIRA_QUEUE, scheduleJiraSync } from '../jira/jobs';
import { jiraHandlers } from '../jira/run';
import { communityLimits } from '../limits';
import {
  AUTO_FIX_JOB_MAX_ATTEMPTS,
  AUTO_FIX_QUEUE,
  autoFixHandlers,
  autoFixKey,
  autoFixPayload,
} from '../llm/auto-fix';
import { baseUrlHash } from '../llm/input';
import { createLlmRuntime, llmHandlers, llmJobPayload } from '../llm/job';
import { AI_FIX_QUEUE, aiFixKey, aiFixPayload } from '../llm/post';
import { LLM_QUEUE } from '../llm/service';
import { REPOSITORY_SETUP_QUEUE, repositorySetupHandlers } from '../onboarding/setup-run';
import { createProject } from '../projects/create';
import { enqueue } from '../queue/queue';
import { runUntilIdle, type JobHandlers } from '../queue/worker';
import { reviewHandlers, type ReviewJobDeps } from '../review/job';
import { queueRemapPurge, queueSnapshotPurge, reviewSnapshotHandlers } from '../review/jobs';
import { REVIEW_MR_STATE_QUEUE, scheduleMergeRequestCheck } from '../review/lifecycle';
import { insertReplies } from '../review/replies';
import { replyHandlers } from '../review/reply-job';
import {
  AI_REPLY_MAX_ATTEMPTS,
  AI_REPLY_QUEUE,
  queueScan,
  replyKey,
  replyPayload,
} from '../review/reply-queue';
import { AI_REVIEW_QUEUE, createReviewRun } from '../review/runs';
import { REVIEW_SNAPSHOT_QUEUE, storeSnapshotUpload } from '../review/snapshot-store';
import { scmHandlers, type DecorationDeps } from '../scm/decorate';
import { enqueueDecoration, SCM_QUEUE } from '../scm/queue';
import { InstallationTokenCache } from '../scm/github/app-auth';
import { createScmRuntime } from '../scm/runtime';
import { makeDatasetCurrent, storeDataset } from '../vulndb/store';
import { ALERTS_QUEUE } from '../vulnerabilities/alerts/enqueue';
import { enqueueRecheck, RECHECK_QUEUE, recheckHandlers } from '../vulnerabilities/recheck';
import { webhookHandlers } from '../webhooks/deliver';
import { createDelivery, WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from '../webhooks/deliveries';
import { deleteOrganization } from './delete';
import { createOrganization } from './service';

/*
 * 0.16 issue #37, spec §4 "Missing rows must be quiet": a job queued for an organisation, or for
 * something in it, can outlive the organisation's delete; its handler then meets rows that are gone
 * and completes quietly. One row per job, as the code that queues it queues it.
 *
 * Queues without a row, because they cannot meet a deleted row by construction:
 * - housekeeping, telemetry, mail.license-check, vulndb.update, vulnerabilities.alerts,
 *   vulnerabilities.digest and webhook.digest: their payload names nothing of an organisation
 *   (`{}`, or the pass's own schedule), and each reads what exists when it runs;
 * - mail: its payload names a `mail_messages` row, whose only foreign key is to its user (SET NULL),
 *   so the delete leaves the message in place;
 * - organization-delete: its own test (delete.db.test.ts, "gone").
 */

const config = testConfig();
const KEY = encryptionKey(config.secretKey);
/** Inactive: the seeded organisations leave no audit events, which are kept anyway. */
const audit = createAuditRecorder({ isActive: () => false, log: QUIET_AUDIT_LOG });

let t: TestDatabase;
let db: Db;
let adminId: string;
let vulndbDir: string;

beforeAll(async () => {
  t = await createTestDatabase();
  db = t.db;
  await bootstrap(db, { username: 'admin', password: 'correct horse battery staple' });
  const [admin] = await db.select({ id: users.id }).from(users).where(eq(users.username, 'admin'));
  adminId = admin!.id;
  // A current vulnerability database, so a re-check gets as far as its projects.
  vulndbDir = await mkdtemp(join(tmpdir(), 'qualor-gone-jobs-'));
  const stored = await storeDataset(db, {
    kind: 'trivy',
    source: 'upload',
    chunks: (async function* () {
      await Promise.resolve();
      yield trivyArchive({ db: Buffer.from('gone jobs database') });
    })(),
    maxBytes: 1024 ** 3,
  });
  if (!('dataset' in stored)) throw new Error(JSON.stringify(stored));
  expect(await makeDatasetCurrent(db, stored.dataset.id)).toBe(true);
});

afterAll(async () => {
  await t.close();
  await rm(vulndbDir, { recursive: true, force: true });
});

/** What every organisation holds: a project mapped to GitLab, its main branch and a merge request. */
interface Org {
  organizationId: string;
  connectionId: string;
  projectId: string;
  mainBranchId: string;
  /** The merge request `!7`, with its newest analysis (succeeded) and an open issue in new code. */
  mrBranchId: string;
  analysisId: string;
  issueId: string;
}

let orgs = 0;

async function seedOrganization(): Promise<Org> {
  orgs += 1;
  const key = `gone-${orgs}`;
  const org = await createOrganization(
    db,
    { key, name: `Gone ${orgs}`, creatorId: adminId },
    { recorder: audit, context: SYSTEM_ACTOR },
  );
  const [connection] = await db
    .insert(scmConnections)
    .values({
      organizationId: org.id,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.example.com',
      tokenEnc: encryptSecret(KEY, 'scm-token', 'scm_connections.token_enc'),
    })
    .returning({ id: scmConnections.id });
  const project = await db.transaction((tx) =>
    createProject(tx, {
      organizationId: org.id,
      key: `${key}-app`,
      name: `${key} app`,
      mainBranchName: 'main',
      createdBy: { audit, actor: SYSTEM_ACTOR },
    }),
  );
  await db
    .update(projects)
    .set({ scmConnectionId: connection!.id, scmProjectRef: '42' })
    .where(eq(projects.id, project.id));
  const [mr] = await db
    .insert(branches)
    .values({
      projectId: project.id,
      kind: 'merge_request',
      name: '7',
      mrSourceBranch: 'feature',
      mrTargetBranch: 'main',
    })
    .returning({ id: branches.id });
  const [analysis] = await db
    .insert(analyses)
    .values({
      projectId: project.id,
      branchId: mr!.id,
      status: 'succeeded',
      revision: 'a'.repeat(40),
      analysisDate: new Date(),
      baselineStatus: 'ok',
      scannerVersion: '0.0.0-test',
      gateStatus: 'passed',
      gateResult: { status: 'passed', conditions: [] },
    })
    .returning({ id: analyses.id });
  await db
    .update(branches)
    .set({ lastAnalysisId: analysis!.id, lastAnalyzedAt: new Date() })
    .where(eq(branches.id, mr!.id));
  const ruleId = await seedRule(db, { key: 'eslint:no-unused-vars' });
  const issueId = await seedIssue(db, {
    projectId: project.id,
    branchId: mr!.id,
    ruleId,
    inNewCode: true,
  });
  return {
    organizationId: org.id,
    connectionId: connection!.id,
    projectId: project.id,
    mainBranchId: await mainBranchId(db, project.id),
    mrBranchId: mr!.id,
    analysisId: analysis!.id,
    issueId,
  };
}

type Level = 'debug' | 'info' | 'warn' | 'error';

/** A logger that keeps every line it is given, by level. */
function recordingLogger() {
  const lines: { level: Level; message: string }[] = [];
  const at =
    (level: Level) =>
    (...args: unknown[]): void => {
      const [first, second] = args;
      lines.push({ level, message: String(typeof first === 'string' ? first : second) });
    };
  return {
    lines,
    logger: { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') },
  };
}
type Logger = ReturnType<typeof recordingLogger>['logger'];

const scm = {
  secretKey: config.secretKey,
  internalHosts: config.scmInternalHosts,
  azureTokenOrigin: null,
  azureTestOrigin: null,
};

const decorationDeps = (logger: Logger): DecorationDeps => ({
  db,
  scm,
  runtime: createScmRuntime(),
  publicUrl: null,
  logger,
  limits: communityLimits,
});

const reviewDeps = (logger: Logger): ReviewJobDeps => ({
  db,
  config,
  logger,
  llmCircuit: createLlmRuntime().circuit,
  scm,
  scmRuntime: createScmRuntime(),
  shutdown: new AbortController().signal,
});

/** An `llm_requests` row of the organisation's issue, as `createAiRequest` writes one. */
async function seedAiRequest(
  org: Org,
  row: Partial<typeof llmRequests.$inferInsert> & { feature: 'explain' | 'fix' },
): Promise<string> {
  const [made] = await db
    .insert(llmRequests)
    .values({
      organizationId: org.organizationId,
      projectId: org.projectId,
      issueId: org.issueId,
      userId: adminId,
      cacheKey: 'c'.repeat(64),
      provider: 'openai',
      providerHost: 'llm.example.com',
      model: 'gpt-test',
      promptVersion: 'test-1',
      inputSha256: 'd'.repeat(64),
      inputBytes: 100,
      fields: ['message'],
      ...row,
    })
    .returning({ id: llmRequests.id });
  return made!.id;
}

/** The organisation's Jira connection, which its Jira jobs are for. */
async function seedJiraConnection(org: Org): Promise<string> {
  const [made] = await db
    .insert(jiraConnections)
    .values({
      organizationId: org.organizationId,
      deployment: 'data_center',
      siteUrl: 'https://jira.example.com',
      tokenEnc: encryptSecret(KEY, 'jira-token', 'jira_connections.token_enc'),
    })
    .returning({ id: jiraConnections.id });
  return made!.id;
}

/** A project with fixes switched on, so the organisation has fix jobs. */
async function enableFixes(org: Org): Promise<void> {
  await db.insert(projectFixSettings).values({ projectId: org.projectId, enabled: true });
}

const fixDeps = (logger: Logger) => ({
  db,
  scm,
  runtime: createScmRuntime(),
  publicUrl: null,
  limits: communityLimits,
  logger,
});

/** An Azure DevOps connection of the organisation with its project mapped to Azure Boards. */
async function seedBoardsConnection(org: Org): Promise<string> {
  const [made] = await db
    .insert(scmConnections)
    .values({
      organizationId: org.organizationId,
      provider: 'azure',
      baseUrl: 'https://dev.azure.com/gone',
      azureAuth: 'pat',
      tokenEnc: encryptSecret(KEY, 'azure-pat', 'scm_connections.token_enc'),
    })
    .returning({ id: scmConnections.id });
  await db.insert(projectBoardsSettings).values({
    projectId: org.projectId,
    connectionId: made!.id,
    azureProjectId: '6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c',
    azureProjectName: 'Payments',
    workItemTypeRef: 'Microsoft.VSTS.WorkItemTypes.Bug',
    workItemTypeName: 'Bug',
  });
  return made!.id;
}

const boardsDeps = (logger: Logger) => ({
  db,
  scm,
  azureTokens: new InstallationTokenCache(),
  publicUrl: null,
  limits: communityLimits,
  logger,
});

const jiraDeps = (logger: Logger) => ({
  db,
  secretKey: config.secretKey,
  internalHosts: config.jiraInternalHosts,
  publicUrl: null,
  limits: communityLimits,
  logger,
});

interface Row {
  /** The queue, and what its payload names. */
  name: string;
  queue: string;
  /**
   * Seeds what the job names in the organisation and queues the job as the code that queues it
   * does; answers the ids of the rows it seeded besides the organisation's own.
   */
  queueJob(org: Org): Promise<string[]>;
  handlers(logger: Logger): JobHandlers;
  /** Global passes the handler's normal path queues (none unless named). */
  globalPasses?: string[];
}

const ROWS: Row[] = [
  {
    name: 'analysis: an analysis id',
    queue: ANALYSIS_QUEUE,
    queueJob: async (org) => [
      await createQueuedAnalysis(db, {
        projectId: org.projectId,
        uploadedByTokenId: null,
        body: Buffer.from('{}'),
      }),
    ],
    handlers: (logger) => jobHandlers({ db, upload: config.upload, logger }),
  },
  {
    name: 'gate: a branch of the project',
    queue: GATE_QUEUE,
    queueJob: async (org) => {
      await db.transaction((tx) => enqueueReevaluations(tx, [org.issueId]));
      return [];
    },
    handlers: (logger) => gateHandlers({ db, logger }),
  },
  {
    name: 'scm: an analysis of the project',
    queue: SCM_QUEUE,
    queueJob: async (org) => {
      await db.transaction((tx) =>
        enqueueDecoration(tx, {
          analysisId: org.analysisId,
          branchId: org.mrBranchId,
          gitlab: { projectId: '42', pipelineId: '1001' },
        }),
      );
      return [];
    },
    handlers: (logger) => scmHandlers(decorationDeps(logger)),
  },
  {
    name: 'scm-ai-fix: a fix request of an issue',
    queue: AI_FIX_QUEUE,
    queueJob: async (org) => {
      const requestId = await seedAiRequest(org, {
        feature: 'fix',
        status: 'succeeded',
        post: { status: 'queued', at: new Date().toISOString() },
      });
      await enqueue(db, {
        queue: AI_FIX_QUEUE,
        payload: aiFixPayload.parse({ requestId, attempt: 0 }),
        concurrencyKey: aiFixKey(requestId),
        maxAttempts: 1,
      });
      return [requestId];
    },
    handlers: (logger) => scmHandlers(decorationDeps(logger)),
  },
  {
    name: 'llm: a request id',
    queue: LLM_QUEUE,
    queueJob: async (org) => {
      const requestId = await seedAiRequest(org, { feature: 'explain' });
      await enqueue(db, {
        queue: LLM_QUEUE,
        payload: llmJobPayload.parse({
          requestId,
          attempt: 0,
          baseUrl: baseUrlHash('https://llm.example.com/v1'),
        }),
        maxAttempts: 1,
      });
      return [requestId];
    },
    handlers: (logger) =>
      llmHandlers({
        db,
        secretKey: config.secretKey,
        internalHosts: config.llmInternalHosts,
        runtime: createLlmRuntime(),
        logger,
        version: '0.0.0',
        limits: communityLimits,
      }),
  },
  {
    name: 'llm-auto-fix: an analysis of a merge request',
    queue: AUTO_FIX_QUEUE,
    queueJob: async (org) => {
      await enqueue(db, {
        queue: AUTO_FIX_QUEUE,
        payload: autoFixPayload.parse({ analysisId: org.analysisId }),
        concurrencyKey: autoFixKey(org.mrBranchId),
        maxAttempts: AUTO_FIX_JOB_MAX_ATTEMPTS,
      });
      return [];
    },
    handlers: (logger) => autoFixHandlers({ db, limits: communityLimits, logger }),
  },
  {
    name: 'ai-review: a run id',
    queue: AI_REVIEW_QUEUE,
    queueJob: async (org) => [
      await db.transaction((tx) =>
        createReviewRun(tx, {
          analysisId: org.analysisId,
          projectId: org.projectId,
          branchId: org.mrBranchId,
        }),
      ),
    ],
    handlers: (logger) => reviewHandlers(reviewDeps(logger)),
  },
  {
    name: 'ai-reply: a reply id',
    queue: AI_REPLY_QUEUE,
    queueJob: async (org) => {
      const [replyId] = await insertReplies(db, [
        {
          projectId: org.projectId,
          branchId: org.mrBranchId,
          provider: 'gitlab',
          noteId: 501,
          threadId: 'a1b2c3d4',
          issueId: org.issueId,
          kind: 'reply',
          author: 'dev',
        },
      ]);
      await enqueue(db, {
        queue: AI_REPLY_QUEUE,
        payload: replyPayload.parse({ kind: 'answer', replyId }),
        concurrencyKey: replyKey(org.mrBranchId),
        maxAttempts: AI_REPLY_MAX_ATTEMPTS,
      });
      return [replyId!];
    },
    handlers: (logger) => replyHandlers(reviewDeps(logger)),
  },
  {
    name: 'ai-reply: the scan of a merge request',
    queue: AI_REPLY_QUEUE,
    queueJob: async (org) => {
      expect(await queueScan(db, org.mrBranchId)).toBe(true);
      return [];
    },
    handlers: (logger) => replyHandlers(reviewDeps(logger)),
  },
  {
    name: 'review-mr-state: a merge request of the project',
    queue: REVIEW_MR_STATE_QUEUE,
    queueJob: async (org) => {
      await db.transaction((tx) => scheduleMergeRequestCheck(tx, org.mrBranchId));
      return [];
    },
    handlers: (logger) => scmHandlers(decorationDeps(logger)),
  },
  {
    name: 'review-snapshot: a snapshot id',
    queue: REVIEW_SNAPSHOT_QUEUE,
    queueJob: async (org) => {
      const body = Buffer.from('an upload that is never unpacked');
      return [
        await storeSnapshotUpload(db, {
          analysisId: org.analysisId,
          projectId: org.projectId,
          body,
          compressedBytes: body.length,
        }),
      ];
    },
    handlers: (logger) => reviewSnapshotHandlers({ db, logger, limits: config.reviewSnapshot }),
  },
  {
    name: 'review-snapshot: the purge of the organisation (purgeOrganizationId)',
    queue: REVIEW_SNAPSHOT_QUEUE,
    queueJob: async (org) => {
      await db.transaction((tx) => queueSnapshotPurge(tx, org.organizationId));
      return [];
    },
    handlers: (logger) => reviewSnapshotHandlers({ db, logger, limits: config.reviewSnapshot }),
  },
  {
    name: 'review-snapshot: the purge of a remapped project (purgeProjectId)',
    queue: REVIEW_SNAPSHOT_QUEUE,
    queueJob: async (org) => {
      await db.transaction((tx) => queueRemapPurge(tx, org.projectId));
      return [];
    },
    handlers: (logger) => reviewSnapshotHandlers({ db, logger, limits: config.reviewSnapshot }),
  },
  {
    name: 'repository-setup: a run of a connection',
    queue: REPOSITORY_SETUP_QUEUE,
    queueJob: async (org) => {
      // As `POST /repository-setups` queues it: the run, its repository, one job per connection.
      const runId = await db.transaction(async (tx) => {
        const [run] = await tx
          .insert(repositorySetupRuns)
          .values({
            organizationId: org.organizationId,
            connectionId: org.connectionId,
            createdBy: adminId,
            ciSetup: false,
          })
          .returning({ id: repositorySetupRuns.id });
        await tx.insert(repositorySetupItems).values({
          runId: run!.id,
          position: 0,
          repositoryRef: 'group/app',
          repositoryName: 'group/app',
        });
        await enqueue(tx, {
          queue: REPOSITORY_SETUP_QUEUE,
          payload: { runId: run!.id },
          concurrencyKey: org.connectionId,
        });
        return run!.id;
      });
      return [runId];
    },
    handlers: (logger) =>
      repositorySetupHandlers({
        db,
        scm,
        runtime: createScmRuntime(),
        publicUrl: null,
        audit,
        logger,
      }),
  },
  {
    name: 'webhook: a delivery id',
    queue: WEBHOOK_QUEUE,
    queueJob: async (org) => {
      const [subscription] = await db
        .insert(webhookSubscriptions)
        .values({
          organizationId: org.organizationId,
          projectId: org.projectId,
          url: 'https://hooks.example.com/qualor',
          secretEnc: encryptSecret(KEY, 'hook-secret', WEBHOOK_SECRET_AAD),
          events: ['analysis.completed'],
        })
        .returning({ id: webhookSubscriptions.id });
      const deliveryId = await db.transaction((tx) =>
        createDelivery(tx, {
          subscriptionId: subscription!.id,
          event: 'analysis.completed',
          payload: { id: org.analysisId, project: { id: org.projectId } },
        }),
      );
      return [subscription!.id, deliveryId];
    },
    handlers: (logger) => webhookHandlers({ db, secretKey: config.secretKey, logger }),
  },
  {
    name: 'vulnerabilities.recheck: { projectIds: [<deleted>] }',
    queue: RECHECK_QUEUE,
    queueJob: async (org) => {
      await enqueueRecheck(db, { projectIds: [org.projectId] });
      return [];
    },
    handlers: (logger) =>
      recheckHandlers({
        db,
        config: { vulndb: { dir: vulndbDir, trivyPath: '/nonexistent/trivy' } },
        runner: { run: () => Promise.resolve({ ok: true, matches: new Map() }) },
        logger,
      }),
    // Every re-check ends by queueing the alert pass, which reads what exists when it runs.
    globalPasses: [ALERTS_QUEUE],
  },
  {
    name: 'jira: a pass of the organisation',
    queue: JIRA_QUEUE,
    queueJob: async (org) => {
      const connectionId = await seedJiraConnection(org);
      expect(await scheduleJiraSync(db, org.organizationId, 0)).toBe(true);
      return [connectionId];
    },
    handlers: (logger) => jiraHandlers(jiraDeps(logger)),
  },
  {
    name: 'jira: a create run of the organisation',
    queue: JIRA_QUEUE,
    queueJob: async (org) => {
      const connectionId = await seedJiraConnection(org);
      expect(await enqueueJiraCreate(db, org.organizationId)).toBe(true);
      return [connectionId];
    },
    handlers: (logger) => jiraHandlers(jiraDeps(logger)),
  },
  {
    name: 'boards: a pass of the Azure DevOps connection',
    queue: BOARDS_QUEUE,
    queueJob: async (org) => {
      const connectionId = await seedBoardsConnection(org);
      expect(await scheduleBoardsSync(db, connectionId, 0)).toBe(true);
      return [connectionId];
    },
    handlers: (logger) => boardsHandlers(boardsDeps(logger)),
  },
  {
    name: 'boards: a create run of the Azure DevOps connection',
    queue: BOARDS_QUEUE,
    queueJob: async (org) => {
      const connectionId = await seedBoardsConnection(org);
      expect(await enqueueBoardsCreate(db, connectionId)).toBe(true);
      return [connectionId];
    },
    handlers: (logger) => boardsHandlers(boardsDeps(logger)),
  },
  {
    name: 'fixes: the commit of a fix',
    queue: FIX_QUEUE,
    queueJob: async (org) => {
      await enableFixes(org);
      const fixId = await seedFix(db, {
        projectId: org.projectId,
        family: 'js',
        packageName: 'lodash',
        state: 'committing',
      });
      await enqueueFixJob(db, { kind: 'commit', fixId, generation: 1, attempt: 0 });
      return [fixId];
    },
    handlers: (logger) => fixHandlers(fixDeps(logger)),
  },
  {
    name: 'fixes: the close of a fix',
    queue: FIX_QUEUE,
    queueJob: async (org) => {
      await enableFixes(org);
      const fixId = await seedFix(db, {
        projectId: org.projectId,
        family: 'js',
        packageName: 'lodash',
        state: 'cancelled',
        mrNumber: 12,
        mrUrl: 'https://gitlab.example.com/group/app/-/merge_requests/12',
        headSha: 'c'.repeat(40),
      });
      await enqueueFixJob(db, { kind: 'close', fixId, generation: 1, attempt: 0 });
      return [fixId];
    },
    handlers: (logger) => fixHandlers(fixDeps(logger)),
  },
  {
    name: 'fixes: a pass of the organisation',
    queue: FIX_QUEUE,
    queueJob: async (org) => {
      await enableFixes(org);
      const fixId = await seedFix(db, {
        projectId: org.projectId,
        family: 'js',
        packageName: 'lodash',
      });
      expect(await scheduleFixSync(db, org.organizationId, 0)).toBe(true);
      return [fixId];
    },
    handlers: (logger) => fixHandlers(fixDeps(logger)),
  },
];

/**
 * The tables (but `jobs`, and `audit_events`, which outlive what they name) holding a row whose
 * JSON names one of `ids`, with how many: a column, a foreign key or a value inside JSON.
 */
async function rowsNaming(ids: readonly string[]): Promise<Record<string, number>> {
  const tables = await db.execute<{ name: string }>(sql`
    SELECT table_name AS name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
       AND table_name NOT IN ('jobs', 'audit_events')
     ORDER BY table_name`);
  const pattern = ids.join('|');
  const counts = await db.execute<{ name: string; n: number }>(
    sql.join(
      tables.rows.map(
        ({ name }) =>
          sql`SELECT ${name}::text AS name, count(*)::int AS n FROM ${sql.identifier(name)} t
               WHERE row_to_json(t)::text ~ ${pattern}`,
      ),
      sql` UNION ALL `,
    ),
  );
  return Object.fromEntries(counts.rows.filter((r) => r.n > 0).map((r) => [r.name, r.n]));
}

const allJobs = () =>
  db
    .select({
      id: jobs.id,
      queue: jobs.queue,
      key: jobs.concurrencyKey,
      payload: jobs.payload,
      status: jobs.status,
      lastError: jobs.lastError,
    })
    .from(jobs);

describe('jobs whose organisation was deleted (0.16 issue #37)', () => {
  it.each(ROWS)('$name: completes quietly', async (row) => {
    await db.delete(jobs);
    const org = await seedOrganization();
    const named = [...Object.values(org), ...(await row.queueJob(org))];
    const queued = await db
      .select({ id: jobs.id })
      .from(jobs)
      .where(and(eq(jobs.queue, row.queue), eq(jobs.status, 'queued')));
    expect(queued).toHaveLength(1);
    const jobId = queued[0]!.id;
    // A job queued for later (a review's deadline, the hourly check) runs at once here.
    await db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(eq(jobs.id, jobId));

    expect(await deleteOrganization(db, org.organizationId)).toBe('deleted');
    expect(await rowsNaming(named)).toEqual({});
    const before = new Set((await allJobs()).map((j) => j.id));

    const { lines, logger } = recordingLogger();
    const handler = row.handlers(logger)[row.queue];
    expect(handler).toBeDefined();
    expect(await runUntilIdle(db, { [row.queue]: handler! }, logger)).toBe(1);

    const after = await allJobs();
    expect(after.find((j) => j.id === jobId)).toMatchObject({
      status: 'succeeded',
      lastError: null,
    });
    expect(await rowsNaming(named)).toEqual({});
    const added = after.filter((j) => !before.has(j.id));
    expect(added.map((j) => j.queue)).toEqual(row.globalPasses ?? []);
    const naming = (text: string) => named.some((id) => text.includes(id));
    expect(added.filter((j) => naming(`${j.key ?? ''} ${JSON.stringify(j.payload)}`))).toEqual([]);
    // Quiet: one line at most, never an error; and the payload was understood.
    expect(lines.length, JSON.stringify(lines)).toBeLessThanOrEqual(1);
    expect(lines.filter((l) => l.level === 'error')).toEqual([]);
    expect(lines.filter((l) => /malformed/.test(l.message))).toEqual([]);
  });
});
