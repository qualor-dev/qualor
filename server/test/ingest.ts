import { eq } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import type { FastifyInstance } from 'fastify';
import type { Config } from '../src/config';
import { analyses } from '../src/db/schema';
import { gateHandlers } from '../src/gates/reevaluate';
import { jobHandlers } from '../src/ingest/handlers';
import type { IngestionStage } from '../src/ingest/process';
import type { Limits } from '../src/limits';
import { runUntilIdle } from '../src/queue/worker';
import {
  addMember,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from './app';
import { gzipJson, uploadReport } from './reports';

export interface IngestHarness {
  ctx: TestContext;
  orgAdmin: Session;
  organizationId: string;
  /**
   * Creates a project (and its analysis token) in the default organisation, or in `owner`'s
   * organisation by `owner`'s session.
   */
  project(
    key: string,
    owner?: { organizationId: string; session: Session },
  ): Promise<IngestProject>;
  close(): Promise<void>;
}

export interface IngestProject {
  id: string;
  key: string;
  token: string;
  /** Uploads the report and runs the queue until idle. Returns the analysis id. */
  ingest(report: Report, stages?: readonly IngestionStage[]): Promise<string>;
  /** Like ingest, and fails the test unless the analysis succeeded. */
  ingestOk(report: Report, stages?: readonly IngestionStage[]): Promise<string>;
}

/** An app on a fresh database, an org admin of `default`, and a helper to ingest reports. */
export async function createIngestHarness(
  options: {
    config?: Partial<Config>;
    limits?: Limits;
    beforeReady?: (app: FastifyInstance) => void;
    /** Plugins and an edition (test/rbac.ts `rbacPlugins`), as createTestContext takes them. */
    pluginsFor?: NonNullable<Parameters<typeof createTestContext>[0]>['pluginsFor'];
  } = {},
): Promise<IngestHarness> {
  const ctx = await createTestContext(options);
  const org = await organizationId(ctx, 'default');
  const user = await createUser(ctx, { username: 'ingest-admin' });
  await addMember(ctx, org, user.id, 'admin');
  const orgAdmin = await login(ctx, user.username, user.password);
  return {
    ctx,
    orgAdmin,
    organizationId: org,
    async project(key, owner = { organizationId: org, session: orgAdmin }) {
      const { id } = await createProject(ctx, owner.session, {
        organizationId: owner.organizationId,
        key,
      });
      const token = await createProjectToken(ctx, owner.session, id);
      const ingest = async (report: Report, stages?: readonly IngestionStage[]) => {
        const analysisId = await uploadReport(ctx, bearer(token), key, gzipJson(report));
        // Like main.ts's analysis worker: re-evaluations (scm.md §7) share the per-project key,
        // so a queued one must run for the analysis behind it to be claimed.
        await runUntilIdle(
          ctx.db,
          {
            ...jobHandlers({ db: ctx.db, upload: ctx.config.upload, stages, logger: ctx.app.log }),
            ...gateHandlers({ db: ctx.db }),
          },
          ctx.app.log,
        );
        return analysisId;
      };
      return {
        id,
        key,
        token,
        ingest,
        async ingestOk(report, stages) {
          const analysisId = await ingest(report, stages);
          const [row] = await ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
          if (row?.status !== 'succeeded') {
            throw new Error(
              `analysis ${analysisId} ended ${row?.status}: ${JSON.stringify(row?.error)}`,
            );
          }
          return analysisId;
        },
      };
    },
    close: () => ctx.close(),
  };
}
