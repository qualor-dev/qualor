import { fileURLToPath } from 'node:url';
import { buildApp } from './app';
import { SYSTEM_ACTOR } from './audit/recorder';
import { bootstrap, BootstrapError } from './auth/bootstrap';
import { ConfigError, loadConfig, type Config } from './config';
import { createDatabase } from './db/client';
import { EmbeddedPostgresError, startEmbeddedPostgres, type EmbeddedPostgres } from './db/embedded';
import { restoreEmbedded } from './db/restore';
import { readinessCheck, runMigrations } from './db/migrate';
import { gateHandlers } from './gates/reevaluate';
import { ensureHousekeepingScheduled, housekeepingHandlers } from './housekeeping/run';
import { createLogger } from './http/logger';
import { loadUiAssets, UiAssetsError, type UiAssets } from './http/ui';
import { VERSION } from './index';
import { jobHandlers } from './ingest/handlers';
import { reconcileDeadAnalyses } from './ingest/process';
import { LicenseFileError } from './license/source';
import {
  createLlmRuntime,
  LLM_LEASE_MS,
  LLM_WORKER_CONCURRENCY,
  llmHandlers,
  reconcileStuckLlmRequests,
} from './llm/job';
import { bootEnterprise, type EnterpriseBoot } from './plugins/boot';
import { ensurePluginSchedules, startPluginWorker } from './plugins/mount';
import { startWorker } from './queue/worker';
import { scmHandlers } from './scm/decorate';
import { createScmRuntime } from './scm/runtime';
import { readSignInSettings } from './sso/sign-in-policy';
import { databaseStartupError, formatStartupError } from './startup-error';
import {
  cancelTelemetry,
  ensureTelemetryScheduled,
  scheduleTelemetryAtBoot,
  telemetryBootMessage,
  telemetryHandlers,
} from './telemetry/schedule';
import { webhookHandlers } from './webhooks/deliver';

/** Webhook deliveries in flight at once (each waits at most 10 s for its receiver). */
const WEBHOOK_WORKER_CONCURRENCY = 4;
/**
 * The webhook worker's job lease: an attempt takes at most 10 s, so a worker that dies mid-attempt
 * has its job retried after 2 minutes rather than the default 10 (the heartbeat keeps a live
 * attempt's lease).
 */
const WEBHOOK_LEASE_MS = 2 * 60_000;
/** GitLab decorations in flight at once (scm.md §4.2), each with a 2-minute lease (heartbeats). */
const SCM_WORKER_CONCURRENCY = 4;
const SCM_LEASE_MS = 2 * 60_000;

// ../drizzle from both src/main.ts (tsx) and dist/main.js (bundle).
const MIGRATIONS_DIR = fileURLToPath(new URL('../drizzle', import.meta.url));

function fail(message: string): never {
  process.stderr.write(`qualor-server: ${message}\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  let config: Config;
  try {
    config = loadConfig(process.env);
  } catch (err) {
    if (err instanceof ConfigError) fail(err.message);
    throw err;
  }
  // Plan 1F ruling Y2: a UI directory that is missing or wrong stops the boot, before migrations.
  let ui: UiAssets | undefined;
  if (config.uiDir !== null) {
    try {
      ui = await loadUiAssets(config.uiDir);
    } catch (err) {
      if (err instanceof UiAssetsError) fail(err.message);
      throw err;
    }
  }
  const logger = createLogger(config.logLevel);
  if (process.argv[2] === 'restore') {
    process.exit(await restoreEmbedded(config, logger));
  }
  logger.info({ version: VERSION }, `Qualor server ${VERSION} starting`);
  // embedded-postgres.md §2: without DATABASE_URL the server runs the PostgreSQL of its image.
  let embedded: EmbeddedPostgres | undefined;
  let stopping = false;
  let databaseUrl = config.databaseUrl;
  if (databaseUrl === null) {
    try {
      embedded = await startEmbeddedPostgres({
        ...config.embedded,
        logger,
        // §5 step 1: another container took the volume over; two servers must never share it.
        lease: {
          onLost: () => {
            logger.error({ component: 'postgres' }, 'another server took over the data directory');
            process.exit(1);
          },
        },
      });
    } catch (err) {
      if (err instanceof EmbeddedPostgresError) fail(err.message);
      throw err;
    }
    databaseUrl = embedded.url;
    // §5: PostgreSQL exiting on its own is fatal; the container's restart policy restarts both.
    void embedded.exited.then((how) => {
      if (stopping) return;
      logger.error({ component: 'postgres', how }, 'the embedded PostgreSQL exited');
      process.exit(1);
    });
  }
  /** A failure after the embedded PostgreSQL started stops it first, so it is never orphaned. */
  const abort = async (message: string): Promise<never> => {
    stopping = true;
    await embedded?.stop();
    return fail(message);
  };
  const database = createDatabase(databaseUrl, {
    onError: (err) => logger.error({ err }, 'idle database connection failed'),
  });
  // Plan 1G: the first use of the database; a failure here is the deployment's to fix.
  try {
    await runMigrations(database.pool, MIGRATIONS_DIR);
  } catch (err) {
    await abort(databaseStartupError(err, embedded !== undefined));
  }
  try {
    const result = await bootstrap(database.db, config.bootstrapAdmin);
    if (result.createdOrganization) logger.info('created the default organization');
    if (result.createdAdmin) {
      logger.info({ username: config.bootstrapAdmin.username }, 'created the first instance admin');
    }
  } catch (err) {
    if (err instanceof BootstrapError) await abort(err.message);
    throw err;
  }
  // enterprise.md §6, §12: the key is read once; plugins load only while it is active or in grace.
  // The API and the workers share the one frozen registry and the one edition.
  let enterprise: EnterpriseBoot;
  try {
    enterprise = await bootEnterprise({
      config,
      db: database.db,
      logger,
      serverVersion: VERSION,
    });
  } catch (err) {
    // The message names the variable and the path, never the file's content.
    if (err instanceof LicenseFileError) await abort(err.message);
    throw err;
  }
  const { edition, plugins, audit } = enterprise;
  logger.info({ component: 'telemetry' }, telemetryBootMessage(config.telemetry.enabled));
  // sso-scim.md §10.4: the emergency switch is loud. One warn line per boot, and the event while
  // audit-log is active; a failure to record (a malformed anchor) is logged and never stops the boot.
  if (config.forcePasswordSignIn) {
    logger.warn(
      { component: 'sign-in' },
      'password sign-in forced by QUALOR_FORCE_PASSWORD_SIGN_IN',
    );
    try {
      const stored = await readSignInSettings(database.db, logger);
      await audit.record(database.db, SYSTEM_ACTOR, [
        {
          action: 'auth.password_sign_in_forced',
          details: { storedPolicy: stored.passwordSignIn },
        },
      ]);
    } catch (err) {
      logger.error(
        {
          component: 'sign-in',
          errorClass: err instanceof Error ? err.constructor.name : typeof err,
        },
        'could not record auth.password_sign_in_forced',
      );
    }
  }
  const app = await buildApp({
    config,
    db: database.db,
    logger,
    checkReady: readinessCheck(database.db, MIGRATIONS_DIR),
    ui,
    edition,
    plugins,
    // The recorder the plugin services record through (rbac-audit.md §9, §15).
    audit,
  });
  // data-model.md §7: one daily housekeeping job, (re)scheduled at boot and after every reap.
  await ensureHousekeepingScheduled(database.db);
  const worker = startWorker({
    db: database.db,
    handlers: {
      ...jobHandlers({ db: database.db, upload: config.upload, logger }),
      ...housekeepingHandlers({ db: database.db, logger }),
      // scm.md §7: re-evaluations share the analysis worker and its per-project key.
      ...gateHandlers({ db: database.db, logger }),
      // telemetry.md: only when enabled; the queue has no handler (and no job) otherwise.
      ...(config.telemetry.enabled
        ? telemetryHandlers({
            db: database.db,
            edition,
            url: config.telemetry.url,
            database: config.databaseUrl === null ? 'embedded' : 'external',
            logger,
          })
        : {}),
    },
    concurrency: config.workerConcurrency,
    logger,
    // Ruling S13 #2: a worker that crashes mid-run never gets to markFailed its own analysis;
    // sweep for that after every reap cycle instead.
    afterReap: async (db) => {
      await reconcileDeadAnalyses(db);
      await ensureHousekeepingScheduled(db);
      if (config.telemetry.enabled) await ensureTelemetryScheduled(db);
    },
  });
  // Ruling W4: deliveries have their own worker, so a slow receiver (10 s per attempt) never holds
  // up analyses, and several deliveries run at once.
  const webhookWorker = startWorker({
    db: database.db,
    handlers: webhookHandlers({ db: database.db, secretKey: config.secretKey, logger }),
    concurrency: WEBHOOK_WORKER_CONCURRENCY,
    leaseMs: WEBHOOK_LEASE_MS,
    logger,
  });
  // scm.md §4.2: GitLab decorations have their own worker, like webhooks, so GitLab being slow or
  // down never delays analyses or webhook deliveries.
  const scmWorker = startWorker({
    db: database.db,
    handlers: scmHandlers({
      db: database.db,
      scm: { secretKey: config.secretKey, internalHosts: config.scmInternalHosts },
      runtime: createScmRuntime(),
      publicUrl: config.publicUrl,
      logger,
    }),
    concurrency: SCM_WORKER_CONCURRENCY,
    leaseMs: SCM_LEASE_MS,
    logger,
  });
  // llm.md §12.3: AI requests have their own worker, so a slow or absent model never delays
  // analyses, deliveries or decorations.
  const llmWorker = startWorker({
    db: database.db,
    handlers: llmHandlers({
      db: database.db,
      secretKey: config.secretKey,
      internalHosts: config.llmInternalHosts,
      runtime: createLlmRuntime(),
      logger,
      version: VERSION,
    }),
    concurrency: LLM_WORKER_CONCURRENCY,
    leaseMs: LLM_LEASE_MS,
    logger,
    // A request whose job died with its worker (or threw) is failed, not left queued or running.
    afterReap: async (db) => {
      const abandoned = await reconcileStuckLlmRequests(db);
      if (abandoned > 0) logger.warn({ abandoned }, 'failed AI requests whose job was lost');
    },
  });
  // enterprise.md §10.3: plugin jobs have their own worker, only when a plugin registered jobs;
  // each job checks its feature against the same edition as the API's routes.
  const pluginWorker = startPluginWorker({ db: database.db, plugins, edition, logger });
  // rbac-audit.md §15: each scheduled plugin queue has its next run waiting (one across replicas).
  await ensurePluginSchedules(database.db, plugins, 'now');
  await app.listen({ host: config.host, port: config.port });
  try {
    if (config.telemetry.enabled) await scheduleTelemetryAtBoot(database.db);
    else await cancelTelemetry(database.db);
  } catch (err) {
    // Never fatal: the worker's afterReap re-creates the run within 30 s.
    logger.warn(
      {
        component: 'telemetry',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
      },
      'telemetry could not be scheduled',
    );
  }

  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, 'shutting down');
    try {
      await app.close();
      await worker.stop();
      await webhookWorker.stop();
      await scmWorker.stop();
      await llmWorker.stop();
      await pluginWorker?.stop();
      await database.close();
      await embedded?.stop();
      process.exit(0);
    } catch (err) {
      logger.error({ err }, 'shutdown failed');
      process.exit(1);
    }
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
  // A parent process that started us with an IPC channel may ask for the same graceful shutdown:
  // on Windows, child processes cannot receive SIGTERM (kill() terminates them outright). Used by
  // the boot smoke test (main.db.test.ts); without an IPC channel this registers nothing.
  if (process.send) {
    process.on('message', (message) => {
      if (message === 'shutdown') void shutdown('ipc');
    });
  }
}

main().catch((err: unknown) => {
  // Never print `err.stack`/`err.message` here: drizzle-orm wraps driver failures in
  // DrizzleQueryError, whose message embeds the failed query and its bind params verbatim, which
  // during bootstrap can include the admin's argon2 hash (task 5 review, ruling S6).
  fail(formatStartupError(err));
});
