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
import {
  ensureLicenseAlertScheduled,
  licenseAlertHandlers,
  scheduleLicenseAlertAtBoot,
} from './mail/alerts/license-alerts';
import { createLogger } from './http/logger';
import { LogBuffer } from './http/log-buffer';
import { loadUiAssets, UiAssetsError, type UiAssets } from './http/ui';
import { VERSION } from './index';
import { jobHandlers } from './ingest/handlers';
import { reconcileDeadAnalyses } from './ingest/process';
import { LicenseFileError } from './license/source';
import { autoFixHandlers } from './llm/auto-fix';
import {
  createModelRuntimes,
  reviewCircuitDeps,
  LLM_LEASE_MS,
  LLM_WORKER_CONCURRENCY,
  llmHandlers,
  reconcileStuckLlmRequests,
} from './llm/job';
import { MAIL_LEASE_MS, MAIL_WORKER_CONCURRENCY, mailHandlers } from './mail/deliver';
import { mailDeps } from './mail/outbox';
import { notifyAnalysesFailed } from './notifications/analysis';
import { notifyDeps } from './notifications/deps';
import { bootEnterprise, type EnterpriseBoot } from './plugins/boot';
import { ensurePluginSchedules, startPluginWorker } from './plugins/mount';
import { startWorker } from './queue/worker';
import { REVIEW_LEASE_MS, reviewHandlers } from './review/job';
import { reviewSnapshotHandlers } from './review/jobs';
import { replyHandlers } from './review/reply-job';
import { reconcileStuckReplies } from './review/reply-queue';
import { reconcileStuckReviewRuns } from './review/runs';
import { scmHandlers } from './scm/decorate';
import { createScmRuntime } from './scm/runtime';
import { supportBundleCommand } from './support/command';
import { readSignInSettings } from './sso/sign-in-policy';
import { databaseStartupError, formatStartupError } from './startup-error';
import {
  cancelTelemetry,
  ensureTelemetryScheduled,
  scheduleTelemetryAtBoot,
  telemetryBootMessage,
  telemetryHandlers,
} from './telemetry/schedule';
import { updateCheckerFor } from './update-check/checker';
import { webhookHandlers } from './webhooks/deliver';
import { digestHandlers, ensureDigestScheduled, scheduleDigestAtBoot } from './webhooks/digest';

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
  // 4E-3b §4: the bundle for when the UI is unreachable. No UI, HTTP, workers or migrations; it
  // logs to standard error, because standard output may carry the zip.
  if (process.argv[2] === 'support-bundle') {
    process.exit(
      await supportBundleCommand({
        args: process.argv.slice(3),
        config,
        version: VERSION,
        migrationsDir: MIGRATIONS_DIR,
      }),
    );
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
  const logBuffer = new LogBuffer();
  const logger = createLogger(config.logLevel, undefined, logBuffer);
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
  // The SCM worker's per-process state; the support bundle reads its circuits (4E-3b §1).
  const scmRuntime = createScmRuntime();
  // enterprise.md §6, §12: the key is read once; plugins load only while it is active or in grace.
  // The API and the workers share the one frozen registry and the one edition.
  let enterprise: EnterpriseBoot;
  try {
    enterprise = await bootEnterprise({
      config,
      db: database.db,
      logger,
      serverVersion: VERSION,
      // 4E-3b §4: the support bundle reads this replica's log tail and SCM circuits.
      support: { migrationsDir: MIGRATIONS_DIR, logBuffer, scmRuntime },
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
  // telemetry.md "Update check": only while telemetry is on; never fatal, never above info.
  const updates = updateCheckerFor(config, { currentVersion: VERSION, logger });
  const app = await buildApp({
    config,
    db: database.db,
    logger,
    checkReady: readinessCheck(database.db, MIGRATIONS_DIR),
    ui,
    edition,
    logBuffer,
    plugins,
    // The recorder the plugin services record through (rbac-audit.md §9, §15).
    audit,
    ...(updates ? { updates } : {}),
  });
  // data-model.md §7: one daily housekeeping job, (re)scheduled at boot and after every reap.
  await ensureHousekeepingScheduled(database.db);
  // mail E3: project notifications, queued by the analysis worker in its transactions.
  const notify = notifyDeps(config);
  const worker = startWorker({
    db: database.db,
    handlers: {
      // The SCM stage queues a merge request's automatic fix suggestions under the edition's limits.
      ...jobHandlers({
        db: database.db,
        upload: config.upload,
        logger,
        notify,
        limits: () => edition.limits(),
      }),
      ...housekeepingHandlers({ db: database.db, logger }),
      // scm.md §7: re-evaluations share the analysis worker and its per-project key.
      ...gateHandlers({ db: database.db, logger, notify }),
      // 6I-2: merge requests' review snapshots are unpacked here; the worker tries the queues in
      // this order, so a waiting analysis is taken first.
      ...reviewSnapshotHandlers({ db: database.db, logger, limits: config.reviewSnapshot }),
      // telemetry.md: only when enabled; the queue has no handler (and no job) otherwise.
      ...(config.telemetry.enabled
        ? telemetryHandlers({
            db: database.db,
            edition,
            url: config.telemetry.url,
            database: config.databaseUrl === null ? 'embedded' : 'external',
            smtpConfigured: config.smtp !== null,
            logger,
          })
        : {}),
      // E1 spec: the daily licence expiry check (it queues email; the mail worker sends it).
      ...licenseAlertHandlers({ db: database.db, edition, config, logger }),
      // 6G R14: the hourly weekly-digest check (it queues deliveries; the webhook worker sends them).
      ...digestHandlers({ db: database.db, logger }),
    },
    concurrency: config.workerConcurrency,
    logger,
    // Ruling S13 #2: a worker that crashes mid-run never gets to markFailed its own analysis;
    // sweep for that after every reap cycle instead.
    afterReap: async (db) => {
      // mail E3: each analysis the sweep failed is mailed to its watchers (never throws).
      await notifyAnalysesFailed(db, notify, await reconcileDeadAnalyses(db), logger);
      await ensureHousekeepingScheduled(db);
      await ensureLicenseAlertScheduled(db);
      await ensureDigestScheduled(db);
      if (config.telemetry.enabled) await ensureTelemetryScheduled(db);
    },
  });
  // Ruling W4: deliveries have their own worker, so a slow receiver (10 s per attempt) never holds
  // up analyses, and several deliveries run at once.
  const webhookWorker = startWorker({
    db: database.db,
    handlers: webhookHandlers({
      db: database.db,
      secretKey: config.secretKey,
      logger,
      mail: mailDeps(config),
      publicUrl: config.publicUrl,
      chatTestHosts: config.chatTestHosts,
    }),
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
      runtime: scmRuntime,
      publicUrl: config.publicUrl,
      logger,
      // An automatic fix post checks the licence's seam again when it runs (4E-3a §3).
      limits: () => edition.limits(),
    }),
    concurrency: SCM_WORKER_CONCURRENCY,
    leaseMs: SCM_LEASE_MS,
    logger,
  });
  // Two circuits (6I R40): the AI requests (explain, triage, fix) have the `llm` runtime, AI reviews
  // and replies one of their own, so failing background reviews never pause the assistant. Only the
  // `llm` worker takes an organisation's slots.
  const modelRuntimes = createModelRuntimes();
  const llmRuntime = modelRuntimes.llm;
  // llm.md §12.3: AI requests have their own worker, so a slow or absent model never delays
  // analyses, deliveries or decorations. It also runs the automatic fix suggestions of an analysed
  // merge request (4E-3a §3), which queue requests and never call the model themselves. Its calls
  // wait on the provider for up to the provider's timeout, 10 minutes at the most: a stop aborts
  // them, and their requests go back to the queue for the next server.
  const llmShutdown = new AbortController();
  const llmWorker = startWorker({
    db: database.db,
    handlers: {
      ...llmHandlers({
        db: database.db,
        secretKey: config.secretKey,
        internalHosts: config.llmInternalHosts,
        runtime: llmRuntime,
        logger,
        version: VERSION,
        limits: () => edition.limits(),
        audit,
        shutdown: llmShutdown.signal,
      }),
      ...autoFixHandlers({ db: database.db, limits: () => edition.limits(), audit, logger }),
    },
    concurrency: LLM_WORKER_CONCURRENCY,
    leaseMs: LLM_LEASE_MS,
    logger,
    // A request whose job died with its worker (or threw) is failed, not left queued or running.
    afterReap: async (db) => {
      const abandoned = await reconcileStuckLlmRequests(db);
      if (abandoned > 0) logger.warn({ abandoned }, 'failed AI requests whose job was lost');
    },
  });
  // 6I-3 R21: AI reviews have their own worker, so a review never holds explain, triage or fix
  // behind it, nor an analysis or a decoration. It has a circuit of its own (R40), and the `scm`
  // worker's runtime for what the answers to replies read and write on GitLab and GitHub (6I-4).
  const reviewShutdown = new AbortController();
  const reviewDeps = {
    db: database.db,
    config,
    logger,
    ...reviewCircuitDeps(modelRuntimes),
    scm: { secretKey: config.secretKey, internalHosts: config.scmInternalHosts },
    scmRuntime,
    shutdown: reviewShutdown.signal,
    audit,
  };
  const reviewWorker = startWorker({
    db: database.db,
    // The worker tries the queues in this order: an answer to a reply, which is short, never
    // waits behind a review.
    handlers: { ...replyHandlers(reviewDeps), ...reviewHandlers(reviewDeps) },
    concurrency: config.reviewWorkerConcurrency,
    leaseMs: REVIEW_LEASE_MS,
    logger,
    afterReap: async (db) => {
      // A run whose job is gone for good (both tries died) is ended, or given a job, here.
      const swept = await reconcileStuckReviewRuns(db, logger);
      if (swept.ended > 0 || swept.queued > 0) {
        logger.warn(swept, 'reconciled AI review runs whose job was lost');
      }
      // So is an answer to a reply that its job left running: the line names each row it ended
      // and the outcome the row kept.
      const replies = await reconcileStuckReplies(db);
      if (replies.length > 0) {
        logger.warn({ ended: replies }, 'ended AI replies whose job was lost');
      }
    },
  });
  // E1 spec: email has its own worker, so a slow SMTP server never delays analyses, deliveries
  // or decorations.
  const mailWorker = startWorker({
    db: database.db,
    handlers: mailHandlers({ db: database.db, config, logger }),
    concurrency: MAIL_WORKER_CONCURRENCY,
    leaseMs: MAIL_LEASE_MS,
    logger,
  });
  // enterprise.md §10.3: plugin jobs have their own worker, only when a plugin registered jobs;
  // each job checks its feature against the same edition as the API's routes.
  const pluginWorker = startPluginWorker({ db: database.db, plugins, edition, logger });
  // rbac-audit.md §15: each scheduled plugin queue has its next run waiting (one across replicas).
  await ensurePluginSchedules(database.db, plugins, 'now');
  await app.listen({ host: config.host, port: config.port });
  updates?.start();
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
  try {
    await scheduleLicenseAlertAtBoot(database.db);
  } catch (err) {
    // Never fatal: the worker's afterReap re-creates the run within 30 s.
    logger.warn(
      {
        component: 'licence',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
      },
      'the licence expiry check could not be scheduled',
    );
  }
  try {
    await scheduleDigestAtBoot(database.db);
  } catch (err) {
    // Never fatal: the worker's afterReap re-creates the run within 30 s.
    logger.warn(
      {
        component: 'digest',
        errorClass: err instanceof Error ? err.constructor.name : typeof err,
      },
      'the weekly digest could not be scheduled',
    );
  }

  const shutdown = async (signal: string): Promise<void> => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, 'shutting down');
    try {
      // A review runs for minutes, longer than a stop's grace period (60 s in Compose and Helm):
      // the running ones end now, failed (the next push reviews again), and the worker takes no
      // new one, before anything is waited for. The calls of AI requests are cut the same way, and
      // their requests wait in the queue for the next server. The database stays up until the
      // workers are done.
      reviewShutdown.abort();
      llmShutdown.abort();
      const reviewsStopped = reviewWorker.stop();
      // The llm worker stops polling now too: a request its stop put back in the queue comes due
      // again in a few seconds, and this server, while it drains, does not claim it and put it back
      // again.
      const requestsStopped = llmWorker.stop();
      updates?.stop();
      await app.close();
      await worker.stop();
      await webhookWorker.stop();
      await scmWorker.stop();
      await requestsStopped;
      await reviewsStopped;
      await mailWorker.stop();
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
