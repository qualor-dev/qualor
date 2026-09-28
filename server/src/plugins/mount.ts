import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import type { Db } from '../db/client';
import { ProblemError } from '../http/problem';
import type { Edition, EditionPlugins } from '../license/edition';
import {
  DEFAULT_LEASE_MS,
  startWorker,
  type JobHandlers,
  type Worker,
  type WorkerLogger,
} from '../queue/worker';
import type { PluginReport } from './contract';
import { describePluginError } from './loader';
import {
  PluginError,
  type JobRegistration,
  type PluginRegistry,
  type RouteRegistration,
  type ScheduleRegistration,
} from './registry';
import { ensurePluginScheduled } from './schedule';

/** Plugin jobs share one worker (enterprise.md §10.3). */
export const PLUGIN_WORKER_CONCURRENCY = 2;
/** enterprise.md §10.3: a plugin job runs at most this long (the queue's lease), then fails. */
export const PLUGIN_JOB_TIMEOUT_MS = DEFAULT_LEASE_MS;
/** Where plugin routes live (enterprise.md §10.2). */
const EE_PREFIX = '/api/v0/ee';

/** What the loader committed, as main.ts and the app use it: read-only, never changed again. */
export interface LoadedPlugins extends EditionPlugins {
  readonly routes: readonly RouteRegistration[];
  readonly jobs: readonly JobRegistration[];
  readonly schedules: readonly ScheduleRegistration[];
}

/** A Set whose add, delete and clear throw once it is built: the features of a frozen registry. */
class ReadOnlySet<T> extends Set<T> {
  private readonly sealed: boolean;

  constructor(items: Iterable<T>) {
    super(items);
    this.sealed = true;
    Object.freeze(this);
  }

  override add(value: T): this {
    // The Set constructor calls add() before `sealed` is set; nothing can call it after.
    if (this.sealed) throw new TypeError('the features of the loaded plugins are read-only');
    return super.add(value);
  }

  override delete(): boolean {
    throw new TypeError('the features of the loaded plugins are read-only');
  }

  override clear(): void {
    throw new TypeError('the features of the loaded plugins are read-only');
  }
}

/**
 * A frozen copy of a registry, taken once after loading. The API, the workers and the edition
 * all read this copy, so nothing can add or swap a route, a job or a feature after the boot.
 */
export function freezePlugins(registry: PluginRegistry | LoadedPlugins): LoadedPlugins {
  const freezeList = <T extends object>(items: readonly T[]): readonly T[] =>
    Object.freeze(items.map((item) => Object.freeze({ ...item })));
  const reports: PluginReport[] = registry.reports.map((r) =>
    Object.freeze({ ...r, features: Object.freeze([...r.features]) as string[] }),
  );
  return Object.freeze({
    reports: Object.freeze(reports),
    features: new ReadOnlySet(registry.features) as ReadonlySet<string>,
    limitOverrides: freezeList(registry.limitOverrides),
    extensions: freezeList(registry.extensions),
    routes: freezeList(registry.routes),
    jobs: freezeList(registry.jobs),
    schedules: freezeList(registry.schedules),
  });
}

/** The route registrations of each plugin, in load order. */
function routesByPlugin(
  routes: readonly RouteRegistration[],
): Map<string, readonly RouteRegistration[]> {
  const byPlugin = new Map<string, RouteRegistration[]>();
  for (const r of routes) {
    const list = byPlugin.get(r.plugin) ?? [];
    list.push(r);
    byPlugin.set(r.plugin, list);
  }
  return byPlugin;
}

/**
 * One plugin's routes in its own encapsulation context under /api/v0/ee, each registration in a
 * context of its own behind its feature's guard. The root authentication hook runs first; the
 * guard answers 403 while the feature is inactive, so a licence that lapses on a running server
 * switches the routes off without a restart.
 */
async function mountPlugin(
  app: FastifyInstance,
  registrations: readonly RouteRegistration[],
  isActive: (feature: string) => boolean,
): Promise<void> {
  await app.register(
    async (pluginScope) => {
      for (const registration of registrations) {
        await pluginScope.register(async (scope) => {
          scope.addHook('onRequest', async () => {
            if (!isActive(registration.feature)) {
              throw new ProblemError(
                403,
                'FEATURE_NOT_LICENSED',
                `The enterprise feature "${registration.feature}" is not licensed`,
              );
            }
          });
          await scope.register(registration.routes);
        });
      }
    },
    { prefix: EE_PREFIX },
  );
}

/**
 * enterprise.md §10.2: each plugin in its own encapsulation context under /api/v0/ee. The
 * registrations are copied when this is called; nothing is mounted for an empty registry. A
 * route that throws here stops the app: `dropPluginsThatFailToMount` ran at boot to keep such a
 * plugin out (ruling R-MOUNT).
 */
export async function mountPluginRoutes(
  app: FastifyInstance,
  plugins: PluginRegistry | LoadedPlugins,
  edition: Edition,
): Promise<void> {
  const routes = freezePlugins(plugins).routes;
  for (const registrations of routesByPlugin(routes).values()) {
    await mountPlugin(app, registrations, (feature) => edition.isFeatureActive(feature));
  }
}

/**
 * Mounts one plugin's routes into a scratch Fastify instance with core's schema compilers, and
 * returns the error they threw, or the method and URL of every route they declared.
 */
async function tryMount(
  registrations: readonly RouteRegistration[],
): Promise<{ error: unknown } | { routes: string[] }> {
  const scratch = Fastify({ logger: false });
  scratch.setValidatorCompiler(validatorCompiler);
  scratch.setSerializerCompiler(serializerCompiler);
  const routes: string[] = [];
  scratch.addHook('onRoute', (route) => {
    const methods = Array.isArray(route.method) ? route.method : [route.method];
    for (const method of methods) routes.push(`${String(method)} ${route.url}`);
  });
  try {
    await mountPlugin(scratch, registrations, () => true);
    await scratch.ready();
    return { routes };
  } catch (error) {
    return { error };
  } finally {
    await scratch.close().catch(() => undefined);
  }
}

/** Takes a plugin out of the registry as a whole and reports it failed (ruling R-MOUNT). */
function dropPlugin(registry: PluginRegistry, name: string, error: string): void {
  const index = registry.reports.findIndex((r) => r.name === name && r.state === 'loaded');
  if (index < 0) return;
  const features = new Set(registry.reports[index]?.features ?? []);
  registry.reports[index] = { name, state: 'failed', features: [], error };
  registry.routes = registry.routes.filter((r) => r.plugin !== name);
  registry.jobs = registry.jobs.filter((j) => j.plugin !== name);
  registry.schedules = registry.schedules.filter((s) => s.plugin !== name);
  registry.limitOverrides = registry.limitOverrides.filter((o) => !features.has(o.feature));
  registry.extensions = registry.extensions.filter((e) => !features.has(e.feature));
  for (const f of features) registry.features.delete(f);
}

/**
 * enterprise.md §10.2 (ruling R-MOUNT): before the app is built, each plugin's routes are mounted
 * into a scratch instance, in load order. A plugin whose routes throw, or declare a method and
 * path an earlier plugin already declared, is treated like a failed register: its routes, jobs,
 * limit overrides, UI extensions and features are all dropped, it is reported failed, and the
 * server boots without it.
 */
export async function dropPluginsThatFailToMount(
  registry: PluginRegistry,
  logger: Pick<WorkerLogger, 'error'>,
): Promise<void> {
  const declared = new Map<string, string>();
  for (const [name, registrations] of routesByPlugin(registry.routes)) {
    const result = await tryMount(registrations);
    let error: string | null = null;
    if ('error' in result) {
      error = describePluginError(result.error);
    } else {
      const taken = result.routes.find((route) => declared.has(route));
      if (taken) error = `${taken} is already declared by the plugin ${declared.get(taken)}`;
      else for (const route of result.routes) declared.set(route, name);
    }
    if (error !== null) {
      dropPlugin(registry, name, `its routes failed to mount: ${error}`);
      logger.error({ plugin: name, err: error }, 'plugin failed to load');
    }
  }
}

/**
 * enterprise.md §10.3: a job of an inactive feature completes without running. The feature is
 * checked against the same edition the API uses, on every job, so the workers switch a feature
 * off at the same moment as its routes. A handler gets `signal`, aborted at the deadline, when
 * the job fails and its worker slot is freed. With `db`, a scheduled queue (rbac-audit.md §15) is
 * rescheduled `everySeconds` after each run finished: after a skip, a failure or a timeout too,
 * so a feature that comes back on renewal resumes without a restart.
 */
export function pluginJobHandlers(
  plugins: PluginRegistry | LoadedPlugins,
  edition: Edition,
  logger: WorkerLogger,
  options: { timeoutMs?: number; db?: Db } = {},
): JobHandlers {
  const timeoutMs = options.timeoutMs ?? PLUGIN_JOB_TIMEOUT_MS;
  const handlers: Record<string, JobHandlers[string]> = {};
  const frozen = freezePlugins(plugins);
  for (const job of frozen.jobs) {
    const run = runPluginJob(job, edition, logger, timeoutMs);
    const schedule = frozen.schedules.find((s) => s.queue === job.queue);
    const db = options.db;
    handlers[job.queue] =
      schedule && db
        ? async (claimed) => {
            try {
              await run(claimed);
            } finally {
              await ensurePluginScheduled(db, job.queue, schedule.everySeconds);
            }
          }
        : run;
  }
  return Object.freeze(handlers);
}

/** One plugin job: skipped while its feature is inactive, else run within its time limit. */
function runPluginJob(
  job: JobRegistration,
  edition: Edition,
  logger: WorkerLogger,
  timeoutMs: number,
): JobHandlers[string] {
  return async (claimed) => {
    if (!edition.isFeatureActive(job.feature)) {
      logger.info(
        { queue: claimed.queue, jobId: claimed.id, feature: job.feature },
        'skipped: feature not licensed',
      );
      return;
    }
    const controller = new AbortController();
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        const error = new PluginError(
          `the plugin job ${claimed.queue} did not finish within ${timeoutMs / 1000} s`,
        );
        controller.abort(error);
        reject(error);
      }, timeoutMs);
    });
    try {
      await Promise.race([
        Promise.resolve().then(() =>
          job.handler({
            id: claimed.id,
            queue: claimed.queue,
            payload: claimed.payload,
            attempts: claimed.attempts,
            signal: controller.signal,
          }),
        ),
        deadline,
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
}

/**
 * rbac-audit.md §15: makes sure every scheduled queue has its next run waiting, `delay` seconds
 * from now (0 at boot, the queue's interval after a reap, when a run lost to a crashed worker
 * would otherwise leave none).
 */
export async function ensurePluginSchedules(
  db: Db,
  plugins: PluginRegistry | LoadedPlugins,
  delay: 'now' | 'interval',
): Promise<void> {
  for (const s of plugins.schedules) {
    await ensurePluginScheduled(db, s.queue, delay === 'now' ? 0 : s.everySeconds);
  }
}

/** enterprise.md §10.3: one extra worker over every plugin queue, only when a plugin has jobs. */
export function startPluginWorker(options: {
  db: Db;
  plugins: LoadedPlugins;
  edition: Edition;
  logger: WorkerLogger;
}): Worker | null {
  const handlers = pluginJobHandlers(options.plugins, options.edition, options.logger, {
    db: options.db,
  });
  if (Object.keys(handlers).length === 0) return null;
  return startWorker({
    db: options.db,
    handlers,
    concurrency: PLUGIN_WORKER_CONCURRENCY,
    logger: options.logger,
    afterReap: async (db) => {
      await ensurePluginSchedules(db, options.plugins, 'interval');
    },
  });
}
