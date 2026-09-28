import type { FastifyPluginAsync } from 'fastify';
import type { Db } from '../db/client';
import type { EditionPlugins } from '../license/edition';
import { FEATURE_PATTERN, type LicensePayload } from '../license/token';
import { ENTERPRISE_MAX_FIX_PER_DAY, type LlmLimits, type PluginLimitOverride } from '../limits';
import { enqueue } from '../queue/queue';
import {
  PLUGIN_API_VERSION,
  type PluginAccess,
  type PluginAudit,
  type PluginContext,
  type PluginJobHandler,
  type PluginLogger,
  type PluginReport,
  type PluginScim,
  type PluginSso,
  type QualorPlugin,
  type UiExtension,
} from './contract';
import { PLUGIN_SCHEDULE_MAX_SECONDS, PLUGIN_SCHEDULE_MIN_SECONDS } from './schedule';
import type { PluginServices } from './services';

export const PLUGIN_NAME_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
export const PLUGIN_QUEUE_PATTERN = /^ee\.[a-z0-9][a-z0-9.-]{0,62}$/;
export const EXTENSION_ID_PATTERN = /^[a-z][a-z0-9-]{0,31}$/;
/** A plugin declares at most this many features; each name is at most 64 characters (token.ts). */
const MAX_FEATURES = 64;
const MAX_FEATURE_LENGTH = 64;

export interface RouteRegistration {
  plugin: string;
  feature: string;
  routes: FastifyPluginAsync;
}

export interface JobRegistration {
  plugin: string;
  feature: string;
  queue: string;
  handler: PluginJobHandler;
  /** The StagedPlugin instance that registered it (its enqueue checks this, not the name). */
  owner?: symbol;
}

/** rbac-audit.md §15: a plugin queue run every `everySeconds` while its feature is active. */
export interface ScheduleRegistration {
  plugin: string;
  feature: string;
  queue: string;
  everySeconds: number;
}

export interface PluginRegistry extends EditionPlugins {
  reports: PluginReport[];
  features: Set<string>;
  limitOverrides: { feature: string; override: PluginLimitOverride }[];
  extensions: { feature: string; extension: UiExtension }[];
  routes: RouteRegistration[];
  jobs: JobRegistration[];
  schedules: ScheduleRegistration[];
}

export function emptyRegistry(): PluginRegistry {
  return {
    reports: [],
    features: new Set(),
    limitOverrides: [],
    extensions: [],
    routes: [],
    jobs: [],
    schedules: [],
  };
}

export class PluginError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PluginError';
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/**
 * The own enumerable string keys of a plugin-supplied object, each value read exactly once into
 * a plain record. Everything below validates and keeps that record, never the plugin's object,
 * so a getter or a Proxy cannot show one value to validation and another to use.
 */
function snapshot(value: unknown, what: string): Record<string, unknown> {
  if (!isObject(value) || Array.isArray(value)) throw new PluginError(`${what} is not an object`);
  const copy: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
  for (const key of Object.keys(value)) copy[key] = value[key];
  return copy;
}

/** A plugin-supplied array of feature names, read once (its length once, each element once). */
function featureList(value: unknown): readonly string[] {
  if (!Array.isArray(value)) throw new PluginError('invalid features');
  const length: unknown = value.length;
  if (
    typeof length !== 'number' ||
    !Number.isInteger(length) ||
    length < 1 ||
    length > MAX_FEATURES
  ) {
    throw new PluginError(`a plugin declares 1 to ${MAX_FEATURES} features`);
  }
  const features: string[] = [];
  for (let i = 0; i < length; i += 1) {
    const f: unknown = value[i];
    if (typeof f !== 'string' || f.length > MAX_FEATURE_LENGTH || !FEATURE_PATTERN.test(f)) {
      throw new PluginError('invalid features');
    }
    if (features.includes(f)) throw new PluginError(`feature ${f} is declared twice`);
    features.push(f);
  }
  return Object.freeze(features);
}

/**
 * enterprise.md §10: checks a module's default export and returns a frozen, plain copy of it.
 * Each field is read once. `register` is kept bound to the original object, so a plugin written
 * as a class or an object with methods keeps its `this`.
 */
export function validatePlugin(value: unknown): QualorPlugin {
  if (!isObject(value)) throw new PluginError('the module has no default export object');
  const name: unknown = value.name;
  if (typeof name !== 'string' || !PLUGIN_NAME_PATTERN.test(name)) {
    throw new PluginError('invalid plugin name');
  }
  const apiVersion: unknown = value.apiVersion;
  if (apiVersion !== PLUGIN_API_VERSION) {
    throw new PluginError(
      `plugin API version ${typeof apiVersion === 'number' ? apiVersion : typeof apiVersion} is not ${PLUGIN_API_VERSION}`,
    );
  }
  const features = featureList(value.features);
  const register: unknown = value.register;
  if (typeof register !== 'function') throw new PluginError('register is not a function');
  return Object.freeze({
    name,
    apiVersion: PLUGIN_API_VERSION,
    features,
    register: (ctx: PluginContext) =>
      (register as QualorPlugin['register']).call(value, ctx) as Promise<void> | void,
  });
}

/** enterprise.md §10.5: only these LLM limits, within the spec's bounds, checked at registration. */
function validateOverride(value: unknown): PluginLimitOverride {
  const override = snapshot(value, 'a limit override');
  for (const key of Object.keys(override)) {
    if (key !== 'llm') throw new PluginError('a plugin may override only llm limits');
  }
  if (override.llm === undefined) return Object.freeze({});
  const raw = snapshot(override.llm, 'llm');
  const llm: Partial<LlmLimits> = {};
  for (const key of Object.keys(raw)) {
    const v = raw[key];
    if (key === 'maxFixPerOrganizationPerDay') {
      if (
        typeof v !== 'number' ||
        !Number.isInteger(v) ||
        v < 0 ||
        v > ENTERPRISE_MAX_FIX_PER_DAY
      ) {
        throw new PluginError(
          'llm.maxFixPerOrganizationPerDay must be an integer from 0 to 100 000',
        );
      }
      llm.maxFixPerOrganizationPerDay = v;
    } else if (key === 'automaticFixSuggestions') {
      if (typeof v !== 'boolean') {
        throw new PluginError('llm.automaticFixSuggestions must be a boolean');
      }
      llm.automaticFixSuggestions = v;
    } else {
      throw new PluginError(`unknown limit llm.${key}`);
    }
  }
  return Object.freeze({ llm: Object.freeze(llm) });
}

/** enterprise.md §10.4. */
function validateExtension(value: unknown): UiExtension {
  const e = snapshot(value, 'a UI extension');
  const { point, id, label, path } = e;
  const valid =
    Object.keys(e).every((k) => k === 'point' || k === 'id' || k === 'label' || k === 'path') &&
    point === 'settings.nav' &&
    typeof id === 'string' &&
    EXTENSION_ID_PATTERN.test(id) &&
    typeof label === 'string' &&
    label.trim().length >= 1 &&
    label.length <= 40 &&
    path === `/settings/ee/${id}`;
  if (!valid) throw new PluginError('invalid UI extension');
  return Object.freeze({
    point: 'settings.nav',
    id: id as string,
    label: label as string,
    path: path as string,
  });
}

export interface ContextBase {
  serverVersion: string;
  db: Db;
  logger: PluginLogger;
  license: LicensePayload;
  /**
   * rbac-audit.md §15, sso-scim.md §17.1: the access, audit, sso and scim services, built
   * by core (bootEnterprise). A context without them (core tests that load a plugin) gives the
   * plugin stand-ins that throw, naming the missing service.
   */
  services?: PluginServices;
}

function unavailable(name: string): () => never {
  return () => {
    throw new PluginError(`the ${name} service is not available in this context`);
  };
}

const MISSING_ACCESS: PluginAccess = Object.freeze({
  requireUser: unavailable('access'),
  requireInstanceAdmin: unavailable('access'),
  requireOrganizationAccess: unavailable('access'),
  projectForUser: unavailable('access'),
  actor: unavailable('access'),
  problem: unavailable('access'),
});

const MISSING_AUDIT: PluginAudit = Object.freeze({
  query: unavailable('audit'),
  exportLines: unavailable('audit'),
  record: unavailable('audit'),
  head: unavailable('audit'),
  verify: unavailable('audit'),
  settings: unavailable('audit'),
  updateSettings: unavailable('audit'),
  regenerateStreamSecret: unavailable('audit'),
  testStream: unavailable('audit'),
  streamOnce: unavailable('audit'),
});

/** sso-scim.md §17.1: what a context without the 4D services gets (and createPluginServices without their deps). */
export const MISSING_SSO: PluginSso = Object.freeze({
  listConnections: unavailable('sso'),
  getConnection: unavailable('sso'),
  createConnection: unavailable('sso'),
  updateConnection: unavailable('sso'),
  deleteConnection: unavailable('sso'),
  testConnection: unavailable('sso'),
  readSamlMetadata: unavailable('sso'),
  mappings: unavailable('sso'),
  replaceMappings: unavailable('sso'),
  signInSettings: unavailable('sso'),
  updateSignInSettings: unavailable('sso'),
  userIdentities: unavailable('sso'),
  unlinkIdentity: unavailable('sso'),
  spMetadata: unavailable('sso'),
  start: unavailable('sso'),
  startLink: unavailable('sso'),
  oidcCallback: unavailable('sso'),
  samlAcs: unavailable('sso'),
  finish: unavailable('sso'),
});

export const MISSING_SCIM: PluginScim = Object.freeze({
  handle: unavailable('scim'),
  listTokens: unavailable('scim'),
  createToken: unavailable('scim'),
  revokeToken: unavailable('scim'),
});

/**
 * Ruling EE4: everything a plugin registers is validated when it is registered, staged here as a
 * plain copy, and applied only by `commit`. After `commit` or `discard` the registration methods
 * refuse, so a plugin that keeps calling after its `register` timed out or failed changes nothing.
 */
export class StagedPlugin {
  private readonly routeCalls: RouteRegistration[] = [];
  private readonly jobCalls: JobRegistration[] = [];
  private readonly overrideCalls: { feature: string; override: PluginLimitOverride }[] = [];
  private readonly extensionCalls: { feature: string; extension: UiExtension }[] = [];
  private readonly scheduleCalls: ScheduleRegistration[] = [];
  private closed = false;
  /** Identifies this instance's job registrations (enqueue ownership, enterprise.md §10.1). */
  private readonly token = Symbol('plugin');
  /** The registry this instance committed into; null until a successful `commit`. */
  private committedTo: PluginRegistry | null = null;

  constructor(
    private readonly plugin: QualorPlugin,
    registry: PluginRegistry,
  ) {
    if (registry.reports.some((r) => r.name === plugin.name && r.state === 'loaded')) {
      throw new PluginError(`a plugin named ${plugin.name} is already loaded`);
    }
    for (const f of plugin.features) {
      if (registry.features.has(f)) {
        throw new PluginError(`feature ${f} is already implemented by another plugin`);
      }
    }
  }

  private open(): void {
    if (this.closed) {
      throw new PluginError(`${this.plugin.name} may register only while its register() runs`);
    }
  }

  private feature(name: unknown): string {
    this.open();
    if (typeof name !== 'string' || !this.plugin.features.includes(name)) {
      throw new PluginError(`feature ${String(name)} is not declared by ${this.plugin.name}`);
    }
    return name;
  }

  context(base: ContextBase, registry?: PluginRegistry): PluginContext {
    const name = this.plugin.name;
    return Object.freeze({
      apiVersion: PLUGIN_API_VERSION,
      serverVersion: base.serverVersion,
      license: Object.freeze({
        ...base.license,
        features: Object.freeze([...base.license.features]) as string[],
      }),
      logger: base.logger,
      db: base.db,
      routes: (feature: string, routes: FastifyPluginAsync) => {
        const f = this.feature(feature);
        if (typeof routes !== 'function') throw new PluginError('routes is not a function');
        this.routeCalls.push({ plugin: name, feature: f, routes });
      },
      jobs: (feature: string, handlers: Readonly<Record<string, PluginJobHandler>>) => {
        const f = this.feature(feature);
        const copy = snapshot(handlers, 'job handlers');
        const staged: JobRegistration[] = [];
        for (const queue of Object.keys(copy)) {
          const handler = copy[queue];
          if (!PLUGIN_QUEUE_PATTERN.test(queue)) {
            throw new PluginError(`queue ${queue} must match ee.<name>`);
          }
          if (typeof handler !== 'function') {
            throw new PluginError(`the handler of ${queue} is not a function`);
          }
          const taken =
            (registry?.jobs.some((j) => j.queue === queue) ?? false) ||
            this.jobCalls.some((j) => j.queue === queue);
          if (taken) throw new PluginError(`queue ${queue} is already registered`);
          staged.push({
            plugin: name,
            feature: f,
            queue,
            handler: handler as PluginJobHandler,
            owner: this.token,
          });
        }
        this.jobCalls.push(...staged);
      },
      enqueue: async (queue: string, payload: unknown) => {
        // Ownership is this instance's committed registration, never a name: a failed or
        // discarded plugin enqueues nothing, even under the name of a loaded one.
        // A registration dropped later (a route that failed to mount, ruling R-MOUNT) no longer
        // counts either.
        const own =
          typeof queue === 'string' &&
          (this.committedTo?.jobs.some((j) => j.queue === queue && j.owner === this.token) ??
            false);
        if (!own) throw new PluginError(`${name} may not enqueue on ${String(queue)}`);
        return enqueue(base.db, { queue, payload });
      },
      limits: (feature: string, override: PluginLimitOverride) => {
        const f = this.feature(feature);
        this.overrideCalls.push({ feature: f, override: validateOverride(override) });
      },
      ui: (feature: string, extension: UiExtension) => {
        const f = this.feature(feature);
        this.extensionCalls.push({ feature: f, extension: validateExtension(extension) });
      },
      access: base.services?.access ?? MISSING_ACCESS,
      audit: base.services?.audit ?? MISSING_AUDIT,
      sso: base.services?.sso ?? MISSING_SSO,
      scim: base.services?.scim ?? MISSING_SCIM,
      schedule: (feature: string, queue: string, everySeconds: number) => {
        const f = this.feature(feature);
        if (typeof queue !== 'string' || !PLUGIN_QUEUE_PATTERN.test(queue)) {
          throw new PluginError(`queue ${String(queue)} must match ee.<name>`);
        }
        if (
          typeof everySeconds !== 'number' ||
          !Number.isInteger(everySeconds) ||
          everySeconds < PLUGIN_SCHEDULE_MIN_SECONDS ||
          everySeconds > PLUGIN_SCHEDULE_MAX_SECONDS
        ) {
          throw new PluginError(
            `a schedule runs every ${PLUGIN_SCHEDULE_MIN_SECONDS} to ${PLUGIN_SCHEDULE_MAX_SECONDS} whole seconds`,
          );
        }
        if (this.scheduleCalls.some((s) => s.queue === queue)) {
          throw new PluginError(`queue ${queue} is already scheduled`);
        }
        this.scheduleCalls.push({ plugin: name, feature: f, queue, everySeconds });
      },
    });
  }

  /** The plugin failed or timed out: nothing it staged is applied, and it may stage no more. */
  discard(): void {
    this.closed = true;
    this.routeCalls.length = 0;
    this.jobCalls.length = 0;
    this.overrideCalls.length = 0;
    this.extensionCalls.length = 0;
    this.scheduleCalls.length = 0;
  }

  commit(registry: PluginRegistry): void {
    this.open();
    this.closed = true;
    // Checked again here: the registry may have changed since the constructor ran.
    if (registry.reports.some((r) => r.name === this.plugin.name && r.state === 'loaded')) {
      throw new PluginError(`a plugin named ${this.plugin.name} is already loaded`);
    }
    for (const f of this.plugin.features) {
      if (registry.features.has(f)) {
        throw new PluginError(`feature ${f} is already implemented by another plugin`);
      }
    }
    for (const j of this.jobCalls) {
      if (registry.jobs.some((r) => r.queue === j.queue)) {
        throw new PluginError(`queue ${j.queue} is already registered`);
      }
    }
    // A schedule names a queue this instance registered, before or after the schedule call.
    for (const s of this.scheduleCalls) {
      if (!this.jobCalls.some((j) => j.queue === s.queue)) {
        throw new PluginError(
          `${this.plugin.name} schedules ${s.queue}, a queue it did not register`,
        );
      }
    }
    registry.routes.push(...this.routeCalls);
    registry.jobs.push(...this.jobCalls);
    registry.limitOverrides.push(...this.overrideCalls);
    registry.extensions.push(...this.extensionCalls);
    registry.schedules.push(...this.scheduleCalls);
    for (const f of this.plugin.features) registry.features.add(f);
    this.committedTo = registry;
    registry.reports.push({
      name: this.plugin.name,
      state: 'loaded',
      features: [...this.plugin.features],
      error: null,
    });
  }
}
