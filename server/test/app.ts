import { eq } from 'drizzle-orm';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { buildApp } from '../src/app';
import type { AuditRecorder } from '../src/audit/recorder';
import { bootstrap } from '../src/auth/bootstrap';
import { hashPassword } from '../src/auth/password';
import { SESSION_COOKIE } from '../src/auth/sessions';
import type { Config } from '../src/config';
import type { Db } from '../src/db/client';
import { memberships, type OrganizationRole, organizations, users } from '../src/db/schema';
import { createLogger } from '../src/http/logger';
import type { Edition } from '../src/license/edition';
import type { Limits } from '../src/limits';
import { freezePlugins, type LoadedPlugins } from '../src/plugins/mount';
import type { PluginRegistry } from '../src/plugins/registry';
import { testConfig } from './config';
import { createTestDatabase, type TestDatabase } from './db';

export const ADMIN_PASSWORD = 'correct horse battery staple';
export const DEFAULT_TEST_PASSWORD = 'a perfectly fine passphrase';

export interface TestContext {
  app: FastifyInstance;
  db: Db;
  database: TestDatabase;
  config: Config;
  /** Every log line the app wrote (level info), for redaction checks. */
  logs: string[];
  adminId: string;
  /** The frozen plugins the app mounted, when `pluginsFor` was given. */
  plugins?: LoadedPlugins;
  /** The edition the app runs with, when `pluginsFor` or `edition` was given. */
  edition?: Edition;
  close(): Promise<void>;
}

/** A migrated database clone, bootstrapped (`default` org + `admin`), and an app on top. */
export async function createTestContext(
  options: {
    config?: Partial<Config>;
    limits?: Limits;
    /** A run-time edition (enterprise.md §7); takes precedence over `limits`. */
    edition?: Edition;
    /**
     * Loads plugins against the test database before the app is built (enterprise.md §10). Give
     * `edition` as a function to build it from the frozen copy the app mounts, as main.ts does
     * (bootEnterprise's result fits as it is). `audit` is the recorder the plugin services record
     * through, given to the app as main.ts does.
     */
    pluginsFor?: (
      db: Db,
      config: Config,
      /** The app's logger (its lines land in `logs`), for the recorder, as main.ts gives it. */
      logger: FastifyBaseLogger,
    ) => Promise<{
      plugins: PluginRegistry | LoadedPlugins;
      edition: Edition | ((frozen: LoadedPlugins) => Edition);
      audit?: AuditRecorder;
    }>;
    /** Runs before the app is ready: the only moment it takes hooks. */
    beforeReady?: (app: FastifyInstance) => void;
  } = {},
): Promise<TestContext> {
  const database = await createTestDatabase();
  const config = testConfig({ databaseUrl: database.url, ...options.config });
  await bootstrap(database.db, { username: 'admin', password: ADMIN_PASSWORD });
  const logs: string[] = [];
  const logger = createLogger('info', {
    write: (line: string) => {
      logs.push(line);
    },
  });
  const loaded = options.pluginsFor
    ? await options.pluginsFor(database.db, config, logger)
    : undefined;
  const plugins = loaded ? freezePlugins(loaded.plugins) : undefined;
  const edition =
    loaded && plugins
      ? typeof loaded.edition === 'function'
        ? loaded.edition(plugins)
        : loaded.edition
      : options.edition;
  const app = await buildApp({
    config,
    db: database.db,
    logger,
    limits: options.limits,
    edition,
    plugins,
    ...(loaded?.audit ? { audit: loaded.audit } : {}),
    checkReady: async () => true,
  });
  options.beforeReady?.(app);
  await app.ready();
  const [admin] = await database.db.select().from(users).where(eq(users.username, 'admin'));
  return {
    app,
    db: database.db,
    database,
    config,
    logs,
    adminId: admin!.id,
    plugins,
    edition,
    close: async () => {
      await app.close();
      await database.close();
    },
  };
}

let ipCounter = 0;
/** A fresh client address per call, so the per-IP login limit never trips by accident. */
export function nextIp(): string {
  ipCounter += 1;
  return `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter & 255}`;
}

export interface Session {
  cookie: string;
  csrf: string;
  /** Cookie + CSRF header, ready for app.inject({ headers }). */
  headers: Record<string, string>;
}

export async function login(
  ctx: TestContext,
  username: string,
  password: string,
): Promise<Session> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/api/v0/auth/login',
    payload: { username, password },
    remoteAddress: nextIp(),
  });
  if (res.statusCode !== 204)
    throw new Error(`login as ${username} failed: ${res.statusCode} ${res.body}`);
  const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)?.value;
  if (!cookie) throw new Error('login set no session cookie');
  const me = await ctx.app.inject({
    method: 'GET',
    url: '/api/v0/auth/me',
    cookies: { [SESSION_COOKIE]: cookie },
  });
  const csrf = (me.json() as { csrfToken: string }).csrfToken;
  return {
    cookie,
    csrf,
    headers: { cookie: `${SESSION_COOKIE}=${cookie}`, 'x-qualor-csrf': csrf },
  };
}

export interface CreatedUser {
  id: string;
  username: string;
  password: string;
}

export async function createUser(
  ctx: TestContext,
  input: {
    username: string;
    password?: string;
    email?: string | null;
    isInstanceAdmin?: boolean;
    passwordChangeRequired?: boolean;
    active?: boolean;
  },
): Promise<CreatedUser> {
  const password = input.password ?? DEFAULT_TEST_PASSWORD;
  const [user] = await ctx.db
    .insert(users)
    .values({
      username: input.username,
      passwordHash: await hashPassword(password),
      email: input.email ?? null,
      isInstanceAdmin: input.isInstanceAdmin ?? false,
      passwordChangeRequired: input.passwordChangeRequired ?? false,
      active: input.active ?? true,
    })
    .returning();
  return { id: user!.id, username: input.username, password };
}

export function bearer(token: string): Record<string, string> {
  return { authorization: `Bearer ${token}` };
}

export async function organizationId(ctx: TestContext, key: string): Promise<string> {
  const [org] = await ctx.db.select().from(organizations).where(eq(organizations.key, key));
  return org!.id;
}

export async function addMember(
  ctx: TestContext,
  organization: string,
  userId: string,
  role: OrganizationRole,
): Promise<void> {
  await ctx.db.insert(memberships).values({ organizationId: organization, userId, role });
}

export async function createProject(
  ctx: TestContext,
  session: Session,
  input: { organizationId: string; key: string; name?: string; mainBranchName?: string },
): Promise<{ id: string; key: string }> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/api/v0/projects',
    headers: session.headers,
    payload: { name: input.key, ...input },
  });
  if (res.statusCode !== 201)
    throw new Error(`createProject failed: ${res.statusCode} ${res.body}`);
  return res.json();
}

export async function createProjectToken(
  ctx: TestContext,
  session: Session,
  projectId: string,
): Promise<string> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: `/api/v0/projects/${projectId}/tokens`,
    headers: session.headers,
    payload: { name: 'ci' },
  });
  if (res.statusCode !== 201)
    throw new Error(`createProjectToken failed: ${res.statusCode} ${res.body}`);
  return (res.json() as { token: string }).token;
}
