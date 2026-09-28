import { execFile, spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildServer } from '../../server/scripts/bundle';
import { createTestDatabase, type TestDatabase } from '../../server/test/db';
import { E2E_SIGNER, signCurrent } from '../../server/test/license-e2e-key';
import { formOf, TinyBrowser } from './browser';
import {
  type Keycloak,
  type Realm,
  samlClientFor,
  samlIdpCertificate,
  splitRealm,
  startKeycloak,
} from './keycloak';

/**
 * Plan 4D Task 20, sso-scim.md §19.4: OIDC and SAML end to end against Keycloak 26.7.4 in Docker
 * (pinned by digest, on 127.0.0.1 only), and the test server bundle with a `test-` licence listing
 * `sso`, `scim` and `audit-log` and the enterprise plugin built from enterprise/src. Only
 * `pnpm sso:keycloak` runs it (vitest.config.ts, tools/live-checks.test.ts). Nothing leaves the
 * machine: the server reaches Keycloak through QUALOR_SSO_INTERNAL_HOSTS, and the browser is
 * {@link TinyBrowser}. No secret, code, state or assertion is printed; a failed flow names the
 * path and the page title only.
 */
const run = promisify(execFile);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
/** One level below server/, like dist/main.js, so the bundle finds ../drizzle; never in an image. */
const MAIN = path.join(root, 'server', '.tmp', 'keycloak-main.js');
/** In enterprise/, so the plugin's npm dependencies resolve from its node_modules. */
const PLUGIN = path.join(root, 'enterprise', '.tmp', 'keycloak-plugin.js');
const REALM_FILE = path.join(root, 'tools', 'sso', 'realm-qualor.json');

const OIDC_SECRET = 'keycloak-test-secret';
const USERS = {
  alice: { username: 'alice', password: 'alice-password-1' },
  bob: { username: 'bob', password: 'bob-password-1' },
  carol: { username: 'carol', password: 'carol-password-1' },
} as const;
const ADMIN_PASSWORD = `kc-admin-${randomBytes(12).toString('hex')}`;
const BOBBY_PASSWORD = `bobby-${randomBytes(12).toString('hex')}`;

/**
 * Active on the real clock (the fixture's T0 lies in the future), with the 4D features and
 * `sso.multi`: the OIDC and the SAML connection are enabled together (sso-scim.md §4.4).
 */
const licence = (): string => signCurrent(E2E_SIGNER, ['sso', 'sso.multi', 'scim', 'audit-log']);

/** A port free on 127.0.0.1 now: the server keeps it across its restart, so the URLs stay. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

/** The enterprise plugin, bundled by its own script (assertEnterpriseInputs) into enterprise/.tmp. */
async function buildPlugin(): Promise<void> {
  const script = `import('./scripts/bundle.ts').then((m) => m.buildEnterprise({ outfile: ${JSON.stringify(
    PLUGIN,
  )} }))`;
  await run(process.execPath, ['--import', 'tsx', '-e', script], {
    cwd: path.join(root, 'enterprise'),
  });
}

interface Server {
  url: string;
  /** The last lines the server wrote, for a failure's message. */
  output(): string;
  stop(): Promise<void>;
}

async function startServer(
  env: Record<string, string>,
  extra: Record<string, string> = {},
): Promise<Server> {
  const child: ChildProcess = spawn(process.execPath, [MAIN], {
    env: { ...env, ...extra },
    // 'ipc': on Windows a child cannot receive SIGTERM; main.ts shuts down on 'shutdown'.
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  const lines: string[] = [];
  const keep = (chunk: Buffer): void => {
    lines.push(...chunk.toString('utf8').split('\n').filter(Boolean));
    if (lines.length > 200) lines.splice(0, lines.length - 200);
  };
  child.stderr?.on('data', keep);
  const url = await new Promise<string>((resolve, reject) => {
    child.stdout?.on('data', (chunk: Buffer) => {
      keep(chunk);
      const match = /Server listening at (http:\/\/127\.0\.0\.1:\d+)/.exec(lines.join('\n'));
      if (match?.[1]) resolve(match[1]);
    });
    child.once('exit', (code) =>
      reject(new Error(`server exited (${code}):\n${lines.slice(-40).join('\n')}`)),
    );
  });
  return {
    url,
    output: () => lines.slice(-60).join('\n'),
    stop: () =>
      new Promise<void>((resolve) => {
        if (child.exitCode !== null || child.signalCode !== null) return resolve();
        const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
        if (process.platform === 'win32') child.send('shutdown');
        else child.kill('SIGTERM');
      }),
  };
}

/** An API caller with a session: the cookie, and the CSRF token on every write. */
class Api {
  private csrf = '';

  constructor(
    private readonly base: string,
    private cookie = '',
  ) {}

  static async login(base: string, username: string, password: string): Promise<Api> {
    const res = await passwordLogin(base, username, password);
    if (res.status !== 204) throw new Error(`login as ${username}: ${res.status}`);
    const session = /qualor_session=([^;]+)/.exec(res.headers.get('set-cookie') ?? '')?.[1];
    if (!session) throw new Error('the login set no session cookie');
    return Api.withSession(base, session);
  }

  static async withSession(base: string, session: string): Promise<Api> {
    const api = new Api(base, `qualor_session=${session}`);
    api.csrf = (await api.json<{ csrfToken: string }>('GET', '/api/v0/auth/me')).csrfToken;
    return api;
  }

  async json<T>(method: string, route: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}${route}`, {
      method,
      headers: {
        cookie: this.cookie,
        ...(method === 'GET' ? {} : { 'x-qualor-csrf': this.csrf }),
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${route}: ${res.status} ${text.slice(0, 500)}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

function passwordLogin(base: string, username: string, password: string): Promise<Response> {
  return fetch(`${base}/api/v0/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
}

/** A page's `<title>` and Keycloak's message, never its URL's query (codes, states). */
function describePage(page: { url: string; status: number; body: string }): string {
  const title = /<title>([^<]*)<\/title>/i.exec(page.body)?.[1]?.trim() ?? '';
  const message =
    /class="[^"]*(?:kc-feedback-text|alert-error|instruction)[^"]*"[^>]*>([^<]*)</i
      .exec(page.body)?.[1]
      ?.trim() ?? '';
  return `${new URL(page.url).pathname} answered ${page.status} (${title}${message ? `: ${message}` : ''})`;
}

/**
 * Signs in as a person would in a browser: the start URL, Keycloak's login form, Keycloak's
 * SAML POST page (submitted as its script would), every redirect, until the flow leaves the API
 * for a page of the server (`/` or `/login?sso_error=…`). Answers that final location.
 */
async function signIn(
  browser: TinyBrowser,
  startUrl: string,
  user: { username: string; password: string },
): Promise<string> {
  const server = new URL(startUrl).origin;
  let page = await browser.get(startUrl);
  for (let step = 0; step < 30; step += 1) {
    if (page.location !== null) {
      const next = new URL(page.location);
      if (next.origin === server && !next.pathname.startsWith('/api/')) return page.location;
      page = await browser.get(page.location);
    } else if (page.status === 200 && /id="kc-form-login"/.test(page.body)) {
      const form = formOf(page.body, 'kc-form-login', page.url);
      page = await browser.postForm(form.action, {
        ...form.fields,
        username: user.username,
        password: user.password,
      });
    } else if (page.status === 200 && /name="SAMLResponse"/.test(page.body)) {
      const form = formOf(page.body, 'saml-post-binding', page.url);
      expect(Object.keys(form.fields)).toContain('SAMLResponse');
      page = await browser.postForm(form.action, form.fields);
    } else {
      throw new Error(`the sign-in stopped: ${describePage(page)}`);
    }
  }
  throw new Error('the sign-in did not end after 30 steps');
}

interface Me {
  user: { id: string; username: string; email: string | null; hasPassword: boolean };
  memberships: { organizationKey: string; role: string | null }[];
  projectGrants: { projectKey: string; role: string }[];
}

/** The signed-in person's `/auth/me`, through the session cookie the browser holds. */
async function meOf(browser: TinyBrowser, server: string): Promise<Me> {
  const session = browser.cookie(new URL(server).host, 'qualor_session');
  expect(session, 'a qualor_session cookie').toBeTruthy();
  const api = await Api.withSession(server, session ?? '');
  return api.json<Me>('GET', '/api/v0/auth/me');
}

const roleIn = (me: Me, organizationKey: string): string | null =>
  me.memberships.find((m) => m.organizationKey === organizationKey)?.role ?? null;

describe('Keycloak 26.7.4 in Docker: OIDC and SAML end to end (sso-scim.md §19.4)', () => {
  let keycloak: Keycloak | undefined;
  let database: TestDatabase | undefined;
  let server: Server | undefined;
  let port = 0;
  let env: Record<string, string> = {};
  let samlTemplate: ReturnType<typeof splitRealm>['samlClient'];
  let admin: Api;
  let adminId = '';
  let organizationId = '';
  let oidcId = '';
  let aliceId = '';
  let bobbyId = '';
  const started = Date.now();

  beforeAll(async () => {
    port = await freePort();
    const split = splitRealm(JSON.parse(readFileSync(REALM_FILE, 'utf8')) as Realm, port);
    samlTemplate = split.samlClient;
    const [kc, ...builds] = await Promise.allSettled([
      startKeycloak(split.realm),
      buildServer({ outfile: MAIN, testLicenseKeys: { [E2E_SIGNER.kid]: E2E_SIGNER.x } }),
      buildPlugin(),
    ]);
    // Kept before anything can throw, so afterAll removes the container.
    if (kc.status === 'fulfilled') keycloak = kc.value;
    for (const result of [kc, ...builds]) if (result.status === 'rejected') throw result.reason;
    if (!keycloak) throw new Error('Keycloak did not start');
    const kcHost = new URL(keycloak.baseUrl).host;
    database = await createTestDatabase({ migrated: false });
    env = {
      PATH: process.env.PATH ?? '',
      SYSTEMROOT: process.env.SYSTEMROOT ?? '', // Windows needs it for sockets
      DATABASE_URL: database.url,
      QUALOR_SECRET_KEY: `keycloak-check-${randomBytes(24).toString('hex')}`,
      QUALOR_BOOTSTRAP_ADMIN_USERNAME: 'admin',
      QUALOR_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PASSWORD,
      QUALOR_LOG_LEVEL: 'info',
      HOST: '127.0.0.1',
      PORT: String(port),
      QUALOR_PUBLIC_URL: `http://127.0.0.1:${port}`,
      QUALOR_SSO_INTERNAL_HOSTS: kcHost,
      QUALOR_LICENSE: licence(),
      QUALOR_PLUGIN_PATHS: PLUGIN,
    };
    server = await startServer(env);
    admin = await Api.login(server.url, 'admin', ADMIN_PASSWORD);
    adminId = (await admin.json<Me>('GET', '/api/v0/auth/me')).user.id;
  });

  afterAll(async () => {
    await server?.stop();
    await keycloak?.stop();
    await database?.close();
    process.stdout.write(
      `keycloak check: ${Math.round((Date.now() - started) / 1000)} s after the image was present\n`,
    );
  });

  /** On a failed step, the server's last lines (fixed-field JSON; it never logs a secret). */
  const withServerLog = async (step: () => Promise<void>): Promise<void> => {
    try {
      await step();
    } catch (err) {
      process.stderr.write(`--- server output ---\n${server?.output() ?? ''}\n`);
      throw err;
    }
  };

  const startUrl = (connectionId: string): string =>
    `${server?.url ?? ''}/api/v0/ee/sso/${connectionId}/start`;
  const identitiesOf = (userId: string) =>
    admin.json<{ connectionId: string }[]>('GET', `/api/v0/ee/sso/users/${userId}/identities`);

  it('the bootstrap admin creates the OIDC connection and its group mappings, and enables it', () =>
    withServerLog(async () => {
      const kc = keycloak!;
      const orgs = await admin.json<{ items: { id: string; key: string }[] }>(
        'GET',
        '/api/v0/organizations',
      );
      const org = orgs.items.find((o) => o.key === 'default') ?? orgs.items[0];
      organizationId = org!.id;
      const project = await admin.json<{ id: string }>('POST', '/api/v0/projects', {
        organizationId,
        key: 'payments',
        name: 'Payments',
      });
      const created = await admin.json<{ id: string; enabled: boolean }>(
        'POST',
        '/api/v0/ee/sso/connections',
        {
          name: 'Keycloak',
          protocol: 'oidc',
          enabled: false,
          linkByEmail: true,
          groupSource: 'claims',
          claims: { groups: 'groups' },
          oidc: { issuer: kc.realmUrl, clientId: 'qualor-oidc', clientSecret: OIDC_SECRET },
        },
      );
      oidcId = created.id;
      expect(created.enabled).toBe(false);
      const test = await admin.json<{ ok: boolean; problem: unknown }>(
        'POST',
        `/api/v0/ee/sso/connections/${oidcId}/test`,
      );
      expect(test).toMatchObject({ ok: true, problem: null });
      const mappings = await admin.json<unknown[]>(
        'PUT',
        `/api/v0/ee/sso/connections/${oidcId}/mappings`,
        [
          { group: 'qualor-admins', organizationId, projectId: null, role: 'admin' },
          { group: 'qualor-devs', organizationId, projectId: project.id, role: 'viewer' },
        ],
      );
      expect(mappings).toHaveLength(2);
      const enabled = await admin.json<{ enabled: boolean; configValid: boolean }>(
        'PATCH',
        `/api/v0/ee/sso/connections/${oidcId}`,
        { enabled: true },
      );
      expect(enabled).toMatchObject({ enabled: true, configValid: true });
      const methods = await admin.json<{ providers: { id: string }[] }>(
        'GET',
        '/api/v0/auth/methods',
      );
      expect(methods.providers.map((p) => p.id)).toEqual([oidcId]);
    }));

  it('OIDC: alice signs in through the login form and is admin of default by her group', () =>
    withServerLog(async () => {
      const browser = new TinyBrowser();
      const end = await signIn(browser, startUrl(oidcId), USERS.alice);
      expect(end).toBe(`${server!.url}/`);
      const me = await meOf(browser, server!.url);
      expect(me.user.username).toBe('alice');
      expect(roleIn(me, 'default')).toBe('admin');
      aliceId = me.user.id;
      // Keycloak's cookies stayed with Keycloak, Qualor's with Qualor.
      const qualorHost = new URL(server!.url).host;
      expect(browser.cookies(qualorHost).map((c) => c.name)).not.toContain('KEYCLOAK_IDENTITY');
    }));

  it('a second sign-in re-uses the identity', () =>
    withServerLog(async () => {
      expect(await identitiesOf(aliceId)).toHaveLength(1);
      const browser = new TinyBrowser();
      expect(await signIn(browser, startUrl(oidcId), USERS.alice)).toBe(`${server!.url}/`);
      expect((await meOf(browser, server!.url)).user.id).toBe(aliceId);
      expect(await identitiesOf(aliceId)).toHaveLength(1);
    }));

  // sso-scim.md §8.3-§8.4 and §19.4: an unverified email never links (bobby keeps no identity),
  // is not stored, and so collides with nothing (refuses only a verified one): bob gets a
  // JIT account of his own without an email, and his group makes him a viewer of the project.
  it('bob, whose email Keycloak has not verified, is not linked to bobby: JIT, no email, a project viewer', () =>
    withServerLog(async () => {
      const bobby = await admin.json<{ id: string }>('POST', '/api/v0/users', {
        username: 'bobby',
        password: BOBBY_PASSWORD,
        email: 'bob@acme.example',
      });
      bobbyId = bobby.id;
      const browser = new TinyBrowser();
      expect(await signIn(browser, startUrl(oidcId), USERS.bob)).toBe(`${server!.url}/`);
      const me = await meOf(browser, server!.url);
      expect(me.user).toMatchObject({ username: 'bob', email: null, hasPassword: false });
      expect(me.user.id).not.toBe(bobbyId);
      expect(me.projectGrants).toEqual([
        expect.objectContaining({ projectKey: 'payments', role: 'viewer' }),
      ]);
      expect(roleIn(me, 'default')).toBeNull();
      expect(await identitiesOf(bobbyId)).toHaveLength(0);
    }));

  it('alice leaves qualor-admins in Keycloak: her next sign-in removes the managed admin role', () =>
    withServerLog(async () => {
      await keycloak!.admin.removeFromGroup('alice', 'qualor-admins');
      const browser = new TinyBrowser();
      expect(await signIn(browser, startUrl(oidcId), USERS.alice)).toBe(`${server!.url}/`);
      const me = await meOf(browser, server!.url);
      expect(me.user.id).toBe(aliceId);
      expect(roleIn(me, 'default')).toBeNull();
    }));

  it("SAML: alice links by her verified email through Keycloak's POST form and the finish step; carol is JIT", () =>
    withServerLog(async () => {
      const kc = keycloak!;
      const created = await admin.json<{
        id: string;
        urls: { entityId: string; acsUrl: string } | null;
      }>('POST', '/api/v0/ee/sso/connections', {
        name: 'Keycloak SAML',
        protocol: 'saml',
        enabled: true,
        linkByEmail: true,
        saml: {
          idpEntityId: kc.realmUrl,
          idpSsoUrl: `${kc.realmUrl}/protocol/saml`,
          idpCertificates: [await samlIdpCertificate(kc.realmUrl)],
          // Keycloak verifies the email of every user of this realm but bob.
          emailVerified: true,
        },
      });
      const client = samlClientFor(samlTemplate, port, created.id);
      expect(created.urls?.entityId).toBe(client.clientId);
      await kc.admin.addClient(client);
      const browser = new TinyBrowser();
      expect(await signIn(browser, startUrl(created.id), USERS.alice)).toBe(`${server!.url}/`);
      const me = await meOf(browser, server!.url);
      expect(me.user.id).toBe(aliceId);
      const identities = await identitiesOf(aliceId);
      expect(identities.map((i) => i.connectionId).sort()).toEqual([oidcId, created.id].sort());

      // JIT through SAML: carol has no Qualor account and no group.
      const carol = new TinyBrowser();
      expect(await signIn(carol, startUrl(created.id), USERS.carol)).toBe(`${server!.url}/`);
      const carolMe = await meOf(carol, server!.url);
      expect(carolMe.user).toMatchObject({ email: 'carol@acme.example', hasPassword: false });
      // §8.4: without a username attribute, SAML's username is the NameID: Keycloak's persistent
      // one is opaque (G-<uuid>), so the guide tells admins to send a username attribute.
      expect(carolMe.user.username).toMatch(/^G-[0-9a-f-]{36}$/);
      expect(carolMe.memberships).toEqual([]);
      expect(carolMe.projectGrants).toEqual([]);
    }));

  it("break_glass_only refuses bobby's password; QUALOR_FORCE_PASSWORD_SIGN_IN=true lets him in", () =>
    withServerLog(async () => {
      const settings = await admin.json<{ passwordSignIn: string }>(
        'PUT',
        '/api/v0/ee/sso/settings',
        { passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId] },
      );
      expect(settings.passwordSignIn).toBe('break_glass_only');
      expect((await passwordLogin(server!.url, 'bobby', BOBBY_PASSWORD)).status).toBe(401);
      expect((await passwordLogin(server!.url, 'admin', ADMIN_PASSWORD)).status).toBe(204);

      await server!.stop();
      server = await startServer(env, { QUALOR_FORCE_PASSWORD_SIGN_IN: 'true' });
      expect((await passwordLogin(server.url, 'bobby', BOBBY_PASSWORD)).status).toBe(204);
      admin = await Api.login(server.url, 'admin', ADMIN_PASSWORD);
    }));

  it('the audit chain verifies', () =>
    withServerLog(async () => {
      const verify = await admin.json<{ ok: boolean; checked: number }>(
        'GET',
        '/api/v0/ee/audit/verify',
      );
      expect(verify.ok).toBe(true);
      expect(verify.checked).toBeGreaterThan(0);
    }));
});
