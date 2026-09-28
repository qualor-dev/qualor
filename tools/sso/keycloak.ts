import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { KEYCLOAK_IMAGE } from './keycloak-image';

/** Runs a command; the default is execFile. A failure's message may hold the whole command line. */
export type Runner = (file: string, args: string[]) => Promise<{ stdout: string; stderr: string }>;
const execFileAsync = promisify(execFile);
const defaultRunner: Runner = (file, args) => execFileAsync(file, args);

/** The realm file's clients name these; {@link splitRealm} and {@link samlClientFor} fill them in. */
export const SAML_PLACEHOLDERS = { port: 'QUALOR_PORT', connection: 'CONNECTION' } as const;
const REALM = 'qualor';
const DIR_PREFIX = 'qualor-kc-';
const READY_ATTEMPTS = 180;

interface RealmClient {
  clientId: string;
  protocol: string;
  [key: string]: unknown;
}
export interface Realm {
  realm: string;
  clients: RealmClient[];
  [key: string]: unknown;
}

export interface Keycloak {
  baseUrl: string;
  realmUrl: string;
  /** The container's name (`qualor-kc-…`). */
  name: string;
  admin: KeycloakAdmin;
  stop(): Promise<void>;
}

/**
 * sso-scim.md §19.4: the realm Keycloak imports at start, for the server on `port`, and its SAML
 * client apart. Keycloak matches a redirect URI's port exactly (a `*` port is refused), so the
 * OIDC client's names the real one. The SAML client's id is Qualor's SP entity id, which also
 * names the connection id, known only once the connection exists, so that client is added later
 * through the admin API ({@link samlClientFor}).
 */
export function splitRealm(realm: Realm, port: number): { realm: Realm; samlClient: RealmClient } {
  const samlClient = realm.clients.find((c) => c.protocol === 'saml');
  if (!samlClient) throw new Error('the realm has no SAML client');
  const others = JSON.stringify(realm.clients.filter((c) => c.protocol !== 'saml'));
  const clients = JSON.parse(
    others.replaceAll(SAML_PLACEHOLDERS.port, String(port)),
  ) as RealmClient[];
  return { realm: { ...realm, clients }, samlClient };
}

/** The SAML client for the server on `port` and the connection `connectionId`. */
export function samlClientFor(
  template: RealmClient,
  port: number,
  connectionId: string,
): RealmClient {
  const text = JSON.stringify(template)
    .replaceAll(SAML_PLACEHOLDERS.port, String(port))
    .replaceAll(SAML_PLACEHOLDERS.connection, connectionId);
  if (/QUALOR_PORT|CONNECTION/.test(text)) throw new Error('a SAML placeholder was left');
  return JSON.parse(text) as RealmClient;
}

/**
 * Global Constraints: the realm directory is a plain directory this process created in the
 * system's temporary directory. It is removed only after `lstat` shows a directory that is not a
 * symbolic link or a junction (Node reports a junction as a symbolic link), named as mkdtemp
 * named it, directly in the temporary directory.
 */
export async function removeRealmDir(dir: string): Promise<void> {
  const info = await lstat(dir).catch(() => null);
  if (info === null) return;
  if (info.isSymbolicLink() || !info.isDirectory()) {
    throw new Error(`refusing to remove ${dir}: not a plain directory`);
  }
  if (resolve(dirname(dir)) !== resolve(tmpdir()) || !basename(dir).startsWith(DIR_PREFIX)) {
    throw new Error(`refusing to remove ${dir}: not a realm directory of this harness`);
  }
  await rm(dir, { recursive: true });
}

async function containerLogs(run: Runner, name: string): Promise<string> {
  const logs = await run('docker', ['logs', '--tail', '40', name]).catch(() => null);
  return logs ? `${logs.stdout}${logs.stderr}` : '(no logs)';
}

/**
 * sso-scim.md §19.4: Keycloak (pinned by digest) on 127.0.0.1 only, the realm imported, the
 * container named `qualor-kc-…` and removed by `stop()` (also when the start fails). The bootstrap
 * admin's password is random per run and never printed: it reaches Docker only through an
 * `--env-file` (mode 0600, in the checked temporary directory, removed with it), never on a
 * command line, which a failed `docker run`'s error message would repeat. The realm sits in the
 * directory's `realm/` subdirectory, the only part mounted into the container.
 */
export async function startKeycloak(
  realm: Realm,
  options: { run?: Runner } = {},
): Promise<Keycloak> {
  const run = options.run ?? defaultRunner;
  const dir = await mkdtemp(join(tmpdir(), DIR_PREFIX));
  const name = `${DIR_PREFIX}${process.pid}-${Date.now()}`;
  const adminPassword = randomBytes(18).toString('base64url');
  const stop = async (): Promise<void> => {
    await run('docker', ['rm', '-f', name]).catch(() => undefined);
    await removeRealmDir(dir);
  };
  try {
    const realmDir = join(dir, 'realm');
    await mkdir(realmDir);
    const file = join(realmDir, `${REALM}.json`);
    await writeFile(file, JSON.stringify(realm));
    // Keycloak runs as its own user in the container; on a POSIX host it must read the realm.
    await chmod(dir, 0o755);
    await chmod(realmDir, 0o755);
    await chmod(file, 0o644);
    // Read by the docker CLI only, as this user; never mounted.
    const envFile = join(dir, 'admin.env');
    await writeFile(
      envFile,
      `KC_BOOTSTRAP_ADMIN_USERNAME=admin
KC_BOOTSTRAP_ADMIN_PASSWORD=${adminPassword}
`,
      { mode: 0o600 },
    );
    await chmod(envFile, 0o600);
    await run('docker', [
      'run',
      '-d',
      '--rm',
      '--name',
      name,
      '-p',
      '127.0.0.1::8080',
      '--env-file',
      envFile,
      '--mount',
      `type=bind,source=${realmDir},target=/opt/keycloak/data/import,readonly`,
      KEYCLOAK_IMAGE,
      'start-dev',
      '--import-realm',
    ]);
    const { stdout } = await run('docker', ['port', name, '8080/tcp']);
    const port = /127\.0\.0\.1:(\d+)/.exec(stdout)?.[1];
    if (!port) throw new Error(`Keycloak is not bound to 127.0.0.1: ${stdout.trim()}`);
    const baseUrl = `http://127.0.0.1:${port}`;
    const realmUrl = `${baseUrl}/realms/${REALM}`;
    for (let i = 0; ; i += 1) {
      const ok = await fetch(`${realmUrl}/.well-known/openid-configuration`).then(
        (r) => r.ok,
        () => false,
      );
      if (ok) break;
      if (i >= READY_ATTEMPTS) {
        throw new Error(`Keycloak did not start:\n${await containerLogs(run, name)}`);
      }
      const running = await run('docker', ['inspect', '-f', '{{.State.Running}}', name]).then(
        (r) => r.stdout.trim() === 'true',
        () => false,
      );
      if (!running) throw new Error(`Keycloak stopped:\n${await containerLogs(run, name)}`);
      await new Promise((r) => setTimeout(r, 1_000));
    }
    return {
      baseUrl,
      realmUrl,
      name,
      admin: new KeycloakAdmin(baseUrl, adminPassword),
      stop,
    };
  } catch (err) {
    await stop();
    throw err;
  }
}

/** The few admin REST calls the scenarios make (an admin-cli token from the master realm). */
export class KeycloakAdmin {
  constructor(
    private readonly baseUrl: string,
    private readonly password: string,
  ) {}

  private async token(): Promise<string> {
    const res = await fetch(`${this.baseUrl}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'password',
        client_id: 'admin-cli',
        username: 'admin',
        password: this.password,
      }),
    });
    if (!res.ok) throw new Error(`Keycloak admin token: ${res.status}`);
    return ((await res.json()) as { access_token: string }).access_token;
  }

  private async call(method: string, path: string, body?: unknown): Promise<unknown> {
    const res = await fetch(`${this.baseUrl}/admin/realms/${REALM}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${await this.token()}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`Keycloak ${method} ${path}: ${res.status} ${text.slice(0, 300)}`);
    return text ? (JSON.parse(text) as unknown) : undefined;
  }

  async addClient(client: RealmClient): Promise<void> {
    await this.call('POST', '/clients', client);
  }

  async userId(username: string): Promise<string> {
    const found = (await this.call(
      'GET',
      `/users?exact=true&username=${encodeURIComponent(username)}`,
    )) as { id: string }[];
    const id = found[0]?.id;
    if (!id) throw new Error(`no Keycloak user ${username}`);
    return id;
  }

  async groupId(name: string): Promise<string> {
    const found = (await this.call(
      'GET',
      `/groups?exact=true&search=${encodeURIComponent(name)}`,
    )) as { id: string; name: string }[];
    const id = found.find((g) => g.name === name)?.id;
    if (!id) throw new Error(`no Keycloak group ${name}`);
    return id;
  }

  async removeFromGroup(username: string, group: string): Promise<void> {
    const [user, id] = await Promise.all([this.userId(username), this.groupId(group)]);
    await this.call('DELETE', `/users/${user}/groups/${id}`);
  }
}

/** The realm's SAML signing certificate as PEM, from its public IdP descriptor. */
export async function samlIdpCertificate(realmUrl: string): Promise<string> {
  const res = await fetch(`${realmUrl}/protocol/saml/descriptor`);
  if (!res.ok) throw new Error(`the SAML descriptor: ${res.status}`);
  const xml = await res.text();
  const base64 = /<(?:ds:|dsig:)?X509Certificate>([^<]+)<\//.exec(xml)?.[1]?.replace(/\s+/g, '');
  if (!base64) throw new Error('the SAML descriptor names no certificate');
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}
