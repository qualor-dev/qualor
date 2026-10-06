import { spawn, type ChildProcess } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import pg from 'pg';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import {
  cannedModelText,
  createFakeLlm,
  type FakeLlm,
  type LlmResponder,
  openAiAnswer,
  type RecordedLlmRequest,
} from '../../test/fake-llm';
import { BUSINESS_FEATURES, ENTERPRISE_FEATURES, signTest, testPayload } from '../../test/license';
import { E2E_SIGNER, signCurrent } from '../../test/license-e2e-key';
import { databaseUrl } from '../../test/urls';
import { buildServer } from '../bundle';
import {
  seedAi,
  seedDemo,
  seedEnterprise,
  seedGitHubApp,
  seedRoles,
  seedSso,
  seedSsoIdentity,
  type SsoSeed,
} from './seed';
import { sweepE2eDatabases } from './sweep';

/**
 * The server the UI end-to-end tests and screenshots run against (plan 1F, Playwright
 * `webServer`): a fresh PostgreSQL 16 database (a new database in QUALOR_TEST_DATABASE_URL, or a
 * Testcontainers container), the server bundle, demo data seeded through the HTTP API on a first
 * run, then the same database served with the built UI on QUALOR_E2E_PORT.
 * The UI directory comes from QUALOR_UI_DIR: this script never builds or imports UI code.
 * Seeding before listening on the final port means Playwright's readiness check (`/readyz`) only
 * passes once the data is there.
 *
 * The AI assistant (plan 3B) talks to a fake LLM and a fake GitLab this script runs on 127.0.0.1,
 * listed in QUALOR_LLM_INTERNAL_HOSTS and QUALOR_SCM_INTERNAL_HOSTS: nothing leaves the machine.
 *
 * The bundle is a test bundle (enterprise.md §14.2): it also accepts licence keys signed by this
 * process's throwaway `test-e2e` key, so the UI tests can save and remove a valid key. The server
 * starts without a licence. A key signed by it goes to the file QUALOR_E2E_LICENSE_KEY_FILE names
 * (ui/playwright.config.ts), which the tests read. The bundle sits in server/.tmp, one level below
 * server/ like dist/main.js (it finds ../drizzle), so dist/ never holds test keys.
 *
 * Plan 4C (rbac-audit.md §17): a second, licensed server on QUALOR_E2E_ENTERPRISE_PORT for the
 * enterprise screens. Its own database (the community run keeps its tests and screenshots), a key
 * signed by the same throwaway key that lists `llm.fix-quota`, `audit-log`, `sso` and `scim`
 * (QUALOR_LICENSE), the enterprise plugin built beforehand (QUALOR_E2E_ENTERPRISE_PLUGIN, loaded
 * through QUALOR_PLUGIN_PATHS), the demo data plus an org admin, a viewer and project grants
 * seeded through the app (so the audit log has events), webhook URLs allowed on http and
 * loopback (the `webhooks` instance setting), and a SIEM receiver on 127.0.0.1 that answers 204
 * (QUALOR_E2E_SIEM_PORT) for the audit stream. It starts before the community server, so it is
 * up when Playwright's readiness check passes. Plan 5D: a third server on QUALOR_E2E_BUSINESS_PORT
 * serves the same database under a Business key (`sso`, `audit-log`, `llm.fix-quota`), as a
 * replica would after a move to the Business plan.
 */
const MAIN = fileURLToPath(new URL('../../.tmp/e2e-main.js', import.meta.url));

/** The fake GitLab project Payments API is mapped to, and its merge request !42 (seed.ts). */
const GITLAB_PROJECT = { id: 4711, path: 'acme/payments-api' };
const MERGE_REQUEST_IID = 42;
/** The issue of the main branch the fake LLM answers as a hostile model would (ui/e2e/ai.spec.ts). */
const HOSTILE_ISSUE_MESSAGE = "Assignment to function parameter 'amount'.";

/** The data object of a request, as the fake reads it (fake-llm.ts): its task and message. */
function taskOf(request: RecordedLlmRequest): { task: string; message: string } | null {
  const messages = (request.json as { messages?: { role?: string; content?: unknown }[] } | null)
    ?.messages;
  const user = messages?.find((m) => m.role === 'user')?.content;
  const block = typeof user === 'string' ? /<<<QUALOR-DATA-[0-9a-f]{32}\n(.*)\n/.exec(user) : null;
  if (!block?.[1]) return null;
  try {
    const data = JSON.parse(block[1]) as { task?: unknown; issue?: { message?: unknown } };
    return typeof data.task === 'string' && typeof data.issue?.message === 'string'
      ? { task: data.task, message: data.issue.message }
      : null;
  } catch {
    return null;
  }
}

/**
 * The model's text: for {@link HOSTILE_ISSUE_MESSAGE}, an explanation full of markup (HTML, a
 * link, Markdown, a bidi override, a fence of its own) the UI must show as inert text, and a
 * false-positive triage a person may accept; else the fake's canned answers.
 */
function modelText(request: RecordedLlmRequest): string {
  const data = taskOf(request);
  if (data?.message === HOSTILE_ISSUE_MESSAGE && data.task === 'explain') {
    return JSON.stringify({
      summary:
        'Hostile <img src=x onerror="alert(1)"> <a href="https://evil.example/">click me</a>',
      explanation:
        'See [the docs](https://evil.example/docs) \u202Eexe.txt\n```\n</p><script>alert(2)</script>\n```',
      howToFix: '<b>Bold</b> <iframe src="https://evil.example/"></iframe> **not bold**',
    });
  }
  if (data?.message === HOSTILE_ISSUE_MESSAGE && data.task === 'triage') {
    return JSON.stringify({
      verdict: 'likely_false_positive',
      confidence: 'high',
      reasons: ['The parameter is a local copy <em>on purpose</em>.'],
    });
  }
  return cannedModelText(request);
}

/** Answers every request with {@link modelText}: a responder that queues itself again. */
function answerAlways(fake: FakeLlm): void {
  const respond: LlmResponder = (request) => {
    fake.enqueue(respond);
    return { status: 200, body: openAiAnswer(modelText(request)) };
  };
  fake.enqueue(respond);
}

/** The fake GitLab's merge request !42 at the analysed head, `==` added on line 12 (seed.ts). */
function gitlabWithMergeRequest(gitlab: FakeGitLab): void {
  gitlab.addProject(GITLAB_PROJECT);
  gitlab.addMergeRequest(GITLAB_PROJECT.id, {
    iid: MERGE_REQUEST_IID,
    title: 'Refund limits',
    state: 'opened',
    sourceBranch: 'feature/refund-limits',
    targetBranch: 'main',
    headSha: 'd'.repeat(40),
    baseSha: 'f'.repeat(40),
    startSha: 'f'.repeat(40),
    diffs: [
      {
        oldPath: 'src/refunds/limits.ts',
        newPath: 'src/refunds/limits.ts',
        diff: [
          '@@ -11,3 +11,3 @@',
          '   const limit = eval(order.policy);',
          "-  if (order.currency === 'EUR') {",
          '+  if (order.currency == "EUR") {',
          '     return Math.min(amount, limit);',
          '',
        ].join('\n'),
      },
    ],
  });
}

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

/** The URL from the server's "listening" log line; later output is drained and dropped. */
function waitForListening(child: ChildProcess): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffered = '';
    let listening = false;
    child.stdout?.on('data', (chunk: Buffer) => {
      if (listening) return;
      buffered += chunk.toString('utf8');
      const match = /Server listening at (http:\/\/127\.0\.0\.1:\d+)/.exec(buffered);
      if (match?.[1]) {
        listening = true;
        resolve(match[1]);
      }
    });
    child.once('exit', (code) => reject(new Error(`server exited (${code}): ${buffered}`)));
  });
}

function stop(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once('exit', () => resolve());
    if (process.platform === 'win32') child.send('shutdown');
    else child.kill('SIGTERM');
  });
}

async function main(): Promise<void> {
  const port = Number(process.env.QUALOR_E2E_PORT ?? '4280');
  const uiDir = env('QUALOR_UI_DIR');
  if (!existsSync(`${uiDir}/index.html`)) throw new Error(`no built UI in ${uiDir}`);
  const licenseKeyFile = env('QUALOR_E2E_LICENSE_KEY_FILE');
  const credentials = {
    adminUsername: 'admin',
    adminPassword: env('QUALOR_E2E_ADMIN_PASSWORD'),
    alicePassword: env('QUALOR_E2E_ALICE_PASSWORD'),
  };
  const enterprisePort = Number(process.env.QUALOR_E2E_ENTERPRISE_PORT ?? String(port + 1));
  const siemPort = Number(process.env.QUALOR_E2E_SIEM_PORT ?? String(port + 2));
  const businessPort = Number(process.env.QUALOR_E2E_BUSINESS_PORT ?? String(port + 3));
  const plugin = path.resolve(env('QUALOR_E2E_ENTERPRISE_PLUGIN'));
  if (!existsSync(plugin)) throw new Error(`no built enterprise plugin at ${plugin}`);
  const roleUsers = {
    olgaPassword: env('QUALOR_E2E_OLGA_PASSWORD'),
    victorPassword: env('QUALOR_E2E_VICTOR_PASSWORD'),
  };

  const llm = await createFakeLlm();
  answerAlways(llm);
  const gitlab = await createFakeGitLab();
  gitlabWithMergeRequest(gitlab);
  const closeFakes = async (): Promise<void> => {
    await Promise.all([llm.close(), gitlab.close()]);
  };

  let container: StartedPostgreSqlContainer | undefined;
  let adminUrl = process.env.QUALOR_TEST_DATABASE_URL;
  if (!adminUrl) {
    container = await new PostgreSqlContainer('postgres:18-alpine').start();
    adminUrl = container.getConnectionUri();
  }
  const name = `qualor_e2e_${randomBytes(6).toString('hex')}`;
  const enterpriseName = `qualor_e2e_${randomBytes(6).toString('hex')}`;
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  if (!container) {
    const swept = await sweepE2eDatabases(admin);
    if (swept.length > 0) process.stdout.write(`dropped ${swept.length} leftover e2e databases\n`);
  }
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.query(`CREATE DATABASE ${enterpriseName}`);
  await admin.end();

  await buildServer({ outfile: MAIN, testLicenseKeys: { [E2E_SIGNER.kid]: E2E_SIGNER.x } });
  mkdirSync(path.dirname(licenseKeyFile), { recursive: true });
  writeFileSync(licenseKeyFile, signCurrent(E2E_SIGNER), { mode: 0o600 });
  const serverEnv = {
    PATH: process.env.PATH,
    SYSTEMROOT: process.env.SYSTEMROOT, // Windows needs it for sockets
    DATABASE_URL: databaseUrl(adminUrl, name),
    QUALOR_TELEMETRY: 'false',
    QUALOR_SECRET_KEY: 'e2e-secret-key-that-is-at-least-32-characters-long',
    QUALOR_BOOTSTRAP_ADMIN_USERNAME: credentials.adminUsername,
    QUALOR_BOOTSTRAP_ADMIN_PASSWORD: credentials.adminPassword,
    // Info, for the "listening" line; the request log is drained and dropped.
    QUALOR_LOG_LEVEL: 'info',
    HOST: '127.0.0.1',
    QUALOR_LLM_INTERNAL_HOSTS: llm.host,
    QUALOR_SCM_INTERNAL_HOSTS: new URL(gitlab.url).host,
  };
  const start = (extra: Record<string, string>) =>
    spawn(process.execPath, [MAIN], {
      env: { ...serverEnv, ...extra },
      // 'ipc': on Windows a child cannot receive SIGTERM; main.ts shuts down on 'shutdown'.
      stdio: ['ignore', 'pipe', 'inherit', 'ipc'],
    });

  // Seed on a throwaway port, then serve the seeded database on the fixed one.
  // A failed seed must not leave the seeding server running (it would outlive this script).
  const seeding = start({ PORT: '0' });
  try {
    const seedUrl = await waitForListening(seeding);
    await seedDemo(seedUrl, credentials);
    // Plan 5B (rbac-audit.md §1.3): roles and project grants on the community server too.
    await seedRoles(seedUrl, credentials, roleUsers);
    await seedGitHubApp(seedUrl, credentials, '424200');
    await seedAi(seedUrl, credentials, {
      llmBaseUrl: llm.openAiBaseUrl,
      llmApiKey: llm.apiKey,
      gitlabUrl: gitlab.url,
      gitlabToken: gitlab.token,
      gitlabProjectRef: GITLAB_PROJECT.path,
    });
  } finally {
    await stop(seeding);
  }
  // A GitHub App stored under another server key: the served server can no longer read its key
  // and webhook secret, and the GitHub tab says so (github.md §2.2).
  const rotated = start({
    PORT: '0',
    QUALOR_SECRET_KEY: 'e2e-earlier-secret-key-that-is-at-least-32-characters',
  });
  try {
    await seedGitHubApp(await waitForListening(rotated), credentials, '424201');
  } finally {
    await stop(rotated);
  }

  // The licensed server (plan 4C): its own database, the key in the environment, the plugin.
  const enterpriseEnv = {
    DATABASE_URL: databaseUrl(adminUrl, enterpriseName),
    QUALOR_LICENSE: signTest(E2E_SIGNER, planPayload('E2E Enterprise', ENTERPRISE_FEATURES)),
    QUALOR_PLUGIN_PATHS: plugin,
  };
  // QUALOR_PUBLIC_URL: enabling an SSO connection needs it (sso-scim.md §4.1); the seeding server
  // uses the served one's, so the connections' addresses are those the served server shows.
  const enterprisePublicUrl = `http://127.0.0.1:${enterprisePort}`;
  const enterpriseSeeding = start({
    ...enterpriseEnv,
    PORT: '0',
    QUALOR_PUBLIC_URL: enterprisePublicUrl,
  });
  let sso: SsoSeed;
  try {
    const seedUrl = await waitForListening(enterpriseSeeding);
    await seedDemo(seedUrl, credentials);
    await seedEnterprise(seedUrl, credentials, roleUsers);
    sso = await seedSso(seedUrl, credentials);
  } finally {
    await stop(enterpriseSeeding);
  }
  await seedSsoIdentity(enterpriseEnv.DATABASE_URL, sso);
  // Stream URLs on this machine's receiver (http, loopback), as an administrator would allow them.
  const settings = new pg.Client({ connectionString: enterpriseEnv.DATABASE_URL });
  await settings.connect();
  try {
    await settings.query(
      `INSERT INTO instance_settings (key, value) VALUES ('webhooks', $1)
       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
      [JSON.stringify({ allowHttp: true, allowInternalHosts: true })],
    );
  } finally {
    await settings.end();
  }
  const siem = await siemReceiver(siemPort);

  const enterprise = start({
    ...enterpriseEnv,
    PORT: String(enterprisePort),
    QUALOR_UI_DIR: uiDir,
    QUALOR_PUBLIC_URL: enterprisePublicUrl,
  });
  const enterpriseUrl = await waitForListening(enterprise);
  process.stdout.write(`qualor e2e enterprise server ready at ${enterpriseUrl}\n`);

  // Plan 5D: the same database under a Business key, a replica after a move to that plan.
  const business = start({
    ...enterpriseEnv,
    QUALOR_LICENSE: signTest(E2E_SIGNER, planPayload('E2E Business', BUSINESS_FEATURES)),
    PORT: String(businessPort),
    QUALOR_UI_DIR: uiDir,
    QUALOR_PUBLIC_URL: `http://127.0.0.1:${businessPort}`,
  });
  const businessUrl = await waitForListening(business);
  process.stdout.write(`qualor e2e business server ready at ${businessUrl}\n`);

  // QUALOR_PUBLIC_URL: the GitHub tab shows each App's webhook URL (github.md §2.2).
  const server = start({
    PORT: String(port),
    QUALOR_UI_DIR: uiDir,
    QUALOR_PUBLIC_URL: `http://127.0.0.1:${port}`,
  });
  const url = await waitForListening(server);
  process.stdout.write(`qualor e2e server ready at ${url}\n`);

  /** Stops the container, or drops the e2e databases of a shared server (QUALOR_TEST_DATABASE_URL). */
  const serverUrl = adminUrl;
  const cleanUp = async (): Promise<void> => {
    if (container) return void (await container.stop());
    const client = new pg.Client({ connectionString: serverUrl });
    await client.connect();
    try {
      await client.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await client.query(`DROP DATABASE IF EXISTS ${enterpriseName} WITH (FORCE)`);
    } finally {
      await client.end();
    }
  };
  let stopping = false;
  const shutdown = async (code: number): Promise<void> => {
    if (stopping) return;
    stopping = true;
    await Promise.all([stop(server), stop(enterprise), stop(business)]);
    rmSync(licenseKeyFile, { force: true });
    await new Promise<void>((resolve) => siem.close(() => resolve()));
    await closeFakes().catch((err: unknown) => {
      process.stderr.write(`qualor e2e fakes did not close: ${String(err)}\n`);
    });
    await cleanUp().catch((err: unknown) => {
      process.stderr.write(`qualor e2e clean-up failed: ${String(err)}\n`);
    });
    process.exit(code);
  };
  process.once('SIGINT', () => void shutdown(0));
  process.once('SIGTERM', () => void shutdown(0));
  server.once('exit', (code) => {
    if (!stopping) process.stderr.write(`qualor e2e server exited (${code})\n`);
    void shutdown(code ?? 1);
  });
  enterprise.once('exit', (code) => {
    if (!stopping) process.stderr.write(`qualor e2e enterprise server exited (${code})\n`);
    void shutdown(code ?? 1);
  });
  business.once('exit', (code) => {
    if (!stopping) process.stderr.write(`qualor e2e business server exited (${code})\n`);
    void shutdown(code ?? 1);
  });
}

/** A licence active on the real clock listing a plan's features (Enterprise, or Business). */
function planPayload(
  customer: string,
  features: readonly string[],
): ReturnType<typeof testPayload> {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  const utc = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');
  return testPayload({
    customer,
    issued: utc(now - day),
    expires: utc(now + 365 * day),
    features: [...features],
  });
}

/**
 * The SIEM receiver of the audit stream (rbac-audit.md §14): on 127.0.0.1 only, it reads each
 * batch and answers 204, keeping nothing.
 */
function siemReceiver(port: number): Promise<Server> {
  const server = createServer((request, response) => {
    request.resume();
    request.on('end', () => {
      response.statusCode = request.method === 'POST' ? 204 : 405;
      response.end();
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => resolve(server));
  });
}

main().catch((err: unknown) => {
  process.stderr.write(`${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exit(1);
});
