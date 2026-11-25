import { createServer, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FixClaimItem, FixResultBody } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { commitAll, gitSync, initRepo, SCAN_TEST_ENV } from '../../test/git';
import { json, problem, useTestServers } from '../../test/http';
import { captureIO } from '../../test/io';
import { useTempDirs, writeTree } from '../../test/tmp';
import type { FixFlags } from '../args';
import { CliError, EXIT } from '../errors';
import type { FixAdapter } from '../fix/adapter';
import { toolFailure } from '../fix/runner';
import { createLogger } from '../log';
import { runFix, type FixDeps } from './fix';

const tmp = useTempDirs();
const serve = useTestServers();

// Test secrets are assembled at runtime, so the repository's own gitleaks pass finds none here.
const TOKEN = ['qlr', 'prj', 'T0KEN', 'f1x', 'job'].join('_');
const NPM_SECRET = ['npm', 'S3CR3T', 'v4lue', '42'].join('_');
const AUTH_VALUE = ['abcd', 'efgh', '1234', 'ijkl'].join('');
const URL_PASSWORD = ['p4ss', 'w0rd', '99'].join('');

const NPM = 'https://registry.npmjs.org';
const packageJson = (range: string) =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }\n}\n`;
/** A `package-lock.json` with `qf-a` at `version` (and `qf`'s extra fields), and other entries. */
const lockOf = (
  version: string,
  entries: Record<string, unknown> = {},
  qf: Record<string, unknown> = {},
) =>
  `${JSON.stringify(
    {
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
        'node_modules/qf-a': {
          version,
          resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
          integrity: `sha512-${version}`,
          ...qf,
        },
        ...entries,
      },
    },
    null,
    2,
  )}\n`;
const packageLock = (version: string) => lockOf(version);
/** The fixed lockfile (1.2.6) with more entries or fields. */
const lockWith = (entries: Record<string, unknown>, qf: Record<string, unknown>) =>
  lockOf('1.2.6', entries, qf);

const BASE: Record<string, string> = {
  'package.json': packageJson('^1.2.5'),
  'package-lock.json': packageLock('1.2.5'),
  'src/index.js': 'module.exports = 1;\n',
};

const b64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');

function item(n: number, over: Partial<FixClaimItem> = {}): FixClaimItem {
  return {
    id: `0193a4c6-1c2e-7a3b-9f00-00000000000${n}`,
    generation: n,
    leaseToken: `lease-${n}`,
    family: 'js',
    packageName: 'qf-a',
    installedVersions: ['1.2.5'],
    vulnerabilities: [
      {
        id: 'CVE-2026-0001',
        severity: 'high',
        title: 'Prototype pollution',
        url: null,
        installedVersions: ['1.2.5'],
        fixedVersions: ['1.2.6'],
      },
      {
        id: 'CVE-2026-0002',
        severity: 'low',
        title: 'No fix yet',
        url: null,
        installedVersions: ['1.2.5'],
        fixedVersions: [],
      },
    ],
    mainBranch: 'main',
    declinedTarget: null,
    ...over,
  };
}

type Answer = (res: ServerResponse) => void;
const claimOf =
  (...items: FixClaimItem[]): Answer =>
  (res) =>
    json(res, 200, { items, reason: null });
const nothing: Answer = (res) => json(res, 200, { items: [], reason: null });

/** The state a real server would answer for each result form. */
function stateOf(body: FixResultBody): string {
  if ('released' in body) return 'requested';
  if ('failure' in body) return 'failed';
  if ('noFix' in body) return 'no_fix';
  return 'committing';
}

interface FakeQualor {
  url: string;
  claims: Record<string, unknown>[];
  results: { id: string; body: FixResultBody }[];
}

/** A Qualor server for the fix routes: scripted claim and result answers, in order. */
async function qualor(o: { claims?: Answer[]; results?: Answer[] } = {}): Promise<FakeQualor> {
  const claims = [...(o.claims ?? [])];
  const results = [...(o.results ?? [])];
  const seen: Omit<FakeQualor, 'url'> = { claims: [], results: [] };
  const server = await serve((req, res, recorded) => {
    const body = JSON.parse(recorded.body.toString('utf8')) as Record<string, unknown>;
    if (req.url?.startsWith('/api/v0/projects/fixes/claim?projectKey=') === true) {
      seen.claims.push(body);
      (claims.shift() ?? nothing)(res);
      return;
    }
    const id = /^\/api\/v0\/fixes\/([0-9a-f-]+)\/result$/.exec(req.url ?? '')?.[1];
    if (id === undefined) {
      problem(res, 404, 'NOT_FOUND');
      return;
    }
    const result = body as FixResultBody;
    seen.results.push({ id, body: result });
    (results.shift() ?? ((r: ServerResponse) => json(r, 202, { state: stateOf(result) })))(res);
  });
  return { url: server.url, ...seen };
}

function repo(files: Record<string, string> = BASE): { dir: string; head: string } {
  const dir = tmp('qualor-fix-repo-');
  initRepo(dir);
  writeTree(dir, files);
  return { dir, head: commitAll(dir, 'base') };
}

const onPath = (tool: string) => `/usr/bin/${tool}`;

/** A JS adapter that fixes `qf-a` in the root `package.json` and `package-lock.json`. */
const goodJs: FixAdapter = {
  family: 'js',
  installed: () => Promise.resolve([{ lockfile: 'package-lock.json', versions: ['1.2.5'] }]),
  apply: (ws, _fix, plan) => {
    writeTree(ws.root, {
      'package.json': packageJson(`^${plan.greatest}`),
      'package-lock.json': packageLock(plan.greatest),
    });
    return Promise.resolve({
      lockfiles: [
        { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
      ],
    });
  },
};

const stopWith = (message: string) =>
  Promise.resolve({ kind: 'failure' as const, code: 'package_manager' as const, message });

interface RunResult {
  code: number;
  lines: string[];
  log: string;
}

async function run(
  dir: string,
  server: { url: string },
  o: { flags?: Partial<FixFlags>; env?: Record<string, string>; deps?: FixDeps } = {},
): Promise<RunResult> {
  const lines: string[] = [];
  const log = createLogger('debug', (text) => lines.push(text));
  const cap = captureIO({
    cwd: dir,
    env: {
      ...SCAN_TEST_ENV,
      QUALOR_URL: server.url,
      QUALOR_TOKEN: TOKEN,
      QUALOR_PROJECT_KEY: 'acme/app',
      ...o.env,
    },
  });
  let code: number;
  try {
    code = await runFix({ max: 10, timeoutSeconds: 1800, ...o.flags }, cap.io, log, {
      tempRoot: tmp('qualor-fix-temp-'),
      resolve: onPath,
      adapters: { js: goodJs },
      wait: () => Promise.resolve(),
      ...o.deps,
    });
  } catch (err) {
    // As main() does: a CliError is logged and its exit code returned.
    if (!(err instanceof CliError)) throw err;
    log.error(err.message);
    code = err.exitCode;
  }
  return { code, lines, log: lines.join('') };
}

/** The paths `git worktree list` names. */
function worktrees(dir: string): string[] {
  return gitSync(dir, 'worktree', 'list', '--porcelain')
    .split('\n')
    .filter((line) => line.startsWith('worktree '));
}

function failureOf(body: FixResultBody | undefined): { code: string; message: string } {
  if (body === undefined || !('failure' in body)) throw new Error('expected a failure');
  return body.failure;
}

function noFixOf(body: FixResultBody | undefined): { reason: string; message: string } {
  if (body === undefined || !('noFix' in body)) throw new Error('expected a no-fix');
  return body.noFix;
}

describe('qualor fix: claiming', () => {
  it('exits 0 after one claim when nothing is requested, and claims as R4 says', async () => {
    const { dir, head } = repo();
    const server = await qualor();
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(server.claims).toEqual([{ families: ['js'], max: 1, branch: 'main', revision: head }]);
    expect(server.results).toEqual([]);
  });

  it('exits 0 with the reason when fix merge requests are switched off', async () => {
    const { dir } = repo();
    const server = await qualor({
      claims: [(res) => json(res, 200, { items: [], reason: 'disabled' })],
    });
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(r.log).toContain('Fix merge requests are off for this project');
    expect(server.claims).toHaveLength(1);
  });

  it('exits 2 off the main branch: 409 NOT_MAIN_BRANCH, or a CI HEAD that is not the job’s commit', async () => {
    const { dir } = repo();
    const refused = await qualor({ claims: [(res) => problem(res, 409, 'NOT_MAIN_BRANCH')] });
    expect((await run(dir, refused)).code).toBe(EXIT.USAGE);

    const ci = await qualor();
    const r = await run(dir, ci, {
      env: { GITLAB_CI: 'true', CI_COMMIT_SHA: '0'.repeat(40), CI_COMMIT_REF_NAME: 'main' },
    });
    expect(r.code).toBe(EXIT.USAGE);
    expect(ci.claims).toEqual([]);
  });

  it('takes the branch from CI and the revision from HEAD; a detached HEAD outside CI exits 2', async () => {
    const { dir, head } = repo();
    const ci = await qualor();
    const r = await run(dir, ci, {
      env: { GITLAB_CI: 'true', CI_COMMIT_SHA: head, CI_COMMIT_REF_NAME: 'trunk' },
    });
    expect(r.code).toBe(EXIT.OK);
    expect(ci.claims[0]).toMatchObject({ branch: 'trunk', revision: head });

    gitSync(dir, 'checkout', '-q', '--detach');
    const detached = await qualor();
    expect((await run(dir, detached)).code).toBe(EXIT.USAGE);
    expect(detached.claims).toEqual([]);
  });

  it('takes an Azure Pipelines branch build’s branch and revision; an Azure tag build exits 2', async () => {
    const { dir, head } = repo();
    const azure = {
      TF_BUILD: 'True',
      BUILD_REPOSITORY_PROVIDER: 'TfsGit',
      BUILD_SOURCEVERSION: head,
    };
    const branch = await qualor();
    const r = await run(dir, branch, {
      env: { ...azure, BUILD_SOURCEBRANCH: 'refs/heads/trunk' },
    });
    expect(r.code).toBe(EXIT.OK);
    expect(branch.claims[0]).toMatchObject({ branch: 'trunk', revision: head });

    const tag = await qualor();
    const t = await run(dir, tag, { env: { ...azure, BUILD_SOURCEBRANCH: 'refs/tags/v1.0.0' } });
    expect(t.code).toBe(EXIT.USAGE);
    expect(tag.claims).toEqual([]);
  });

  it('exits 5 when the token is refused and 4 when the server cannot be reached', async () => {
    const { dir } = repo();
    const refused = await qualor({ claims: [(res) => problem(res, 401, 'UNAUTHENTICATED')] });
    expect((await run(dir, refused)).code).toBe(EXIT.AUTH);

    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const { port } = closed.address() as AddressInfo;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    expect((await run(dir, { url: `http://127.0.0.1:${port}` })).code).toBe(EXIT.SERVER);
  });
});

describe('qualor fix: families (B7, ruling F6)', () => {
  const FILES = {
    ...BASE,
    'yarn.lock': '# yarn lockfile v1\n',
    'svc/go.mod': 'module example.com/svc\n\ngo 1.22\n',
    'svc/go.sum': '',
  };
  const goAdapter: FixAdapter = {
    family: 'go',
    installed: () => Promise.resolve([]),
    apply: () => stopWith('unused'),
  };

  it('claims only the families whose every tool resolves, and names the others in one line', async () => {
    const { dir } = repo(FILES);
    const server = await qualor();
    const noYarn = (tool: string) => (tool === 'yarn' ? null : onPath(tool));
    const r = await run(dir, server, {
      deps: { resolve: noYarn, adapters: { js: goodJs, go: goAdapter } },
    });
    expect(r.code).toBe(EXIT.OK);
    expect(server.claims[0]?.['families']).toEqual(['go']);
    const info = r.lines.filter((line) => line.includes('yarn'));
    expect(info).toHaveLength(1);
    expect(info[0]).toContain('js');

    const both = await qualor();
    await run(dir, both, { deps: { adapters: { js: goodJs, go: goAdapter } } });
    expect(both.claims[0]?.['families']).toEqual(['js', 'go']);
  });

  it('fails a fix as missing_tool when a tool of its family is gone after the claim', async () => {
    const { dir } = repo(FILES);
    let claimed = false;
    const server = await qualor({
      claims: [
        (res) => {
          claimed = true;
          claimOf(item(1))(res);
        },
      ],
    });
    const vanishing = (tool: string) => (tool === 'yarn' && claimed ? null : onPath(tool));
    const r = await run(dir, server, { deps: { resolve: vanishing } });
    expect(r.code).toBe(EXIT.OK);
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('missing_tool');
    expect(failure.message).toContain('yarn');
  });

  it('claims nothing when no family can be served', async () => {
    const { dir } = repo({ 'README.md': 'docs only\n' });
    const server = await qualor();
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(server.claims).toEqual([]);
  });

  it.runIf(process.platform === 'win32')(
    'names why a .cmd that is no npm cmd-shim is not served (ruling T12a)',
    async () => {
      const { dir } = repo({ ...BASE, 'pom.xml': '<project/>\n' });
      const bin = tmp('qualor-fix-bin-');
      writeTree(bin, {
        'mvn.cmd': '@echo off\r\n"%JAVA_HOME%\\bin\\java.exe" -classpath x %*\r\n',
      });
      const maven: FixAdapter = {
        family: 'maven',
        installed: () => Promise.resolve([]),
        apply: () => stopWith('unused'),
      };
      const pathKey = Object.keys(SCAN_TEST_ENV).find((k) => k.toUpperCase() === 'PATH') ?? 'PATH';
      const server = await qualor();
      const r = await run(dir, server, {
        env: { [pathKey]: `${bin};${SCAN_TEST_ENV[pathKey] ?? ''}` },
        deps: { resolve: undefined, adapters: { maven } },
      });
      expect(r.code).toBe(EXIT.OK);
      const info = r.lines.filter((line) => line.includes('mvn.cmd'));
      expect(info).toHaveLength(1);
      expect(info[0]).toContain('maven');
      expect(server.claims).toEqual([]);
    },
  );
});

describe('qualor fix: the scratch worktree', () => {
  it('uploads each fix and leaves the checkout, its HEAD and its worktree list as they were', async () => {
    const { dir, head } = repo();
    const server = await qualor({ claims: [claimOf(item(1)), claimOf(item(2))] });
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(server.claims).toHaveLength(3);
    expect(server.results.map((x) => x.id)).toEqual([item(1).id, item(2).id]);
    expect(server.results[0]?.body).toEqual({
      generation: 1,
      leaseToken: 'lease-1',
      baseSha: head,
      installedVersion: '1.2.5',
      targetVersion: '1.2.6',
      targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
      files: [
        { path: 'package-lock.json', content: b64(packageLock('1.2.6')) },
        { path: 'package.json', content: b64(packageJson('^1.2.6')) },
      ],
      lockfiles: [
        { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
      ],
      unfixable: ['CVE-2026-0002'],
    });
    expect(server.results[1]?.body).toMatchObject({ generation: 2, leaseToken: 'lease-2' });
    expect(worktrees(dir)).toHaveLength(1);
    expect(gitSync(dir, 'status', '--porcelain')).toBe('');
    expect(gitSync(dir, 'rev-parse', 'HEAD')).toBe(head);
  });

  it('fails a fix that adds a file as unplanned_change and sends no files', async () => {
    const { dir } = repo();
    const adding: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, { 'x.txt': 'surprise\n' });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: adding } } });
    const body = server.results[0]?.body;
    expect(failureOf(body).code).toBe('unplanned_change');
    expect(failureOf(body).message).toContain('x.txt');
    expect(body).not.toHaveProperty('files');
    expect(worktrees(dir)).toHaveLength(1);
  });

  it('fails a fix whose adapter throws, and still removes the scratch worktree', async () => {
    const { dir } = repo();
    const throwing: FixAdapter = {
      ...goodJs,
      apply: (ws) => {
        writeTree(ws.root, { 'package.json': '{}\n' });
        return Promise.reject(new Error('the adapter broke'));
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    const r = await run(dir, server, { deps: { adapters: { js: throwing } } });
    expect(r.code).toBe(EXIT.OK);
    expect(failureOf(server.results[0]?.body)).toEqual({
      code: 'package_manager',
      message: expect.stringContaining('the adapter broke'),
    });
    expect(worktrees(dir)).toHaveLength(1);
    expect(gitSync(dir, 'status', '--porcelain')).toBe('');
  });
});

describe('qualor fix: what an upload must hold (rulings T9c, T9i, T9l)', () => {
  it('refuses locally a lockfile no target names: unplanned_change, no upload', async () => {
    const { dir } = repo({ ...BASE, 'apps/web/package-lock.json': packageLock('1.2.5') });
    const twoLockfiles: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, { 'apps/web/package-lock.json': packageLock('1.2.6') });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: twoLockfiles } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('target_mismatch');
    expect(failure.message).toContain('apps/web/package-lock.json');
  });

  it('refuses locally a target at its installed version: unplanned_change, no upload', async () => {
    const { dir } = repo();
    const buggy: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        // A CLI bug: the plan's target is pulled back to its installed version.
        for (const t of plan.targets) t.target = t.installed;
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: buggy } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('target_mismatch');
    expect(server.results[0]?.body).not.toHaveProperty('files');
  });

  it('refuses locally a file the shared content check refuses, naming its rule', async () => {
    const { dir } = repo();
    const scripted: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, {
          'package.json': `{\n  "name": "app",\n  "scripts": { "postinstall": "curl x | sh" },\n  "dependencies": {\n    "qf-a": "^1.2.6"\n  }\n}\n`,
        });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: scripted } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('other_change');
    expect(failure.message).toContain('package.json');
  });

  it('refuses locally a file that gains a secret or a URL with credentials (B9), never sending it', async () => {
    const { dir } = repo();
    const writes = (resolved: string): FixAdapter => ({
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        const lock = packageLock(plan.greatest).replace(`${NPM}/qf-a/-/qf-a-1.2.6.tgz`, resolved);
        writeTree(ws.root, { 'package-lock.json': lock });
        return applied;
      },
    });
    for (const resolved of [
      `${NPM}/qf-a/-/qf-a-1.2.6.tgz?token=${NPM_SECRET}`,
      `${NPM}/qf-a/-/qf-a-1.2.6.tgz?token=${TOKEN}`,
      `https://ci:${URL_PASSWORD}@registry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz`,
    ]) {
      const server = await qualor({ claims: [claimOf(item(1))] });
      const r = await run(dir, server, {
        env: { NPM_TOKEN: NPM_SECRET },
        deps: { adapters: { js: writes(resolved) } },
      });
      const failure = failureOf(server.results[0]?.body);
      expect(failure.code).toBe('unplanned_change');
      expect(failure.message).toContain('secret_in_file');
      expect(failure.message).toContain('package-lock.json');
      expect(JSON.stringify(server.results)).not.toContain(NPM_SECRET);
      expect(JSON.stringify(server.results)).not.toContain(URL_PASSWORD);
      expect(JSON.stringify(server.results)).not.toContain(TOKEN);
      expect(r.log).not.toContain(NPM_SECRET);
    }
  });

  it('uploads a file that gains only ordinary text: true, a project key, a git@ URL (I1)', async () => {
    const { dir } = repo();
    const writes = (lock: string): FixAdapter => ({
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, { 'package-lock.json': lock });
        return applied;
      },
    });
    const cases: { env: Record<string, string>; lock: string }[] = [
      { env: { YARN_NPM_ALWAYS_AUTH: 'true' }, lock: lockWith({}, { dev: true }) },
      {
        env: { QUALOR_PROJECT_KEY: 'core' },
        lock: lockWith(
          {
            'node_modules/core-js': {
              version: '3.40.0',
              resolved: `${NPM}/core-js/-/core-js-3.40.0.tgz`,
              integrity: 'sha512-cj',
            },
          },
          { dependencies: { 'core-js': '^3.0.0' } },
        ),
      },
    ];
    for (const { env, lock } of cases) {
      const server = await qualor({ claims: [claimOf(item(1))] });
      await run(dir, server, { env, deps: { adapters: { js: writes(lock) } } });
      const body = server.results[0]?.body;
      expect(body, JSON.stringify(env)).toHaveProperty('files');
    }
    // A git@ user name is no credential: the shared check refuses the git source, not this rule.
    const gitSsh = lockWith(
      { 'node_modules/y': { version: '1.0.0', resolved: 'git+ssh://git@github.com/x/y.git#abc' } },
      { dependencies: { y: 'github:x/y' } },
    );
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: writes(gitSsh) } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.message).toContain('source_kind');
    expect(failure.message).not.toContain('secret_in_file');
  });

  it('refuses locally a new https URL with a token as its user name (ruling T12l)', async () => {
    const { dir } = repo();
    const ghp = ['ghp', 'abcdefgh12345678'].join('_');
    const tokenUrl = lockWith(
      { 'node_modules/y': { version: '1.0.0', resolved: `https://${ghp}@github.com/o/r.git` } },
      { dependencies: { y: 'github:o/r' } },
    );
    const writes: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, { 'package-lock.json': tokenUrl });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    const r = await run(dir, server, { deps: { adapters: { js: writes } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('secret_in_file');
    expect(JSON.stringify(server.results)).not.toContain(ghp);
    expect(r.log).not.toContain(ghp);
  });

  it('uploads the committed form of a file .gitattributes checks out with CRLF (ruling T12e)', async () => {
    const { dir } = repo({ ...BASE, '.gitattributes': 'package.json text eol=crlf\n' });
    const crlf: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        // A package manager keeps the line endings of the file it edits.
        const manifest = packageJson(`^${plan.greatest}`).replaceAll('\n', '\r\n');
        writeTree(ws.root, { 'package.json': manifest });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: crlf } } });
    const body = server.results[0]?.body;
    const files = body !== undefined && 'files' in body ? body.files : [];
    const content = files.find((f) => f.path === 'package.json')?.content ?? '';
    const uploaded = Buffer.from(content, 'base64').toString('utf8');
    expect(uploaded).toBe(packageJson('^1.2.6'));
    const base = packageJson('^1.2.5').split('\n');
    expect(uploaded.split('\n').filter((line, i) => line !== base[i])).toEqual([
      '    "qf-a": "^1.2.6"',
    ]);
  });

  it('refuses locally a file with a NUL byte, naming not_utf8', async () => {
    const { dir } = repo();
    const nul: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        const applied = await goodJs.apply(ws, fix, plan);
        writeTree(ws.root, { 'package.json': `${packageJson('^1.2.6')}\u0000` });
        return applied;
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: nul } } });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('not_utf8');
  });

  it('keeps at most 5 dependents per lockfile line, as the result schema takes them', async () => {
    const { dir } = repo();
    const many: FixAdapter = {
      ...goodJs,
      apply: async (ws, fix, plan) => {
        await goodJs.apply(ws, fix, plan);
        const dependents = ['p1', 'p2', 'p3', 'p4', 'p5', 'p6', 'p7'];
        return {
          lockfiles: [
            {
              path: 'package-lock.json',
              relation: 'transitive',
              mechanism: 'overrides',
              dependents,
            },
          ],
        };
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: many } } });
    expect(server.results[0]?.body).toMatchObject({
      lockfiles: [{ dependents: ['p1', 'p2', 'p3', 'p4', 'p5'] }],
    });
  });

  it('sends a result the schema would refuse as unplanned_change, naming the field', async () => {
    const { dir } = repo();
    const longId = `GHSA-${'x'.repeat(200)}`;
    const server = await qualor({
      claims: [
        claimOf(
          item(1, {
            vulnerabilities: [
              ...item(1).vulnerabilities,
              {
                id: longId,
                severity: 'low',
                title: null,
                url: null,
                installedVersions: ['1.2.5'],
                fixedVersions: [],
              },
            ],
          }),
        ),
      ],
    });
    await run(dir, server);
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('unplanned_change');
    expect(failure.message).toContain('unfixable');
  });
});

describe('qualor fix: no fix (B3, B4)', () => {
  it('answers no_fix declined when the greatest target was declined, without applying', async () => {
    const { dir } = repo();
    let applied = false;
    const watching: FixAdapter = {
      ...goodJs,
      apply: (ws, fix, plan) => {
        applied = true;
        return goodJs.apply(ws, fix, plan);
      },
    };
    const server = await qualor({ claims: [claimOf(item(1, { declinedTarget: '1.2.6' }))] });
    await run(dir, server, { deps: { adapters: { js: watching } } });
    expect(noFixOf(server.results[0]?.body).reason).toBe('declined');
    expect(server.results[0]?.body).not.toHaveProperty('files');
    expect(applied).toBe(false);
  });

  it('answers not_installed when no lockfile has a version the server named', async () => {
    const { dir } = repo();
    const elsewhere: FixAdapter = {
      ...goodJs,
      installed: () => Promise.resolve([{ lockfile: 'package-lock.json', versions: ['2.0.0'] }]),
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: elsewhere } } });
    expect(noFixOf(server.results[0]?.body).reason).toBe('not_installed');
  });

  it('answers no_fixed_version when no fixed version is above the installed one', async () => {
    const { dir } = repo();
    const server = await qualor({
      claims: [
        claimOf(
          item(1, {
            vulnerabilities: [
              {
                id: 'CVE-2026-0003',
                severity: 'high',
                title: null,
                url: null,
                installedVersions: ['1.2.5'],
                fixedVersions: ['1.2.4'],
              },
            ],
          }),
        ),
      ],
    });
    await run(dir, server);
    expect(noFixOf(server.results[0]?.body).reason).toBe('no_fixed_version');
  });

  it('sends what verify answers', async () => {
    const { dir } = repo();
    const verifying: FixAdapter = {
      ...goodJs,
      verify: () =>
        Promise.resolve({ kind: 'no_fix', reason: 'several_lines', message: '1.x and 2.x' }),
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: verifying } } });
    expect(noFixOf(server.results[0]?.body)).toEqual({
      reason: 'several_lines',
      message: '1.x and 2.x',
    });
  });

  it('uploads the targets it checked, whatever verify does to the plan (ruling T12i)', async () => {
    const { dir } = repo();
    const meddling: FixAdapter = {
      ...goodJs,
      verify: (_ws, _fix, plan) => {
        for (const t of plan.targets) t.target = '9.9.9';
        plan.targets.push({ installed: '0.0.1', target: '0.0.2', lockfile: 'x/package-lock.json' });
        return Promise.resolve(null);
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, { deps: { adapters: { js: meddling } } });
    const body = server.results[0]?.body;
    expect(body !== undefined && 'targets' in body ? body.targets : null).toEqual([
      { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
    ]);
  });
});

describe('qualor fix: the tool environment and its output (B9, §11.6)', () => {
  it('runs the tools without the Qualor and CI job credentials, with the registry ones', async () => {
    const { dir } = repo();
    let names: string[] = [];
    const probing: FixAdapter = {
      ...goodJs,
      apply: async (ws) => {
        const r = await ws.run(
          'node',
          ['-e', 'process.stdout.write(JSON.stringify(Object.keys(process.env)))'],
          { cwd: ws.root, timeoutMs: 30_000 },
        );
        names = (JSON.parse(r.stdout) as string[]).map((n) => n.toUpperCase());
        return stopWith('probed');
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, {
      env: {
        CI_JOB_TOKEN: 'ci-job-token-value',
        GITHUB_TOKEN: 'github-token-value',
        ACTIONS_RUNTIME_TOKEN: 'actions-token-value',
        NPM_TOKEN: NPM_SECRET,
      },
      deps: { adapters: { js: probing } },
    });
    for (const name of [
      'QUALOR_TOKEN',
      'QUALOR_URL',
      'QUALOR_PROJECT_KEY',
      'CI_JOB_TOKEN',
      'GITHUB_TOKEN',
      'ACTIONS_RUNTIME_TOKEN',
    ]) {
      expect(names, name).not.toContain(name);
    }
    expect(names).toContain('NPM_TOKEN');
  });

  it('gives the adapter the tool environment as ws.env: the job’s GOFLAGS, no Qualor or CI job credentials (ruling T14a)', async () => {
    const { dir } = repo();
    let seen: Readonly<Record<string, string>> | undefined;
    const probing: FixAdapter = {
      ...goodJs,
      apply: (ws) => {
        seen = ws.env;
        return stopWith('probed');
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    await run(dir, server, {
      env: { GOFLAGS: '-modcacherw', CI_JOB_TOKEN: 'ci-job-token-value' },
      deps: { adapters: { js: probing } },
    });
    expect(seen?.['GOFLAGS']).toBe('-modcacherw');
    const names = Object.keys(seen ?? {}).map((n) => n.toUpperCase());
    for (const name of ['QUALOR_TOKEN', 'QUALOR_URL', 'QUALOR_PROJECT_KEY', 'CI_JOB_TOKEN']) {
      expect(names, name).not.toContain(name);
    }
  });

  it('keeps every secret out of the failure message and the log, within 2 KiB', async () => {
    const { dir } = repo();
    const script = [
      "const auth = ['abcd', 'efgh', '1234', 'ijkl'].join('');",
      "const pass = ['p4ss', 'w0rd', '99'].join('');",
      "for (let i = 0; i < 200; i++) console.error('npm verbose line ' + i + ' ' + 'y'.repeat(40));",
      "console.error('//npm.example.org/:_authToken=' + auth);",
      "console.error('npm ERR! GET https://ci-user:' + pass + '@npm.example.org/qf-a 401');",
      "console.error('npm ERR! token ' + process.env.NPM_TOKEN);",
      "console.error('npm ERR! project ' + process.env.LEAK);",
      // exitCode, not exit(): stderr to a pipe is written asynchronously on Linux, and exit()
      // would drop the lines still queued (the npm ERR! ones the test looks for).
      'process.exitCode = 1;',
    ].join('\n');
    const leaking: FixAdapter = {
      ...goodJs,
      apply: async (ws) => {
        const r = await ws.run('node', ['-e', script], {
          cwd: ws.root,
          env: { LEAK: TOKEN },
          timeoutMs: 30_000,
        });
        ws.log.info(`npm said: ${r.stderr}`);
        return { kind: 'failure', ...toolFailure('npm', r, []) };
      },
    };
    const server = await qualor({ claims: [claimOf(item(1))] });
    const r = await run(dir, server, {
      env: { NPM_TOKEN: NPM_SECRET },
      deps: { adapters: { js: leaking } },
    });
    const failure = failureOf(server.results[0]?.body);
    expect(failure.code).toBe('package_manager');
    expect(failure.message).toContain('npm ERR! token [redacted]');
    expect(Buffer.byteLength(failure.message)).toBeLessThanOrEqual(2048);
    for (const secret of [AUTH_VALUE, URL_PASSWORD, NPM_SECRET, TOKEN]) {
      expect(failure.message).not.toContain(secret);
      expect(r.log).not.toContain(secret);
    }
  });
});

describe('qualor fix: time (§6.5 limits, R4)', () => {
  const hanging: FixAdapter = {
    ...goodJs,
    apply: async (ws) => {
      const r = await ws.run('node', ['-e', 'setInterval(() => {}, 1000)'], {
        cwd: ws.root,
        timeoutMs: 600_000,
      });
      return { kind: 'failure', ...toolFailure('npm', r, []) };
    },
  };

  it('fails a fix that passes its own budget as timeout and claims the next one', async () => {
    const { dir } = repo();
    const server = await qualor({ claims: [claimOf(item(1))] });
    const r = await run(dir, server, { deps: { adapters: { js: hanging }, perFixMs: 300 } });
    expect(r.code).toBe(EXIT.OK);
    expect(failureOf(server.results[0]?.body).code).toBe('timeout');
    expect(server.claims).toHaveLength(2);
    expect(worktrees(dir)).toHaveLength(1);
  });

  it('hands the fix in flight back when the job’s --timeout ends, and exits 0', async () => {
    const { dir } = repo();
    // The job's clock jumps 60 s at the claim, so 3 s of the 63 s --timeout remain for the fix.
    let skipped = 0;
    const now = () => Date.now() + skipped;
    const server = await qualor({
      claims: [
        (res) => {
          skipped = 60_000;
          claimOf(item(1))(res);
        },
        claimOf(item(2)),
      ],
    });
    const r = await run(dir, server, {
      flags: { timeoutSeconds: 63 },
      deps: { adapters: { js: hanging }, now },
    });
    expect(r.code).toBe(EXIT.OK);
    expect(server.results.map((x) => x.body)).toEqual([
      { generation: 1, leaseToken: 'lease-1', released: true },
    ]);
    expect(server.claims).toHaveLength(1);
    expect(worktrees(dir)).toHaveLength(1);
  });

  it('claims at most --max fixes', async () => {
    const { dir } = repo();
    const server = await qualor({ claims: [claimOf(item(1)), claimOf(item(2))] });
    await run(dir, server, { flags: { max: 1 } });
    expect(server.claims).toHaveLength(1);
    expect(server.results).toHaveLength(1);
  });

  it('starts no upload that cannot finish before --timeout ends: the claim goes back (ruling FW13)', async () => {
    const { dir } = repo();
    // The job's clock jumps 75 s at the claim: the fix is prepared, but 45 s of the 120 s are left.
    let skipped = 0;
    const now = () => Date.now() + skipped;
    const server = await qualor({
      claims: [
        (res) => {
          skipped = 75_000;
          claimOf(item(1))(res);
        },
      ],
    });
    const r = await run(dir, server, { flags: { timeoutSeconds: 120 }, deps: { now } });
    expect(r.code).toBe(EXIT.OK);
    expect(server.results.map((x) => x.body)).toEqual([
      { generation: 1, leaseToken: 'lease-1', released: true },
    ]);
    expect(r.log).toMatch(/--timeout/);
    expect(worktrees(dir)).toHaveLength(1);
  });

  it('claims nothing with less than 60 s of --timeout left (ruling T12g)', async () => {
    const { dir } = repo();
    const server = await qualor({ claims: [claimOf(item(1))] });
    const r = await run(dir, server, { flags: { timeoutSeconds: 59 } });
    expect(r.code).toBe(EXIT.OK);
    expect(server.claims).toEqual([]);
    expect(r.log).toContain('--timeout');
  });
});

describe('qualor fix: the result route’s answers (R16, rulings T9b, T9d)', () => {
  it('logs a lost lease and goes on', async () => {
    const { dir } = repo();
    const server = await qualor({
      claims: [claimOf(item(1))],
      results: [(res) => problem(res, 409, 'FIX_LEASE_LOST')],
    });
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(r.log).toMatch(/lease/i);
    expect(server.claims).toHaveLength(2);
  });

  it('stops, exit 0, when the result route says the project cannot take fixes now (rulings T12f, FW15)', async () => {
    for (const code of ['SCM_NOT_BOUND', 'FIX_MRS_NOT_ALLOWED', 'FIXES_DISABLED']) {
      const { dir } = repo();
      const server = await qualor({
        claims: [claimOf(item(1)), claimOf(item(2))],
        results: [(res) => problem(res, 409, code)],
      });
      const r = await run(dir, server);
      expect(r.code, code).toBe(EXIT.OK);
      expect(server.claims, code).toHaveLength(1);
      expect(r.lines.filter((line) => line.includes(code))).toHaveLength(1);
    }
  });

  it('retries an upload the server could not check (503, 503, 202)', async () => {
    const { dir } = repo();
    const waits: number[] = [];
    const server = await qualor({
      claims: [claimOf(item(1))],
      results: [
        (res) => problem(res, 503, 'SCM_UNAVAILABLE'),
        (res) => problem(res, 503, 'SCM_UNAVAILABLE'),
        (res) => json(res, 202, { state: 'committing' }),
      ],
    });
    const r = await run(dir, server, {
      deps: {
        wait: (ms) => {
          waits.push(ms);
          return Promise.resolve();
        },
      },
    });
    expect(r.code).toBe(EXIT.OK);
    expect(server.results).toHaveLength(3);
    expect(server.results[2]?.body).toEqual(server.results[0]?.body);
    expect(waits).toEqual([10_000, 10_000]);
  });

  it('logs one line when an accepted upload did not reach committing, and a refusal, and exits 0', async () => {
    const { dir } = repo();
    const server = await qualor({
      claims: [claimOf(item(1)), claimOf(item(2))],
      results: [
        (res) => json(res, 202, { state: 'failed' }),
        (res) =>
          json(res, 422, {
            title: 'A lockfile entry comes from a host the lockfile did not use.',
            status: 422,
            code: 'UPLOAD_REFUSED',
            reason: 'new_source',
            detail: 'package-lock.json',
          }),
      ],
    });
    const r = await run(dir, server);
    expect(r.code).toBe(EXIT.OK);
    expect(r.lines.filter((line) => line.includes('failed'))).toHaveLength(1);
    expect(r.log).toContain('new_source');
  });
});
