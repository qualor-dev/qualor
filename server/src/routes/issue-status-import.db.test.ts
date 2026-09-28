import { eq } from 'drizzle-orm';
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  type ImportCommentLabel,
  importCommentHeader,
  SONAR_MAPPING,
  sonarLineHash,
} from '@qualor/shared';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { expectPgError } from '../../test/db';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule, type IssueSeed } from '../../test/issues';
import { engine, file, finding, reportWith } from '../../test/reports';
import { issueChanges, issues, organizations, projects, users } from '../db/schema';
import {
  importIssueStatuses,
  sanitizeImportComment,
  type ImportRequestItem,
} from '../issues/status-import';

const LINES = ['const a = 1;', 'if (a == 1) {}', 'if (a == 2) {}', 'export {};'];
const MESSAGE = "Expected '===' and instead saw '=='.";

describe('POST /projects/{id}/issue-status-import (import-sonarqube.md §10–§11)', () => {
  let h: IngestHarness;
  let p: IngestProject;
  let member: Session;
  const post = (body: unknown, session: Session = h.orgAdmin, projectId = p.id) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/issue-status-import`,
      headers: session.headers,
      payload: body as object,
    });
  const item = (over: Record<string, unknown> = {}) => ({
    ref: 'AYi-1',
    ruleKeys: ['eslint:eqeqeq'],
    path: 'src/a.ts',
    line: 2,
    sonarLineHash: sonarLineHash(LINES[1]!),
    message: MESSAGE,
    status: 'false_positive',
    comment: 'Imported from SonarQube issue AYi-1 (False positive on 2026-09-10): safe here',
    ...over,
  });
  const issueAt = async (line: number) =>
    (await h.ctx.db.select().from(issues).where(eq(issues.startLine, line))).find(
      (i) => i.projectId === p.id,
    )!;
  const changesOf = (id: string) =>
    h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, id))
      .orderBy(issueChanges.id);
  const statusOf = async (id: string) =>
    (await h.ctx.db.select().from(issues).where(eq(issues.id, id)))[0]!.status;

  beforeAll(async () => {
    h = await createIngestHarness();
    p = await h.project('acme/import');
    const snippet = { startLine: 1, lines: LINES };
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: LINES.length })],
        findings: [
          finding({ ruleId: 'eqeqeq', line: 2, message: MESSAGE, snippet }),
          finding({ ruleId: 'eqeqeq', line: 3, message: MESSAGE, snippet }),
        ],
      }),
    );
    const m = await createUser(h.ctx, { username: 'plain-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
  });
  afterAll(async () => {
    await h.close();
  });

  it('reports would_apply under dryRun and writes nothing', async () => {
    const res = await post({ dryRun: true, items: [item()] });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().results).toEqual([
      { ref: 'AYi-1', outcome: 'would_apply', issueId: (await issueAt(2)).id, status: 'open' },
    ]);
    expect((await issueAt(2)).status).toBe('open');
  });

  it('applies the status with the item comment, then reports already_set', async () => {
    const res = await post({ dryRun: false, items: [item()] });
    expect(res.json().results[0]).toMatchObject({ outcome: 'applied', status: 'false_positive' });
    const changes = await h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, (await issueAt(2)).id));
    expect(changes.at(-1)).toMatchObject({ newValue: 'false_positive', comment: item().comment });
    const again = await post({ dryRun: false, items: [item()] });
    expect(again.json().results[0]).toMatchObject({ outcome: 'already_set' });
  });

  it('never overwrites another resolved status (conflict)', async () => {
    const res = await post({ dryRun: false, items: [item({ ref: 'AYi-2', status: 'wont_fix' })] });
    expect(res.json().results[0]).toMatchObject({ outcome: 'conflict', status: 'false_positive' });
  });

  it('gives each item its own changelog comment', async () => {
    const res = await post({
      dryRun: false,
      items: [
        item({
          ref: 'AYi-3',
          line: 3,
          sonarLineHash: sonarLineHash(LINES[2]!),
          status: 'wont_fix',
          comment: 'own comment',
        }),
      ],
    });
    expect(res.json().results[0]).toMatchObject({ outcome: 'applied' });
    const changes = await h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, (await issueAt(3)).id));
    expect(changes.at(-1)?.comment).toBe('own comment');
  });

  it('reports unmatched items', async () => {
    const res = await post({ dryRun: true, items: [item({ ref: 'AYi-4', path: 'src/zzz.ts' })] });
    expect(res.json().results[0]).toEqual({
      ref: 'AYi-4',
      outcome: 'unmatched',
      issueId: null,
      status: null,
    });
  });

  it('applies the status of an external_roslyn issue to the roslyn issue of a C# file (§6.1)', async () => {
    const cs = await h.project('acme/import-cs');
    const lines = ['class Cart', '{', '    public int Count() => 0;', '}'];
    const message = "Member 'Count' does not access instance data and can be marked as static";
    await cs.ingestOk(
      reportWith({
        projectKey: cs.key,
        engines: [engine('roslyn')],
        files: [file('src/Shop/Cart.cs', { language: 'csharp', lines: lines.length })],
        findings: [
          finding({
            engineId: 'roslyn',
            ruleId: 'CA1822',
            path: 'src/Shop/Cart.cs',
            line: 3,
            message,
            snippet: { startLine: 1, lines },
          }),
        ],
      }),
    );
    const ruleKeys = SONAR_MAPPING.targets('external_roslyn:CA1822').map((t) => t.key);
    expect(ruleKeys).toEqual(['roslyn:CA1822']);
    const res = await post(
      {
        dryRun: false,
        items: [
          item({
            ref: 'AYr-1',
            ruleKeys,
            path: 'src/Shop/Cart.cs',
            line: 3,
            sonarLineHash: sonarLineHash(lines[2]!),
            message,
            comment: 'Imported from SonarQube issue AYr-1 (False positive on 2026-09-10)',
          }),
        ],
      },
      h.orgAdmin,
      cs.id,
    );
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().results[0]).toMatchObject({ outcome: 'applied', status: 'false_positive' });
    const [row] = await h.ctx.db.select().from(issues).where(eq(issues.projectId, cs.id));
    expect(row?.status).toBe('false_positive');
  });

  it('is 409 PROJECT_NOT_ANALYSED before the first analysis', async () => {
    const fresh = await h.project('acme/import-fresh');
    const res = await post({ dryRun: true, items: [item()] }, h.orgAdmin, fresh.id);
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe('PROJECT_NOT_ANALYSED');
  });

  it('is for org admins only, and validates every item', async () => {
    expect((await post({ dryRun: true, items: [item()] }, member)).statusCode).toBe(403);
    const dup = await post({ dryRun: true, items: [item(), item()] });
    expect(dup.statusCode).toBe(422);
    expect(dup.json().errors[0].path).toBe('body.items.1.ref');
    for (const bad of [
      { comment: 'a\u0000b' },
      { comment: '   ' },
      { comment: '\u0007\u001b ' },
      { path: '../etc/passwd' },
      { path: '/abs' },
      { path: 'src\\a.ts' },
      { path: 'src/./a.ts' },
      { path: 'src/a\u0000.ts' },
      { message: 'a\u0000b' },
      { sonarLineHash: 'XYZ' },
      { ruleKeys: [] },
      { ruleKeys: ['no-engine'] },
      { status: 'resolved' },
      { ref: 'bad ref' },
      { line: 0 },
      { extra: true },
      { comment: undefined },
      { competitorsUnknown: 'yes' },
      { status: 'open', competitorsUnknown: true },
      { status: 'open', comment: '' },
    ]) {
      const res = await post({ dryRun: true, items: [item(bad)] });
      expect(res.statusCode, JSON.stringify(bad)).toBe(422);
    }
    expect((await post({ dryRun: true, items: [] })).statusCode).toBe(422);
    expect((await post({ dryRun: true, items: [item()], more: 1 })).statusCode).toBe(422);
  });

  it('needs the admin scope on a token: a read or write token is 403 INSUFFICIENT_SCOPE', async () => {
    const mint = async (scopes: string[]) =>
      (
        await h.ctx.app.inject({
          method: 'POST',
          url: '/api/v0/tokens',
          headers: h.orgAdmin.headers,
          payload: { name: `import-${scopes.join('-')}`, scopes },
        })
      ).json<{ token: string }>().token;
    const withToken = async (scopes: string[]) =>
      h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/projects/${p.id}/issue-status-import`,
        headers: bearer(await mint(scopes)),
        payload: { dryRun: true, items: [item()] },
      });
    for (const scopes of [['read'], ['write'], ['read', 'write']]) {
      const res = await withToken(scopes);
      expect([res.statusCode, res.json().code], scopes.join()).toEqual([403, 'INSUFFICIENT_SCOPE']);
    }
    expect((await withToken(['admin'])).statusCode).toBe(200);
  });

  it('turns a CRLF or a lone CR of a comment into a line feed', () => {
    expect(sanitizeImportComment('a\r\nb\rc\n\u0007d\te\u009b')).toBe('a\nb\nc\nd\te');
  });

  it('refuses items that select too many candidates (413 IMPORT_TOO_LARGE)', async () => {
    const [admin] = await h.ctx.db.select().from(users).limit(1);
    const one = { ...item(), status: 'false_positive' as const };
    await expect(
      importIssueStatuses({ db: h.ctx.db }, admin!, p.id, [{ ...one, ref: 'x', line: 2 }], true, {
        maxCandidates: 0,
      }),
    ).rejects.toMatchObject({ status: 413, code: 'IMPORT_TOO_LARGE' });
  });

  describe('bounds, tenancy, ambiguity and atomicity', () => {
    let q: IngestProject;
    let branchId: string;
    let ruleId: string;
    const seed = (line: number, over: Partial<IssueSeed> = {}) =>
      seedIssue(h.ctx.db, {
        projectId: q.id,
        branchId,
        ruleId,
        path: 'src/b.ts',
        startLine: line,
        message: MESSAGE,
        ...over,
      });
    const postQ = (body: unknown) => post(body, h.orgAdmin, q.id);
    const at = (line: number, over: Record<string, unknown> = {}) =>
      item({ path: 'src/b.ts', line, sonarLineHash: null, ref: `B-${line}`, ...over });

    beforeAll(async () => {
      q = await h.project('acme/import-more');
      await q.ingestOk(reportWith({ projectKey: q.key }));
      branchId = await mainBranchId(h.ctx.db, q.id);
      ruleId = await seedRule(h.ctx.db, { key: 'eslint:eqeqeq' });
    });

    it('answers 404 for a project of another organisation', async () => {
      const [org] = await h.ctx.db
        .insert(organizations)
        .values({ key: 'elsewhere', name: 'Elsewhere' })
        .returning();
      const [other] = await h.ctx.db
        .insert(projects)
        .values({ organizationId: org!.id, key: 'elsewhere/app', name: 'App' })
        .returning();
      const res = await post({ dryRun: true, items: [item()] }, h.orgAdmin, other!.id);
      expect([res.statusCode, res.json().code]).toEqual([404, 'NOT_FOUND']);
    });

    it('takes at most 1 000 items (422) and a body of at most 1 MiB (413)', async () => {
      const many = Array.from({ length: 1001 }, (_, n) => at(1, { ref: `M-${n}` }));
      const tooMany = await postQ({ dryRun: true, items: many });
      expect(tooMany.statusCode).toBe(422);
      const long = 'x'.repeat(1990);
      const big = Array.from({ length: 600 }, (_, n) =>
        at(1, { ref: `L-${n}`, comment: long, message: long }),
      );
      const tooBig = await postQ({ dryRun: true, items: big });
      expect([tooBig.statusCode, tooBig.json().code]).toEqual([413, 'BODY_TOO_LARGE']);
    });

    it('marks two items asking different statuses of two identical issues ambiguous', async () => {
      const a = await seed(1000);
      const b = await seed(1000);
      const res = await postQ({
        dryRun: false,
        items: [at(1000, { ref: 'D-1' }), at(1000, { ref: 'D-2', status: 'wont_fix' })],
      });
      expect(res.json().results).toEqual([
        { ref: 'D-1', outcome: 'ambiguous', issueId: null, status: null },
        { ref: 'D-2', outcome: 'ambiguous', issueId: null, status: null },
      ]);
      expect([await statusOf(a), await statusOf(b)]).toEqual(['open', 'open']);
    });

    it('pairs twins fully only when their whole comments are the same (S6, S8, S8c)', async () => {
      const twin = (
        ref: string,
        text: string,
        label: ImportCommentLabel = 'False positive',
        date = '2026-09-10',
      ) =>
        at(4500, {
          ref,
          status: label === 'False positive' ? 'false_positive' : 'wont_fix',
          comment: importCommentHeader({ key: ref, label, date }) + text,
        });
      const a = await seed(4500);
      const b = await seed(4500);
      const outcomes = async (items: unknown[], dryRun = true) =>
        (await postQ({ dryRun, items })).json().results.map((r: { outcome: string }) => r.outcome);
      expect(await outcomes([twin('T-1', ': a is unused'), twin('T-2', ': b is needed')])).toEqual([
        'ambiguous',
        'ambiguous',
      ]);
      // The status label counts: Won't fix and Accepted twins (both wont_fix) differ.
      expect(
        await outcomes([twin('T-1', ': x', "Won't fix"), twin('T-2', ': x', 'Accepted')]),
      ).toEqual(['ambiguous', 'ambiguous']);
      expect(await outcomes([twin('T-1', ': x'), twin('T-2', '')])).toEqual([
        'ambiguous',
        'ambiguous',
      ]);
      // Only the key and the date are masked.
      expect(
        await outcomes(
          [twin('T-1', ': safe here'), twin('T-2', ': safe here', 'False positive', '2025-01-02')],
          false,
        ),
      ).toEqual(['applied', 'applied']);
      expect([await statusOf(a), await statusOf(b)]).toEqual(['false_positive', 'false_positive']);
    });

    it('holds back one issue that twins with different comments tie on (S8b)', async () => {
      const only = await seed(4600);
      const tied = (ref: string, text: string) =>
        at(4600, {
          ref,
          comment: `${importCommentHeader({ key: ref, label: 'False positive', date: '2026-09-10' })}: ${text}`,
        });
      const differ = await postQ({
        dryRun: false,
        items: [tied('U-1', 'a is unused'), tied('U-2', 'b is needed')],
      });
      expect(differ.json().results).toEqual([
        { ref: 'U-1', outcome: 'ambiguous', issueId: null, status: null },
        { ref: 'U-2', outcome: 'ambiguous', issueId: null, status: null },
      ]);
      expect(await statusOf(only)).toBe('open');
      const same = await postQ({
        dryRun: true,
        items: [tied('U-1', 'safe here'), tied('U-2', 'safe here')],
      });
      expect(same.json().results.map((r: { outcome: string }) => r.outcome)).toEqual([
        'would_apply',
        'unmatched',
      ]);
    });

    it('mirrors the item comment onto duplicates and strips control characters', async () => {
      const primary = await seed(2000);
      const duplicate = await seed(2001, { duplicateOfIssueId: primary });
      const res = await postQ({
        dryRun: false,
        items: [at(2000, { comment: 'from\u0007 Sonar\r\nsecond line\u009b' })],
      });
      expect(res.json().results[0]).toMatchObject({ outcome: 'applied', issueId: primary });
      expect(await statusOf(duplicate)).toBe('false_positive');
      for (const id of [primary, duplicate]) {
        expect((await changesOf(id)).at(-1)?.comment).toBe('from Sonar\nsecond line');
      }
    });

    it('applies both statuses in one transaction: a held lock changes nothing', async () => {
      const x = await seed(3000);
      const y = await seed(3100);
      const items = [at(3000), at(3100, { status: 'wont_fix', comment: 'accepted' })];
      const [admin] = await h.ctx.db.select().from(users).where(eq(users.username, 'ingest-admin'));
      const holder = new pg.Client({ connectionString: h.ctx.database.url });
      await holder.connect();
      try {
        await holder.query('BEGIN');
        await holder.query('SELECT 1 FROM issues WHERE id = $1 FOR UPDATE', [y]);
        await expectPgError(
          importIssueStatuses({ db: h.ctx.db }, admin!, q.id, items as ImportRequestItem[], false, {
            lockTimeoutMs: 100,
          }),
          '55P03',
        );
      } finally {
        await holder.query('ROLLBACK');
        await holder.end();
      }
      expect([await statusOf(x), await statusOf(y)]).toEqual(['open', 'open']);
      expect(await changesOf(x)).toEqual([]);

      const res = await postQ({ dryRun: false, items });
      expect(res.json().results).toEqual([
        { ref: 'B-3000', outcome: 'applied', issueId: x, status: 'false_positive' },
        { ref: 'B-3100', outcome: 'applied', issueId: y, status: 'wont_fix' },
      ]);
      expect((await changesOf(y)).at(-1)).toMatchObject({
        userId: admin!.id,
        oldValue: 'open',
        newValue: 'wont_fix',
        comment: 'accepted',
      });
    });

    it('answers 503 CONCURRENCY_CONFLICT over HTTP while an ingestion holds an issue, writing nothing', async () => {
      const x = await seed(3200);
      const y = await seed(3300);
      const holder = new pg.Client({ connectionString: h.ctx.database.url });
      await holder.connect();
      try {
        await holder.query('BEGIN');
        await holder.query('SELECT 1 FROM issues WHERE id = $1 FOR UPDATE', [y]);
        // The route's own lock timeout expires, and the CLI is told when to retry (spec §5.1).
        const res = await postQ({ dryRun: false, items: [at(3200), at(3300)] });
        expect([res.statusCode, res.json().code]).toEqual([503, 'CONCURRENCY_CONFLICT']);
        expect(res.headers['retry-after']).toBe('1');
      } finally {
        await holder.query('ROLLBACK');
        await holder.end();
      }
      expect([await statusOf(x), await statusOf(y)]).toEqual(['open', 'open']);
      expect(await changesOf(x)).toEqual([]);
    });

    /** An open competitor as the CLI sends it: without a comment. */
    const open = (line: number, over: Record<string, unknown> = {}) =>
      Object.fromEntries(
        Object.entries(at(line, { ref: `O-${line}`, status: 'open', ...over })).filter(
          ([k]) => k !== 'comment' || 'comment' in over,
        ),
      );

    it('takes open items as competitors: never applied, never listed, only counted', async () => {
      // One issue, a resolved item and an open one on its line: nothing tells whose it is.
      const x = await seed(6000);
      const res = await postQ({ dryRun: false, items: [open(6000), at(6000)] });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({
        results: [{ ref: 'B-6000', outcome: 'ambiguous', issueId: null, status: null }],
        competitors: 1,
      });
      expect(await statusOf(x)).toBe('open');
      // An open item that matches its own issue by the message leaves the other to the resolved one.
      const mine = await seed(6100, { message: 'the open one' });
      const other = await seed(6100);
      const split = await postQ({
        dryRun: false,
        items: [open(6100, { message: 'the open one' }), at(6100, { message: null })],
      });
      expect(split.json().results).toEqual([
        { ref: 'B-6100', outcome: 'applied', issueId: other, status: 'false_positive' },
      ]);
      expect(await statusOf(mine)).toBe('open');
      const only = await postQ({ dryRun: false, items: [open(7000, { comment: 'ignored' })] });
      expect(only.json()).toMatchObject({ results: [], competitors: 1 });
      const dup = await postQ({ dryRun: true, items: [at(1), open(1, { ref: 'B-1' })] });
      expect([dup.statusCode, dup.json().errors[0].path]).toEqual([422, 'body.items.1.ref']);
    });

    it('reports competitors_unknown items and never applies them', async () => {
      const x = await seed(6200);
      for (const dryRun of [true, false]) {
        const res = await postQ({ dryRun, items: [at(6200, { competitorsUnknown: true })] });
        expect(res.json().results).toEqual([
          { ref: 'B-6200', outcome: 'competitors_unknown', issueId: null, status: null },
        ]);
      }
      expect(await statusOf(x)).toBe('open');
    });

    it('applies nothing in a component with a marked item (ruling S12)', async () => {
      // A -> {x, y}, B -> {y, z}, the rule of z not read in full: B is marked, and A, which
      // would pair with its own issue on line 10, shares the issue of y with B.
      const [rx, ry, rz] = await Promise.all(
        ['eslint:s12-x', 'eslint:s12-y', 'eslint:s12-z'].map((key) => seedRule(h.ctx.db, { key })),
      );
      const on = (rule: string, line: number) =>
        seedIssue(h.ctx.db, {
          projectId: q.id,
          branchId,
          ruleId: rule,
          path: 'src/s12.ts',
          startLine: line,
          message: MESSAGE,
        });
      const [x, y, z] = [await on(rx!, 10), await on(ry!, 20), await on(rz!, 30)];
      const a = at(10, {
        ref: 'S12-A',
        path: 'src/s12.ts',
        ruleKeys: ['eslint:s12-x', 'eslint:s12-y'],
      });
      const b = at(30, {
        ref: 'S12-B',
        path: 'src/s12.ts',
        ruleKeys: ['eslint:s12-y', 'eslint:s12-z'],
        competitorsUnknown: true,
      });
      for (const dryRun of [true, false]) {
        const res = await postQ({ dryRun, items: [a, b] });
        expect(res.json().results).toEqual([
          { ref: 'S12-A', outcome: 'competitors_unknown', issueId: null, status: null },
          { ref: 'S12-B', outcome: 'competitors_unknown', issueId: null, status: null },
        ]);
      }
      expect([await statusOf(x), await statusOf(y), await statusOf(z)]).toEqual([
        'open',
        'open',
        'open',
      ]);
      // Without B, A applies: the marking reaches A only through B.
      const alone = await postQ({ dryRun: true, items: [a] });
      expect(alone.json().results).toEqual([
        { ref: 'S12-A', outcome: 'would_apply', issueId: x, status: 'open' },
      ]);
    });

    it('never mirrors a primary onto a duplicate matched to another status (§10.5)', async () => {
      const primary = await seed(8000);
      const duplicate = await seed(8001, { duplicateOfIssueId: primary });
      const items = [at(8000), at(8001, { status: 'wont_fix', comment: 'accepted' })];
      for (const dryRun of [true, false]) {
        const res = await postQ({ dryRun, items });
        expect(res.json().results).toEqual([
          { ref: 'B-8000', outcome: 'ambiguous', issueId: null, status: null },
          { ref: 'B-8001', outcome: 'ambiguous', issueId: null, status: null },
        ]);
      }
      // An open competitor on the duplicate holds the primary back just as well.
      const withOpen = await postQ({ dryRun: false, items: [at(8000), open(8001)] });
      expect(withOpen.json().results[0]).toMatchObject({ outcome: 'ambiguous' });
      expect([await statusOf(primary), await statusOf(duplicate)]).toEqual(['open', 'open']);

      // The same status on both: the dry run and the apply agree.
      const p2 = await seed(8100);
      const d2 = await seed(8101, { duplicateOfIssueId: p2 });
      const same = [at(8100), at(8101)];
      const dry = await postQ({ dryRun: true, items: same });
      expect(dry.json().results.map((r: { outcome: string }) => r.outcome)).toEqual([
        'would_apply',
        'would_apply',
      ]);
      const applied = await postQ({ dryRun: false, items: same });
      expect(applied.json().results.map((r: { outcome: string }) => r.outcome)).toEqual([
        'applied',
        'applied',
      ]);
      expect([await statusOf(p2), await statusOf(d2)]).toEqual([
        'false_positive',
        'false_positive',
      ]);
    });

    it('never mirrors a status onto a held-back duplicate (I-1)', async () => {
      // p and its duplicate d on one line; X and the open O both reach d (held back), so applying
      // Y to p would mirror false_positive onto d, whose counterpart O is still open.
      const es = await seedRule(h.ctx.db, { key: 'spotbugs:ES_COMPARING_STRINGS_WITH_EQ' });
      const use = await seedRule(h.ctx.db, { key: 'pmd:UseEqualsToCompareStrings' });
      const primary = await seed(9000, { ruleId: es });
      const duplicate = await seed(9000, { ruleId: use, duplicateOfIssueId: primary });
      const items = [
        at(9000, { ref: 'I1-Y', ruleKeys: ['spotbugs:ES_COMPARING_STRINGS_WITH_EQ'] }),
        at(9000, { ref: 'I1-X', ruleKeys: ['pmd:UseEqualsToCompareStrings'] }),
        open(9000, { ref: 'I1-O', ruleKeys: ['pmd:UseEqualsToCompareStrings'] }),
      ];
      for (const dryRun of [true, false]) {
        const res = await postQ({ dryRun, items });
        expect(res.statusCode).toBe(200);
        expect(res.json().results).toEqual([
          { ref: 'I1-Y', outcome: 'ambiguous', issueId: null, status: null },
          { ref: 'I1-X', outcome: 'ambiguous', issueId: null, status: null },
        ]);
      }
      expect([await statusOf(primary), await statusOf(duplicate)]).toEqual(['open', 'open']);
    });

    it('never touches a resolved issue, and ignores closed ones', async () => {
      const resolved = await seed(4000, { status: 'resolved' });
      await seed(5000, { status: 'closed' });
      const res = await postQ({ dryRun: false, items: [at(4000), at(5000)] });
      expect(res.json().results).toEqual([
        { ref: 'B-4000', outcome: 'conflict', issueId: resolved, status: 'resolved' },
        { ref: 'B-5000', outcome: 'unmatched', issueId: null, status: null },
      ]);
      expect(await changesOf(resolved)).toEqual([]);
    });
  });
});
