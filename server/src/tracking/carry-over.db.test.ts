import { and, asc, eq, isNull } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { engine, file, finding, reportWith, type ReportParts } from '../../test/reports';
import { uuidv7 } from '../db/ids';
import { branches, issueChanges, issues, rules, users } from '../db/schema';
import { CARRY_OVER_COMMENT_CHARS, writeCarryOver } from './carry-over';

type RuleMeta = Report['engines'][number]['rules'][number];
const JAVA = 'src/main/java/com/acme/OrderRepository.java';
const LINE = 15;
const RULES: Record<string, RuleMeta> = {
  spotbugs: { id: 'SQL_INJECTION_JDBC', quality: 'security', kind: 'issue', cwe: [89] },
  semgrep: { id: 'my-sqli', quality: 'security', kind: 'issue', cwe: [89] },
  qualor: {
    id: 'java/sql-injection',
    quality: 'security',
    kind: 'issue',
    defaultSeverity: 'high',
    cwe: [89],
  },
};

function report(
  key: string,
  analysisDate: string,
  engineIds: string[],
  extra: ReportParts = {},
): Report {
  return reportWith({
    ...extra,
    projectKey: key,
    analysisDate,
    engines: engineIds.map((id) => engine(id, [RULES[id]!])),
    files: [file(JAVA, { language: 'java' })],
    findings: engineIds.map((id) =>
      finding({ engineId: id, ruleId: RULES[id]!.id, path: JAVA, line: LINE }),
    ),
  });
}

describe('status carry-over to a new qualor issue (data-model.md §5.3, plan 6B-1)', () => {
  let h: IngestHarness;
  let adminId: string;
  const byRule = async (p: IngestProject, key: string) =>
    (
      await h.ctx.db
        .select({ issue: issues })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .where(and(eq(issues.projectId, p.id), eq(rules.key, key)))
    )[0]!.issue;
  const changelog = (issueId: string) =>
    h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issueId))
      .orderBy(asc(issueChanges.id));
  const triage = async (
    p: IngestProject,
    key: string,
    status: 'false_positive' | 'wont_fix',
    comment: string,
  ) => {
    const issue = await byRule(p, key);
    await h.ctx.db
      .update(issues)
      .set({ status, resolvedAt: new Date('2026-09-01T10:00:00Z'), resolvedBy: adminId })
      .where(eq(issues.id, issue.id));
    await h.ctx.db.insert(issueChanges).values({
      id: uuidv7(),
      issueId: issue.id,
      userId: adminId,
      field: 'status',
      oldValue: 'open',
      newValue: status,
      comment,
    });
  };
  const byRuleOn = async (p: IngestProject, branch: string, key: string) =>
    (
      await h.ctx.db
        .select({ issue: issues })
        .from(issues)
        .innerJoin(rules, eq(rules.id, issues.ruleId))
        .innerJoin(branches, eq(branches.id, issues.branchId))
        .where(and(eq(issues.projectId, p.id), eq(branches.name, branch), eq(rules.key, key)))
    )[0]!.issue;
  const entriesOf = async (issueId: string) =>
    (await changelog(issueId)).map((c) => [c.userId, c.oldValue, c.newValue, c.comment]);
  const visibleOpen = (p: IngestProject) =>
    h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .where(
        and(
          eq(issues.projectId, p.id),
          eq(issues.status, 'open'),
          isNull(issues.duplicateOfIssueId),
        ),
      );

  beforeAll(async () => {
    h = await createIngestHarness();
    adminId = (
      await h.ctx.db.select({ id: users.id }).from(users).where(eq(users.username, 'ingest-admin'))
    )[0]!.id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('takes a SpotBugs false positive on its line with its resolver and comment, once', async () => {
    const p = await h.project('carry/fp');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    await triage(
      p,
      'spotbugs:SQL_INJECTION_JDBC',
      'false_positive',
      'the customer id is a UUID from our own table',
    );
    const second = await p.ingestOk(report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor']));
    const q = await byRule(p, 'qualor:java/sql-injection');
    const sb = await byRule(p, 'spotbugs:SQL_INJECTION_JDBC');
    expect(q).toMatchObject({
      status: 'false_positive',
      resolvedBy: adminId,
      duplicateOfIssueId: null,
    });
    expect(q.resolvedAt?.toISOString()).toBe('2026-09-01T10:00:00.000Z');
    expect(sb).toMatchObject({ status: 'false_positive', duplicateOfIssueId: q.id });
    expect(await changelog(q.id)).toEqual([
      expect.objectContaining({
        userId: null,
        analysisId: second,
        field: 'status',
        oldValue: 'open',
        newValue: 'false_positive',
        comment:
          'Status carried over from spotbugs:SQL_INJECTION_JDBC. the customer id is a UUID from our own table',
      }),
    ]);
    expect(await visibleOpen(p)).toEqual([]);
    // A later reopen sticks: the issue exists now, so nothing is carried again.
    await h.ctx.db
      .update(issues)
      .set({ status: 'open', resolvedAt: null, resolvedBy: null })
      .where(eq(issues.id, q.id));
    await p.ingestOk(report(p.key, '2026-10-03T10:00:00Z', ['spotbugs', 'qualor']));
    expect(await byRule(p, 'qualor:java/sql-injection')).toMatchObject({ status: 'open' });
    expect(await changelog(q.id)).toHaveLength(1);
  });

  it('prefers a false positive to a won’t fix of another engine on the line', async () => {
    const p = await h.project('carry/precedence');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs', 'semgrep']));
    await triage(p, 'semgrep:my-sqli', 'wont_fix', 'accepted for now');
    await triage(p, 'spotbugs:SQL_INJECTION_JDBC', 'false_positive', 'a constant');
    await p.ingestOk(report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'semgrep', 'qualor']));
    const q = await byRule(p, 'qualor:java/sql-injection');
    expect(q.status).toBe('false_positive');
    expect((await byRule(p, 'semgrep:my-sqli')).duplicateOfIssueId).toBe(q.id);
    expect((await byRule(p, 'spotbugs:SQL_INJECTION_JDBC')).duplicateOfIssueId).toBe(q.id);
    expect((await changelog(q.id))[0]?.comment).toBe(
      'Status carried over from spotbugs:SQL_INJECTION_JDBC. a constant',
    );
  });

  it('carries nothing to a new root of another engine, nor from an open issue', async () => {
    const other = await h.project('carry/other-engine');
    await other.ingestOk(report(other.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    await triage(other, 'spotbugs:SQL_INJECTION_JDBC', 'false_positive', 'a constant');
    await other.ingestOk(report(other.key, '2026-10-02T10:00:00Z', ['spotbugs', 'semgrep']));
    expect(await byRule(other, 'semgrep:my-sqli')).toMatchObject({
      status: 'open',
      duplicateOfIssueId: null,
    });
    const open = await h.project('carry/open');
    await open.ingestOk(report(open.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    await open.ingestOk(report(open.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor']));
    const q = await byRule(open, 'qualor:java/sql-injection');
    expect(q.status).toBe('open');
    expect(await changelog(q.id)).toEqual([]);
  });

  it('writes a source comment cut at an astral character without a lone surrogate', async () => {
    const p = await h.project('carry/astral');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    // The longest comment the database takes (2,000 code points), an emoji where a cut by code
    // units would fall: the carried comment is longer than the bound and must be cut there.
    const note = 'Status carried over from spotbugs:SQL_INJECTION_JDBC. ';
    const head = 'y'.repeat(CARRY_OVER_COMMENT_CHARS - 2 - note.length);
    const comment = `${head}😀${'z'.repeat(CARRY_OVER_COMMENT_CHARS - 1 - head.length)}`;
    await triage(p, 'spotbugs:SQL_INJECTION_JDBC', 'false_positive', comment);
    await p.ingestOk(report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor']));
    const q = await byRule(p, 'qualor:java/sql-injection');
    expect(q.status).toBe('false_positive');
    const [entry] = await changelog(q.id);
    expect(entry?.comment).toBe(`${note}${head}😀…`);
  });

  it("never undoes a reopen on main in a new branch's inherited copy (data-model.md §5.4)", async () => {
    const p = await h.project('carry/inherited-reopen');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    await triage(p, 'spotbugs:SQL_INJECTION_JDBC', 'false_positive', 'a constant');
    await p.ingestOk(report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor']));
    const q = await byRuleOn(p, 'main', 'qualor:java/sql-injection');
    expect(q.status).toBe('false_positive');
    // A user reopens the qualor issue on main; the SpotBugs one stays a false positive.
    await h.ctx.db
      .update(issues)
      .set({ status: 'open', resolvedAt: null, resolvedBy: null })
      .where(eq(issues.id, q.id));
    await h.ctx.db.insert(issueChanges).values({
      id: uuidv7(),
      issueId: q.id,
      userId: adminId,
      field: 'status',
      oldValue: 'false_positive',
      newValue: 'open',
      comment: 'the id comes from the request after all',
    });
    // The first analysis of a feature branch inherits both: S′ false_positive, Q′ open.
    await p.ingestOk(
      report(p.key, '2026-10-03T10:00:00Z', ['spotbugs', 'qualor'], { branch: 'feature/x' }),
    );
    const q2 = await byRuleOn(p, 'feature/x', 'qualor:java/sql-injection');
    const s2 = await byRuleOn(p, 'feature/x', 'spotbugs:SQL_INJECTION_JDBC');
    expect(q2).toMatchObject({ status: 'open', resolvedBy: null, duplicateOfIssueId: null });
    expect(s2).toMatchObject({ status: 'false_positive', duplicateOfIssueId: q2.id });
    // Only the changelog copied from main: the carry-over there and the reopen, nothing new.
    expect(await entriesOf(q2.id)).toEqual(await entriesOf(q.id));
    expect(await entriesOf(q2.id)).toHaveLength(2);
  });

  it('carries to a qualor issue new on a branch whose SpotBugs issue was inherited', async () => {
    const p = await h.project('carry/new-on-branch');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    await triage(p, 'spotbugs:SQL_INJECTION_JDBC', 'false_positive', 'a constant');
    // Main has no qualor issue: on the branch's first analysis it is genuinely new.
    await p.ingestOk(
      report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor'], { branch: 'feature/y' }),
    );
    const q = await byRuleOn(p, 'feature/y', 'qualor:java/sql-injection');
    expect(q).toMatchObject({ status: 'false_positive', resolvedBy: adminId });
    expect(await entriesOf(q.id)).toEqual([
      [
        null,
        'open',
        'false_positive',
        'Status carried over from spotbugs:SQL_INJECTION_JDBC. a constant',
      ],
    ]);
  });

  it('writes nothing when the source no longer has the planned status (a concurrent reopen)', async () => {
    const p = await h.project('carry/source-moved');
    await p.ingestOk(report(p.key, '2026-10-01T10:00:00Z', ['spotbugs']));
    const analysisId = await p.ingestOk(
      report(p.key, '2026-10-02T10:00:00Z', ['spotbugs', 'qualor']),
    );
    const q = await byRule(p, 'qualor:java/sql-injection');
    const sb = await byRule(p, 'spotbugs:SQL_INJECTION_JDBC');
    expect(sb.status).toBe('open');
    const planned = [
      {
        issueId: q.id,
        status: 'false_positive' as const,
        sourceIssueId: sb.id,
        sourceRuleKey: 'spotbugs:SQL_INJECTION_JDBC',
      },
    ];
    expect(await writeCarryOver(h.ctx.db, planned, analysisId)).toBe(0);
    expect(await byRule(p, 'qualor:java/sql-injection')).toMatchObject({
      status: 'open',
      resolvedAt: null,
      resolvedBy: null,
    });
    expect(await changelog(q.id)).toEqual([]);
  });
});
