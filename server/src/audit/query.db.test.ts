import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { ProblemError } from '../http/problem';
import { auditEvents, type AuditEventRow } from '../db/schema';
import { eventHash, recordOf, type AuditEventRecord } from './chain';
import { appendEvents, SYSTEM_ACTOR, type AuditActorContext } from './recorder';
import {
  decodeSeqCursor,
  encodeSeqCursor,
  exportAuditLines,
  MAX_EXPORT_DAYS,
  queryAuditEvents,
} from './query';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const t0 = new Date('2026-03-01T00:00:00.000Z');
const t1 = new Date(t0.getTime() + 20 * HOUR);

const orgA = randomUUID();
const orgB = randomUUID();
const projectA = randomUUID();
const alice: AuditActorContext = {
  actor: { type: 'user', userId: randomUUID(), username: 'alice', tokenId: null },
  ip: '10.0.0.5',
  userAgent: 'test',
};
const bob: AuditActorContext = {
  actor: { type: 'user', userId: randomUUID(), username: 'bob', tokenId: null },
  ip: null,
  userAgent: null,
};
const userTarget = (id: string) => ({ type: 'user' as const, id, label: 'someone' });

async function collect(lines: AsyncIterable<string>): Promise<string[]> {
  const out: string[] = [];
  for await (const line of lines) out.push(line);
  return out;
}

describe('audit query and export (rbac-audit.md §12, §13)', () => {
  let database: TestDatabase;
  const targetOfSeven = randomUUID();

  beforeAll(async () => {
    database = await createTestDatabase();
    const db = database.db;
    // 30 events, one an hour from t0: member.added in orgA and orgB, project_member.added in a
    // project of orgA, and instance-level sign-outs.
    for (let i = 0; i < 30; i += 1) {
      const at = new Date(t0.getTime() + i * HOUR);
      const kind = i % 3;
      const actor = i % 2 === 0 ? alice : bob;
      if (kind === 0) {
        await appendEvents(
          db,
          actor,
          [
            {
              action: 'member.added',
              organization: { id: i % 2 === 0 ? orgA : orgB, key: i % 2 === 0 ? 'a' : 'b' },
              target: userTarget(i === 6 ? targetOfSeven : randomUUID()),
              details: { role: 'member' },
            },
          ],
          at,
        );
      } else if (kind === 1) {
        await appendEvents(
          db,
          actor,
          [
            {
              action: 'project_member.added',
              organization: { id: orgA, key: 'a' },
              project: { id: projectA, key: 'pa' },
              target: userTarget(randomUUID()),
              details: { role: 'viewer' },
            },
          ],
          at,
        );
      } else {
        await appendEvents(
          db,
          SYSTEM_ACTOR,
          [{ action: 'auth.sign_out', outcome: i === 29 ? 'failure' : 'success', details: {} }],
          at,
        );
      }
    }
    // `member_x.y` is not a catalogue action: one raw row (an INSERT is allowed by the trigger),
    // with a correct hash of its own so the export test's per-line check holds for it too.
    const raw: AuditEventRow = {
      id: randomUUID(),
      seq: 31,
      createdAt: new Date(t0.getTime() + 30 * HOUR),
      action: 'member_x.y',
      outcome: 'success',
      actorType: 'system',
      actorUserId: null,
      actorUsername: null,
      actorTokenId: null,
      organizationId: orgA,
      organizationKey: 'a',
      projectId: null,
      projectKey: null,
      targetType: null,
      targetId: null,
      targetLabel: null,
      ip: null,
      userAgent: null,
      details: {},
      prevHash: '0'.repeat(64),
      hash: '',
    };
    raw.hash = eventHash(raw.prevHash, recordOf(raw));
    await db.insert(auditEvents).values(raw);
  });
  afterAll(async () => database.close());

  it('filters by each parameter and pages newest first', async () => {
    const page1 = await queryAuditEvents(database.db, { actions: ['member.*'] }, { limit: 5 });
    expect(page1.items).toHaveLength(5);
    expect(page1.items.map((e) => Number(e.seq))).toEqual(
      [...page1.items.map((e) => Number(e.seq))].sort((a, b) => b - a),
    );
    expect(page1.items.every((e) => e.action.startsWith('member.'))).toBe(true);
    const page2 = await queryAuditEvents(
      database.db,
      { actions: ['member.*'] },
      { limit: 5, cursor: page1.nextCursor! },
    );
    expect(Number(page2.items[0]!.seq)).toBeLessThan(Number(page1.items.at(-1)!.seq));
    expect(page2.nextCursor).toBeNull(); // 10 member.added events in all
  });

  it('matches an action prefix literally: member_x is not member.*', async () => {
    const r = await queryAuditEvents(database.db, { actions: ['member.*'] }, { limit: 500 });
    expect(r.items).toHaveLength(10);
    expect(r.items.some((e) => e.action === 'member_x.y')).toBe(false);
    expect(r.items.some((e) => e.action.startsWith('project_member.'))).toBe(false);
  });

  it('combines exact names and prefixes', async () => {
    const r = await queryAuditEvents(
      database.db,
      { actions: ['auth.sign_out', 'project_member.*'] },
      { limit: 500 },
    );
    expect(r.items).toHaveLength(20);
    expect(new Set(r.items.map((e) => e.action))).toEqual(
      new Set(['auth.sign_out', 'project_member.added']),
    );
  });

  it('keeps instance-level events out of an organisation’s view', async () => {
    const r = await queryAuditEvents(
      database.db,
      { organizationId: orgA, instanceLevel: 'exclude' },
      { limit: 500 },
    );
    expect(r.items.length).toBeGreaterThan(0);
    expect(r.items.every((e) => e.organization?.id === orgA)).toBe(true);
    const all = await queryAuditEvents(database.db, { instanceLevel: 'exclude' }, { limit: 500 });
    expect(all.items.some((e) => e.organization === null)).toBe(false);
    const included = await queryAuditEvents(database.db, {}, { limit: 500 });
    expect(included.items.some((e) => e.organization === null)).toBe(true);
  });

  it('filters by outcome, actor, project, target and period', async () => {
    const failures = await queryAuditEvents(database.db, { outcome: 'failure' }, { limit: 500 });
    expect(failures.items.map((e) => e.seq)).toEqual(['30']);

    const byAlice = await queryAuditEvents(
      database.db,
      { actorUserId: (alice.actor as { userId: string }).userId },
      { limit: 500 },
    );
    expect(byAlice.items.length).toBeGreaterThan(0);
    expect(byAlice.items.every((e) => e.actor.username === 'alice')).toBe(true);

    const inProject = await queryAuditEvents(database.db, { projectId: projectA }, { limit: 500 });
    expect(inProject.items).toHaveLength(10);
    expect(inProject.items.every((e) => e.project?.id === projectA)).toBe(true);

    const oneTarget = await queryAuditEvents(
      database.db,
      { targetType: 'user', targetId: targetOfSeven },
      { limit: 500 },
    );
    expect(oneTarget.items.map((e) => e.seq)).toEqual(['7']);

    // `from` inclusive, `to` exclusive: hours 5, 6, 7 are seq 6, 7, 8.
    const period = await queryAuditEvents(
      database.db,
      { from: new Date(t0.getTime() + 5 * HOUR), to: new Date(t0.getTime() + 8 * HOUR) },
      { limit: 500 },
    );
    expect(period.items.map((e) => e.seq)).toEqual(['8', '7', '6']);
  });

  it('binds every value: a quote or a LIKE wildcard in a filter matches nothing', async () => {
    for (const action of ["x' OR '1'='1", '%', 'member%.*', '_ember.*']) {
      const r = await queryAuditEvents(database.db, { actions: [action] }, { limit: 500 });
      expect(r.items).toHaveLength(0);
    }
    const r = await queryAuditEvents(
      database.db,
      { targetType: "user' OR '1'='1", targetId: '%' },
      { limit: 500 },
    );
    expect(r.items).toHaveLength(0);
  });

  it('pages stably while events are appended between pages', async () => {
    const db = database.db;
    const page1 = await queryAuditEvents(db, { actions: ['project_member.*'] }, { limit: 4 });
    // Newer events arrive between the two pages; the seq cursor neither repeats nor skips.
    await appendEvents(
      db,
      alice,
      [
        {
          action: 'project_member.added',
          organization: { id: orgA, key: 'a' },
          project: { id: projectA, key: 'pa' },
          target: userTarget(randomUUID()),
          details: { role: 'viewer' },
        },
      ],
      new Date(t0.getTime() + 40 * DAY),
    );
    const rest: AuditEventRecord[] = [];
    let cursor = page1.nextCursor;
    while (cursor !== null) {
      const page = await queryAuditEvents(
        db,
        { actions: ['project_member.*'] },
        { limit: 4, cursor },
      );
      rest.push(...page.items);
      cursor = page.nextCursor;
    }
    const seqs = [...page1.items, ...rest].map((e) => Number(e.seq));
    expect(seqs).toHaveLength(10);
    expect(new Set(seqs).size).toBe(10);
    expect(seqs).toEqual([...seqs].sort((a, b) => b - a));
  });

  it('refuses a malformed cursor with 422 on query.cursor', async () => {
    expect(decodeSeqCursor(encodeSeqCursor(42))).toBe(42);
    expect(decodeSeqCursor(undefined)).toBeUndefined();
    for (const bad of ['', 'not-a-cursor', encodeSeqCursor(1).concat('!'), 'LTE', 'MS41']) {
      let error: unknown;
      try {
        await queryAuditEvents(database.db, {}, { limit: 5, cursor: bad });
      } catch (err) {
        error = err;
      }
      expect(error).toBeInstanceOf(ProblemError);
      expect((error as ProblemError).status).toBe(422);
      expect((error as ProblemError).errors).toEqual([
        { path: 'query.cursor', message: 'Invalid cursor' },
      ]);
    }
  });

  it('exports a period oldest first, each line self-verifying', async () => {
    const lines = await collect(exportAuditLines(database.db, { from: t0, to: t1 }));
    expect(lines).toHaveLength(20);
    expect(lines.every((l) => !l.includes('\n'))).toBe(true);
    const records = lines.map((l) => JSON.parse(l) as AuditEventRecord);
    expect(records.map((r) => Number(r.seq))).toEqual(
      [...records.map((r) => Number(r.seq))].sort((a, b) => a - b),
    );
    for (const r of records) {
      const { prevHash, hash, ...record } = r;
      expect(eventHash(prevHash, record)).toBe(hash);
    }
    // Without filters, each line's prevHash is the previous line's hash.
    for (let i = 1; i < records.length; i += 1) {
      expect(records[i]!.prevHash).toBe(records[i - 1]!.hash);
    }
  });

  it('applies the filters to an export', async () => {
    const lines = await collect(
      exportAuditLines(database.db, {
        from: t0,
        to: new Date(t0.getTime() + 60 * DAY),
        organizationId: orgA,
        instanceLevel: 'exclude',
      }),
    );
    const records = lines.map((l) => JSON.parse(l) as AuditEventRecord);
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((r) => r.organization?.id === orgA)).toBe(true);
  });

  it('refuses an export period that is empty, reversed or longer than 366 days', async () => {
    const periods: [Date, Date][] = [
      [t0, t0],
      [t1, t0],
      [t0, new Date(t0.getTime() + (MAX_EXPORT_DAYS + 1) * DAY)],
    ];
    for (const [from, to] of periods) {
      let error: unknown;
      try {
        await collect(exportAuditLines(database.db, { from, to }));
      } catch (err) {
        error = err;
      }
      expect((error as ProblemError).status).toBe(422);
      expect((error as ProblemError).errors?.[0]?.path).toBe('query.to');
    }
    // Exactly 366 days is allowed.
    await collect(
      exportAuditLines(database.db, {
        from: t0,
        to: new Date(t0.getTime() + MAX_EXPORT_DAYS * DAY),
      }),
    );
  });
});

describe('audit export across pages', () => {
  let database: TestDatabase;
  const start = new Date('2026-05-01T00:00:00.000Z');

  beforeAll(async () => {
    database = await createTestDatabase();
    await appendEvents(
      database.db,
      SYSTEM_ACTOR,
      Array.from({ length: 2_050 }, () => ({ action: 'auth.sign_out' as const, details: {} })),
      start,
    );
  });
  afterAll(async () => database.close());

  it('streams more than one keyset page in seq order, every event exactly once', async () => {
    const lines = await collect(
      exportAuditLines(database.db, { from: start, to: new Date(start.getTime() + DAY) }),
    );
    expect(lines.map((l) => Number((JSON.parse(l) as AuditEventRecord).seq))).toEqual(
      Array.from({ length: 2_050 }, (_, i) => i + 1),
    );
  });

  it('reads lazily: the first line arrives before the rest is read', async () => {
    const iterator = exportAuditLines(database.db, {
      from: start,
      to: new Date(start.getTime() + DAY),
    })[Symbol.asyncIterator]();
    const first = await iterator.next();
    expect((JSON.parse(first.value as string) as AuditEventRecord).seq).toBe('1');
    await iterator.return?.();
  });
});
