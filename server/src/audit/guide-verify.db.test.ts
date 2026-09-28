import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { exportAuditLines } from './query';
import { appendEvents, SYSTEM_ACTOR, type AuditActorContext } from './recorder';

const run = promisify(execFile);
const GUIDE = 'docs/guide/roles-and-audit.md';

/** The guide's one ```js block, read when the test runs (the guide's authors may change it). */
async function guideScript(): Promise<string> {
  const lines = (await readFile(GUIDE, 'utf8')).split('\n');
  const start = lines.findIndex((l) => l.trim() === '```js');
  expect(start, `${GUIDE} has a \`\`\`js block`).toBeGreaterThanOrEqual(0);
  const end = lines.findIndex((l, i) => i > start && l.trim() === '```');
  expect(end, 'the ```js block is closed').toBeGreaterThan(start);
  return lines.slice(start + 1, end).join('\n');
}

const alice: AuditActorContext = {
  actor: {
    type: 'user',
    userId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    username: 'alice',
    tokenId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e61',
  },
  ip: '203.0.113.7',
  userAgent: 'Mozilla/5.0 (Zoë; ✓)',
};
const organization = { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e62', key: 'acme' };
const project = { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e63', key: 'acme-web' };

/**
 * B I-2 of the 4C final review: the guide's verification script (roles-and-audit.md) run with
 * node on a real export body. It must verify every line (rbac-audit.md §10.1, §12), and a line
 * with a changed field must make it throw.
 */
describe("the guide's audit verification script", () => {
  let database: TestDatabase;
  let dir: string;
  let script: string;
  let lines: string[];

  beforeAll(async () => {
    database = await createTestDatabase();
    dir = await mkdtemp(join(tmpdir(), 'qualor-guide-verify-'));
    script = join(dir, 'verify-audit.mjs');
    await writeFile(script, await guideScript());
    const at = new Date('2026-12-01T10:00:00.000Z');
    await appendEvents(
      database.db,
      alice,
      [
        {
          action: 'member.role_changed',
          organization,
          target: {
            type: 'user',
            id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e64',
            label: 'Bob «the builder» 🚧',
          },
          details: { from: 'member', to: 'viewer' },
        },
        {
          action: 'quality_gate.condition_added',
          organization,
          target: { type: 'quality_gate', id: organization.id, label: 'Strict "gate"\t\\' },
          details: {
            conditionId: project.id,
            metric: 'coverage',
            operator: 'lt',
            threshold: '80.5',
          },
        },
        {
          action: 'project.updated',
          organization,
          project,
          target: { type: 'project', id: project.id, label: project.key },
          details: {
            changes: [
              { field: 'name', from: 'Web', to: 'Web app' },
              { field: 'newCodeDefinition', from: null, to: { type: 'days', value: 30 } },
            ],
          },
        },
      ],
      at,
    );
    await appendEvents(
      database.db,
      { actor: { type: 'anonymous', userId: null, username: null }, ip: null, userAgent: null },
      [
        {
          action: 'auth.sign_in_failed',
          outcome: 'failure',
          details: { reason: 'invalid_credentials', knownUser: false },
        },
      ],
      at,
    );
    await appendEvents(
      database.db,
      SYSTEM_ACTOR,
      [
        {
          action: 'audit.pruned',
          details: {
            throughSeq: '0',
            throughHash: '0'.repeat(64),
            deleted: 0,
            cutoff: '2025-12-01T00:00:00.000Z',
          },
        },
      ],
      at,
    );
    lines = [];
    for await (const line of exportAuditLines(database.db, {
      from: new Date('2026-11-01T00:00:00Z'),
      to: new Date('2027-01-01T00:00:00Z'),
    })) {
      lines.push(line);
    }
    expect(lines).toHaveLength(5);
  });
  afterAll(async () => {
    await database?.close();
    // A directory mkdtemp just created: it holds two plain files, no link.
    if (dir) await rm(dir, { recursive: true, force: true });
  });

  /** Runs the guide's script with node on `body`; its exit code, stdout and stderr. */
  const verify = async (body: string) => {
    const file = join(dir, 'audit.jsonl');
    await writeFile(file, body);
    try {
      const { stdout, stderr } = await run(process.execPath, [script, file]);
      return { code: 0, stdout, stderr };
    } catch (err) {
      const e = err as { code?: number; stdout?: string; stderr?: string };
      return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
    }
  };

  it('verifies every line of an export', async () => {
    const result = await verify(`${lines.join('\n')}\n`);
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe('5 events verified');
  });

  it('throws on a line with a changed field', async () => {
    for (const change of [
      (e: Record<string, unknown>) => ({
        ...e,
        actor: { ...(e.actor as object), username: 'eve' },
      }),
      (e: Record<string, unknown>) => ({ ...e, details: { from: 'member', to: 'admin' } }),
      (e: Record<string, unknown>) => ({ ...e, occurredAt: '2026-12-01T10:00:01.000Z' }),
    ]) {
      const changed = lines.map((l, i) =>
        i === 0 ? JSON.stringify(change(JSON.parse(l) as Record<string, unknown>)) : l,
      );
      const result = await verify(`${changed.join('\n')}\n`);
      // It throws: a failing exit and the error, naming the event, never "verified".
      expect(result.code).not.toBe(0);
      expect(result.stderr).toContain('event 1');
      expect(result.stdout).not.toContain('verified');
    }
  });

  it('still verifies each line of a filtered export (a gap in seq)', async () => {
    const result = await verify(`${lines.filter((_, i) => i !== 2).join('\n')}\n`);
    expect(result.code, result.stderr).toBe(0);
    expect(result.stdout.trim()).toBe('4 events verified');
  });
});
