import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { uuidv7 } from '../db/ids';
import { instanceSettings, jobs } from '../db/schema';
import { runUntilIdle } from '../queue/worker';
import { TELEMETRY_SETTING_KEY } from './installation-id';
import {
  cancelTelemetry,
  ensureTelemetryScheduled,
  scheduleTelemetryAtBoot,
  TELEMETRY_QUEUE,
  telemetryHandlers,
} from './schedule';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

describe('telemetry schedule (telemetry.md)', () => {
  let database: TestDatabase;
  let receiver: Server;
  let url: string;
  const received: unknown[] = [];
  const queued = () =>
    database.db.execute<{ secs: number }>(sql`
      SELECT extract(epoch FROM run_at - now())::int AS secs FROM jobs
       WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued' ORDER BY run_at`);

  beforeAll(async () => {
    database = await createTestDatabase();
    receiver = createServer((req, res) => {
      let body = '';
      req.on('data', (c: Buffer) => (body += c.toString('utf8')));
      req.on('end', () => {
        received.push(JSON.parse(body));
        res.writeHead(204).end();
      });
    });
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r));
    url = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/api/telemetry`;
  });
  beforeEach(async () => {
    await database.db.delete(jobs).where(eq(jobs.queue, TELEMETRY_QUEUE));
    await database.db.delete(instanceSettings).where(eq(instanceSettings.key, TELEMETRY_SETTING_KEY));
    received.length = 0;
  });
  afterAll(async () => {
    await new Promise<void>((r) => receiver.close(() => r()));
    await database.close();
  });

  it('boot reschedules a waiting run to 60 s', async () => {
    await database.db.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${TELEMETRY_QUEUE}, ${TELEMETRY_QUEUE}, '{}'::jsonb, now() + interval '20 hours')`);
    await scheduleTelemetryAtBoot(database.db);
    await scheduleTelemetryAtBoot(database.db); // a second replica booting
    const rows = (await queued()).rows;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.secs).toBeGreaterThan(50);
    expect(rows[0]!.secs).toBeLessThanOrEqual(60);
  });

  it('the job sends the payload and schedules the next run in 24 h, even when the send fails', async () => {
    await database.db.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${TELEMETRY_QUEUE}, ${TELEMETRY_QUEUE}, '{}'::jsonb, now())`);
    const handlers = telemetryHandlers({
      db: database.db,
      edition: { edition: () => 'community' },
      url,
      database: 'external',
    });
    await runUntilIdle(database.db, handlers, silent);
    expect(received).toHaveLength(1);
    expect(received[0]).toMatchObject({ schema: 1, edition: 'community', database: 'external' });
    const next = (await queued()).rows;
    expect(next).toHaveLength(1);
    expect(next[0]!.secs).toBeGreaterThan(86_000);

    await database.db.execute(sql`UPDATE jobs SET run_at = now() WHERE queue = ${TELEMETRY_QUEUE} AND status = 'queued'`);
    const failing = telemetryHandlers({
      db: database.db,
      edition: { edition: () => 'community' },
      url: 'http://127.0.0.1:9/t',
      database: 'external',
    });
    await runUntilIdle(database.db, failing, silent);
    expect((await queued()).rows).toHaveLength(1);
    const dead = await database.db.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${TELEMETRY_QUEUE} AND status IN ('dead', 'failed')`);
    expect(dead.rows).toHaveLength(0);
  });

  it('ensureTelemetryScheduled adds a run only when none is queued or running', async () => {
    expect(await ensureTelemetryScheduled(database.db)).toBe(true);
    expect(await ensureTelemetryScheduled(database.db)).toBe(false);
  });

  it('disabled: removes queued runs, creates no id', async () => {
    await scheduleTelemetryAtBoot(database.db);
    expect(await cancelTelemetry(database.db)).toBe(1);
    expect((await queued()).rows).toHaveLength(0);
    const ids = await database.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, TELEMETRY_SETTING_KEY));
    expect(ids).toHaveLength(0);
  });
});
