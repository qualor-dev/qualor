import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { openBolt, type BoltFile } from './bolt';

// 0.16 debts D31-1 (rulings B2-a, B2-b): the Trivy database that install.sh unpacks is filtered
// to its library sources by filter-trivy-db.sh, in the scanner images, the toolbox and CI.

const DB = process.env['QUALOR_TEST_TRIVY_DB'] ?? '/opt/qualor/share/trivy/db/trivy.db';
const GO = '/opt/qualor/lib/go/bin/go';
const MODULE = 'tools/analyzers/go-tools/trivy-db-filter';
const SCRIPT = path.resolve('tools/analyzers/filter-trivy-db.sh');
const required = process.env['QUALOR_REQUIRE_ANALYZERS'] === '1';

/** The data-source IDs whose buckets stay (ruling B2-b); `KEEP` in main.go must say the same. */
const KEPT = [
  'ghsa',
  'bitnami',
  'php-security-advisories',
  'glad',
  'govulndb',
  'julia',
  'k8s',
  'nodejs-security-wg',
  'aqua',
  'ruby-advisory-db',
];
/** Trivy's bucket prefixes of the ecosystems purlOf maps (server/src/vulnerabilities/purl.ts). */
const PREFIXES = [
  'npm',
  'pip',
  'maven',
  'nuget',
  'go',
  'cargo',
  'composer',
  'rubygems',
  'pub',
  'erlang',
  'swift',
  'cocoapods',
  'conan',
];
const METADATA = ['vulnerability', 'data-source'];

const goEnv = {
  ...process.env,
  CGO_ENABLED: '0',
  GOTOOLCHAIN: 'local',
  GOFLAGS: '-trimpath -mod=readonly',
};

describe('trivy-db-filter (0.16 debts D31-1)', () => {
  it("keeps the IDs of ruling B2-b, as main.go's KEEP lists them", () => {
    const main = readFileSync(`${MODULE}/main.go`, 'utf8');
    const literal = /^var KEEP = \[\]string\{\r?\n([^}]*)\}/m.exec(main)?.[1] ?? '';
    expect([...literal.matchAll(/"([^"]+)"/g)].map((m) => m[1])).toEqual(KEPT);
  });

  it.runIf(existsSync(GO))(
    "passes its own tests with install-go.sh's Go",
    { timeout: 300_000 },
    () => {
      const run = spawnSync(GO, ['test', './...'], { cwd: MODULE, env: goEnv, encoding: 'utf8' });
      expect(run.status, run.stderr + run.stdout).toBe(0);
    },
  );
});

describe('filter-trivy-db.sh (0.16 debts D31-1)', () => {
  const posix = (p: string) => p.replace(/\\/g, '/');
  const dirs: string[] = [];
  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });
  /** A prefix with a database, and a fake filter that logs its arguments and fails `-check` on demand. */
  function setup(withDatabase = true) {
    const dir = mkdtempSync(path.join(tmpdir(), 'trivy-db-filter-'));
    dirs.push(dir);
    const db = path.join(dir, 'prefix', 'share', 'trivy', 'db');
    mkdirSync(db, { recursive: true });
    if (withDatabase) writeFileSync(path.join(db, 'trivy.db'), 'not a real database');
    const filter = path.join(dir, 'fake-filter');
    writeFileSync(
      filter,
      [
        '#!/bin/sh',
        `printf '%s\\n' "$*" >> "$FAKE_FILTER_LOG"`,
        '[ "$1" != -check ] || exit "${FAKE_CHECK_STATUS:-0}"',
        '',
      ].join('\n'),
      { mode: 0o755 },
    );
    const log = path.join(dir, 'filter.log');
    const run = (env: Record<string, string>) =>
      spawnSync('sh', [SCRIPT], {
        encoding: 'utf8',
        env: {
          ...process.env,
          QUALOR_TOOLS: posix(path.join(dir, 'prefix')),
          QUALOR_TRIVY_DB_FILTER: posix(filter),
          FAKE_FILTER_LOG: posix(log),
          ...env,
        },
      });
    const calls = () => (existsSync(log) ? readFileSync(log, 'utf8') : '');
    return { run, calls, database: `${posix(path.join(dir, 'prefix'))}/share/trivy/db/trivy.db` };
  }

  it('filters the database, then checks it', () => {
    const { run, calls, database } = setup();
    const result = run({});
    expect(result.status, result.stderr).toBe(0);
    expect(calls()).toBe(`${database}\n-check ${database}\n`);
  });

  it('fails when the check fails', () => {
    const { run } = setup();
    expect(run({ FAKE_CHECK_STATUS: '1' }).status).not.toBe(0);
  });

  it('fails without a database, and runs nothing', () => {
    const { run, calls } = setup(false);
    const result = run({});
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/no Trivy database at .*: run install\.sh first/);
    expect(calls()).toBe('');
  });

  it("fails without install-go.sh's Go when no filter is given", () => {
    const { run, calls } = setup();
    const result = run({ QUALOR_TRIVY_DB_FILTER: '' });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/no Go at .*\/lib\/go\/bin\/go: run install-go\.sh first/);
    expect(calls()).toBe('');
  });
});

describe(`the filtered Trivy database (${DB})`, () => {
  const present = existsSync(DB);
  let file: BoltFile | undefined;
  const db = () => (file ??= openBolt(DB));
  const buckets = () => db().topLevel.filter((name) => !METADATA.includes(name));
  afterAll(() => file?.close());

  it.runIf(required)('is installed where QUALOR_REQUIRE_ANALYZERS=1 requires it', () => {
    expect(present, 'run install.sh, install-go.sh and filter-trivy-db.sh').toBe(true);
  });

  it.runIf(present)(
    'holds the metadata buckets and buckets of the kept sources, each with its data-source entry',
    () => {
      for (const name of METADATA) expect(db().topLevel).toContain(name);
      const sources = db().entries('data-source');
      for (const name of buckets()) {
        const entry = sources.get(name);
        expect(entry, name).toBeDefined();
        const { ID } = JSON.parse(entry?.toString('utf8') ?? '{}') as { ID?: string };
        expect(KEPT, `${name}: ${ID}`).toContain(ID);
      }
      expect([...sources.keys()].sort()).toEqual([...buckets()].sort());
      expect(db().topLevel.filter((name) => name.startsWith('seal '))).toEqual([]);
    },
  );

  it.runIf(present)(
    'has a data-source entry for every kept ID: a renamed source fails here',
    () => {
      const ids = new Set(
        [...db().entries('data-source').values()].map(
          (entry) => (JSON.parse(entry.toString('utf8')) as { ID?: string }).ID,
        ),
      );
      for (const id of KEPT) expect(ids.has(id), id).toBe(true);
    },
  );

  it.runIf(present)('keeps a bucket for every ecosystem purlOf maps', () => {
    for (const prefix of PREFIXES)
      expect(
        buckets().some((name) => name.startsWith(`${prefix}::`)),
        prefix,
      ).toBe(true);
  });

  it.runIf(present)('is compacted: under 120 MiB (about 85 MiB, ruling B2-b)', () => {
    expect(statSync(DB).size).toBeLessThan(120 * 2 ** 20);
  });

  it.runIf(present && existsSync(GO))(
    "passes the filter's check: no other bucket, no orphan detail, no dropped source's severity",
    { timeout: 300_000 },
    () => {
      const run = spawnSync(GO, ['run', '.', '-check', path.resolve(DB)], {
        cwd: MODULE,
        env: goEnv,
        encoding: 'utf8',
      });
      expect(run.status, run.stderr).toBe(0);
    },
  );
});
