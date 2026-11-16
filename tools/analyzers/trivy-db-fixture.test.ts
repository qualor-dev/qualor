import { spawnSync } from 'node:child_process';
import {
  copyFileSync,
  createReadStream,
  createWriteStream,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readTarGz } from '../../packages/shared/src/tar';
import { openBolt, type BoltFile } from './bolt';

// 0.16 SBOM (ruling R12): the small Trivy database that the server's real re-check tests store as
// a dataset. make-trivy-db-fixture.sh cuts it from the pinned trivy-db layer with
// trivy-db-filter's -fixture mode and allowlist.json.

const FIXTURE = 'server/test/fixtures/trivy-db-os';
const ARCHIVE = `${FIXTURE}/db.tar.gz`;
const SCRIPT = path.resolve('tools/analyzers/make-trivy-db-fixture.sh');
const METADATA = ['data-source', 'vulnerability'];
/** The sources the README attributes (R12); `nvd` is public domain. */
const SOURCES = ['alpine', 'debian', 'redhat-oval'];

/** A bucket's list of keys kept whole, or its nested buckets with their own allowlists. */
interface Allowlist {
  [name: string]: string[] | Allowlist;
}
const allowlist = JSON.parse(readFileSync(`${FIXTURE}/allowlist.json`, 'utf8')) as Allowlist;
const sorted = (names: Iterable<string>) => [...names].sort();

/** Red Hat's RHSA advisories name their CVEs in `Entries[].Cves[].ID`; the others are their key. */
function vulnerabilityIds(key: string, advisory: Buffer): string[] {
  const { Entries } = JSON.parse(advisory.toString('utf8')) as {
    Entries?: { Cves?: { ID?: string }[] }[];
  };
  const named = (Entries ?? []).flatMap((e) => (e.Cves ?? []).map((c) => c.ID ?? ''));
  return named.some((id) => id !== '') ? named.filter((id) => id !== '') : [key];
}

describe('the fixture Trivy database (0.16 SBOM)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'trivy-db-fixture-'));
  const names: string[] = [];
  let metadata = '';
  let db: BoltFile;
  const details = () => db.entries('vulnerability');
  /** The top-level buckets that hold advisories: those with a data-source entry. */
  const advisoryBuckets = () => [...db.entries('data-source').keys()];

  beforeAll(async () => {
    await readTarGz(
      createReadStream(ARCHIVE),
      (name) => (name === 'trivy.db' ? 'stream' : 'keep'),
      async (entry) => {
        names.push(entry.name);
        if (entry.want === 'keep') metadata = entry.data.toString('utf8');
        else
          await pipeline(Readable.from(entry.body), createWriteStream(path.join(dir, 'trivy.db')));
      },
    );
    db = openBolt(path.join(dir, 'trivy.db'));
  });
  afterAll(() => {
    db?.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('is under 1 MiB', () => {
    expect(statSync(ARCHIVE).size).toBeLessThan(2 ** 20);
  });

  it("holds trivy.db and metadata.json as the server's dataset reader takes them", () => {
    expect(sorted(names)).toEqual(['metadata.json', 'trivy.db']);
    const { Version, UpdatedAt } = JSON.parse(metadata) as { Version?: number; UpdatedAt?: string };
    expect(Version).toBe(2);
    expect(Number.isNaN(Date.parse(UpdatedAt ?? ''))).toBe(false);
  });

  it("has exactly the vulnerability, data-source and allowlist's top-level buckets", () => {
    expect(sorted(db.topLevel)).toEqual(sorted([...METADATA, ...Object.keys(allowlist)]));
  });

  it('holds openssl and shadow in debian 12', () => {
    expect(db.buckets('debian 12')).toEqual(['openssl', 'shadow']);
  });

  it('holds exactly what the allowlist lists, each package with advisories', () => {
    const walk = (list: string[] | Allowlist, at: [string, ...string[]]) => {
      const kept = [...db.entries(...at).keys(), ...db.buckets(...at)];
      if (Array.isArray(list)) {
        expect(sorted(kept), at.join(' / ')).toEqual(sorted(list));
        if (advisoryBuckets().includes(at[0]) && at.length === 1)
          for (const pkg of list) expect(db.entries(...at, pkg).size, pkg).toBeGreaterThan(0);
      } else {
        expect(sorted(kept), at.join(' / ')).toEqual(sorted(Object.keys(list)));
        for (const [name, nested] of Object.entries(list)) walk(nested, [...at, name]);
      }
    };
    for (const [bucket, list] of Object.entries(allowlist)) walk(list, [bucket]);
  });

  it('has a vulnerability entry for every advisory id, and no entry has a Title or Description', () => {
    const ids = new Set<string>();
    for (const bucket of advisoryBuckets())
      for (const pkg of db.buckets(bucket))
        for (const [key, advisory] of db.entries(bucket, pkg))
          for (const id of vulnerabilityIds(key, advisory)) ids.add(id);
    expect(ids.size).toBeGreaterThan(0);
    const all = details();
    for (const id of ids) expect(all.has(id), id).toBe(true);
    for (const [id, detail] of all) {
      const fields = JSON.parse(detail.toString('utf8')) as Record<string, unknown>;
      expect(fields, id).not.toHaveProperty('Title');
      expect(fields, id).not.toHaveProperty('Description');
    }
  });

  it("keeps only the attributed sources: their data-source entries, and their and nvd's severities", () => {
    const ids = [...db.entries('data-source').values()].map(
      (entry) => (JSON.parse(entry.toString('utf8')) as { ID?: string }).ID,
    );
    expect(sorted(ids as string[])).toEqual(SOURCES);
    for (const [id, detail] of details()) {
      const { VendorSeverity, CVSS } = JSON.parse(detail.toString('utf8')) as Record<
        string,
        Record<string, unknown> | undefined
      >;
      for (const vendor of [...Object.keys(VendorSeverity ?? {}), ...Object.keys(CVSS ?? {})])
        expect([...SOURCES, 'nvd'], `${id}: ${vendor}`).toContain(vendor);
    }
  });

  it("names its source snapshot in the README: the metadata's UpdatedAt", () => {
    const { UpdatedAt } = JSON.parse(metadata) as { UpdatedAt: string };
    expect(readFileSync(`${FIXTURE}/README.md`, 'utf8')).toContain(UpdatedAt);
  });
});

describe('make-trivy-db-fixture.sh (0.16 SBOM)', () => {
  const posix = (p: string) => p.replace(/\\/g, '/');
  const dirs: string[] = [];
  afterAll(() => {
    for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
  });

  it('refuses a layer that is not the pinned one, and writes no archive', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'trivy-db-fixture-sh-'));
    dirs.push(dir);
    copyFileSync(`${FIXTURE}/allowlist.json`, path.join(dir, 'allowlist.json'));
    writeFileSync(path.join(dir, 'layer.tar.gz'), 'not the pinned layer');
    const filter = path.join(dir, 'fake-filter');
    writeFileSync(filter, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    const result = spawnSync('sh', [SCRIPT], {
      encoding: 'utf8',
      env: {
        ...process.env,
        QUALOR_TRIVY_DB_FIXTURE: posix(dir),
        QUALOR_TRIVY_DB_LAYER: posix(path.join(dir, 'layer.tar.gz')),
        QUALOR_TRIVY_DB_FILTER: posix(filter),
      },
    });
    expect(result.status).not.toBe(0);
    expect(result.stderr).toMatch(/checksum mismatch: trivy-db sha256:[0-9a-f]{64}/);
    expect(existsSync(path.join(dir, 'db.tar.gz'))).toBe(false);
  });
});
