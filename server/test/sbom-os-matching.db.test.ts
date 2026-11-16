import { spawnSync } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { eq, sql } from 'drizzle-orm';
import { readTarGz } from '@qualor/shared/tar';
import { bom, lib, os, sample } from '@qualor/shared/test/sbom';
import { afterAll, beforeAll, expect, it } from 'vitest';
import { resolveBinary } from '../../cli/src/analyzers/binary';
import { describeWithTools } from '../../cli/test/analyzers';
import {
  matchedPackages,
  targetVulnerabilities,
  versionDependencies,
  vulnerabilityMatches,
} from '../src/db/schema';
import {
  recheckProjects,
  type RecheckDeps,
  type RecheckResult,
} from '../src/vulnerabilities/recheck';
import { trivySbomArgs } from '../src/vulnerabilities/trivy';
import { writeVulndbSettings } from '../src/vulndb/settings';
import { makeDatasetCurrent, storeDataset } from '../src/vulndb/store';
import {
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  login,
  organizationId,
  type Session,
  type TestContext,
} from './app';

/**
 * 0.16 SBOM, spec §4 and §9: the server's re-check of an image SBOM finds what `trivy sbom` finds
 * on the same file with the same database (the fixture of server/test/fixtures/trivy-db-os), OS
 * packages included, and packages whose source package differs from the binary (`libssl3` from
 * `openssl`, `login` from `shadow`). A Syft SBOM of the same image finds the same through the purls'
 * `upstream` qualifiers (Review Focus 1).
 *
 * Runs where Trivy is installed (the server image, CI); required under QUALOR_REQUIRE_ANALYZERS=1.
 */
const ARCHIVE = path.resolve(__dirname, 'fixtures/trivy-db-os/db.tar.gz');
const silent = { info: () => undefined, warn: () => undefined };

interface Upload {
  /** What the case is called in the messages. */
  name: string;
  /** The SBOM text. */
  text: string;
  contentType: string;
}

/** `<name>@<version> <vulnerability id>`, the set every comparison is made on. */
type Findings = Set<string>;

const sorted = (set: Findings): string[] => [...set].sort();

describeWithTools(['trivy'])('OS packages against real Trivy (0.16 SBOM)', () => {
  let ctx: TestContext;
  let admin: Session;
  let org: string;
  let trivyPath: string;
  let work: string;
  let cacheDir: string;
  let deps: RecheckDeps;
  let n = 0;

  /** The project of an uploaded SBOM, its version pinned. */
  const upload = async ({ name, text, contentType }: Upload) => {
    const project = await createProject(ctx, admin, {
      organizationId: org,
      key: `acme/image-${++n}`,
    });
    const token = await createProjectToken(ctx, admin, project.id);
    const res = await ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/projects/sbom?projectKey=${encodeURIComponent(project.key)}&version=image-${n}`,
      headers: { ...bearer(token), 'content-type': contentType },
      payload: text,
    });
    expect(res.statusCode, `${name}: ${res.body}`).toBe(201);
    const answer = res.json() as {
      version: { id: string };
      osPackages: number;
      monitoring: { recheckQueued: boolean };
    };
    expect(answer.osPackages, name).toBeGreaterThan(0);
    expect(answer.monitoring.recheckQueued, name).toBe(true);
    const pinned = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${project.id}/versions/${answer.version.id}`,
      headers: admin.headers,
      payload: { tracking: 'pinned' },
    });
    expect(pinned.statusCode, pinned.body).toBe(200);
    return { projectId: project.id, versionId: answer.version.id };
  };

  /** What Qualor stored for a project: its rows, as {@link Findings}. */
  const qualorFindings = async (projectId: string): Promise<Findings> => {
    const rows = await ctx.db
      .select({
        name: targetVulnerabilities.packageName,
        version: targetVulnerabilities.packageVersion,
        id: targetVulnerabilities.vulnerabilityId,
      })
      .from(targetVulnerabilities)
      .where(eq(targetVulnerabilities.projectId, projectId));
    return new Set(rows.map((r) => `${r.name}@${r.version} ${r.id}`));
  };

  /** `<name>@<version>` of a version's stored packages. */
  const storedPackages = async (versionId: string): Promise<Set<string>> => {
    const rows = await ctx.db
      .select({ name: versionDependencies.name, version: versionDependencies.version })
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, versionId));
    return new Set(rows.map((r) => `${r.name}@${r.version}`));
  };

  /**
   * `trivy sbom` on the SBOM text, with the server's own arguments (trivy.ts) and environment,
   * against the fixture extracted on its own: its exit code and its findings.
   */
  const direct = async (label: string, text: string) => {
    const dir = path.join(work, `direct-${label}`);
    await mkdir(dir, { recursive: true });
    const input = path.join(dir, 'sbom.json');
    const output = path.join(dir, 'out.json');
    await writeFile(input, text);
    const env: NodeJS.ProcessEnv = { HOME: dir, TMPDIR: dir };
    if (process.env.PATH !== undefined) env.PATH = process.env.PATH;
    const run = spawnSync(trivyPath, trivySbomArgs(cacheDir, output, input), {
      env,
      cwd: dir,
      encoding: 'utf8',
      windowsHide: true,
    });
    const findings: Findings = new Set();
    if (run.status !== 0) return { status: run.status, stderr: run.stderr, findings };
    const doc = JSON.parse(await readFile(output, 'utf8')) as {
      Results?: {
        Vulnerabilities?: { PkgName: string; InstalledVersion: string; VulnerabilityID: string }[];
      }[];
    };
    for (const result of doc.Results ?? []) {
      for (const v of result.Vulnerabilities ?? []) {
        findings.add(`${v.PkgName}@${v.InstalledVersion} ${v.VulnerabilityID}`);
      }
    }
    return { status: run.status, stderr: run.stderr, findings };
  };

  /** Forgets every match, so that the next re-check runs Trivy on everything again. */
  const forgetMatches = async () => {
    await ctx.db.delete(targetVulnerabilities);
    await ctx.db.delete(vulnerabilityMatches);
    await ctx.db.delete(matchedPackages);
  };

  const recheck = async (scope: Parameters<typeof recheckProjects>[1]): Promise<RecheckResult> =>
    recheckProjects(deps, scope);

  const TRIVY_DEBIAN = sample('trivy-debian.cdx.json');
  const SYFT_DEBIAN = sample('syft-debian.spdx.json');
  const TRIVY_ALPINE = sample('trivy-alpine.cdx.json');
  const TRIVY_UBI8 = sample('trivy-ubi8.cdx.json');
  const CDX = 'application/vnd.cyclonedx+json';
  /**
   * A Red Hat release no Trivy database has content sets for: Trivy 0.74.0 exits 1 on it
   * ("unable to find CPE indices"), whatever else the SBOM holds.
   */
  const ODD_REDHAT = bom([
    os('redhat', '12.0'),
    lib('pkg:rpm/redhat/openssl-libs@1.1.1k-18.el8_6?arch=x86_64&epoch=1&distro=redhat-12.0'),
  ]);

  let debian: { projectId: string; versionId: string };
  let syft: { projectId: string; versionId: string };
  let alpine: { projectId: string; versionId: string };
  let ubi8: { projectId: string; versionId: string };
  let odd: { projectId: string; versionId: string };
  /** The Syft file's findings from a re-check of its project alone (nothing to borrow from). */
  let syftAlone: Findings;
  let full: RecheckResult;

  beforeAll(async () => {
    const found = resolveBinary('trivy', { root: process.cwd(), env: process.env });
    if (found === null) throw new Error('Trivy is not installed (QUALOR_REQUIRE_ANALYZERS=1)');
    trivyPath = found;
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    work = await mkdtemp(path.join(tmpdir(), 'qualor-sbom-os-'));

    // The fixture, extracted on its own for the direct runs.
    cacheDir = path.join(work, 'direct-cache');
    await mkdir(path.join(cacheDir, 'db'), { recursive: true });
    await readTarGz(
      createReadStream(ARCHIVE),
      () => 'stream',
      async (entry) => {
        if (entry.want !== 'stream') return;
        await pipeline(
          Readable.from(entry.body),
          createWriteStream(path.join(cacheDir, 'db', entry.name)),
        );
      },
    );

    // The same archive, as the server's current dataset, with monitoring on.
    const stored = await storeDataset(ctx.db, {
      kind: 'trivy',
      source: 'upload',
      chunks: createReadStream(ARCHIVE),
      maxBytes: 1024 ** 3,
    });
    if (!('dataset' in stored)) throw new Error(JSON.stringify(stored));
    expect(await makeDatasetCurrent(ctx.db, stored.dataset.id)).toBe(true);
    await writeVulndbSettings(ctx.db, { enabled: true }, ctx.config.secretKey);
    deps = {
      db: ctx.db,
      config: { vulndb: { dir: path.join(work, 'server'), trivyPath } },
      logger: silent,
    };

    // The Trivy-made Debian file first: in the full re-check its packages come first.
    debian = await upload({ name: 'trivy debian', text: TRIVY_DEBIAN, contentType: CDX });
    alpine = await upload({ name: 'trivy alpine', text: TRIVY_ALPINE, contentType: CDX });
    ubi8 = await upload({ name: 'trivy ubi8', text: TRIVY_UBI8, contentType: CDX });
    syft = await upload({
      name: 'syft debian',
      text: SYFT_DEBIAN,
      contentType: 'application/spdx+json',
    });
    odd = await upload({ name: 'odd redhat', text: ODD_REDHAT, contentType: CDX });

    // Syft's packages have the same match keys as Trivy's file: matched alone, they cannot use
    // the source packages Trivy's file names.
    expect(await recheck({ projectIds: [syft.projectId] })).toMatchObject({ kind: 'done' });
    syftAlone = await qualorFindings(syft.projectId);
    await forgetMatches();

    full = await recheck({ all: true });
  }, 600_000);

  afterAll(async () => {
    await ctx?.close();
    if (work !== undefined) await rm(work, { recursive: true, force: true, maxRetries: 10 });
  });

  it('the full re-check is done, with the odd distribution left unchecked', async () => {
    expect(full).toMatchObject({ kind: 'done' });
    if (full.kind !== 'done') return;
    expect(full.summary.projects).toBe(5);
    expect(full.summary.unchecked).toBeGreaterThanOrEqual(1);
    // Given up as a distribution Trivy cannot scan, and shown so (R16).
    expect(full.summary.givenUp).toEqual({
      invalid: 0,
      trivyFailed: 0,
      overBudget: 0,
      unsupported: ['redhat 12.0'],
    });
    // Trivy really fails on that file alone: one odd SBOM must not stop every other project.
    const alone = await direct('odd', ODD_REDHAT);
    expect(alone.status).not.toBe(0);
    expect(alone.stderr).toContain('unable to find CPE indices');
    expect(await qualorFindings(odd.projectId)).toEqual(new Set());
    // Its one package is counted unchecked, as Trivy failed on its distribution.
    expect(await recheck({ projectIds: [odd.projectId] })).toMatchObject({
      kind: 'done',
      summary: { packages: 0, unchecked: 1 },
    });
    const marks = await ctx.db
      .select({ purl: matchedPackages.purl })
      .from(matchedPackages)
      .where(sql`${matchedPackages.purl} LIKE '%distro=redhat-12.0%'`);
    expect(marks).toEqual([]);
  });

  it('(a) a Trivy-made Debian SBOM: Qualor finds what trivy sbom finds', async () => {
    const trivy = await direct('debian', TRIVY_DEBIAN);
    expect(trivy.status, trivy.stderr).toBe(0);
    const qualor = await qualorFindings(debian.projectId);
    expect(sorted(qualor)).toEqual(sorted(trivy.findings));
    expect(qualor.size).toBeGreaterThan(0);
    // Matched through the source package, not the binary's name.
    expect([...qualor].some((f) => f.startsWith('libssl3@'))).toBe(true);
    expect([...qualor].some((f) => f.startsWith('login@'))).toBe(true);
    console.info(`(a) trivy-debian.cdx.json: ${qualor.size} findings`, sorted(qualor));
  });

  it('(b) a Syft SPDX SBOM of the same image: the same findings, through upstream', async () => {
    const trivy = await direct('debian-for-syft', TRIVY_DEBIAN);
    expect(trivy.status, trivy.stderr).toBe(0);
    const held = await storedPackages(syft.versionId);
    const both = new Set([...trivy.findings].filter((f) => held.has(f.slice(0, f.indexOf(' ')))));
    expect(both.size).toBeGreaterThan(0);
    expect([...both].some((f) => f.startsWith('libssl3@'))).toBe(true);
    expect([...both].some((f) => f.startsWith('login@'))).toBe(true);
    expect(sorted(syftAlone)).toEqual(sorted(both));
    expect(sorted(await qualorFindings(syft.projectId))).toEqual(sorted(both));
    console.info(
      `(b) syft-debian.spdx.json: ${syftAlone.size} findings (trivy sbom on the Trivy file: ${trivy.findings.size}, on the packages both hold: ${both.size})`,
    );
  });

  it('(c) a Trivy-made Alpine SBOM: Qualor finds what trivy sbom finds', async () => {
    const trivy = await direct('alpine', TRIVY_ALPINE);
    expect(trivy.status, trivy.stderr).toBe(0);
    const qualor = await qualorFindings(alpine.projectId);
    expect(qualor.size).toBeGreaterThan(0);
    expect(sorted(qualor)).toEqual(sorted(trivy.findings));
    console.info(`(c) trivy-alpine.cdx.json: ${qualor.size} findings`);
  });

  it('(d) a Trivy-made UBI 8 SBOM: Qualor finds what trivy sbom finds', async () => {
    const trivy = await direct('ubi8', TRIVY_UBI8);
    expect(trivy.status, trivy.stderr).toBe(0);
    const qualor = await qualorFindings(ubi8.projectId);
    expect(qualor.size).toBeGreaterThan(0);
    expect(sorted(qualor)).toEqual(sorted(trivy.findings));
    console.info(`(d) trivy-ubi8.cdx.json: ${qualor.size} findings`);
  });
});
