import { gzipSync } from 'node:zlib';
import { and, asc, eq } from 'drizzle-orm';
import { LONE_SURROGATE_SOURCE } from '@qualor/shared';
import { bom, inventory, lib, os, sample } from '@qualor/shared/test/sbom';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { rbacPlugins } from '../../test/rbac';
import type { RouteDeps } from '../app';
import { createAuditRecorder } from '../audit/recorder';
import { analyses, auditEvents, jobs, projectVersions, versionDependencies } from '../db/schema';
import { TransferSlots } from '../ingest/upload';
import { RECHECK_QUEUE } from '../vulnerabilities/recheck';
import { writeVulndbSettings } from '../vulndb/settings';
import { sbomUploadRoutes } from './sbom-upload';

const MiB = 1024 * 1024;
const NOW = new Date('2027-01-01T00:00:00Z');
const KEY = 'acme/shop';
const CDX = 'application/vnd.cyclonedx+json';
const DEBIAN = sample('trivy-debian.cdx.json');
const DEBIAN_SUBJECT =
  'buildpack-deps:bookworm-curl@sha256:58021c2a0204361b62a23d2e0244d144d74c29af2d678e2a1f7e6611885d6949';

/** A CycloneDX document of one npm package whose subject is `shop` at `version`. */
const appBom = (version: string, purl = 'pkg:npm/left-pad@1.3.0') =>
  bom([lib(purl)], {
    metadata: { component: { type: 'application', name: 'shop', version } },
  });

/**
 * PUT /projects/sbom (0.16 SBOM, spec §6.1, §6.6). The context records audit events (as
 * audit/recording-b.db.test.ts sets it up). Two more instances of the plugin run under their own
 * prefixes with slots the tests hold: `/one` with one slot of each kind, `/two` with two.
 */
describe('PUT /projects/sbom', () => {
  let ctx: TestContext;
  let orgAdmin: Session;
  let memberSession: Session;
  let viewerSession: Session;
  let projectId: string;
  let projectToken: string;
  let otherProjectToken: string;
  let readOnlyPat: string;
  const slotDeps = {} as RouteDeps;
  const one = { uploadSlots: new TransferSlots(1), parseSlots: new TransferSlots(1) };
  const two = { uploadSlots: new TransferSlots(2), parseSlots: new TransferSlots(2) };

  const put = (
    headers: Record<string, string>,
    body: string | Buffer,
    query = `version=1.4.0`,
    options: { key?: string; prefix?: string } = {},
  ) =>
    ctx.app.inject({
      method: 'PUT',
      url: `${options.prefix ?? ''}/api/v0/projects/sbom?projectKey=${encodeURIComponent(options.key ?? KEY)}${query === '' ? '' : `&${query}`}`,
      headers: { 'content-type': CDX, ...headers },
      payload: body,
    });
  const mintPat = async (session: Session, scopes: string[]) =>
    (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: { name: 'pat', scopes },
      })
    ).json().token as string;
  const versionOf = async (label: string, project = projectId) => {
    const [row] = await ctx.db
      .select()
      .from(projectVersions)
      .where(and(eq(projectVersions.projectId, project), eq(projectVersions.label, label)));
    return row;
  };
  const rowsOf = (versionId: string) =>
    ctx.db
      .select()
      .from(versionDependencies)
      .where(eq(versionDependencies.versionId, versionId))
      .orderBy(asc(versionDependencies.name));
  const codeOf = (res: { statusCode: number; json(): { code: string } }) => [
    res.statusCode,
    res.json().code,
  ];

  beforeAll(async () => {
    ctx = await createTestContext({
      pluginsFor: rbacPlugins({ now: () => NOW }),
      beforeReady: (app) => {
        for (const [prefix, slots] of [
          ['/one', one],
          ['/two', two],
        ] as const) {
          void app.register(sbomUploadRoutes, {
            prefix: `${prefix}/api/v0`,
            deps: slotDeps,
            ...slots,
          });
        }
      },
    });
    Object.assign(slotDeps, {
      config: ctx.config,
      db: ctx.db,
      edition: ctx.edition!,
      audit: createAuditRecorder({ isActive: () => false, log: QUIET_AUDIT_LOG }),
      checkReady: async () => true,
    } satisfies RouteDeps);
    await writeVulndbSettings(ctx.db, { enabled: false }, ctx.config.secretKey);
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const org = await organizationId(ctx, 'default');
    const member = async (username: string, role: 'admin' | 'member' | 'viewer') => {
      const user = await createUser(ctx, { username });
      await addMember(ctx, org, user.id, role);
      return login(ctx, user.username, user.password);
    };
    orgAdmin = await member('sbom-admin', 'admin');
    memberSession = await member('sbom-member', 'member');
    viewerSession = await member('sbom-viewer', 'viewer');
    projectId = (await createProject(ctx, admin, { organizationId: org, key: KEY })).id;
    const other = await createProject(ctx, admin, { organizationId: org, key: 'acme/other' });
    projectToken = await createProjectToken(ctx, admin, projectId);
    otherProjectToken = await createProjectToken(ctx, admin, other.id);
    readOnlyPat = await mintPat(orgAdmin, ['read']);
  });
  afterAll(async () => {
    await ctx?.close();
  });

  it('creates a version with the project token', async () => {
    const res = await put(bearer(projectToken), DEBIAN);
    expect(res.statusCode, res.body).toBe(201);
    const answer = res.json();
    expect(answer).toEqual({
      version: { id: expect.any(String), label: '1.4.0', source: 'sbom' },
      format: 'CycloneDX 1.7',
      subject: DEBIAN_SUBJECT,
      distribution: { family: 'debian', version: '12.15' },
      packages: 22,
      osPackages: 22,
      skipped: { noPurl: 0, unsupportedType: 0, duplicate: 0 },
      warnings: [],
      monitoring: { enabled: false, recheckQueued: false },
    });
    expect(await versionOf('1.4.0')).toMatchObject({
      id: answer.version.id,
      source: 'sbom',
      tag: null,
      analysisId: null,
      hasInventory: true,
      dependencyIgnores: null,
      osFamily: 'debian',
      osVersion: '12.15',
      sbomFormat: 'CycloneDX 1.7',
      sbomSubject: DEBIAN_SUBJECT,
    });
    const rows = await rowsOf(answer.version.id);
    expect(rows).toHaveLength(22);
    expect(rows.find((r) => r.name === 'libssl3')).toMatchObject({
      ecosystem: 'deb',
      sourceName: 'openssl',
      analysisId: null,
      // Stored for every OS package; only an rpm's goes to Trivy (Task 9b).
      arch: 'amd64',
      modularityLabel: null,
    });
    // An upload is not an analysis.
    expect(await ctx.db.select().from(analyses).where(eq(analyses.projectId, projectId))).toEqual(
      [],
    );
  });

  it('queues a re-check when both switches are on', async () => {
    await writeVulndbSettings(ctx.db, { enabled: true }, ctx.config.secretKey);
    try {
      await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      const res = await put(bearer(projectToken), DEBIAN, 'version=1.5.0');
      expect(res.statusCode, res.body).toBe(201);
      expect(res.json().monitoring).toEqual({ enabled: true, recheckQueued: true });
      const queued = await ctx.db.select().from(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      expect(queued).toHaveLength(1);
      expect(queued[0]).toMatchObject({ status: 'queued', payload: { projectIds: [projectId] } });
    } finally {
      await writeVulndbSettings(ctx.db, { enabled: false }, ctx.config.secretKey);
      await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
    }
  });

  it('replaces it', async () => {
    const first = await put(bearer(projectToken), DEBIAN, 'version=1.6.0');
    expect(first.statusCode).toBe(201);
    const second = await put(bearer(projectToken), appBom('9.9.9'), 'version=1.6.0');
    expect(second.statusCode, second.body).toBe(200);
    expect(second.json()).toMatchObject({
      version: { id: first.json().version.id, label: '1.6.0', source: 'sbom' },
      format: 'CycloneDX 1.6',
      subject: 'shop 9.9.9',
      distribution: null,
      packages: 1,
      osPackages: 0,
    });
    expect(await versionOf('1.6.0')).toMatchObject({
      sbomFormat: 'CycloneDX 1.6',
      sbomSubject: 'shop 9.9.9',
      osFamily: null,
      osVersion: null,
    });
    expect((await rowsOf(first.json().version.id)).map((r) => [r.ecosystem, r.name])).toEqual([
      ['npm', 'left-pad'],
    ]);
  });

  it('takes gzip, the three types and their parameters; without a version query, the subject version', async () => {
    const cdx = await put(
      { ...bearer(projectToken), 'content-type': `${CDX}; version=1.6` },
      appBom('2.1.0'),
      '',
    );
    expect(cdx.statusCode, cdx.body).toBe(201);
    expect(cdx.json().version.label).toBe('2.1.0');
    const spdx = await put(
      { ...bearer(projectToken), 'content-type': 'application/spdx+json' },
      sample('trivy-debian.spdx.json'),
      'version=2.2.0',
    );
    expect(spdx.statusCode, spdx.body).toBe(201);
    expect(spdx.json()).toMatchObject({ format: 'SPDX 2.3', packages: 22, osPackages: 22 });
    const zipped = await put(
      {
        ...bearer(projectToken),
        'content-type': 'application/json; charset=utf-8',
        'content-encoding': 'GZIP',
      },
      gzipSync(Buffer.from(appBom('2.3.0'))),
      '',
    );
    expect(zipped.statusCode, zipped.body).toBe(201);
    expect(zipped.json().version.label).toBe('2.3.0');
  });

  describe('access', () => {
    it('admits a member session (project.analyze)', async () => {
      const res = await put(memberSession.headers, appBom('3.0.0'), '');
      expect(res.statusCode, res.body).toBe(201);
    });

    it('refuses a viewer, a token without analysis:write, another project and an unknown key', async () => {
      expect(codeOf(await put(viewerSession.headers, appBom('3.1.0'), ''))).toEqual([
        403,
        'FORBIDDEN',
      ]);
      expect(codeOf(await put(bearer(readOnlyPat), appBom('3.1.0'), ''))).toEqual([
        403,
        'INSUFFICIENT_SCOPE',
      ]);
      expect(codeOf(await put(bearer(otherProjectToken), appBom('3.1.0'), ''))).toEqual([
        404,
        'PROJECT_NOT_FOUND',
      ]);
      expect(
        codeOf(await put(bearer(projectToken), appBom('3.1.0'), '', { key: 'acme/none' })),
      ).toEqual([404, 'PROJECT_NOT_FOUND']);
      expect((await put({}, appBom('3.1.0'), '')).statusCode).toBe(401);
      expect(await versionOf('3.1.0')).toBeUndefined();
    });
  });

  it('warns that the OS packages of a RHEL 10 image are not checked (R29)', async () => {
    const res = await put(
      bearer(otherProjectToken),
      bom([os('redhat', '10.0'), lib('pkg:rpm/redhat/bash@5.2.26-6.el10?arch=x86_64')]),
      'version=rhel-10',
      { key: 'acme/other' },
    );
    expect(res.statusCode, res.body).toBe(201);
    expect(res.json()).toMatchObject({
      distribution: { family: 'redhat', version: '10.0' },
      osPackages: 1,
      warnings: [
        {
          code: 'SBOM_OS_PACKAGES_UNCHECKED',
          message: expect.stringContaining('content sets of redhat 10.0') as unknown,
        },
      ],
    });
  });

  it('answers 415 to another type or encoding, after the project check', async () => {
    const text = await put(
      { ...bearer(projectToken), 'content-type': 'text/plain' },
      appBom('4.0.0'),
      '',
    );
    expect(codeOf(text)).toEqual([415, 'UNSUPPORTED_MEDIA_TYPE']);
    expect(text.headers.connection).toBe('close');
    const br = await put(
      { ...bearer(projectToken), 'content-encoding': 'br' },
      appBom('4.0.0'),
      '',
    );
    expect(codeOf(br)).toEqual([415, 'UNSUPPORTED_ENCODING']);
    const hidden = await put(
      { ...bearer(otherProjectToken), 'content-type': 'text/plain' },
      appBom('4.0.0'),
      '',
    );
    expect(codeOf(hidden)).toEqual([404, 'PROJECT_NOT_FOUND']);
    expect(await versionOf('4.0.0')).toBeUndefined();
  });

  it('answers 413 to a body over 32 MiB and to one inflating past 64 MiB', async () => {
    const big = await put(bearer(projectToken), Buffer.alloc(32 * MiB + 1, 0x20));
    expect(codeOf(big)).toEqual([413, 'SBOM_TOO_LARGE']);
    expect(big.headers.connection).toBe('close');
    const bomb = await put(
      { ...bearer(projectToken), 'content-encoding': 'gzip' },
      gzipSync(Buffer.alloc(64 * MiB + 1, 0x20)),
    );
    expect(codeOf(bomb)).toEqual([413, 'SBOM_TOO_LARGE']);
  });

  describe('422', () => {
    it('SBOM_INVALID names the JSON path', async () => {
      const res = await put(
        bearer(projectToken),
        JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', components: 'none' }),
      );
      expect(codeOf(res)).toEqual([422, 'SBOM_INVALID']);
      expect(res.json().detail).toContain('components');
      expect(codeOf(await put(bearer(projectToken), 'not json'))).toEqual([422, 'SBOM_INVALID']);
    });

    it('SBOM_FORMAT_UNSUPPORTED for CycloneDX XML', async () => {
      const res = await put(bearer(projectToken), sample('cyclonedx.xml'));
      expect(codeOf(res)).toEqual([422, 'SBOM_FORMAT_UNSUPPORTED']);
      expect(res.json().detail).toContain('CycloneDX JSON');
    });

    it('SBOM_TOO_MANY_PACKAGES for 50 001 packages', async () => {
      const many = bom(Array.from({ length: 50_001 }, (_, i) => lib(`pkg:npm/p${i}@1.0.0`)));
      expect(codeOf(await put(bearer(projectToken), many, 'version=5.0.0'))).toEqual([
        422,
        'SBOM_TOO_MANY_PACKAGES',
      ]);
      expect(await versionOf('5.0.0')).toBeUndefined();
    });

    it('SBOM_MULTIPLE_OS', async () => {
      const res = await put(
        bearer(projectToken),
        bom([os('debian', '12.15'), os('alpine', '3.20.3'), lib('pkg:npm/a@1.0.0')]),
      );
      expect(codeOf(res)).toEqual([422, 'SBOM_MULTIPLE_OS']);
      expect(res.json().detail).toContain('alpine');
    });

    it('VERSION_LABEL_INVALID for a blank label, a long one, and none at all', async () => {
      for (const query of ['version=%20%20', `version=${'x'.repeat(101)}`, '']) {
        expect(codeOf(await put(bearer(projectToken), DEBIAN, query)), query).toEqual([
          422,
          'VERSION_LABEL_INVALID',
        ]);
      }
      expect(codeOf(await put(bearer(projectToken), DEBIAN, 'version=a%00b'))).toEqual([
        422,
        'VALIDATION_FAILED',
      ]);
    });
  });

  it('answers 409 VERSION_LABEL_TAKEN over a tag version, and changes nothing', async () => {
    const analyzedAt = new Date('2026-11-01T00:00:00Z');
    const [tagged] = await ctx.db
      .insert(projectVersions)
      .values({ projectId, label: '6.0.0', source: 'tag', tag: 'v6.0.0', analyzedAt })
      .returning();
    const res = await put(bearer(projectToken), DEBIAN, 'version=6.0.0');
    expect(codeOf(res)).toEqual([409, 'VERSION_LABEL_TAKEN']);
    expect(res.json().detail).toContain('project of its own');
    expect(res.json().detail).toContain(`${KEY}-image`);
    expect(await versionOf('6.0.0')).toEqual(tagged);
    expect(await rowsOf(tagged!.id)).toEqual([]);
  });

  describe('503 UPLOADS_BUSY', () => {
    const putOne = (label: string) =>
      put(bearer(projectToken), appBom(label), `version=${label}`, { prefix: '/one' });

    it('while the shared upload slots are taken', async () => {
      one.uploadSlots.take();
      try {
        const busy = await putOne('7.0.0');
        expect(codeOf(busy)).toEqual([503, 'UPLOADS_BUSY']);
        expect(busy.headers['retry-after']).toBe('1');
        expect(busy.headers.connection).toBe('close');
      } finally {
        one.uploadSlots.release();
      }
      expect((await putOne('7.0.0')).statusCode).toBe(201);
    });

    it('while another SBOM is read (R2)', async () => {
      one.parseSlots.take();
      try {
        expect(codeOf(await putOne('7.1.0'))).toEqual([503, 'UPLOADS_BUSY']);
      } finally {
        one.parseSlots.release();
      }
      expect((await putOne('7.1.0')).statusCode).toBe(201);
    });

    it('frees both slots after every refusal', async () => {
      const refusals = [
        put(bearer(projectToken), 'not json', 'version=7.2.0', { prefix: '/one' }),
        put(bearer(projectToken), DEBIAN, 'version=6.0.0', { prefix: '/one' }),
        put({ ...bearer(projectToken), 'content-encoding': 'gzip' }, 'plain', 'version=7.2.0', {
          prefix: '/one',
        }),
        put(bearer(projectToken), DEBIAN, '', { prefix: '/one' }),
      ];
      for (const refusal of refusals) expect((await refusal).statusCode).toBeGreaterThan(400);
      expect((await putOne('7.2.0')).statusCode).toBe(201);
    });
  });

  it('records project_version.sbom_uploaded, created then replaced', async () => {
    const before = await ctx.db
      .select({ seq: auditEvents.seq })
      .from(auditEvents)
      .orderBy(asc(auditEvents.seq));
    const last = before.at(-1)?.seq ?? 0;
    const audited = await createProject(ctx, orgAdmin, {
      organizationId: await organizationId(ctx, 'default'),
      key: 'acme/audited',
    });
    for (const status of [201, 200]) {
      const res = await put(orgAdmin.headers, DEBIAN, 'version=1.4.0', { key: 'acme/audited' });
      expect(res.statusCode, res.body).toBe(status);
    }
    const events = (
      await ctx.db
        .select()
        .from(auditEvents)
        .where(eq(auditEvents.action, 'project_version.sbom_uploaded'))
        .orderBy(asc(auditEvents.seq))
    ).filter((e) => e.seq > last);
    expect(events.map((e) => e.details)).toEqual([
      { label: '1.4.0', format: 'CycloneDX 1.7', packages: 22, osPackages: 22, outcome: 'created' },
      {
        label: '1.4.0',
        format: 'CycloneDX 1.7',
        packages: 22,
        osPackages: 22,
        outcome: 'replaced',
      },
    ]);
    expect(events[0]).toMatchObject({
      projectId: audited.id,
      projectKey: 'acme/audited',
      targetType: 'project',
      targetId: audited.id,
      actorUsername: 'sbom-admin',
    });
  });

  it('leaves JSON parsing of the other routes alone', async () => {
    const version = await versionOf('1.4.0');
    const res = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${projectId}/versions/${version!.id}`,
      headers: orgAdmin.headers,
      payload: { tracking: 'pinned' },
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({ label: '1.4.0', tracking: 'pinned' });
  });

  it('keeps one version for two uploads of one label at once (201 and 200)', async () => {
    const [a, b] = await Promise.all(
      [appBom('8.0.0', 'pkg:npm/a@1.0.0'), appBom('8.0.0', 'pkg:npm/b@1.0.0')].map((text) =>
        put(bearer(projectToken), text, 'version=8.0.0', { prefix: '/two' }),
      ),
    );
    expect([a!.statusCode, b!.statusCode].sort()).toEqual([200, 201]);
    const versions = await ctx.db
      .select()
      .from(projectVersions)
      .where(and(eq(projectVersions.projectId, projectId), eq(projectVersions.label, '8.0.0')));
    expect(versions).toHaveLength(1);
    expect(await rowsOf(versions[0]!.id)).toHaveLength(1);
  });

  it('stores NUL and lone surrogate escapes clean (Review Focus 6)', async () => {
    const text = bom([
      lib('pkg:npm/left-pad@1.3.0', {
        properties: [{ name: 'aquasecurity:trivy:FilePath', value: 'app\u0000/package.json' }],
        licenses: [{ license: { name: 'Custom \ud800 licence' } }],
      }),
    ]);
    expect(text).toContain('\\u0000');
    expect(text).toContain('\\ud800');
    const res = await put(bearer(projectToken), text, 'version=9.0.0');
    expect(res.statusCode, res.body).toBe(201);
    const [row] = await rowsOf(res.json().version.id);
    const expected = inventory(text).entries[0]!;
    expect(row).toMatchObject({ path: expected.path, licenses: expected.licenses });
    expect(row!.path).toBe('app/package.json');
    expect(row!.licenses.join()).not.toContain('\u0000');
    expect(new RegExp(LONE_SURROGATE_SOURCE).test(row!.licenses.join())).toBe(false);
  });
});
