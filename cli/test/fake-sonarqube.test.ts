import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  branchesSchema,
  componentShowSchema,
  componentsPageSchema,
  currentUserSchema,
  gateByProjectSchema,
  gateListSchema,
  gateShowSchema,
  hotspotsPageSchema,
  issuesPageSchema,
  organizationsSchema,
  profilesSchema,
  rulesPageSchema,
} from '@qualor/shared';
import { afterEach, describe, expect, it } from 'vitest';
import type { z } from 'zod';
import {
  type FakeSonar,
  type FakeSonarData,
  sampleSonarData,
  startFakeSonarQube,
} from './fake-sonarqube';
import { sourceLinesSchema } from './sonar-live';

const shapes = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../packages/shared/test/sonarqube-shapes',
);
const shape = (f: string) =>
  JSON.parse(readFileSync(path.join(shapes, f), 'utf8')) as Record<string, unknown>;
const keysOf = (v: unknown): string[] =>
  v !== null && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v) : [];

let fake: FakeSonar | undefined;
afterEach(async () => {
  await fake?.close();
  fake = undefined;
});

async function get(p: string): Promise<Record<string, unknown>> {
  const res = await fetch(`${fake!.url}/${p}`, {
    headers: { authorization: `Bearer ${fake!.data.token}` },
  });
  return (await res.json()) as Record<string, unknown>;
}

describe('the fake SonarQube follows the documented shapes (ruling SQ16)', () => {
  it.each<[string, string | string[], string | null, z.ZodType, Partial<FakeSonarData>]>([
    ['api/users/current', 'users-current.json', null, currentUserSchema, {}],
    [
      'api/organizations/search?organizations=acme&organization=acme',
      'organizations-search.json',
      'organizations',
      organizationsSchema,
      { kind: 'cloud', organization: 'acme' },
    ],
    ['api/qualityprofiles/search', 'qualityprofiles-search.json', 'profiles', profilesSchema, {}],
    [
      'api/rules/search?qprofile=p-ts&activation=true&ps=500',
      'rules-search-active.json',
      'rules',
      rulesPageSchema,
      {},
    ],
    [
      'api/rules/search?qprofile=p-ts&activation=true&ps=500',
      // 9.9 carries only the top-level total; its rule items are those of every version.
      ['rules-search-9.9.json', 'rules-search-active.json'],
      'rules',
      rulesPageSchema,
      { version: '9.9.4.87374' },
    ],
    [
      'api/rules/search?qprofile=p-ts&activation=false&languages=ts&f=lang&ps=500',
      'rules-search-inactive.json',
      'rules',
      rulesPageSchema,
      {},
    ],
    ['api/qualitygates/list', 'qualitygates-list.json', 'qualitygates', gateListSchema, {}],
    [
      'api/qualitygates/show?name=Sonar%20way',
      'qualitygates-show.json',
      'conditions',
      gateShowSchema,
      {},
    ],
    [
      'api/qualitygates/get_by_project?project=acme:shop',
      'qualitygates-get_by_project.json',
      null,
      gateByProjectSchema,
      {},
    ],
    [
      'api/components/search?qualifiers=TRK&ps=500',
      'components-search.json',
      'components',
      componentsPageSchema,
      {},
    ],
    [
      'api/components/show?component=acme:shop',
      'components-show.json',
      null,
      componentShowSchema,
      {},
    ],
    [
      'api/project_branches/list?project=acme:shop',
      'project_branches-list.json',
      'branches',
      branchesSchema,
      {},
    ],
    [
      'api/issues/search?projects=acme:shop&issueStatuses=ACCEPTED,FALSE_POSITIVE&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      {},
    ],
    [
      'api/issues/search?projects=acme:shop&resolutions=FALSE-POSITIVE,WONTFIX&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      { version: '9.9.4.87374' },
    ],
    [
      'api/issues/search?projects=acme:shop&issueStatuses=OPEN,CONFIRMED&rules=typescript:S1440&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      {},
    ],
    [
      'api/issues/search?projects=acme:shop&issueStatuses=OPEN,CONFIRMED,IN_SANDBOX&rules=typescript:S1440&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      { version: '2025.5.0.113872' },
    ],
    [
      'api/issues/search?projects=acme:shop&resolved=false&rules=typescript:S1440&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      { version: '9.9.4.87374' },
    ],
    [
      'api/issues/search?projects=acme:shop&statuses=RESOLVED&resolutions=FIXED&rules=typescript:S1440&ps=500',
      'issues-search.json',
      'issues',
      issuesPageSchema,
      {
        version: '9.9.4.87374',
        issues: [
          {
            key: 'AYi-rf-1',
            rule: 'typescript:S1440',
            project: 'acme:shop',
            path: 'src/a.ts',
            line: 5,
            message: 'Fixed by hand.',
            status: 'RESOLVED_FIXED',
          },
        ],
      },
    ],
    [
      'api/hotspots/search?project=acme:shop&status=REVIEWED&ps=1',
      'hotspots-search.json',
      null,
      hotspotsPageSchema,
      {},
    ],
    [
      'api/hotspots/search?projectKey=acme:shop&status=REVIEWED&ps=1',
      'hotspots-search.json',
      null,
      hotspotsPageSchema,
      { kind: 'cloud', organization: 'acme' },
    ],
    [
      // The live check's line hash read only (§17.1); the import never reads source code.
      'api/sources/lines?key=acme:shop:src/a.ts&from=2&to=2',
      'sources-lines.json',
      'sources',
      sourceLinesSchema,
      { sources: { 'acme:shop:src/a.ts': ['// a', '<span class="k">if</span> (a == 1) {}'] } },
    ],
  ])('%s (%s)', async (p, file, list, schema, over) => {
    const data = sampleSonarData(over);
    fake = await startFakeSonarQube(data);
    const res = await fetch(`${fake.url}/${p}`, {
      headers: {
        authorization: data.version.startsWith('9.')
          ? `Basic ${Buffer.from(`${data.token}:`).toString('base64')}`
          : `Bearer ${data.token}`,
      },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    const parsed = schema.safeParse(body);
    expect(parsed.error?.message).toBeUndefined();
    const files = typeof file === 'string' ? [file] : file;
    const documented = shape(files[0]!);
    for (const k of keysOf(body)) expect(keysOf(documented), `top-level ${k}`).toContain(k);
    if (list !== null) {
      const items = body[list] as unknown[];
      expect(items.length, `${list} is not empty`).toBeGreaterThan(0);
      const documentedKeys = files.flatMap((f) => keysOf((shape(f)[list] as unknown[])[0]));
      for (const item of items) {
        for (const k of keysOf(item)) expect(documentedKeys, `${list}[].${k}`).toContain(k);
      }
    }
    expect(fake.requests.every((r) => r.method === 'GET')).toBe(true);
  });

  it('answers the rules facet in the documented facet shape', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const body = await get(
      'api/issues/search?projects=acme:shop&issueStatuses=ACCEPTED,FALSE_POSITIVE&ps=1&facets=rules',
    );
    expect(issuesPageSchema.safeParse(body).success).toBe(true);
    const documented = shape('issues-search-facets.json');
    const facet = (body['facets'] as Record<string, unknown>[])[0];
    const documentedFacet = (documented['facets'] as Record<string, unknown>[])[0];
    for (const k of keysOf(facet)) expect(keysOf(documentedFacet)).toContain(k);
    const value = (facet?.['values'] as unknown[])[0];
    const documentedValue = (documentedFacet?.['values'] as unknown[])[0];
    for (const k of keysOf(value)) expect(keysOf(documentedValue)).toContain(k);
  });

  it('refuses a page past the result window with 400, like SonarQube', async () => {
    fake = await startFakeSonarQube(sampleSonarData(), { window: 2 });
    const res = await fetch(
      `${fake.url}/api/issues/search?projects=acme:shop&issueStatuses=ACCEPTED&ps=1&p=3`,
      { headers: { authorization: `Bearer ${fake.data.token}` } },
    );
    expect(res.status).toBe(400);
  });

  it('requires organization on the org endpoints of SonarQube Cloud', async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const res = await fetch(`${fake.url}/api/qualityprofiles/search`, {
      headers: { authorization: `Bearer ${fake.data.token}` },
    });
    expect(res.status).toBe(400);
  });

  it("answers SonarQube Cloud's hotspot search by `projectKey` only, like Cloud (finding L1)", async () => {
    fake = await startFakeSonarQube(sampleSonarData({ kind: 'cloud', organization: 'acme' }));
    const status = async (q: string) =>
      (
        await fetch(`${fake!.url}/api/hotspots/search?${q}&status=REVIEWED&ps=1`, {
          headers: { authorization: `Bearer ${fake!.data.token}` },
        })
      ).status;
    expect(await status('project=acme:shop')).toBe(400);
    expect(await status('projectKey=acme:shop&project=acme:shop')).toBe(400);
    expect(await status('projectKey=acme:shop')).toBe(200);
    const body = await get('api/hotspots/search?projectKey=acme:shop&status=REVIEWED&ps=1');
    expect(body['paging']).toMatchObject({ total: 2 });
  });

  it('refuses an issue filter value it does not know, like a strict SonarQube (I-2)', async () => {
    const ask = async (over: Partial<FakeSonarData>, query: string) => {
      const f = await startFakeSonarQube(sampleSonarData(over));
      try {
        const token = f.data.token;
        const auth =
          over.version?.startsWith('9.') === true
            ? `Basic ${Buffer.from(`${token}:`).toString('base64')}`
            : `Bearer ${token}`;
        const res = await fetch(`${f.url}/api/issues/search?projects=acme:shop&${query}`, {
          headers: { authorization: auth },
        });
        return res.status;
      } finally {
        await f.close();
      }
    };
    expect(await ask({}, 'issueStatuses=OPEN,CONFIRMED')).toBe(200);
    expect(await ask({}, 'issueStatuses=OPEN,BOGUS')).toBe(400);
    // IN_SANDBOX only from 2025.5.
    expect(await ask({}, 'issueStatuses=IN_SANDBOX')).toBe(400);
    expect(await ask({ version: '2025.5.0.113872' }, 'issueStatuses=IN_SANDBOX')).toBe(200);
    // issueStatuses only from 10.4.
    expect(await ask({ version: '9.9.4.87374' }, 'issueStatuses=OPEN')).toBe(400);
    expect(await ask({ version: '9.9.4.87374' }, 'statuses=RESOLVED&resolutions=FIXED')).toBe(200);
    expect(await ask({ version: '9.9.4.87374' }, 'statuses=FIXED')).toBe(400);
    expect(await ask({ version: '9.9.4.87374' }, 'resolutions=ACCEPTED')).toBe(400);
    expect(await ask({ version: '9.9.4.87374' }, 'resolved=no')).toBe(400);
  });

  it('answers every method but GET with 405, and records it', async () => {
    fake = await startFakeSonarQube(sampleSonarData());
    const res = await fetch(`${fake.url}/api/issues/search`, { method: 'POST' });
    expect(res.status).toBe(405);
    expect(fake.requests[0]?.method).toBe('POST');
  });
});
