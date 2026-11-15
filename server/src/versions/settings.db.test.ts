import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { organizations, projects, projectVulnerabilitySettings } from '../db/schema';
import {
  DEFAULT_VULNERABILITY_SETTINGS,
  vulnerabilitySettings,
  vulnerabilitySettingsOf,
} from './settings';

describe('vulnerabilitySettings', () => {
  let t: TestDatabase;
  let orgId: string;
  beforeAll(async () => {
    t = await createTestDatabase();
    const [org] = await t.db
      .insert(organizations)
      .values({ key: 'acme', name: 'Acme' })
      .returning();
    orgId = org!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  async function newProject(key: string): Promise<string> {
    const [p] = await t.db
      .insert(projects)
      .values({ organizationId: orgId, key, name: key })
      .returning();
    return p!.id;
  }

  it('reads the settings of 70 000 projects in one statement', async () => {
    const id = await newProject('acme/many');
    await t.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId: id, branchPatterns: ['x/*'] });
    const ids = [id, ...Array.from({ length: 69_999 }, () => randomUUID())];
    const got = await vulnerabilitySettingsOf(t.db, ids);
    expect(got.size).toBe(70_000);
    expect(got.get(id)?.branchPatterns).toEqual(['x/*']);
  });

  it('returns the defaults when the project has no row', async () => {
    const id = await newProject('acme/none');
    expect(await vulnerabilitySettings(t.db, id)).toEqual(DEFAULT_VULNERABILITY_SETTINGS);
    expect(DEFAULT_VULNERABILITY_SETTINGS).toEqual({
      enabled: true,
      branchPatterns: [],
      versionRule: { kind: 'lines', lines: 5 },
      labelVersions: false,
    });
  });

  it('maps a stored row', async () => {
    const id = await newProject('acme/row');
    await t.db.insert(projectVulnerabilitySettings).values({
      projectId: id,
      enabled: false,
      branchPatterns: ['release/*'],
      versionRule: 'all',
      versionLines: 3,
      labelVersions: true,
    });
    expect(await vulnerabilitySettings(t.db, id)).toEqual({
      enabled: false,
      branchPatterns: ['release/*'],
      versionRule: { kind: 'all' },
      labelVersions: true,
    });
    const id2 = await newProject('acme/lines');
    await t.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId: id2, versionRule: 'lines', versionLines: 3 });
    expect((await vulnerabilitySettings(t.db, id2)).versionRule).toEqual({
      kind: 'lines',
      lines: 3,
    });
  });
});
