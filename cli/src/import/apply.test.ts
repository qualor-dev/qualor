import { planGate, planProfile, type PlannedProfile, type SonarProjectData } from '@qualor/shared';
import { beforeEach, describe, expect, it } from 'vitest';
import { MemoryQualor, ORG_ID } from '../../test/memory-qualor';
import { CliError, EXIT } from '../errors';
import { UnreachableError } from '../server/http';
import {
  applyGates,
  applyProfiles,
  applyProjects,
  cutName,
  type ApplyOptions,
  type ProfileResult,
  type ProjectResult,
} from './apply';

const o = (over: Partial<ApplyOptions> = {}): ApplyOptions => ({
  dryRun: false,
  overwrite: false,
  setDefaults: false,
  createProjects: false,
  ...over,
});
const javaProfile = (): PlannedProfile =>
  planProfile({
    key: 'p-java',
    name: 'Team Java',
    language: 'java',
    isDefault: true,
    isBuiltIn: false,
    active: [
      {
        key: 'pmd:SystemPrintln',
        name: 'r',
        language: 'java',
        defaultSeverity: 'MAJOR',
        severity: 'CRITICAL',
        defaultImpacts: [],
        impacts: [],
        paramsCustomised: false,
      },
    ],
    inactive: ['pmd:EmptyCatchBlock'],
    complete: true,
  });
const gate = () =>
  planGate({
    name: 'Sonar way',
    isDefault: true,
    isBuiltIn: true,
    conditions: [
      { metric: 'new_violations', op: 'GT', error: '0' },
      { metric: 'new_coverage', op: 'LT', error: '80' },
    ],
  });
const sonar: SonarProjectData = {
  key: 'acme:shop',
  name: 'Shop',
  mainBranch: 'trunk',
  profiles: [{ language: 'java', profileKey: 'p-java', isDefault: false }],
  gate: { name: 'Sonar way', isDefault: false },
};
const OTHER_ORG = '00000000-0000-7000-8000-0000000000ff';

let q: MemoryQualor;
beforeEach(() => {
  q = new MemoryQualor();
});

describe('applyProfiles (import-sonarqube.md §7, §13)', () => {
  it('creates a profile with its rows, then finds it unchanged and writes nothing', async () => {
    const [first] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(first).toMatchObject({ outcome: 'created' });
    expect(await q.profileRows(first!.qualorProfileId!)).toEqual([
      { ruleKey: 'pmd:EmptyCatchBlock', active: false, severityOverride: null },
      { ruleKey: 'pmd:SystemPrintln', active: true, severityOverride: 'high' },
    ]);
    q.writes = [];
    const [again] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(again).toMatchObject({ outcome: 'unchanged', qualorProfileId: first!.qualorProfileId });
    expect(q.writes).toEqual([]);
  });

  it('sets unknownRules to activate explicitly on a created profile, whatever the default', async () => {
    q.defaultUnknownRules = 'ignore';
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(q.writes.slice(0, 2)).toEqual(['createProfile', 'setProfileUnknownRules']);
    expect(q.profilesList.find((p) => p.id === r!.qualorProfileId)?.unknownRules).toBe('activate');
  });

  it('treats an existing profile that ignores unknown rules as changed: conflict, then --overwrite resets it', async () => {
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const stored = q.profilesList.find((p) => p.id === r!.qualorProfileId)!;
    stored.unknownRules = 'ignore';
    q.writes = [];
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]).toMatchObject({
      outcome: 'conflict',
    });
    expect(q.writes).toEqual([]);
    expect(stored.unknownRules).toBe('ignore');
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ overwrite: true })))[0],
    ).toMatchObject({
      outcome: 'updated',
    });
    expect(q.writes).toEqual(['setProfileUnknownRules']);
    expect(stored.unknownRules).toBe('activate');
  });

  it('writes nothing under dryRun', async () => {
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o({ dryRun: true }));
    expect(r).toMatchObject({ outcome: 'would_create', qualorProfileId: null });
    expect(q.writes).toEqual([]);
  });

  it('reports a conflict and leaves a changed profile alone without --overwrite', async () => {
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    await q.setProfileRule(r!.qualorProfileId!, {
      ruleKey: 'pmd:Other',
      active: true,
      severityOverride: null,
    });
    q.writes = [];
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]).toMatchObject({
      outcome: 'conflict',
    });
    expect(q.writes).toEqual([]);
    expect((await q.profileRows(r!.qualorProfileId!)).map((x) => x.ruleKey)).toContain('pmd:Other');
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ overwrite: true, dryRun: true })))[0],
    ).toMatchObject({ outcome: 'would_update' });
    expect(q.writes).toEqual([]);
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ overwrite: true })))[0],
    ).toMatchObject({
      outcome: 'updated',
    });
    expect(q.writes).toEqual(['deleteProfileRule']);
    expect((await q.profileRows(r!.qualorProfileId!)).map((x) => x.ruleKey)).toEqual([
      'pmd:EmptyCatchBlock',
      'pmd:SystemPrintln',
    ]);
  });

  it('skips planned skips and built-in names, and makes defaults only with --set-defaults', async () => {
    q.profilesList.push({
      id: '00000000-0000-7000-8000-00000000000a',
      name: 'Team Java',
      language: 'java',
      isBuiltin: true,
      isDefault: true,
      unknownRules: 'activate',
      parentId: null,
      orgId: ORG_ID,
      rows: new Map(),
    });
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]).toMatchObject({
      outcome: 'skipped',
      reason: 'name_reserved',
    });
    q.profilesList = [];
    const [plain] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(q.profilesList.find((p) => p.id === plain!.qualorProfileId)?.isDefault).toBe(false);
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true }));
    expect(r).toMatchObject({ outcome: 'unchanged', qualorProfileId: plain!.qualorProfileId });
    expect(q.profilesList.find((p) => p.id === r!.qualorProfileId)?.isDefault).toBe(true);
    const empty = planProfile({
      key: 'p-empty',
      name: 'Nothing',
      language: 'java',
      isDefault: false,
      isBuiltIn: false,
      active: [],
      inactive: [],
      complete: true,
    });
    expect((await applyProfiles(q, ORG_ID, [empty], o()))[0]).toMatchObject({
      outcome: 'skipped',
      reason: 'no_mapped_rules',
    });
  });

  it('matches by name within the organisation and the language only', async () => {
    q.profilesList.push({
      id: '00000000-0000-7000-8000-00000000000b',
      name: 'Team Java',
      language: 'java',
      isBuiltin: false,
      isDefault: false,
      unknownRules: 'activate',
      parentId: null,
      orgId: OTHER_ORG,
      rows: new Map(),
    });
    q.profilesList.push({
      id: '00000000-0000-7000-8000-00000000000c',
      name: 'Team Java',
      language: 'typescript',
      isBuiltin: false,
      isDefault: false,
      unknownRules: 'activate',
      parentId: null,
      orgId: ORG_ID,
      rows: new Map(),
    });
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]).toMatchObject({
      outcome: 'created',
    });
  });

  it('records a failed profile and goes on', async () => {
    q.failOn.add('createProfile');
    const other = { ...javaProfile(), sonarKey: 'p-java-2', name: 'Team Java 2' };
    const results = await applyProfiles(q, ORG_ID, [javaProfile(), other], o());
    expect(results[0]).toMatchObject({ outcome: 'failed' });
    expect(results[0]?.reason).toContain('500');
    expect(results[1]).toMatchObject({ outcome: 'failed' });
    q.failOn = new Set(['setProfileRule']);
    const [partial] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(partial).toMatchObject({ outcome: 'failed' });
    expect(partial?.qualorProfileId).not.toBeNull();
  });

  it('never adopts a profile of that name that inherits from another, even with --overwrite (§13)', async () => {
    const parent = await q.createProfile(ORG_ID, 'Base', 'java');
    const child = await q.createProfile(ORG_ID, 'Team Java', 'java');
    q.profilesList.find((p) => p.id === child.id)!.parentId = parent.id;
    q.writes = [];
    for (const over of [{}, { overwrite: true }, { overwrite: true, dryRun: true }]) {
      const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o(over));
      expect(r).toMatchObject({ outcome: 'conflict', qualorProfileId: child.id });
      expect(r?.reason).toContain('inherits from another profile');
    }
    expect(q.writes).toEqual([]);
  });

  it('reports the default it sets, or would set in a dry run, with --set-defaults', async () => {
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true, dryRun: true })))[0],
    ).toMatchObject({ outcome: 'would_create', defaultChange: 'would_set' });
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]).toMatchObject({
      outcome: 'created',
      defaultChange: null,
    });
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true, dryRun: true })))[0],
    ).toMatchObject({ outcome: 'unchanged', defaultChange: 'would_set' });
    expect(q.writes).not.toContain('setDefaultProfile');
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true })))[0],
    ).toMatchObject({ outcome: 'unchanged', defaultChange: 'set' });
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true })))[0],
    ).toMatchObject({ outcome: 'unchanged', defaultChange: null });
    q.profilesList = [];
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ setDefaults: true })))[0],
    ).toMatchObject({ outcome: 'created', defaultChange: 'set' });
  });

  it('records 409 and 422 answers to writes as failures, with the rerun hint once created', async () => {
    q.failWith.set('createProfile', { status: 409, code: 'PROFILE_EXISTS' });
    const [taken] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(taken).toMatchObject({ outcome: 'failed', qualorProfileId: null });
    expect(taken?.reason).toContain('409 PROFILE_EXISTS');
    expect(taken?.reason).not.toContain('--overwrite');
    q.failWith = new Map([['setProfileRule', { status: 422, code: 'VALIDATION_FAILED' }]]);
    const [half] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    expect(half).toMatchObject({ outcome: 'failed' });
    expect(half?.qualorProfileId).not.toBeNull();
    expect(half?.reason).toContain('422 VALIDATION_FAILED');
    expect(half?.reason).toContain('run the import again with --overwrite');
    // The rerun sees a profile with other rows: a conflict, which --overwrite completes.
    q.failWith = new Map();
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]?.outcome).toBe('conflict');
    expect(
      (await applyProfiles(q, ORG_ID, [javaProfile()], o({ overwrite: true })))[0],
    ).toMatchObject({ outcome: 'updated', qualorProfileId: half?.qualorProfileId });
    expect((await applyProfiles(q, ORG_ID, [javaProfile()], o()))[0]?.outcome).toBe('unchanged');
  });

  it('stops on a password change required and on an unreachable Qualor', async () => {
    for (const err of [
      new CliError(EXIT.AUTH, 'Qualor refused POST /x: 403 PASSWORD_CHANGE_REQUIRED'),
      new UnreachableError('cannot reach http://127.0.0.1:1 (POST /x): ECONNREFUSED'),
    ]) {
      const api = Object.assign(new MemoryQualor(), {
        createProfile: () => Promise.reject(err),
        createGate: () => Promise.reject(err),
        createProject: () => Promise.reject(err),
      });
      await expect(applyProfiles(api, ORG_ID, [javaProfile()], o())).rejects.toBe(err);
      await expect(applyGates(api, ORG_ID, [gate()], o())).rejects.toBe(err);
      await expect(
        applyProjects(api, ORG_ID, [sonar], [], [], o({ createProjects: true })),
      ).rejects.toBe(err);
    }
  });

  it('records the profile a fatal failure interrupted, with the rerun hint, then stops (ruling S13)', async () => {
    const err = new CliError(EXIT.AUTH, 'Qualor refused PUT: 401');
    const api = Object.assign(new MemoryQualor(), {
      setProfileRule: () => Promise.reject(err),
    });
    const out: ProfileResult[] = [];
    await expect(applyProfiles(api, ORG_ID, [javaProfile()], o(), out)).rejects.toBe(err);
    expect(out).toMatchObject([{ outcome: 'failed' }]);
    expect(out[0]?.reason).toContain('401');
    expect(out[0]?.reason).toContain('--overwrite');
    expect(out[0]?.qualorProfileId).toBe(api.profilesList[0]?.id);
  });

  it("fails each planned profile when Qualor's list fails, and lists nothing when nothing is planned", async () => {
    q.failOn.add('profiles');
    const skipped = { ...javaProfile(), skip: 'no_mapped_rules' as const };
    const results = await applyProfiles(q, ORG_ID, [javaProfile(), skipped], o());
    expect(results.map((r) => r.outcome)).toEqual(['failed', 'skipped']);
    expect(results[0]?.reason).toContain('500');
    expect(await applyProfiles(q, ORG_ID, [skipped], o())).toMatchObject([{ outcome: 'skipped' }]);
    expect(await applyProfiles(q, ORG_ID, [], o())).toEqual([]);
    q.failOn.add('gates');
    expect(await applyGates(q, ORG_ID, [], o())).toEqual([]);
    const [g] = await applyGates(q, ORG_ID, [gate()], o());
    expect(g).toMatchObject({
      outcome: 'failed',
      reason: expect.stringContaining('500') as unknown,
    });
  });

  it('stops on an authentication failure instead of recording it', async () => {
    const api = Object.assign(new MemoryQualor(), {
      profiles: () => Promise.resolve([]),
      createProfile: () => Promise.reject(new CliError(EXIT.AUTH, 'Qualor refused POST')),
    });
    await expect(applyProfiles(api, ORG_ID, [javaProfile()], o())).rejects.toMatchObject({
      exitCode: EXIT.AUTH,
    });
  });
});

describe('applyGates (import-sonarqube.md §8, §13)', () => {
  it('creates, then finds unchanged; conflict and --overwrite; an ambiguous name', async () => {
    const [created] = await applyGates(q, ORG_ID, [gate()], o());
    expect(created).toMatchObject({ outcome: 'created' });
    expect(q.gatesList[0]?.conditions.map((c) => c.metric).sort()).toEqual([
      'new_coverage',
      'new_issues',
    ]);
    q.writes = [];
    expect((await applyGates(q, ORG_ID, [gate()], o()))[0]?.outcome).toBe('unchanged');
    expect(q.writes).toEqual([]);
    q.gatesList[0]!.conditions[0]!.threshold = 5;
    expect((await applyGates(q, ORG_ID, [gate()], o()))[0]?.outcome).toBe('conflict');
    expect(q.writes).toEqual([]);
    expect(q.gatesList[0]!.conditions[0]!.threshold).toBe(5);
    expect(
      (await applyGates(q, ORG_ID, [gate()], o({ overwrite: true, dryRun: true })))[0]?.outcome,
    ).toBe('would_update');
    expect(q.writes).toEqual([]);
    expect((await applyGates(q, ORG_ID, [gate()], o({ overwrite: true })))[0]?.outcome).toBe(
      'updated',
    );
    expect(q.writes).toEqual(['updateCondition']);
    expect((await applyGates(q, ORG_ID, [gate()], o()))[0]?.outcome).toBe('unchanged');
    await q.createGate(ORG_ID, 'Sonar way');
    expect((await applyGates(q, ORG_ID, [gate()], o({ overwrite: true })))[0]).toMatchObject({
      outcome: 'conflict',
      reason: 'name_ambiguous',
    });
  });

  it('with --overwrite adds, changes and deletes conditions to match', async () => {
    const [created] = await applyGates(q, ORG_ID, [gate()], o());
    const stored = q.gatesList.find((g) => g.id === created!.qualorGateId)!;
    await q.deleteCondition(
      stored.id,
      stored.conditions.find((c) => c.metric === 'new_issues')!.id,
    );
    await q.addCondition(stored.id, { metric: 'coverage', operator: 'lt', threshold: 50 });
    q.writes = [];
    expect((await applyGates(q, ORG_ID, [gate()], o({ overwrite: true })))[0]?.outcome).toBe(
      'updated',
    );
    expect(q.writes.sort()).toEqual(['addCondition', 'deleteCondition']);
    expect(stored.conditions.map((c) => c.metric).sort()).toEqual(['new_coverage', 'new_issues']);
  });

  it('hints at a rerun with --overwrite when an update fails part way (profile and gate)', async () => {
    const [created] = await applyGates(q, ORG_ID, [gate()], o());
    const stored = q.gatesList.find((g) => g.id === created!.qualorGateId)!;
    await q.addCondition(stored.id, { metric: 'coverage', operator: 'lt', threshold: 50 });
    q.failWith.set('addCondition', { status: 422, code: 'VALIDATION_FAILED' });
    await q.deleteCondition(
      stored.id,
      stored.conditions.find((c) => c.metric === 'new_issues')!.id,
    );
    const [g] = await applyGates(q, ORG_ID, [gate()], o({ overwrite: true }));
    expect(g).toMatchObject({ outcome: 'failed', qualorGateId: stored.id });
    expect(g?.reason).toContain('it was updated in part: run the import again with --overwrite');

    q.failWith = new Map();
    const [p] = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    await q.setProfileRule(p!.qualorProfileId!, {
      ruleKey: 'pmd:Other',
      active: true,
      severityOverride: null,
    });
    q.failWith.set('deleteProfileRule', { status: 422, code: 'VALIDATION_FAILED' });
    const [r] = await applyProfiles(q, ORG_ID, [javaProfile()], o({ overwrite: true }));
    expect(r).toMatchObject({ outcome: 'failed', qualorProfileId: p!.qualorProfileId });
    expect(r?.reason).toContain('it was updated in part: run the import again with --overwrite');
  });

  it('with --overwrite updates a condition whose operator changed', async () => {
    const [created] = await applyGates(q, ORG_ID, [gate()], o());
    const stored = q.gatesList.find((g) => g.id === created!.qualorGateId)!;
    const cond = stored.conditions.find((c) => c.metric === 'new_coverage')!;
    cond.operator = 'gt';
    q.writes = [];
    expect((await applyGates(q, ORG_ID, [gate()], o()))[0]?.outcome).toBe('conflict');
    expect((await applyGates(q, ORG_ID, [gate()], o({ overwrite: true })))[0]?.outcome).toBe(
      'updated',
    );
    expect(q.writes).toEqual(['updateCondition']);
    expect(stored.conditions.find((c) => c.metric === 'new_coverage')).toMatchObject({
      id: cond.id,
      operator: 'lt',
      threshold: 80,
    });
  });

  it('records 409 and 422 answers to condition writes, with the rerun hint', async () => {
    q.failWith.set('addCondition', { status: 422, code: 'VALIDATION_FAILED' });
    const [r] = await applyGates(q, ORG_ID, [gate()], o());
    expect(r).toMatchObject({ outcome: 'failed' });
    expect(r?.reason).toContain('422 VALIDATION_FAILED');
    expect(r?.reason).toContain('--overwrite');
    q.failWith = new Map([['createGate', { status: 409, code: 'CONFLICT' }]]);
    const [again] = await applyGates(q, ORG_ID, [{ ...gate(), name: 'Other' }], o());
    expect(again).toMatchObject({ outcome: 'failed', qualorGateId: null });
    expect(again?.reason).toContain('409');
  });

  it('reports the default gate it sets, or would set in a dry run', async () => {
    expect(
      (await applyGates(q, ORG_ID, [gate()], o({ setDefaults: true, dryRun: true })))[0],
    ).toMatchObject({ outcome: 'would_create', defaultChange: 'would_set' });
    expect((await applyGates(q, ORG_ID, [gate()], o({ setDefaults: true })))[0]).toMatchObject({
      outcome: 'created',
      defaultChange: 'set',
    });
    expect((await applyGates(q, ORG_ID, [gate()], o({ setDefaults: true })))[0]).toMatchObject({
      outcome: 'unchanged',
      defaultChange: null,
    });
  });

  it('skips built-in names, planned skips, and a gate without mapped conditions', async () => {
    q.gatesList.push({
      id: '00000000-0000-7000-8000-00000000000d',
      name: 'Sonar way',
      isBuiltin: true,
      isDefault: true,
      conditions: [],
      orgId: ORG_ID,
    });
    expect((await applyGates(q, ORG_ID, [gate()], o()))[0]).toMatchObject({
      outcome: 'skipped',
      reason: 'name_reserved',
    });
    const none = planGate({
      name: 'Hotspots',
      isDefault: false,
      isBuiltIn: false,
      conditions: [{ metric: 'security_hotspots_reviewed', op: 'LT', error: '100' }],
    });
    expect((await applyGates(q, ORG_ID, [none], o()))[0]).toMatchObject({
      outcome: 'skipped',
      reason: 'no_mapped_conditions',
    });
    expect(q.writes).toEqual([]);
  });

  it('makes the default gate only with --set-defaults, once', async () => {
    await applyGates(q, ORG_ID, [gate()], o());
    expect(q.gatesList[0]?.isDefault).toBe(false);
    q.writes = [];
    await applyGates(q, ORG_ID, [gate()], o({ setDefaults: true }));
    expect(q.writes).toEqual(['setDefaultGate']);
    expect(q.gatesList[0]?.isDefault).toBe(true);
    q.writes = [];
    await applyGates(q, ORG_ID, [gate()], o({ setDefaults: true }));
    expect(q.writes).toEqual([]);
  });

  it('records a failed gate and goes on', async () => {
    q.failOn.add('addCondition');
    const [r] = await applyGates(q, ORG_ID, [gate()], o());
    expect(r).toMatchObject({ outcome: 'failed' });
    expect(r?.qualorGateId).not.toBeNull();
  });
});

describe('applyProjects (import-sonarqube.md §9)', () => {
  it('reports a missing project, creates it with --create-projects, and assigns profile and gate', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const gates = await applyGates(q, ORG_ID, [gate()], o());
    expect((await applyProjects(q, ORG_ID, [sonar], profiles, gates, o()))[0]).toMatchObject({
      outcome: 'missing',
    });
    const [r] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      gates,
      o({ createProjects: true }),
    );
    expect(r).toMatchObject({
      outcome: 'created',
      profiles: [{ language: 'java', outcome: 'assigned' }],
      gate: { outcome: 'assigned' },
    });
    q.writes = [];
    const [again] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      gates,
      o({ createProjects: true }),
    );
    expect(again).toMatchObject({
      outcome: 'found',
      profiles: [{ outcome: 'unchanged' }],
      gate: { outcome: 'unchanged' },
    });
    expect(q.writes).toEqual([]);
  });

  it('never overwrites another explicit assignment without --overwrite', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const gates = await applyGates(q, ORG_ID, [gate()], o());
    const project = await q.createProject(ORG_ID, 'acme:shop', 'Shop');
    const other = await q.createGate(ORG_ID, 'Other');
    await q.setProjectGate(project.id, other.id);
    const otherProfile = await q.createProfile(ORG_ID, 'Other Java', 'java');
    await q.setProjectProfile(project.id, 'java', otherProfile.id);
    q.writes = [];
    const [r] = await applyProjects(q, ORG_ID, [sonar], profiles, gates, o());
    expect(r?.gate).toMatchObject({ outcome: 'conflict' });
    expect(r?.profiles).toMatchObject([{ outcome: 'conflict' }]);
    expect(q.projectsList[0]?.qualityGateId).toBe(other.id);
    expect(q.writes).toEqual([]);
    const [dry] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      gates,
      o({ overwrite: true, dryRun: true }),
    );
    expect(dry).toMatchObject({
      gate: { outcome: 'would_assign' },
      profiles: [{ outcome: 'would_assign' }],
    });
    expect(q.writes).toEqual([]);
    const [forced] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      gates,
      o({ overwrite: true }),
    );
    expect(forced).toMatchObject({
      gate: { outcome: 'assigned' },
      profiles: [{ outcome: 'assigned' }],
    });
    expect(q.projectsList[0]?.qualityGateId).toBe(gates[0]?.qualorGateId);
  });

  it('leaves SonarQube defaults to the organisation, and skips assignments of objects not imported', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const gates = await applyGates(q, ORG_ID, [gate()], o());
    await q.createProject(ORG_ID, 'acme:shop', 'Shop');
    q.writes = [];
    const onDefaults: SonarProjectData = {
      ...sonar,
      profiles: [{ language: 'java', profileKey: 'p-java', isDefault: true }],
      gate: { name: 'Sonar way', isDefault: true },
    };
    expect((await applyProjects(q, ORG_ID, [onDefaults], profiles, gates, o()))[0]).toMatchObject({
      outcome: 'found',
      profiles: [],
      gate: null,
    });
    const conflicted = profiles.map((p) => ({ ...p, outcome: 'conflict' as const }));
    const [r] = await applyProjects(
      q,
      ORG_ID,
      [{ ...sonar, gate: { name: 'Unknown', isDefault: false } }],
      conflicted,
      gates,
      o(),
    );
    expect(r).toMatchObject({ profiles: [{ outcome: 'skipped' }], gate: { outcome: 'skipped' } });
    expect(q.writes).toEqual([]);
  });

  it('fails the assignments of a profile or gate that failed (exit 4, not a silent skip)', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const gates = await applyGates(q, ORG_ID, [gate()], o());
    await q.createProject(ORG_ID, 'acme:shop', 'Shop');
    q.writes = [];
    const failedProfiles = profiles.map((p) => ({
      ...p,
      outcome: 'failed' as const,
      reason: 'Qualor answered 500 INTERNAL_ERROR to profiles',
    }));
    const failedGates = gates.map((g) => ({ ...g, outcome: 'failed' as const, reason: 'boom' }));
    const [r] = await applyProjects(q, ORG_ID, [sonar], failedProfiles, failedGates, o());
    expect(r).toMatchObject({
      outcome: 'found',
      profiles: [{ outcome: 'failed', reason: expect.stringContaining('500') as unknown }],
      gate: { outcome: 'failed', reason: expect.stringContaining('boom') as unknown },
    });
    expect(q.writes).toEqual([]);
  });

  it('records the project a fatal failure interrupted, then stops (ruling S13)', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const err = new CliError(EXIT.AUTH, 'Qualor refused PUT: 401');
    const api = Object.assign(q, { setProjectProfile: () => Promise.reject(err) });
    const out: ProjectResult[] = [];
    await expect(
      applyProjects(api, ORG_ID, [sonar], profiles, [], o({ createProjects: true }), out),
    ).rejects.toBe(err);
    expect(out).toMatchObject([
      { outcome: 'created', profiles: [{ outcome: 'failed', reason: 'Qualor refused PUT: 401' }] },
    ]);
  });

  it('refuses a key Qualor cannot hold', async () => {
    const [r] = await applyProjects(
      q,
      ORG_ID,
      [{ ...sonar, key: 'bad key!' }],
      [],
      [],
      o({ createProjects: true }),
    );
    expect(r?.outcome).toBe('key_invalid');
    expect(q.writes).toEqual([]);
  });

  it('does not touch a project of that key in another organisation', async () => {
    await q.createProject(OTHER_ORG, 'acme:shop', 'Shop');
    q.writes = [];
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o({ dryRun: true }));
    const [r] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      [],
      o({ createProjects: true, overwrite: true }),
    );
    expect(r).toMatchObject({ outcome: 'failed', qualorProjectId: null, profiles: [], gate: null });
    expect(q.writes).toEqual([]);
  });

  it('records a failed assignment without losing the created project, and still tries the gate', async () => {
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], o());
    const gates = await applyGates(q, ORG_ID, [gate()], o());
    q.failOn.add('setProjectProfile');
    const [r] = await applyProjects(
      q,
      ORG_ID,
      [sonar],
      profiles,
      gates,
      o({ createProjects: true }),
    );
    expect(r).toMatchObject({
      outcome: 'created',
      reason: null,
      profiles: [{ language: 'java', outcome: 'failed' }],
      gate: { outcome: 'assigned' },
    });
    expect(r?.qualorProjectId).toBe(q.projectsList[0]?.id);
    expect(r?.profiles[0]?.reason).toContain('500');
    q.failOn = new Set(['setProjectGate']);
    q.projectsList[0]!.qualityGateId = null;
    const [h] = await applyProjects(q, ORG_ID, [sonar], profiles, gates, o());
    expect(h).toMatchObject({
      outcome: 'found',
      profiles: [{ outcome: 'assigned' }],
      gate: { outcome: 'failed' },
    });
  });

  it('names the likely cause when Qualor says the key is taken (another organisation)', async () => {
    q.failWith.set('createProject', { status: 409, code: 'PROJECT_KEY_TAKEN' });
    const [r] = await applyProjects(q, ORG_ID, [sonar], [], [], o({ createProjects: true }));
    expect(r).toMatchObject({
      outcome: 'failed',
      reason:
        'a Qualor project of this key exists in another organisation or is not visible to this user',
      qualorProjectId: null,
    });
  });

  it('cuts a long SonarQube name to 255 UTF-16 units without splitting a surrogate pair', async () => {
    const name = `${'a'.repeat(254)}\u{1F600}tail`;
    expect(cutName(name, 255)).toBe('a'.repeat(254));
    expect(cutName(`${'a'.repeat(253)}\u{1F600}`, 255)).toBe(`${'a'.repeat(253)}\u{1F600}`);
    expect(cutName('short', 255)).toBe('short');
    await applyProjects(q, ORG_ID, [{ ...sonar, name }], [], [], o({ createProjects: true }));
    expect(q.projectsList[0]?.name).toBe('a'.repeat(254));
  });

  it('records a failed project and goes on', async () => {
    q.failOn.add('createProject');
    const results = await applyProjects(
      q,
      ORG_ID,
      [sonar, { ...sonar, key: 'acme:cart' }],
      [],
      [],
      o({ createProjects: true }),
    );
    expect(results.map((r) => r.outcome)).toEqual(['failed', 'failed']);
  });
});

describe('the whole import (import-sonarqube.md §12, §13)', () => {
  const run = async (over: Partial<ApplyOptions>) => {
    const options = o({ setDefaults: true, createProjects: true, ...over });
    const profiles = await applyProfiles(q, ORG_ID, [javaProfile()], options);
    const gates = await applyGates(q, ORG_ID, [gate()], options);
    const projects = await applyProjects(q, ORG_ID, [sonar], profiles, gates, options);
    return { profiles, gates, projects };
  };

  it('a dry run sends no write request at all, on an empty Qualor and on a differing one with --overwrite', async () => {
    const dry = await run({ dryRun: true, overwrite: true });
    expect(q.writes).toEqual([]);
    expect(dry.profiles[0]?.outcome).toBe('would_create');
    expect(dry.gates[0]?.outcome).toBe('would_create');
    expect(dry.projects[0]).toMatchObject({
      outcome: 'would_create',
      profiles: [{ outcome: 'would_assign' }],
      gate: { outcome: 'would_assign' },
    });
    await run({});
    q.gatesList[0]!.conditions[0]!.threshold = 7;
    q.profilesList[0]!.unknownRules = 'ignore';
    q.projectsList[0]!.qualityGateId = null;
    q.writes = [];
    const again = await run({ dryRun: true, overwrite: true });
    expect(q.writes).toEqual([]);
    expect(again.profiles[0]?.outcome).toBe('would_update');
    expect(again.gates[0]?.outcome).toBe('would_update');
    expect(again.projects[0]).toMatchObject({
      outcome: 'found',
      gate: { outcome: 'would_assign' },
    });
  });

  it('a second run with the same data writes nothing and reports only unchanged', async () => {
    await run({});
    q.writes = [];
    const second = await run({ overwrite: true });
    expect(q.writes).toEqual([]);
    expect(second.profiles.map((r) => r.outcome)).toEqual(['unchanged']);
    expect(second.gates.map((r) => r.outcome)).toEqual(['unchanged']);
    expect(second.projects[0]).toMatchObject({
      outcome: 'found',
      profiles: [{ outcome: 'unchanged' }],
      gate: { outcome: 'unchanged' },
    });
  });
});
