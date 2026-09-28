import type { PlannedRow, StatusImportRequestItem } from '@qualor/shared';
import {
  QualorApiError,
  type Membership,
  type NewCondition,
  type QualorApi,
  type QualorGate,
  type QualorProfile,
  type QualorProject,
  type StatusImportAnswer,
  type UnknownRules,
} from '../src/import/qualor-api';

export const ORG_ID = '00000000-0000-7000-8000-000000000001';

type Profile = QualorProfile & { orgId: string; rows: Map<string, PlannedRow> };
type Gate = QualorGate & { orgId: string };
type Project = QualorProject & { name: string; profiles: Map<string, string> };

/**
 * Qualor's API as the import uses it, in memory. `writes` lists every write, in order (reads are
 * not recorded); `failOn` makes the named methods (reads included) fail with a 500.
 */
export class MemoryQualor implements QualorApi {
  writes: string[] = [];
  profilesList: Profile[] = [];
  gatesList: Gate[] = [];
  projectsList: Project[] = [];
  identity: { isInstanceAdmin: boolean; memberships: Membership[] } = {
    isInstanceAdmin: false,
    memberships: [{ organizationId: ORG_ID, organizationKey: 'default', role: 'admin' }],
  };
  /** What a new profile gets when the client does not say (the database default). */
  defaultUnknownRules: UnknownRules = 'activate';
  /** Method names that throw a 500 (a step that fails). */
  failOn = new Set<string>();
  /** Method names that throw the given status and code instead (a 409, a 422, a 403...). */
  failWith = new Map<string, { status: number; code: string }>();
  statusHandler: (
    projectId: string,
    items: readonly StatusImportRequestItem[],
    dryRun: boolean,
  ) => StatusImportAnswer = () => ({ kind: 'not_analysed' });
  statusCalls: { projectId: string; items: readonly StatusImportRequestItem[]; dryRun: boolean }[] =
    [];
  #n = 1;

  #id(): string {
    this.#n += 1;
    return `00000000-0000-7000-8000-${String(this.#n).padStart(12, '0')}`;
  }
  #write(what: string): void {
    this.#fail(what);
    this.writes.push(what);
  }
  /** A read: fails like a write, but is not recorded. */
  #read(what: string): void {
    this.#fail(what);
  }
  #fail(what: string): void {
    const fail = this.failWith.get(what);
    if (fail !== undefined) {
      throw new QualorApiError(
        fail.status,
        fail.code,
        `Qualor answered ${String(fail.status)} ${fail.code} to ${what}`,
      );
    }
    if (this.failOn.has(what)) {
      throw new QualorApiError(
        500,
        'INTERNAL_ERROR',
        `Qualor answered 500 INTERNAL_ERROR to ${what}`,
      );
    }
  }
  #profile(id: string): Profile {
    return this.profilesList.find((p) => p.id === id)!;
  }
  #gate(id: string): Gate {
    return this.gatesList.find((g) => g.id === id)!;
  }
  #project(id: string): Project {
    return this.projectsList.find((p) => p.id === id)!;
  }

  async me() {
    return this.identity;
  }
  async organizations() {
    return [{ id: ORG_ID, key: 'default' }];
  }
  async profiles(orgId: string) {
    this.#read('profiles');
    return this.profilesList.filter((p) => p.orgId === orgId);
  }
  async createProfile(orgId: string, name: string, language: string) {
    this.#write('createProfile');
    const p: Profile = {
      id: this.#id(),
      name,
      language,
      isBuiltin: false,
      isDefault: false,
      unknownRules: this.defaultUnknownRules,
      parentId: null,
      orgId,
      rows: new Map(),
    };
    this.profilesList.push(p);
    return { ...p };
  }
  async setProfileUnknownRules(profileId: string, unknownRules: UnknownRules) {
    this.#write('setProfileUnknownRules');
    this.#profile(profileId).unknownRules = unknownRules;
  }
  async profileRows(profileId: string) {
    this.#read('profileRows');
    return [...(this.profilesList.find((p) => p.id === profileId)?.rows.values() ?? [])]
      .map((r) => ({ ...r }))
      .sort((a, b) => (a.ruleKey < b.ruleKey ? -1 : a.ruleKey > b.ruleKey ? 1 : 0));
  }
  async setProfileRule(profileId: string, row: PlannedRow) {
    this.#write('setProfileRule');
    this.#profile(profileId).rows.set(row.ruleKey, { ...row });
  }
  async deleteProfileRule(profileId: string, ruleKey: string) {
    this.#write('deleteProfileRule');
    this.#profile(profileId).rows.delete(ruleKey);
  }
  async setDefaultProfile(profileId: string) {
    this.#write('setDefaultProfile');
    const target = this.#profile(profileId);
    for (const p of this.profilesList) {
      if (p.orgId === target.orgId && p.language === target.language) p.isDefault = p === target;
    }
  }
  async gates(orgId: string) {
    this.#read('gates');
    return this.gatesList
      .filter((g) => g.orgId === orgId)
      .map((g) => ({ ...g, conditions: g.conditions.map((c) => ({ ...c })) }));
  }
  async createGate(orgId: string, name: string) {
    this.#write('createGate');
    const g: Gate = {
      id: this.#id(),
      name,
      isBuiltin: false,
      isDefault: false,
      conditions: [],
      orgId,
    };
    this.gatesList.push(g);
    return { ...g, conditions: [] };
  }
  async addCondition(gateId: string, c: NewCondition) {
    this.#write('addCondition');
    const g = this.#gate(gateId);
    if (g.conditions.some((x) => x.metric === c.metric)) {
      throw new QualorApiError(409, 'CONDITION_EXISTS', 'Qualor answered 409 CONDITION_EXISTS');
    }
    g.conditions.push({ id: this.#id(), ...c });
  }
  async updateCondition(gateId: string, condId: string, c: NewCondition) {
    this.#write('updateCondition');
    Object.assign(
      this.#gate(gateId).conditions.find((x) => x.id === condId)!,
      c,
    );
  }
  async deleteCondition(gateId: string, condId: string) {
    this.#write('deleteCondition');
    const g = this.#gate(gateId);
    g.conditions = g.conditions.filter((x) => x.id !== condId);
  }
  async setDefaultGate(gateId: string) {
    this.#write('setDefaultGate');
    const target = this.#gate(gateId);
    for (const g of this.gatesList) if (g.orgId === target.orgId) g.isDefault = g === target;
  }
  async projectByKey(key: string) {
    this.#read('projectByKey');
    const p = this.projectsList.find((x) => x.key === key);
    return p === undefined
      ? null
      : { id: p.id, organizationId: p.organizationId, key: p.key, qualityGateId: p.qualityGateId };
  }
  async createProject(orgId: string, key: string, name: string) {
    this.#write('createProject');
    const p: Project = {
      id: this.#id(),
      organizationId: orgId,
      key,
      name,
      qualityGateId: null,
      profiles: new Map(),
    };
    this.projectsList.push(p);
    return { id: p.id, organizationId: orgId, key, qualityGateId: null };
  }
  async projectProfiles(projectId: string) {
    this.#read('projectProfiles');
    const p = this.#project(projectId);
    return ['typescript', 'javascript', 'java'].map((language) => {
      const own = p.profiles.get(language);
      return own !== undefined
        ? { language, profileId: own, source: 'project' as const }
        : {
            language,
            profileId:
              this.profilesList.find(
                (x) => x.orgId === p.organizationId && x.language === language && x.isDefault,
              )?.id ?? null,
            source: 'default' as const,
          };
    });
  }
  async setProjectProfile(projectId: string, language: string, profileId: string) {
    this.#write('setProjectProfile');
    this.#project(projectId).profiles.set(language, profileId);
  }
  async setProjectGate(projectId: string, gateId: string) {
    this.#write('setProjectGate');
    this.#project(projectId).qualityGateId = gateId;
  }
  async importStatuses(
    projectId: string,
    items: readonly StatusImportRequestItem[],
    dryRun: boolean,
  ) {
    this.statusCalls.push({ projectId, items, dryRun });
    return this.statusHandler(projectId, items, dryRun);
  }
}
