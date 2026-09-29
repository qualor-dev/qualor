import { sql } from 'drizzle-orm';
import type { Severity } from '@qualor/shared';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { PROFILE_LANGUAGES, type ProfileLanguage } from '../orgs/builtins';

/** data-model.md §4.4: at most 3 levels (a profile, its parent, its grandparent). */
export const MAX_PROFILE_DEPTH = 3;

/**
 * Ruling P2: engines whose rules belong to a language; their findings are governed by the
 * profile of the finding's file language (Roslyn: plan 2D; sonarjs: phase 8A, JS/TS only). Every
 * other engine (Semgrep, Gitleaks, Trivy, any external SARIF) — and any file-less finding or file
 * of language `other` — is governed by `*`.
 */
export const LANGUAGE_BOUND_ENGINES: ReadonlySet<string> = new Set([
  'eslint',
  'sonarjs',
  'pmd',
  'spotbugs',
  'roslyn',
]);

export interface RuleSetting {
  active: boolean;
  severityOverride: Severity | null;
}

/** The effective profile for one language: the chosen profile first, then its ancestors. */
export interface ProfileChain {
  profileIds: readonly string[];
  unknownRules: 'activate' | 'ignore';
}

export interface ProfileSet {
  chains: ReadonlyMap<ProfileLanguage, ProfileChain>;
  /** profile id → rule id → its row in that profile. Only rows for the rules asked about. */
  settings: ReadonlyMap<string, ReadonlyMap<string, RuleSetting>>;
}

export function governingLanguage(engineId: string, fileLanguage: string | null): ProfileLanguage {
  if (!LANGUAGE_BOUND_ENGINES.has(engineId) || fileLanguage === null) return '*';
  return (PROFILE_LANGUAGES as readonly string[]).includes(fileLanguage)
    ? (fileLanguage as ProfileLanguage)
    : '*';
}

/**
 * data-model.md §4.4: a rule's row in the nearest profile of the chain wins (a child overrides
 * its parent); a rule with no row anywhere is active iff the chosen profile says
 * `unknown_rules = 'activate'`. No profile at all for the language (not reachable once the
 * built-ins exist) means no filtering.
 */
export function ruleSetting(
  set: ProfileSet,
  language: ProfileLanguage,
  ruleId: string,
): RuleSetting {
  const chain = set.chains.get(language);
  if (!chain) return { active: true, severityOverride: null };
  for (const profileId of chain.profileIds) {
    const row = set.settings.get(profileId)?.get(ruleId);
    if (row) return row;
  }
  return { active: chain.unknownRules === 'activate', severityOverride: null };
}

interface ProfileRow {
  id: string;
  language: string;
  parentId: string | null;
  isDefault: boolean;
  unknownRules: 'activate' | 'ignore';
}
interface SettingRow {
  profileId: string;
  ruleId: string;
  active: boolean;
  severityOverride: string | null;
}

/**
 * Loads the project's effective profile per language (`project_profiles`, else the
 * organisation's default) with its ancestors, and the `profile_rules` rows of those profiles for
 * `ruleIds` only. One statement, so one snapshot even in a READ COMMITTED transaction: an admin
 * editing profiles meanwhile is seen entirely before or entirely after, never half-applied. It
 * reads the rows of every profile of the organisation for those rules (at most
 * MAX_PROFILES_PER_ORGANIZATION profiles), and the chains are walked here.
 */
export async function loadProfileSet(
  tx: Executor,
  project: { id: string; organizationId: string },
  ruleIds: readonly string[],
): Promise<ProfileSet> {
  const settingsQuery =
    ruleIds.length === 0
      ? sql`'[]'::json`
      : sql`(SELECT coalesce(json_agg(json_build_object(
                'profileId', pr.profile_id, 'ruleId', pr.rule_id, 'active', pr.active,
                'severityOverride', pr.severity_override)), '[]'::json)
               FROM profile_rules pr
              WHERE pr.profile_id IN (SELECT id FROM org_profiles)
                AND pr.rule_id IN ${uuidList(ruleIds)})`;
  const result = await tx.execute<{
    profiles: ProfileRow[];
    overrides: { language: string; profileId: string }[];
    settings: SettingRow[];
  }>(sql`
    WITH org_profiles AS (
      SELECT id, language, parent_id, is_default, unknown_rules
        FROM quality_profiles WHERE organization_id = ${project.organizationId})
    SELECT
      (SELECT coalesce(json_agg(json_build_object(
                'id', id, 'language', language, 'parentId', parent_id,
                'isDefault', is_default, 'unknownRules', unknown_rules)), '[]'::json)
         FROM org_profiles) AS profiles,
      (SELECT coalesce(json_agg(json_build_object(
                'language', language, 'profileId', profile_id)), '[]'::json)
         FROM project_profiles WHERE project_id = ${project.id}) AS overrides,
      ${settingsQuery} AS settings`);
  const [loaded] = result.rows;
  const all = loaded?.profiles ?? [];
  const byId = new Map(all.map((p) => [p.id, p]));
  const chosen = new Map<string, string>();
  for (const p of all) if (p.isDefault) chosen.set(p.language, p.id);
  for (const o of loaded?.overrides ?? []) {
    if (byId.has(o.profileId)) chosen.set(o.language, o.profileId);
  }

  const chains = new Map<ProfileLanguage, ProfileChain>();
  for (const language of PROFILE_LANGUAGES) {
    const leafId = chosen.get(language);
    const leaf = leafId === undefined ? undefined : byId.get(leafId);
    if (!leaf) continue;
    const profileIds: string[] = [];
    for (
      let p: typeof leaf | undefined = leaf;
      p && profileIds.length < MAX_PROFILE_DEPTH && !profileIds.includes(p.id);
      p = p.parentId === null ? undefined : byId.get(p.parentId)
    ) {
      profileIds.push(p.id);
    }
    chains.set(language, { profileIds, unknownRules: leaf.unknownRules });
  }

  const settings = new Map<string, Map<string, RuleSetting>>();
  const inChains = new Set([...chains.values()].flatMap((c) => c.profileIds));
  for (const row of loaded?.settings ?? []) {
    if (!inChains.has(row.profileId)) continue;
    let forProfile = settings.get(row.profileId);
    if (!forProfile) settings.set(row.profileId, (forProfile = new Map()));
    forProfile.set(row.ruleId, {
      active: row.active,
      severityOverride: (row.severityOverride as Severity | null) ?? null,
    });
  }
  return { chains, settings };
}
