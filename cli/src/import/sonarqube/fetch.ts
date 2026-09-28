import {
  branchesSchema,
  componentShowSchema,
  componentsPageSchema,
  gateByProjectSchema,
  gateListSchema,
  gateShowSchema,
  hotspotsPageSchema,
  issuesPageSchema,
  profilesSchema,
  rulesPageSchema,
  SONAR_MAPPING,
  type SonarActiveRule,
  type SonarGateData,
  type SonarIssue,
  type SonarMapping,
  type SonarProfileData,
  type SonarProjectData,
  type SonarRulesPage,
  versionAtLeast,
} from '@qualor/shared';
import { CliError, EXIT } from '../../errors';
import { UnreachableError } from '../../server/http';
import {
  PAGE_SIZE,
  RESULT_WINDOW,
  type SonarClient,
  type SonarConnection,
  SonarNotFound,
} from './client';

/** Spec §5.3: rules a profile leaves off, read per profile. */
const MAX_INACTIVE = 20_000;
/** Spec §4.4: at most this many rule keys in one open-issue query. */
const MAX_RULES_PER_QUERY = 100;

/** Test hooks: a smaller window and page size, to reach the window with a few items. */
export interface ReadBounds {
  window?: number;
  pageSize?: number;
}

/**
 * The active rules of one rules page, each with its activation in `profileKey`, by key. A rule
 * whose activations do not name `profileKey` is unreadable (another profile's severity or
 * parameters would be imported as this one's): its `rule` is `null`, and it stays in the page's
 * count so that paging and the window see every rule.
 */
function activeRules(
  page: SonarRulesPage,
  profileKey: string,
): { key: string; rule: SonarActiveRule | null }[] {
  return page.rules.map((r) => {
    const a = (page.actives?.[r.key] ?? []).find((x) => x.qProfile === profileKey);
    if (a === undefined) return { key: r.key, rule: null };
    const defaults = new Map((r.params ?? []).map((p) => [p.key, p.defaultValue ?? '']));
    return {
      key: r.key,
      rule: {
        key: r.key,
        name: r.name ?? r.key,
        language: r.lang ?? '',
        defaultSeverity: r.severity ?? null,
        severity: a.severity ?? null,
        defaultImpacts: r.impacts ?? [],
        impacts: a.impacts ?? [],
        paramsCustomised: (a.params ?? []).some((p) => defaults.get(p.key) !== p.value),
      },
    };
  });
}

/**
 * Spec §7.1, §4.4: every profile; the active and left-off rules only of the profiles of a
 * supported language. A profile whose active rules were not all read is `complete: false`.
 */
export async function fetchProfiles(
  c: SonarClient,
  mapping: SonarMapping = SONAR_MAPPING,
  bounds: ReadBounds = {},
): Promise<SonarProfileData[]> {
  const { profiles } = await c.get(
    'api/qualityprofiles/search',
    {},
    profilesSchema,
    'profile list',
  );
  const out: SonarProfileData[] = [];
  for (const p of profiles) {
    const base = {
      key: p.key,
      name: p.name,
      language: p.language,
      isDefault: p.isDefault,
      isBuiltIn: p.isBuiltIn,
    };
    if (mapping.language(p.language) === null) {
      out.push({ ...base, active: [], inactive: [], complete: true });
      continue;
    }
    const active = await c.pages(
      'api/rules/search',
      { qprofile: p.key, activation: 'true', f: 'name,lang,severity,params,actives' },
      rulesPageSchema,
      (page) => activeRules(page, p.key),
      (r) => r.key,
      'rule page',
      RESULT_WINDOW,
      bounds,
    );
    const rules = active.items.flatMap((r) => (r.rule === null ? [] : [r.rule]));
    const unreadable = active.items.length - rules.length;
    if (!active.complete) {
      c.warn(
        'SONARQUBE_RULE_WINDOW',
        `a ${p.language} profile has ${Math.max(0, active.total - active.items.length)} active rules that were not read (or the rules changed while they were read); it is not imported`,
      );
    }
    if (unreadable > 0) {
      c.warn(
        'SONARQUBE_ACTIVATION_MISSING',
        `a ${p.language} profile has ${unreadable} active rules whose activation in it SonarQube did not send; it is not imported`,
      );
    }
    const inactive = await c.pages(
      'api/rules/search',
      { qprofile: p.key, activation: 'false', languages: p.language, f: 'lang' },
      rulesPageSchema,
      (page) => page.rules.map((r) => r.key),
      (k) => k,
      'rule page',
      MAX_INACTIVE,
      bounds,
    );
    if (!inactive.complete) {
      c.warn(
        'SONARQUBE_INACTIVE_RULES_TRUNCATED',
        `a ${p.language} profile leaves off ${Math.max(0, inactive.total - inactive.items.length)} rules that were not read and are not turned off (or the rules changed while they were read)`,
      );
    }
    out.push({
      ...base,
      active: rules,
      inactive: inactive.items,
      complete: active.complete && unreadable === 0,
    });
  }
  return out;
}

export async function fetchGates(c: SonarClient): Promise<SonarGateData[]> {
  const list = await c.get('api/qualitygates/list', {}, gateListSchema, 'gate list');
  const out: SonarGateData[] = [];
  for (const g of list.qualitygates) {
    const shown = await c.get('api/qualitygates/show', { name: g.name }, gateShowSchema, 'gate');
    const byId =
      list.default !== undefined && g.id !== undefined && String(list.default) === String(g.id);
    out.push({
      name: g.name,
      isDefault: g.isDefault ?? byId,
      isBuiltIn: g.isBuiltIn,
      conditions: shown.conditions.map(({ metric, op, error }) => ({ metric, op, error })),
    });
  }
  return out;
}

/** Every project the token can browse, or the named ones (a 404 is reported missing). */
export async function listProjects(
  c: SonarClient,
  keys: readonly string[],
  bounds: ReadBounds = {},
): Promise<{ projects: { key: string; name: string }[]; missing: string[] }> {
  if (keys.length === 0) {
    const r = await c.pages(
      'api/components/search',
      { qualifiers: 'TRK' },
      componentsPageSchema,
      (p) => p.components,
      (p) => p.key,
      'project page',
      RESULT_WINDOW,
      bounds,
    );
    if (!r.complete) {
      c.warn(
        'SONARQUBE_PROJECT_WINDOW',
        `${Math.max(0, r.total - r.items.length)} projects were not read (or the list changed while it was read); name them with --project`,
      );
    }
    return { projects: r.items.map((p) => ({ key: p.key, name: p.name ?? p.key })), missing: [] };
  }
  const projects: { key: string; name: string }[] = [];
  const missing: string[] = [];
  for (const key of keys) {
    try {
      const shown = await c.get(
        'api/components/show',
        { component: key },
        componentShowSchema,
        'project',
      );
      projects.push({ key: shown.component.key, name: shown.component.name ?? key });
    } catch (err) {
      if (!(err instanceof SonarNotFound)) throw err;
      missing.push(key);
    }
  }
  return { projects, missing };
}

export async function fetchProjectSettings(
  c: SonarClient,
  project: { key: string; name: string },
): Promise<SonarProjectData> {
  const profiles = await c.get(
    'api/qualityprofiles/search',
    { project: project.key },
    profilesSchema,
    'project profile list',
  );
  const gate = await c.get(
    'api/qualitygates/get_by_project',
    { project: project.key },
    gateByProjectSchema,
    'project gate',
  );
  const branches = await c.get(
    'api/project_branches/list',
    { project: project.key },
    branchesSchema,
    'branch list',
  );
  return {
    key: project.key,
    name: project.name,
    mainBranch: branches.branches.find((b) => b.isMain)?.name ?? 'main',
    profiles: profiles.profiles.map((p) => ({
      language: p.language,
      profileKey: p.key,
      isDefault: p.isDefault,
    })),
    gate: { name: gate.qualityGate.name, isDefault: gate.qualityGate.default },
  };
}

/** Whether the server takes `issueStatuses` (SonarQube Server 10.4+); else the older parameters. */
const issueStatusesSupported = (conn: SonarConnection) =>
  conn.kind === 'server' && conn.version !== null && versionAtLeast(conn.version, 10, 4);

interface IssueRead {
  /** Only issues of the query's own rules (all rules when it names none), each once. */
  issues: SonarIssue[];
  /** The query's total as last seen: a whole read's final total, else the slices' finals. */
  total: number;
  /** The rules (of `ownRules`, or of the facet without them) whose issues were all read. */
  completeRules: Set<string>;
  /** Ruling S10: every issue of the query was read (each read, whole or slice, complete). */
  complete: boolean;
  /** The rules the `rules` facet listed (of `ownRules`, when given). */
  listedRules: string[];
  /**
   * Ruling S11: no rule the facet did not list has an issue left unread (the read was complete,
   * or the facet covered the whole query and the counts could be trusted). Only meaningful
   * without `ownRules`; with them, the rules not listed are judged in `completeRules`.
   */
  othersComplete: boolean;
  /** Ruling S14 (c): the first probe's total and `rules` facet counts, unfiltered. */
  probe: IssueProbe;
}

/** Ruling S14 (c): what one probe (`ps=1`, `facets=rules`) of a query saw. */
export interface IssueProbe {
  total: number;
  counts: Record<string, number>;
}

/** One probe of `query`: its total and its `rules` facet, every value listed. */
async function probeIssues(c: SonarClient, query: Record<string, string>) {
  const probe = await c.get(
    'api/issues/search',
    { ...query, ps: '1', p: '1', facets: 'rules' },
    issuesPageSchema,
    'issue page',
  );
  return {
    total: probe.paging.total,
    values: probe.facets?.find((f) => f.property === 'rules')?.values ?? [],
  };
}

/**
 * Spec §5.2: one issue query, read whole when its total fits the window, else rule by rule
 * through the `rules` facet (each rule up to the window); at most `maxIssues`, never a page past
 * the window.
 *
 * SonarQube's facets are sticky: the `rules` facet ignores the query's own `rules=` filter, so it
 * may list rules the query did not ask for, with counts that are not the query's. Only the facet
 * values of `ownRules` (when given) are used, to slice and to judge completeness, and each rule is
 * judged on its own.
 *
 * Ruling S10: a read (the whole query, or one rule's slice) is complete only when its issues,
 * each counted once, reach its final total and that total did not change between its pages (a
 * difference between the probe and the pages is fine). A rule is complete when its slice was
 * complete, or when the whole query was. When a capped whole read was not complete, a rule is
 * still complete if the issues read of it reach its facet count, but only when that read was
 * stable and its total is the probe's (else the facet's counts are stale); a rule of `ownRules`
 * the facet does not list is complete then only if the listed ones add up to the probe's total
 * (so it has none) and none of it was read.
 */
async function readIssues(
  c: SonarClient,
  query: Record<string, string>,
  ownRules: readonly string[] | null,
  maxIssues: number,
  bounds: ReadBounds,
): Promise<IssueRead> {
  const window = bounds.window ?? RESULT_WINDOW;
  const pageSize = bounds.pageSize ?? PAGE_SIZE;
  const probe = await probeIssues(c, query);
  const own = ownRules === null ? null : new Set(ownRules);
  const values = probe.values.filter((v) => own === null || own.has(v.val));
  const listed = new Set(values.map((v) => v.val));
  const ownSum = values.reduce((sum, v) => sum + v.count, 0);
  const probeTotal = probe.total;
  const seenProbe: IssueProbe = {
    total: probeTotal,
    counts: Object.fromEntries(probe.values.map((v) => [v.val, v.count])),
  };
  const seen = new Set<string>();
  const issues: SonarIssue[] = [];
  const add = (items: readonly SonarIssue[], rule: string | null) => {
    for (const i of items) {
      if (seen.has(i.key)) continue;
      if (rule !== null ? i.rule !== rule : own !== null && !own.has(i.rule)) continue;
      seen.add(i.key);
      issues.push(i);
    }
  };
  const read = (q: Record<string, string>, max: number) =>
    c.pages(
      'api/issues/search',
      q,
      issuesPageSchema,
      (p) => p.issues,
      (i) => i.key,
      'issue page',
      max,
      { window, pageSize },
    );
  const completeRules = new Set<string>();
  /** Rules of the query the facet does not list: none of them has an issue, or unknown. */
  const unlisted = (own === null ? [] : [...own]).filter((r) => !listed.has(r));
  const unlistedEmpty = ownSum >= probeTotal;
  const listedRules = [...listed];
  if (probeTotal === 0) {
    for (const r of [...listed, ...unlisted]) completeRules.add(r);
    return {
      issues,
      total: 0,
      completeRules,
      complete: true,
      listedRules,
      othersComplete: true,
      probe: seenProbe,
    };
  }
  if (probeTotal <= window) {
    if (maxIssues <= 0) {
      return {
        issues,
        total: probeTotal,
        completeRules,
        complete: false,
        listedRules,
        othersComplete: unlistedEmpty,
        probe: seenProbe,
      };
    }
    const r = await read(query, maxIssues);
    add(r.items, null);
    // The probe's facet counts hold for this read only when nothing changed in between.
    const counted = r.stable && r.total === probeTotal;
    const byRule = new Map<string, number>();
    for (const i of issues) byRule.set(i.rule, (byRule.get(i.rule) ?? 0) + 1);
    for (const v of values) {
      if (r.complete || (counted && (byRule.get(v.val) ?? 0) >= v.count)) completeRules.add(v.val);
    }
    for (const rule of unlisted) {
      if (r.complete || (counted && unlistedEmpty && !byRule.has(rule))) completeRules.add(rule);
    }
    return {
      issues,
      total: r.total,
      completeRules,
      complete: r.complete,
      listedRules,
      othersComplete: r.complete || (counted && unlistedEmpty),
      probe: seenProbe,
    };
  }
  let total = unlistedEmpty ? 0 : probeTotal - ownSum;
  // Past the window, only the rule slices are read: complete when the facet covers the whole
  // query and every slice was complete.
  let complete = unlistedEmpty;
  for (const v of values) {
    const left = maxIssues - issues.length;
    if (left <= 0) {
      total += v.count;
      complete = false;
      continue;
    }
    const r = await read({ ...query, rules: v.val }, left);
    add(r.items, v.val);
    total += r.total;
    if (r.complete) completeRules.add(v.val);
    else complete = false;
  }
  if (unlistedEmpty) for (const rule of unlisted) completeRules.add(rule);
  return {
    issues,
    total,
    completeRules,
    complete,
    listedRules,
    othersComplete: unlistedEmpty,
    probe: seenProbe,
  };
}

/**
 * Ruling S11: the SonarQube rules whose resolved issues were not all read. Such an issue is a
 * competitor the matching never sees, just as an open one not read. `rules`: those rules, by
 * name. `all_but`: the facet did not name every rule of the query, or its counts could not be
 * trusted (a capped read without slices), so every rule is unread but the `complete` ones.
 */
export type UnreadResolved =
  { kind: 'rules'; rules: string[] } | { kind: 'all_but'; complete: string[] };

/** Spec §10.1: the query of the resolved read, and of its re-probe (ruling S14 (c)). */
function resolvedQuery(conn: SonarConnection, projectKey: string): Record<string, string> {
  return {
    projects: projectKey,
    ...(issueStatusesSupported(conn)
      ? { issueStatuses: 'ACCEPTED,FALSE_POSITIVE' }
      : { resolutions: 'FALSE-POSITIVE,WONTFIX' }),
    additionalFields: 'comments',
    s: 'FILE_LINE',
    asc: 'true',
  };
}

/**
 * Spec §10.1: the main branch's issues resolved by a person (`issueStatuses` from 10.4,
 * `resolutions` before and on Cloud), at most `maxIssues`; what stays unread is counted and
 * warned about, never dropped silently; and (ruling S11) the rules whose resolved issues were
 * not all read (`unread`): the resolved items of the mapping component of one of them are sent
 * `competitorsUnknown` (ruling S14, `buildWithCompetitors`). The reviewed hotspots are counted
 * apart, by `countReviewedHotspots` (finding L1).
 */
export async function fetchResolvedIssues(
  c: SonarClient,
  conn: SonarConnection,
  projectKey: string,
  maxIssues: number,
  bounds: ReadBounds = {},
): Promise<{
  issues: SonarIssue[];
  total: number;
  notRead: number;
  unread: UnreadResolved;
  /** Ruling S14 (c): the read's first probe, to compare with `reprobeResolvedIssues`. */
  probe: IssueProbe;
}> {
  const read = await readIssues(c, resolvedQuery(conn, projectKey), null, maxIssues, bounds);
  const { issues, total, complete } = read;
  const unread: UnreadResolved = read.othersComplete
    ? { kind: 'rules', rules: read.listedRules.filter((r) => !read.completeRules.has(r)).sort() }
    : { kind: 'all_but', complete: [...read.completeRules].sort() };
  // Ruling S10: a read that is not complete may have skipped issues even when the count read
  // reaches the total (items moved between pages); at least one is then counted as not read.
  const notRead = complete ? 0 : Math.max(1, total - issues.length);
  if (notRead > 0) {
    c.warn(
      'SONARQUBE_ISSUE_WINDOW',
      issues.length >= total
        ? `some resolved issues of a project may not have been read (they changed while they were read)`
        : `${notRead} resolved issues of a project were not read (SonarQube's 10 000-result window, or --max-issues)`,
    );
  }
  return {
    issues,
    total,
    notRead,
    unread,
    probe: read.probe,
  };
}

/**
 * Spec §4.4: how many reviewed security hotspots a project has (reported, not imported).
 * SonarQube Server names the project `project`; SonarQube Cloud `projectKey` (finding L1: Cloud
 * answers `project` with 400). The count is informative only, so a failure of it never costs the
 * project's issues: it is `null` (unknown) with a `HOTSPOTS_NOT_COUNTED` warning. An unreachable
 * SonarQube still ends the run (spec §13), as it would at the next read. Read apart from
 * `fetchResolvedIssues`, so that nothing of the hotspot count can cost the issues already read.
 */
export async function countReviewedHotspots(
  c: SonarClient,
  conn: SonarConnection,
  projectKey: string,
): Promise<number | null> {
  try {
    const page = await c.get(
      'api/hotspots/search',
      {
        [conn.kind === 'cloud' ? 'projectKey' : 'project']: projectKey,
        status: 'REVIEWED',
        ps: '1',
      },
      hotspotsPageSchema,
      'hotspot page',
    );
    return page.paging.total;
  } catch (err) {
    if (!(err instanceof CliError) || err instanceof UnreachableError) throw err;
    c.warn(
      'HOTSPOTS_NOT_COUNTED',
      `the reviewed security hotspots of a project were not counted (${err.message.slice(0, 200)}); its issues were read`,
    );
    return null;
  }
}

/**
 * Ruling S14 (c): after the open read, probes the resolved query again (`ps=1`, `facets=rules`,
 * the same filters) and compares it with the resolved read's first probe. `rules`: the rules
 * whose count changed (listed in one probe only counts as changed): an issue of theirs was
 * resolved or reopened while the import read, so a competitor may have been seen in neither
 * read. `total`: the total changed, so any rule may have changed, even one no facet lists.
 * Changes that leave every count as it was (one issue resolved and another reopened of the same
 * rule) are not detected (§17). `listed` (fix 12c): when either probe's facet did not cover its
 * total (SonarQube caps a facet's values), a rule neither probe listed may have changed unseen;
 * `listed` then holds every rule either probe listed, and the caller treats any other rule as
 * changed. `null` when both facets covered their totals (an unlisted rule has no issue).
 */
export async function reprobeResolvedIssues(
  c: SonarClient,
  conn: SonarConnection,
  projectKey: string,
  before: IssueProbe,
): Promise<{ total: boolean; rules: string[]; listed: string[] | null }> {
  const now = await probeIssues(c, resolvedQuery(conn, projectKey));
  const after = new Map(now.values.map((v) => [v.val, v.count]));
  const changed = new Set<string>();
  for (const [rule, n] of Object.entries(before.counts)) {
    if (after.get(rule) !== n) changed.add(rule);
  }
  for (const [rule, n] of after) if (before.counts[rule] !== n) changed.add(rule);
  const sum = (counts: Iterable<number>) => [...counts].reduce((a, n) => a + n, 0);
  const capped =
    sum(Object.values(before.counts)) < before.total || sum(after.values()) < now.total;
  return {
    total: now.total !== before.total,
    rules: [...changed].sort(),
    listed: capped ? [...new Set([...Object.keys(before.counts), ...after.keys()])].sort() : null,
  };
}

/**
 * Spec §4.4, §10.1 (final review I-2): the status filters of the open read, one query each. Every
 * issue still in the code but not resolved by a person as false positive or accepted competes:
 * - SonarQube Server 10.4+: `issueStatuses=OPEN,CONFIRMED`, plus `IN_SANDBOX` from 2025.5 (the
 *   sandbox's issues; whether `resolved=false` covers them is not documented, and a server before
 *   2025.5 refuses the value). A person can no longer resolve an issue as fixed there.
 * - SonarQube Server before 10.4, and SonarQube Cloud: `resolved=false`, and
 *   `statuses=RESOLVED&resolutions=FIXED`: an issue a person resolved as fixed stays in the code
 *   until the next analysis closes or reopens it (one SonarQube closed itself is `CLOSED`).
 */
export function openIssueFilters(conn: SonarConnection): Record<string, string>[] {
  if (issueStatusesSupported(conn)) {
    const sandbox = conn.version !== null && versionAtLeast(conn.version, 2025, 5);
    return [{ issueStatuses: sandbox ? 'OPEN,CONFIRMED,IN_SANDBOX' : 'OPEN,CONFIRMED' }];
  }
  return [{ resolved: 'false' }, { statuses: 'RESOLVED', resolutions: 'FIXED' }];
}

/**
 * Spec §10.1 (rulings S3, S7 and S14): the main branch's **open** issues of `ruleKeys`, read as
 * competitors for the matching. `ruleKeys` must be every SonarQube rule of the mapping
 * components of the project's resolved issues' rules (`SonarMapping.componentRules`), not only
 * the resolved issues' own rules: an open issue of another rule of the component competes for
 * the same Qualor issues, directly or through a chain of shared targets. Read with the filters of
 * `openIssueFilters` (each one query), at most 100 rules per query, the same pages, rule
 * partitioning and window as the resolved read, at most `maxIssues` in all; an issue two queries
 * list is kept once.
 * `unreadRules` are the rules whose open issues were not all read (the window, a capped facet or
 * the cap), each rule judged on its own (see `readIssues`): a resolved issue whose rule is in the
 * component of one of them cannot be trusted and is sent `competitorsUnknown`.
 */
export async function fetchOpenIssues(
  c: SonarClient,
  conn: SonarConnection,
  projectKey: string,
  ruleKeys: readonly string[],
  maxIssues: number,
  bounds: ReadBounds = {},
): Promise<{ issues: SonarIssue[]; total: number; unreadRules: string[] }> {
  const rules = [...new Set(ruleKeys)].sort();
  const issues: SonarIssue[] = [];
  const seen = new Set<string>();
  const unread = new Set<string>();
  let total = 0;
  for (let k = 0; k < rules.length; k += MAX_RULES_PER_QUERY) {
    const batch = rules.slice(k, k + MAX_RULES_PER_QUERY);
    for (const filter of openIssueFilters(conn)) {
      const left = maxIssues - issues.length;
      if (left <= 0) {
        // The cap is reached: nothing tells whether these rules have open issues.
        for (const rule of batch) unread.add(rule);
        continue;
      }
      const query = {
        projects: projectKey,
        ...filter,
        s: 'FILE_LINE',
        asc: 'true',
        rules: batch.join(','),
      };
      let r: IssueRead;
      try {
        r = await readIssues(c, query, batch, left, bounds);
      } catch (err) {
        // Only the extra query of issues resolved as fixed (`statuses=RESOLVED&resolutions=FIXED`,
        // not verified against SonarQube Cloud, spec §17) fails closed: a refusal or an
        // unexpected answer makes the batch's rules count as not read, so their resolved items
        // are `competitors_unknown`, instead of costing the project's issues. An unreachable
        // SonarQube, a refused token and any other query still end as before.
        const refused =
          err instanceof CliError &&
          !(err instanceof UnreachableError) &&
          err.exitCode !== EXIT.AUTH;
        if (filter['statuses'] === undefined || !refused) throw err;
        c.warn(
          'SONARQUBE_ISSUE_WINDOW',
          `SonarQube did not answer the query of issues resolved as fixed (${err.message.slice(0, 200)}); the resolved issues they may compete with are not applied`,
        );
        for (const rule of batch) unread.add(rule);
        continue;
      }
      total += r.total;
      for (const i of r.issues) {
        if (seen.has(i.key)) continue;
        seen.add(i.key);
        issues.push(i);
      }
      for (const rule of batch) if (!r.completeRules.has(rule)) unread.add(rule);
    }
  }
  if (unread.size > 0) {
    c.warn(
      'SONARQUBE_ISSUE_WINDOW',
      `the open issues of ${unread.size} rules of a project were not all read (SonarQube's 10 000-result window, or --max-issues); their resolved issues are not applied`,
    );
  }
  return { issues, total, unreadRules: [...unread] };
}
