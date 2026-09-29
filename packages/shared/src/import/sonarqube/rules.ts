import { z } from 'zod';
import data from '../../../rules/sonarqube.json' with { type: 'json' };
import sonaranalyzerCsharpKeys from '../../../rules/sonaranalyzer-csharp-keys.json' with { type: 'json' };
import sonarjsKeys from '../../../rules/sonarjs-keys.json' with { type: 'json' };
import {
  BUILTIN_ENGINES,
  LANGUAGES,
  type BuiltinEngine,
  type Language,
} from '../../report/taxonomy';

/**
 * Spec §6.2, §6.4 ("Keys files"): the bare rule ids a repository row's `keysFile` names, loaded
 * with the same static-import style `sonarqube.json` itself uses so the Bun-compiled CLI binary
 * bundles them (no runtime fs read). Each file is a sorted JSON array of `S####` ids only.
 */
const KEYS_FILES: Readonly<Record<string, readonly string[]>> = {
  'sonaranalyzer-csharp-keys.json': sonaranalyzerCsharpKeys,
  'sonarjs-keys.json': sonarjsKeys,
};

export type ProfileLanguage = Exclude<Language, 'other'>;

export interface RuleTarget {
  key: string;
  relation: 'equivalent' | 'overlap';
  reviewed: boolean;
  source: 'repository' | 'table';
}

export interface SonarLanguage {
  language: ProfileLanguage;
  engines: readonly BuiltinEngine[];
}

const SONAR_RULE = /^[a-z_][a-z0-9_-]*:.+$/;
const REPOSITORY = /^[a-z_][a-z0-9_-]*$/;
const QUALOR_RULE = new RegExp(`^(?:${BUILTIN_ENGINES.join('|')}):.{1,512}$`, 's');
/** report-format.md §9: a rule id is at most 512 characters. */
const MAX_RULE_ID = 512;

const engine = z.enum(BUILTIN_ENGINES);
const reason = z
  .string()
  .min(1)
  .max(120)
  .regex(/^[^\n]*$/);
const profileLanguages = LANGUAGES.filter((l): l is ProfileLanguage => l !== 'other');

const tableSchema = z.strictObject({
  $comment: z.string().optional(),
  languages: z.record(
    z.string().regex(/^[a-z]{1,16}$/),
    z.strictObject({ language: z.enum(profileLanguages), engines: z.array(engine).min(1) }),
  ),
  aliases: z.record(z.string().regex(REPOSITORY), z.string().regex(REPOSITORY)),
  repositories: z.array(
    z.strictObject({
      repository: z.string().regex(REPOSITORY),
      engine,
      reason,
      keysFile: z
        .string()
        .regex(/^[a-z0-9-]+-keys\.json$/)
        .optional(),
    }),
  ),
  rules: z.array(
    z.strictObject({
      sonar: z.array(z.string().regex(SONAR_RULE)).min(1),
      qualor: z.array(z.string().regex(QUALOR_RULE)).min(1),
      relation: z.enum(['equivalent', 'overlap']),
      reviewed: z.boolean(),
      reason,
    }),
  ),
});

/** The engine of a Qualor rule key (`eslint` of `eslint:eqeqeq`); `''` when it has no colon. */
export function engineOf(ruleKey: string): string {
  const colon = ruleKey.indexOf(':');
  return colon < 0 ? '' : ruleKey.slice(0, colon);
}

export class SonarMapping {
  readonly #languages: ReadonlyMap<string, SonarLanguage>;
  readonly #aliases: ReadonlyMap<string, string>;
  /** A repository's engine and, for a row with `keysFile`, the set of rule ids it actually covers. */
  readonly #repositories: ReadonlyMap<
    string,
    { engine: BuiltinEngine; keys: ReadonlySet<string> | null }
  >;
  readonly #rules: ReadonlyMap<string, readonly RuleTarget[]>;
  /** Ruling S14: each Qualor target of the table's components → its component's key. */
  readonly #componentOf: ReadonlyMap<string, string>;
  /** Ruling S14: each table component's key → its Qualor targets, sorted. */
  readonly #members: ReadonlyMap<string, readonly string[]>;
  /** Qualor target → the table's SonarQube keys that map to it, in every spelling. */
  readonly #sonarByTarget: ReadonlyMap<string, readonly string[]>;

  constructor(table: z.infer<typeof tableSchema>) {
    this.#languages = new Map(Object.entries(table.languages));
    this.#aliases = new Map(Object.entries(table.aliases));
    this.#repositories = new Map(
      table.repositories.map((r) => {
        let keys: ReadonlySet<string> | null = null;
        if (r.keysFile !== undefined) {
          const list = KEYS_FILES[r.keysFile];
          if (list === undefined) throw new Error(`sonarqube.json: unknown keysFile ${r.keysFile}`);
          keys = new Set(list);
        }
        return [r.repository, { engine: r.engine, keys }] as const;
      }),
    );
    const rules = new Map<string, RuleTarget[]>();
    for (const entry of table.rules) {
      for (const key of entry.sonar) {
        if (rules.has(key)) throw new Error(`sonarqube.json names ${key} twice`);
        rules.set(
          key,
          entry.qualor.map((q) => ({
            key: q,
            relation: entry.relation,
            reviewed: entry.reviewed,
            source: 'table' as const,
          })),
        );
      }
    }
    this.#rules = rules;

    // Ruling S14: union-find over the Qualor targets; every target of one SonarQube key (in any
    // spelling, the repository target included) is joined. A target the table never names is a
    // component of its own, keyed by itself, so a repository-mapped rule needs no enumeration.
    const parent = new Map<string, string>();
    const find = (x: string): string => {
      let root = x;
      for (let p = parent.get(root); p !== undefined && p !== root; p = parent.get(root)) root = p;
      for (let y = x; y !== root;) {
        const next = parent.get(y) ?? root;
        parent.set(y, root);
        y = next;
      }
      return root;
    };
    const sonarByTarget = new Map<string, string[]>();
    for (const canonical of rules.keys()) {
      for (const spelling of this.#spellings(canonical)) {
        const keys = this.targets(spelling).map((t) => t.key);
        for (const k of keys) {
          if (!parent.has(k)) parent.set(k, k);
          sonarByTarget.set(k, [...(sonarByTarget.get(k) ?? []), spelling]);
        }
        for (const k of keys.slice(1)) {
          const a = find(keys[0] ?? k);
          const b = find(k);
          if (a !== b) parent.set(a < b ? b : a, a < b ? a : b);
        }
      }
    }
    const members = new Map<string, string[]>();
    for (const t of parent.keys()) members.set(find(t), [...(members.get(find(t)) ?? []), t]);
    const componentOf = new Map<string, string>();
    const keyed = new Map<string, readonly string[]>();
    for (const list of members.values()) {
      list.sort();
      const key = list[0] ?? '';
      keyed.set(key, list);
      for (const t of list) componentOf.set(t, key);
    }
    this.#componentOf = componentOf;
    this.#members = keyed;
    this.#sonarByTarget = new Map([...sonarByTarget].map(([t, l]) => [t, [...new Set(l)]]));
  }

  /** `canonical` (`java:S1`) and its spellings through every alias (`squid:S1`). */
  #spellings(canonical: string): string[] {
    const colon = canonical.indexOf(':');
    const repository = canonical.slice(0, colon);
    const rest = canonical.slice(colon);
    const aliases = [...this.#aliases].filter(([, to]) => to === repository).map(([a]) => a);
    return [canonical, ...aliases.map((a) => `${a}${rest}`)];
  }

  language(sonarLanguage: string): SonarLanguage | null {
    return this.#languages.get(sonarLanguage) ?? null;
  }

  /** Spec §6.2: the union of the repository mapping and the curated table; [] when unmapped. */
  targets(sonarKey: string): RuleTarget[] {
    const colon = sonarKey.indexOf(':');
    if (colon <= 0) return [];
    const repository = sonarKey.slice(0, colon);
    const ruleId = sonarKey.slice(colon + 1);
    const canonical = `${this.#aliases.get(repository) ?? repository}:${ruleId}`;
    const out: RuleTarget[] = [...(this.#rules.get(canonical) ?? [])];
    const repo = this.#repositories.get(repository);
    if (
      repo !== undefined &&
      ruleId.length > 0 &&
      ruleId.length <= MAX_RULE_ID &&
      (repo.keys === null || repo.keys.has(ruleId))
    ) {
      const key = `${repo.engine}:${ruleId}`;
      if (!out.some((t) => t.key === key)) {
        out.push({ key, relation: 'equivalent', reviewed: true, source: 'repository' });
      }
    }
    return out;
  }

  /**
   * Spec §10.1 (ruling S7): every SonarQube rule key whose targets (§6.2, every relation and review
   * state) overlap the targets of `sonarKeys`, sorted, `sonarKeys` themselves included when they
   * have targets. An open issue of any of them competes for the same Qualor issues as a resolved
   * issue of `sonarKeys` (`typescript:S1440` and `external_eslint_repo:eqeqeq` both target
   * `eslint:eqeqeq`). Table keys come with their aliased spellings (`squid:` for `java:`), and a
   * repository-mapped target `<engine>:<id>` with `<repository>:<id>` for every repository of
   * that engine. A key without targets adds nothing.
   */
  competingRules(sonarKeys: Iterable<string>): string[] {
    const wanted = new Set<string>();
    for (const k of sonarKeys) for (const t of this.targets(k)) wanted.add(t.key);
    const out = new Set<string>();
    for (const [sonar, targets] of this.#rules) {
      if (targets.some((t) => wanted.has(t.key)))
        for (const s of this.#spellings(sonar)) out.add(s);
    }
    for (const t of wanted) {
      const e = engineOf(t);
      const id = t.slice(e.length + 1);
      if (e === '' || id.length === 0) continue;
      for (const [repository, repo] of this.#repositories) {
        if (repo.engine === e) out.add(`${repository}:${id}`);
      }
    }
    // Every key listed maps to one of the wanted targets (a repository key also through the table).
    return [...out].filter((k) => this.targets(k).some((t) => wanted.has(t.key))).sort();
  }

  /**
   * Ruling S14: the key of the mapping component of `sonarKey`, `null` when it has no target.
   * Mapping components are the connected components of the bipartite graph SonarQube rule ↔
   * Qualor target (§6.2, every relation and review state), static, computed from the table. Two
   * SonarQube rules in different components can never compete for one Qualor issue, however
   * their issues are matched; two in one component can, through any chain of shared targets. A
   * component the table never names (a repository-mapped `<engine>:<id>`, shared by every
   * repository of that engine) is keyed by that target, so it is found without enumeration.
   */
  component(sonarKey: string): string | null {
    const first = this.targets(sonarKey)[0];
    if (first === undefined) return null;
    return this.#componentOf.get(first.key) ?? first.key;
  }

  /** Ruling S14: the component keys of `sonarKeys`, deduplicated and sorted (none for no target). */
  componentsOf(sonarKeys: Iterable<string>): string[] {
    const out = new Set<string>();
    for (const k of sonarKeys) {
      const c = this.component(k);
      if (c !== null) out.add(c);
    }
    return [...out].sort();
  }

  /**
   * Ruling S14: every SonarQube rule key of the component `key` (from `component`), sorted: the
   * table's keys in every alias spelling, and `<repository>:<id>` for each repository of the
   * engine of each target `<engine>:<id>`. Every key listed has `component(k) === key`.
   */
  componentRules(key: string): string[] {
    const out = new Set<string>();
    for (const t of this.#members.get(key) ?? [key]) {
      for (const s of this.#sonarByTarget.get(t) ?? []) out.add(s);
      const e = engineOf(t);
      const id = t.slice(e.length + 1);
      if (e === '' || id.length === 0 || id.length > MAX_RULE_ID) continue;
      for (const [repository, repo] of this.#repositories) {
        if (repo.engine === e) out.add(`${repository}:${id}`);
      }
    }
    return [...out].filter((k) => this.component(k) === key).sort();
  }
}

export function loadSonarMapping(raw: unknown): SonarMapping {
  return new SonarMapping(tableSchema.parse(raw));
}

export const SONAR_MAPPING: SonarMapping = loadSonarMapping(data);
