import { z } from 'zod';
import data from '../../rules/equivalences.json' with { type: 'json' };

const RULE_KEY = /^[a-z0-9][a-z0-9-]{0,39}:.+$/;

const equivalencesSchema = z.object({
  $comment: z.string().optional(),
  engineCwe: z.record(
    z.string(),
    z.strictObject({ cwe: z.array(z.number().int().positive()).min(1), reason: z.string().min(1) }),
  ),
  pairs: z.array(
    z.strictObject({
      rules: z.tuple([z.string().regex(RULE_KEY), z.string().regex(RULE_KEY)]),
      reason: z.string().min(1),
    }),
  ),
});

export type Equivalences = z.infer<typeof equivalencesSchema>;

/**
 * `packages/shared/rules/equivalences.json`, validated once at load.
 *
 * Pending verification (ruling U3): the pair `eslint:no-eval` ↔
 * `semgrep:javascript.browser.security.eval-detected.eval-detected` still needs a human to
 * confirm the Semgrep rule id; its `reason` in the JSON says so too.
 */
export const EQUIVALENCES: Equivalences = equivalencesSchema.parse(data);

/**
 * data-model.md §5.3: which engine's issue is primary when two engines report the same problem.
 * Higher wins; external engines (any id not listed) rank lowest. `gitleaks` > `semgrep` >
 * `spotbugs` > `roslyn` > `pmd` > `eslint` > `sonarjs` > `ruff` > `stylelint` > `htmlhint` >
 * `detekt` > external (plan 8D ruling D5, plan 8E ruling E4).
 */
export const ENGINE_PRIORITY: readonly string[] = [
  'gitleaks',
  'semgrep',
  'spotbugs',
  'roslyn',
  'pmd',
  'eslint',
  'sonarjs',
  'ruff',
  'stylelint',
  'htmlhint',
  'detekt',
];

export function enginePriority(engineId: string): number {
  const index = ENGINE_PRIORITY.indexOf(engineId);
  return index === -1 ? 0 : ENGINE_PRIORITY.length - index;
}

export interface EquivalenceRule {
  key: string;
  engineId: string;
  cwe: readonly number[];
}

function pairKey(a: string, b: string): string {
  return a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`;
}

const PAIRS = new Set(EQUIVALENCES.pairs.map((p) => pairKey(p.rules[0], p.rules[1])));

const PARTNERS = new Map<string, string[]>();
for (const { rules } of EQUIVALENCES.pairs) {
  for (const [key, partner] of [rules, [rules[1], rules[0]]] as const) {
    const list = PARTNERS.get(key);
    if (list) list.push(partner);
    else PARTNERS.set(key, [partner]);
  }
}

/**
 * External engine id → built-in engine: a rule of the external engine is equivalent to the
 * built-in rule with the identical rule id (`ext-ruff:F401` ↔ `ruff:F401`), so a project that
 * still imports its own SARIF of a tool Qualor now runs does not see every finding twice. The
 * built-in engine is primary: `enginePriority` ranks every external engine lowest.
 *
 * `ext-stylelint` and `ext-htmlhint` (plan 8D ruling D4): the same dedupe bug 8C's own final
 * review found for `ext-ruff` — a project importing its own stylelint/HTMLHint SARIF would
 * otherwise see every finding twice once Qualor runs the tool itself.
 */
export const EXTERNAL_BUILTIN_ALIASES: Readonly<Record<string, string>> = Object.freeze({
  'ext-ruff': 'ruff',
  'ext-stylelint': 'stylelint',
  'ext-htmlhint': 'htmlhint',
  // Plan 8E ruling E5; detekt's own SARIF ids are `detekt.<ruleset>.<Rule>` (RULE_ID_NORMALISERS).
  'ext-detekt': 'detekt',
});

/**
 * Per aliased external engine: how its own SARIF rule ids map to the built-in rule ids, when they
 * differ. detekt writes `detekt.<ruleset>.<Rule>` (`detekt.style.MagicNumber`), the built-in
 * engine's rules are `<Rule>`.
 */
const RULE_ID_NORMALISERS: Readonly<Record<string, (ruleId: string) => string>> = Object.freeze({
  'ext-detekt': (id) => /^detekt\.[^.]+\.([^.]+)$/.exec(id)?.[1] ?? id,
});

/**
 * The key with an aliased external engine's rule id normalised (`ext-detekt:detekt.style.X` →
 * `ext-detekt:X`); every other key is returned as it is. Dedupe indexes issues by this key too.
 */
export function normalizedRuleKey(key: string): string {
  const colon = key.indexOf(':');
  if (colon <= 0) return key;
  const engineId = key.slice(0, colon);
  const normalise = Object.hasOwn(RULE_ID_NORMALISERS, engineId)
    ? RULE_ID_NORMALISERS[engineId]
    : undefined;
  return normalise === undefined ? key : `${engineId}:${normalise(key.slice(colon + 1))}`;
}

const BUILTIN_TO_EXTERNAL = new Map(
  Object.entries(EXTERNAL_BUILTIN_ALIASES).map(([external, builtin]) => [builtin, external]),
);

/** The key of the same rule id under the aliased engine (either direction), or null. */
function aliasPartner(rawKey: string): string | null {
  const key = normalizedRuleKey(rawKey);
  const colon = key.indexOf(':');
  if (colon <= 0 || colon === key.length - 1) return null;
  const engineId = key.slice(0, colon);
  const other = Object.hasOwn(EXTERNAL_BUILTIN_ALIASES, engineId)
    ? EXTERNAL_BUILTIN_ALIASES[engineId]
    : BUILTIN_TO_EXTERNAL.get(engineId);
  return other === undefined ? null : other + key.slice(colon);
}

/**
 * The rule keys equivalent to `key` by name: its curated pairs in equivalences.json (any engine)
 * plus, for an aliased engine, the rule of the same id on the other side of the alias.
 */
export function equivalentPartners(key: string): readonly string[] {
  const curated = PARTNERS.get(key) ?? [];
  const alias = aliasPartner(key);
  return alias === null || curated.includes(alias) ? curated : [...curated, alias];
}

/** A rule's own CWE list plus its engine's curated default (`engineCwe`). */
export function effectiveCwe(rule: EquivalenceRule): number[] {
  const extra = Object.hasOwn(EQUIVALENCES.engineCwe, rule.engineId)
    ? (EQUIVALENCES.engineCwe[rule.engineId]?.cwe ?? [])
    : [];
  return [...new Set([...rule.cwe, ...extra])];
}

/**
 * data-model.md §5.3: rules of two different engines are equivalent when they share at
 * least one CWE, the pair is listed in equivalences.json, or one is a rule of an aliased external
 * engine and the other the built-in rule of the same id (`EXTERNAL_BUILTIN_ALIASES`). Rules of one
 * engine never are.
 */
export function rulesEquivalent(a: EquivalenceRule, b: EquivalenceRule): boolean {
  if (a.engineId === b.engineId) return false;
  if (PAIRS.has(pairKey(a.key, b.key)) || aliasPartner(a.key) === normalizedRuleKey(b.key))
    return true;
  const cwe = new Set(effectiveCwe(a));
  return effectiveCwe(b).some((c) => cwe.has(c));
}
