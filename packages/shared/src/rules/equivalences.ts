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
 * Higher wins; external engines (any id not listed) rank lowest.
 */
export const ENGINE_PRIORITY: readonly string[] = [
  'gitleaks',
  'semgrep',
  'spotbugs',
  'roslyn',
  'pmd',
  'eslint',
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

/** The rule keys that equivalences.json lists as a curated pair with `key` (any engine). */
export function equivalentPartners(key: string): readonly string[] {
  return PARTNERS.get(key) ?? [];
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
 * least one CWE or the pair is listed in equivalences.json. Rules of one engine never are.
 */
export function rulesEquivalent(a: EquivalenceRule, b: EquivalenceRule): boolean {
  if (a.engineId === b.engineId) return false;
  if (PAIRS.has(pairKey(a.key, b.key))) return true;
  const cwe = new Set(effectiveCwe(a));
  return effectiveCwe(b).some((c) => cwe.has(c));
}
