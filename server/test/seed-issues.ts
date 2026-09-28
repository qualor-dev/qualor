import { sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../src/db/client';

/** Rule `k` of the seed is `<SEED_ENGINES[k % 5]>:seed-rule-<k>`. */
export const SEED_ENGINES = ['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks'] as const;
export const SEED_RULES = 200;
/** Files `src/module<f % 50>/file<f>.ts`: 40 files in each of 50 directories. */
export const SEED_FILES = 2_000;

export function seedRuleKey(k: number): string {
  return `${SEED_ENGINES[k % SEED_ENGINES.length]}:seed-rule-${k}`;
}

/**
 * A deterministic pseudo-random integer in `[0, n)` for row `g`, independent for each `salt`:
 * `hashtextextended` is a seeded 64-bit hash, so attributes drawn with different salts do not
 * correlate the way `g mod a` and `g mod b` do when `a` and `b` share factors.
 */
function draw(salt: number, n: number): SQL {
  return sql.raw(`((hashtextextended(g::text, ${salt}) & 9223372036854775807) % ${n})::int`);
}

/**
 * Seeds `count` issues on one branch in two set-based statements, with the spread a real branch
 * has: 200 rules over five engines, 2 000 files in 50 directories (`src/module<d>/file<f>.ts`),
 * every severity and quality, 70 % open, 5 % each resolved / won't fix / false positive, 15 %
 * closed, 10 % in new code, 1 % hotspots, 2 % duplicates — each attribute drawn independently
 * (a seeded hash per attribute), so every combination of filters finds rows in proportion, and
 * the seed is the same on every run. Ids are UUIDv7-shaped (a millisecond timestamp, then the
 * sequence), so id order is creation order, as in production. Ends with `ANALYZE`, so the planner
 * sees the real table sizes.
 */
export async function seedIssues(
  db: Executor,
  target: { projectId: string; branchId: string; count: number },
): Promise<void> {
  await db.execute(sql`
    INSERT INTO rules (id, key, engine_id, engine_rule_id, name, default_severity, quality, kind,
                       origin)
    SELECT gen_random_uuid(), e.engine || ':seed-rule-' || k, e.engine, 'seed-rule-' || k,
           'Seed rule ' || k, 'medium', 'maintainability', 'issue', 'reported'
      FROM generate_series(0, ${SEED_RULES - 1}) AS k,
           LATERAL (SELECT (ARRAY['eslint','pmd','spotbugs','semgrep','gitleaks'])[k % 5 + 1]
                    AS engine) e
    ON CONFLICT (key) DO NOTHING`);
  await db.execute(sql`
    WITH rule_ids AS (
      SELECT array_agg(id ORDER BY substring(key FROM ':seed-rule-([0-9]+)$')::int) AS ids
        FROM rules WHERE key ~ ':seed-rule-[0-9]+$'),
    base AS (SELECT (extract(epoch FROM now()) * 1000)::bigint AS ms),
    seed AS (
      SELECT g,
             ${draw(1, SEED_RULES)} AS rule_k,
             ${draw(2, SEED_FILES)} AS file,
             ${draw(3, 500)} AS line,
             ${draw(4, 5)} AS severity,
             ${draw(5, 3)} AS quality,
             ${draw(6, 20)} AS status,
             ${draw(7, 10)} AS new_code,
             ${draw(8, 100)} AS hotspot,
             ${draw(9, 50)} AS duplicate,
             (lpad(to_hex((SELECT ms FROM base) + g), 12, '0') || '70008'
               || lpad(to_hex(g), 15, '0'))::uuid AS id,
             (lpad(to_hex((SELECT ms FROM base) + g - 1), 12, '0') || '70008'
               || lpad(to_hex(g - 1), 15, '0'))::uuid AS previous_id
        FROM generate_series(1, ${target.count}) AS g)
    INSERT INTO issues (id, project_id, branch_id, rule_id, fingerprint, line_hash, context_hash,
                        path, start_line, message, severity, quality, kind, status, in_new_code,
                        duplicate_of_issue_id, first_seen_at, closed_at)
    SELECT id, ${target.projectId}, ${target.branchId}, (SELECT ids FROM rule_ids)[rule_k + 1],
           md5('f' || g), md5('l' || g), md5('c' || g),
           'src/module' || (file % 50) || '/file' || file || '.ts',
           line + 1, 'Seeded issue number ' || g || ' about ' || md5(g::text),
           (ARRAY['blocker','high','medium','low','info'])[severity + 1],
           (ARRAY['security','reliability','maintainability'])[quality + 1],
           CASE WHEN hotspot = 0 THEN 'hotspot' ELSE 'issue' END,
           CASE WHEN status < 14 THEN 'open' WHEN status = 14 THEN 'resolved'
                WHEN status = 15 THEN 'wont_fix' WHEN status = 16 THEN 'false_positive'
                ELSE 'closed' END,
           new_code = 0,
           CASE WHEN duplicate = 0 AND g > 1 THEN previous_id END,
           now(),
           CASE WHEN status >= 17 THEN now() END
      FROM seed`);
  await db.execute(sql`ANALYZE rules`);
  await db.execute(sql`ANALYZE issues`);
}
