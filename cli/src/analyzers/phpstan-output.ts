import {
  PHPSTAN_NO_DEPENDENCY_IDS,
  PHPSTAN_UNKNOWN_SYMBOL_IDS,
  phpstanNotFinding,
  sarifLogSchema,
  type SarifLog,
} from '@qualor/shared';
import { z } from 'zod';
import type { Logger } from '../log';

const messageSchema = z.looseObject({
  message: z.string(),
  line: z.number().int().nullable().optional(),
  identifier: z.string().optional(),
});
const reportSchema = z.looseObject({
  totals: z.looseObject({}),
  // `[]` when there is no finding (SonarSource's reader notes it), else an object by path.
  files: z.union([
    z.array(z.unknown()).max(0),
    z.record(z.string(), z.looseObject({ messages: z.array(messageSchema) })),
  ]),
  errors: z.array(z.unknown()),
});

/** PHPStan's key for a trait's message: "<file> (in context of class X)" (fact P3). */
const IN_CONTEXT = / \(in context of [^)]*\)$/;
const slashes = (p: string) => p.replaceAll('\\', '/');

/**
 * config.md §6, report-format.md §5: PHPStan's JSON report as SARIF 2.1.0. Paths become
 * repository paths (the copy's prefix removed, each segment percent-encoded so the normaliser
 * decodes the same name); messages that are not findings, unknown symbols and, without
 * dependencies, the artefacts of an unseen parent class are dropped and counted at debug level;
 * a trait's message is kept once. Every result is a `warning`: the identifier decides (§7.1).
 */
export function phpstanSarif(
  output: unknown,
  o: {
    input: string;
    workDir: string;
    version: string | null;
    withDependencies: boolean;
    log: Logger;
  },
): SarifLog {
  const report = reportSchema.parse(output);
  const files = Array.isArray(report.files) ? {} : report.files;
  const prefix = `${slashes(o.input).replace(/\/+$/, '')}/`;
  // Messages hold PHP names with backslashes (`Shop\Cart::clear()`): only the work paths, as
  // written or with forward slashes, are replaced, never any other backslash.
  const bases = [...new Set([o.input, slashes(o.input)])].map((p) => p.replace(/[\\/]+$/, ''));
  const works = [...new Set([o.workDir, slashes(o.workDir)])];
  const shown = (text: string) => {
    let t = text;
    for (const b of bases) t = t.split(`${b}/`).join('').split(`${b}\\`).join('');
    for (const w of works) t = t.split(w).join('<work>');
    return t;
  };
  const seen = new Set<string>();
  const rules = new Set<string>();
  const results: unknown[] = [];
  let notFindings = 0;
  let unknown = 0;
  for (const [key, file] of Object.entries(files)) {
    const abs = slashes(key.replace(IN_CONTEXT, ''));
    if (!abs.startsWith(prefix)) continue;
    const rel = abs.slice(prefix.length);
    for (const m of file.messages) {
      const id = m.identifier ?? 'phpstan.unidentified';
      if (phpstanNotFinding(id)) {
        notFindings++;
        continue;
      }
      if (
        PHPSTAN_UNKNOWN_SYMBOL_IDS.has(id) ||
        (!o.withDependencies && PHPSTAN_NO_DEPENDENCY_IDS.has(id))
      ) {
        unknown++;
        continue;
      }
      const line = typeof m.line === 'number' && m.line >= 1 ? m.line : 1;
      const text = shown(m.message);
      const key2 = `${rel}\u0000${line}\u0000${id}\u0000${text}`;
      if (seen.has(key2)) continue;
      seen.add(key2);
      rules.add(id);
      results.push({
        ruleId: id,
        level: 'warning',
        message: { text },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: rel.split('/').map(encodeURIComponent).join('/') },
              region: { startLine: line },
            },
          },
        ],
      });
    }
  }
  if (notFindings + unknown > 0) {
    o.log.debug(
      `phpstan: ${notFindings} message(s) that are not findings and ${unknown} unknown-symbol message(s) dropped`,
    );
  }
  return sarifLogSchema.parse({
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'PHPStan',
            ...(o.version !== null && { version: o.version }),
            informationUri: 'https://phpstan.org',
            rules: [...rules].sort().map((id) => ({
              id,
              name: id,
              helpUri: `https://phpstan.org/error-identifiers/${id}`,
            })),
          },
        },
        results,
      },
    ],
  });
}
