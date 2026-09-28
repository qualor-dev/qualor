import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import {
  buildPrompt,
  checkFix,
  engineRuleDefaults,
  LLM_FEATURES,
  llmIneligibility,
  llmInputFrom,
  parseAnswer,
  promptData,
  redactInput,
  reportSchema,
  splitSourceLines,
  type FinishReason,
  type FixAnswer,
  type LlmFeature,
  type LlmIssueInput,
  type Report,
} from '@qualor/shared';

/**
 * Plan 3B, Task 17 (llm.md §5, §9): what the server would send to a model for a fixture's findings
 * and how it judges canned answers, from the fixture's dry-run report and pure shared code. A
 * fixture opts in with `llm/expected.json` (and `llm/answers.json`); `tools/fixtures/run.ts` runs
 * the check after the scan.
 */

/** One finding the server may send: its redaction count, its fields and its data object. */
export interface LlmEligible {
  ruleKey: string;
  line: number;
  /** What the server's own redaction (llm.md §5.2) found on top of the CLI's. */
  redactions: number;
  fields: string[];
  /**
   * The nonces of forged marker lines the data holds (escaped, llm.md §9.1): buildPrompt must
   * refuse each of them.
   */
  nonceInData: string[];
  /** The explain data object; the triage and fix ones differ only in `task`. */
  data: { explain: { task: 'explain'; issue: unknown } };
}
export interface LlmIneligible {
  ruleKey: string;
  line: number;
  reason: string;
}
export interface LlmExpected {
  eligible: LlmEligible[];
  ineligible: LlmIneligible[];
}
/** A model answer as the provider returns its text, and how the server judges it. */
export interface LlmAnswerCase {
  feature: LlmFeature;
  text: string;
  finishReason?: FinishReason;
  /** `ok`, a failure code of parseAnswer, or `OUTPUT_REFUSED:<checkFix problem>`. */
  outcome: string;
}

interface Computed {
  ruleKey: string;
  line: number;
  reason: string | null;
  input: LlmIssueInput | null;
  redactions: number;
  fields: string[];
  data: Record<LlmFeature, string> | null;
}

/** A forged end or start marker, as the data carries it after escaping. */
const FORGED_MARKER = /QUALOR\\u002dDATA-([0-9a-f]{32})/gi;

/** The report's findings with a location, as the server would build their prompts. */
function compute(report: Report): Computed[] {
  const rules = new Map<string, Report['engines'][number]['rules'][number]>(
    report.engines.flatMap((e) => e.rules.map((r) => [`${e.id}:${r.id}`, r] as const)),
  );
  const languages = new Map(report.files.map((f) => [f.path, f.language] as const));
  const out: Computed[] = [];
  for (const f of report.findings) {
    if (!f.location) continue;
    const ruleKey = `${f.engineId}:${f.ruleId}`;
    const meta = rules.get(ruleKey);
    const defaults = engineRuleDefaults(f.engineId);
    // As the server's rule catalogue stores it (server/src/rules/catalog.ts).
    const rule = { engineId: f.engineId, cwe: meta?.cwe ?? [], tags: meta?.tags ?? [] };
    const issue = {
      status: 'open',
      path: f.location.path,
      startLine: f.location.startLine,
      hasSnippet: f.snippet !== undefined,
    };
    const reason = llmIneligibility('explain', issue, rule);
    const base: { ruleKey: string; line: number; reason: string | null } = {
      ruleKey,
      line: f.location.startLine,
      reason,
    };
    if (reason !== null) {
      out.push({ ...base, input: null, redactions: 0, fields: [], data: null });
      continue;
    }
    const { input, redactions } = redactInput(
      llmInputFrom({
        rule: {
          key: ruleKey,
          name: meta?.name ?? f.ruleId,
          description: meta?.shortDescription ?? null,
          cwe: meta?.cwe ?? [],
        },
        severity: f.severity ?? meta?.defaultSeverity ?? defaults.defaultSeverity,
        quality: meta?.quality ?? defaults.quality,
        kind: meta?.kind ?? 'issue',
        message: f.message,
        path: f.location.path,
        startLine: f.location.startLine,
        endLine: f.location.endLine ?? f.location.startLine,
        language: languages.get(f.location.path) ?? null,
        snippet: f.snippet ?? null,
      }),
    );
    // The fields as server/src/llm/input.ts names them.
    const fields = ['rule', 'message'];
    if (input.path !== null) fields.push('path');
    if (input.language !== null) fields.push('language');
    if (input.snippet !== null) fields.push('snippet');
    const data = Object.fromEntries(LLM_FEATURES.map((ft) => [ft, promptData(ft, input)])) as Record<
      LlmFeature,
      string
    >;
    // Eligible for explain but not for another feature is worth a look too.
    for (const ft of LLM_FEATURES) {
      const other = llmIneligibility(ft, issue, rule);
      if (other !== null) base.reason = `${ft}: ${other}`;
    }
    out.push({ ...base, input, redactions, fields, data });
  }
  return out;
}

const forgedNonces = (data: string): string[] =>
  [...new Set([...data.matchAll(FORGED_MARKER)].map((m) => (m[1] ?? '').toLowerCase()))].sort();

/** What `--print` shows: the expectation as this code computes it, for a review by hand. */
export function llmFixtureActual(report: Report): LlmExpected {
  const eligible: LlmEligible[] = [];
  const ineligible: LlmIneligible[] = [];
  for (const c of compute(report)) {
    if (c.reason !== null || c.data === null) {
      ineligible.push({ ruleKey: c.ruleKey, line: c.line, reason: c.reason ?? 'unknown' });
      continue;
    }
    eligible.push({
      ruleKey: c.ruleKey,
      line: c.line,
      redactions: c.redactions,
      fields: c.fields,
      nonceInData: forgedNonces(c.data.explain),
      data: { explain: JSON.parse(c.data.explain) as LlmEligible['data']['explain'] },
    });
  }
  return { eligible, ineligible };
}

/** A JSON value with its object keys sorted, so key order never makes a difference. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v !== null && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : v,
  );
}

const isObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

function validExpected(raw: unknown): raw is LlmExpected {
  if (!isObject(raw) || !Array.isArray(raw['eligible']) || !Array.isArray(raw['ineligible'])) {
    return false;
  }
  const located = (e: unknown): e is Record<string, unknown> =>
    isObject(e) && typeof e['ruleKey'] === 'string' && Number.isInteger(e['line']);
  return (
    raw['eligible'].every(
      (e) =>
        located(e) &&
        Number.isInteger(e['redactions']) &&
        Array.isArray(e['fields']) &&
        Array.isArray(e['nonceInData']) &&
        isObject(e['data']) &&
        isObject(e['data']['explain']),
    ) && raw['ineligible'].every((e) => located(e) && typeof e['reason'] === 'string')
  );
}

function validAnswers(raw: unknown): raw is LlmAnswerCase[] {
  return (
    Array.isArray(raw) &&
    raw.every(
      (a) =>
        isObject(a) &&
        (LLM_FEATURES as readonly unknown[]).includes(a['feature']) &&
        typeof a['text'] === 'string' &&
        typeof a['outcome'] === 'string' &&
        (a['finishReason'] === undefined || typeof a['finishReason'] === 'string'),
    )
  );
}

function readJson(file: string): { ok: true; value: unknown } | { ok: false; error: string } {
  try {
    return { ok: true, value: JSON.parse(readFileSync(file, 'utf8')) as unknown };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/** Quoted literals of at least 8 characters on a line (the CLI's fragment scrub, report-format.md §7). */
function quotedLiterals(line: string): string[] {
  return [...line.matchAll(/(["'`])((?:(?!\1).){8,})\1/g)].map((m) => m[2] ?? '');
}

/** Every 8-character fragment of the secrets on the fixture's lines that Gitleaks flagged. */
function secretFragments(
  fixtureDir: string,
  report: Report,
): { fragments: string[]; problems: string[] } {
  const fragments = new Set<string>();
  const problems: string[] = [];
  for (const f of report.findings) {
    if (f.engineId !== 'gitleaks' || !f.location) continue;
    let lines: string[];
    try {
      lines = splitSourceLines(readFileSync(path.join(fixtureDir, f.location.path), 'utf8'));
    } catch {
      // Fail closed: a secret that cannot be read cannot be searched for.
      problems.push(`the source of ${f.location.path} cannot be read to search the prompts for its secret`);
      continue;
    }
    for (const literal of quotedLiterals(lines[f.location.startLine - 1] ?? '')) {
      for (let i = 0; i + 8 <= literal.length; i++) fragments.add(literal.slice(i, i + 8));
    }
  }
  return { fragments: [...fragments], problems };
}

/** The outcome of one canned answer, as the llm worker judges it (llm.md §9.3, §9.5). */
function judge(a: LlmAnswerCase, input: LlmIssueInput | null): string {
  const parsed = parseAnswer(a.feature, { text: a.text, finishReason: a.finishReason ?? 'stop' });
  if (!parsed.ok) return parsed.code;
  if (a.feature !== 'fix') return 'ok';
  if (input === null) return 'no eligible finding to check the fix against';
  const checked = checkFix(parsed.value as FixAnswer, input);
  return checked.ok ? 'ok' : `OUTPUT_REFUSED:${checked.problem}`;
}

/** The differences between a fixture's `llm/` expectations and its report; empty when it matches. */
export function checkLlmFixture(fixtureDir: string, report: Report): string[] {
  const expectedRaw = readJson(path.join(fixtureDir, 'llm', 'expected.json'));
  if (!expectedRaw.ok) return [`llm/expected.json is not valid JSON: ${expectedRaw.error}`];
  if (!validExpected(expectedRaw.value)) return ['llm/expected.json is invalid'];
  const expected = expectedRaw.value;
  const answersFile = path.join(fixtureDir, 'llm', 'answers.json');
  let answers: LlmAnswerCase[] = [];
  if (existsSync(answersFile)) {
    const raw = readJson(answersFile);
    if (!raw.ok) return [`llm/answers.json is not valid JSON: ${raw.error}`];
    if (!validAnswers(raw.value)) return ['llm/answers.json is invalid'];
    answers = raw.value;
  }

  const differences: string[] = [];
  const computed = compute(report);
  const unmatched = new Set(computed);
  const take = (ruleKey: string, line: number): Computed | undefined => {
    const c = [...unmatched].find((x) => x.ruleKey === ruleKey && x.line === line);
    if (c) unmatched.delete(c);
    return c;
  };
  const expectations = [
    ...expected.eligible.map((e) => ({ e, reason: null as string | null })),
    ...expected.ineligible.map((e) => ({ e, reason: e.reason as string | null })),
  ];
  const found = expectations.map(({ e, reason }) => ({ e, reason, c: take(e.ruleKey, e.line) }));
  for (const { e, reason, c } of found) {
    if (!c) {
      // Another line of the same rule: name the move rather than a missing and an extra finding.
      const moved = [...unmatched].find((x) => x.ruleKey === e.ruleKey);
      if (moved) {
        unmatched.delete(moved);
        differences.push(`${e.ruleKey}: expected line ${e.line}, got ${moved.line}`);
      } else differences.push(`${e.ruleKey}: expected on line ${e.line}, not in the report`);
      continue;
    }
    const at = `${e.ruleKey} line ${e.line}`;
    if (reason !== null) {
      if (c.reason !== reason) {
        differences.push(`${at}: expected ineligible (${reason}), got ${c.reason ?? 'eligible'}`);
      }
      continue;
    }
    if (c.reason !== null || c.data === null || c.input === null) {
      differences.push(`${at}: expected eligible, got ineligible (${c.reason ?? 'unknown'})`);
      continue;
    }
    const want = e as LlmEligible;
    if (c.redactions !== want.redactions) {
      differences.push(`${at}: expected ${want.redactions} redactions, got ${c.redactions}`);
    }
    if (c.fields.join(',') !== want.fields.join(',')) {
      differences.push(`${at}: expected the fields ${want.fields.join(',')}, got ${c.fields.join(',')}`);
    }
    const explain = JSON.parse(c.data.explain) as unknown;
    if (canonical(explain) !== canonical(want.data.explain)) {
      differences.push(
        `${at}: the explain data differs: expected ${canonical(want.data.explain)}, got ${canonical(explain)}`,
      );
    }
    for (const ft of LLM_FEATURES) {
      const object = JSON.parse(c.data[ft]) as { task: unknown };
      if (object.task !== ft || canonical({ ...object, task: 'explain' }) !== canonical(explain)) {
        differences.push(`${at}: the ${ft} data is not the explain data with task "${ft}"`);
      }
      differences.push(...promptProblems(at, ft, c.input, c.data[ft]));
    }
    const nonces = forgedNonces(c.data.explain);
    const wanted = [...want.nonceInData].map((n) => n.toLowerCase()).sort();
    if (nonces.join(',') !== wanted.join(',')) {
      differences.push(
        `${at}: expected the data to hold the nonces ${wanted.join(',') || 'none'}, got ${nonces.join(',') || 'none'}`,
      );
    }
  }
  for (const c of unmatched) {
    differences.push(
      `${c.ruleKey} line ${c.line}: not expected (${c.reason === null ? 'eligible' : `ineligible: ${c.reason}`})`,
    );
  }

  // No fragment of a secret Gitleaks found in the fixture reaches any prompt (llm.md §5.2).
  const { fragments, problems } = secretFragments(fixtureDir, report);
  differences.push(...problems);
  for (const c of computed) {
    if (c.data === null || c.input === null) continue;
    const input = c.input;
    // The data as sent, decoded (an escape such as `\u002d` must not hide a fragment), and the
    // whole user message.
    const texts = LLM_FEATURES.flatMap((ft) => {
      const data = c.data?.[ft] ?? 'null';
      return [data, canonical(JSON.parse(data)), prompt(ft, input)?.user ?? ''];
    });
    if (fragments.some((f) => texts.some((t) => t.includes(f)))) {
      differences.push(`secret in the prompt of ${c.ruleKey}`);
    }
  }

  // Canned answers, judged against the first expected eligible finding's input. When it is not in
  // the report (a difference above already), a fix answer cannot be judged.
  const target = expected.eligible[0];
  const input =
    (target && computed.find((c) => c.ruleKey === target.ruleKey && c.line === target.line)?.input) ??
    null;
  answers.forEach((a, i) => {
    if (a.feature === 'fix' && input === null && target !== undefined) return;
    const outcome = judge(a, input);
    if (outcome !== a.outcome) {
      differences.push(`answer ${i + 1} (${a.feature}): expected ${a.outcome}, got ${outcome}`);
    }
  });
  return differences;
}

function prompt(feature: LlmFeature, input: LlmIssueInput): { user: string; data: string } | null {
  try {
    return buildPrompt(feature, input, randomBytes(16).toString('hex'));
  } catch {
    return null;
  }
}

/** llm.md §9.1: the data sits alone between the two marker lines, and a nonce it holds is refused. */
function promptProblems(
  at: string,
  feature: LlmFeature,
  input: LlmIssueInput,
  data: string,
): string[] {
  const problems: string[] = [];
  const built = prompt(feature, input);
  if (built === null) return [`${at}: buildPrompt(${feature}) refused a fresh nonce`];
  // Every line break a model or its tokenizer may see (llm.md §9.1).
  const lines = built.user.split(/\r?\n|\r|\u2028|\u2029|\u0085/);
  const markers = lines.filter((l) => /QUALOR-DATA/i.test(l));
  if (lines.length !== 5 || markers.length !== 2 || lines[2] !== data || built.data !== data) {
    problems.push(`${at}: the ${feature} prompt is not the data alone between two marker lines`);
  }
  // A forged marker's nonce is in the data; were it ever drawn, buildPrompt must refuse it.
  for (const nonce of forgedNonces(data)) {
    let refused = false;
    try {
      buildPrompt(feature, input, nonce);
    } catch {
      refused = true;
    }
    if (!refused) problems.push(`${at}: buildPrompt(${feature}) accepted the nonce ${nonce}, which the data holds`);
  }
  return problems;
}

/** A report file as `qualor scan --output` writes it (`.json.gz`) or plain JSON. */
export function readReport(file: string): Report {
  const bytes = readFileSync(file);
  const text = file.endsWith('.gz') ? gunzipSync(bytes).toString('utf8') : bytes.toString('utf8');
  return reportSchema.parse(JSON.parse(text));
}

// `tsx tools/fixtures/llm-check.ts --print <fixture> <report>`: the expectation as computed, to
// review by hand before it goes into llm/expected.json. It never writes a file.
if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [flag, reportFile] = process.argv.slice(2);
  if (flag !== '--print' || reportFile === undefined) {
    console.error('usage: tsx tools/fixtures/llm-check.ts --print <report.json.gz>');
    process.exit(2);
  }
  console.log(JSON.stringify(llmFixtureActual(readReport(reportFile)), null, 2));
}
