import type { SarifLog, SarifResult, SarifRule } from '@qualor/shared';
import { z } from 'zod';

/** A rule's `shortDescription` is cut to this many characters. */
const MAX_DESCRIPTION = 4_000;
/** A target inside a packaged chart (`chart.tgz:templates/x.yaml`). */
const PACKAGED_CHART = /\.(?:tgz|tar\.gz):/;
const NOT_MAPPED = ' (line not mapped from the rendered chart)';

const text = z.string().max(4_096);
const codeLine = z.looseObject({
  Number: z.number().int().optional(),
  Content: z.string().optional(),
  IsCause: z.boolean().optional(),
});
const cause = z.looseObject({
  Resource: text.optional(),
  Provider: text.optional(),
  Service: text.optional(),
  StartLine: z.number().int().nullish(),
  EndLine: z.number().int().nullish(),
  Code: z.looseObject({ Lines: z.array(codeLine).nullish() }).nullish(),
});
const misconfiguration = z.looseObject({
  ID: z.string().min(1).max(256),
  Title: z.string().optional(),
  Description: z.string().optional(),
  Message: z.string().optional(),
  Resolution: z.string().optional(),
  Severity: text.optional(),
  PrimaryURL: z.string().optional(),
  Status: text.optional(),
  CauseMetadata: cause.nullish(),
});
const result = z.looseObject({
  Target: z.string(),
  Class: text.optional(),
  Type: text.optional(),
  Misconfigurations: z.array(z.unknown()).nullish(),
});
/**
 * `trivy fs --scanners misconfig --format json`, only the fields Qualor uses. Results and entries
 * are checked one by one (below): one that breaks a bound is dropped alone, not the whole run.
 */
export const trivyIacReportSchema = z.looseObject({
  Results: z.array(z.unknown()).nullish(),
});

type Target = z.infer<typeof result>;
type Misconfiguration = z.infer<typeof misconfiguration>;
type CodeLine = z.infer<typeof codeLine>;

type Region = { startLine: number; endLine: number };

/** The repository's file lines for a path, or null when they cannot be read. */
type ReadLines = (repoPath: string) => readonly string[] | null;

/** The reader above, asked once per path. */
function cached(read: ReadLines): ReadLines {
  const seen = new Map<string, readonly string[] | null>();
  return (repoPath) => {
    if (!seen.has(repoPath)) seen.set(repoPath, read(repoPath));
    return seen.get(repoPath) ?? null;
  };
}

/**
 * Helm reports lines of the rendered manifest, not of the template. The first cause line whose
 * text is also a template line anchors the shift: the equal template line nearest to the rendered
 * start (the lower one on a tie) gives the offset, applied to start and end alike. Null when no
 * cause line is a template line (every one is a rendered value) or the template is unreadable.
 */
function helmRegion(
  start: number,
  end: number,
  causeLines: readonly CodeLine[],
  template: readonly string[] | null,
): Region | null {
  if (template === null) return null;
  const trimmed = template.map((l) => l.trim());
  for (const line of causeLines) {
    const content = line.Content?.trim() ?? '';
    if (line.IsCause !== true || content === '' || line.Number === undefined) continue;
    const best = nearestLine(trimmed, content, start);
    if (best === -1) continue;
    const offset = best + 1 - line.Number;
    const mappedStart = start + offset;
    if (mappedStart < 1 || mappedStart > template.length) continue;
    return {
      startLine: mappedStart,
      endLine: Math.min(Math.max(end + offset, mappedStart), template.length),
    };
  }
  return null;
}

/**
 * The 0-based index of the trimmed template line equal to `content` that is nearest to the
 * rendered start (the lower one on a tie); -1 when no line is.
 */
function nearestLine(trimmed: readonly string[], content: string, start: number): number {
  let best = -1;
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] !== content) continue;
    if (best === -1 || Math.abs(i + 1 - (start - 1)) < Math.abs(best + 1 - (start - 1))) best = i;
  }
  return best;
}

/** The 1-based number of the last line with text, or 0 when there is none or no lines. */
function lastNonEmptyLine(lines: readonly string[] | null): number {
  if (lines === null) return 0;
  for (let i = lines.length - 1; i >= 0; i--) if ((lines[i] ?? '').trim() !== '') return i + 1;
  return 0;
}

const severityOf = (s: string | undefined) => (s === undefined || s === '' ? 'UNKNOWN' : s);

function ruleOf(m: Misconfiguration): SarifRule {
  const title = m.Title?.trim();
  const description = m.Description?.trim();
  const resolution = m.Resolution?.trim();
  const body = description ? description : (title ?? m.ID);
  const full = resolution ? `${body}\n\nHow to fix: ${resolution}` : body;
  const provider = m.CauseMetadata?.Provider?.toLowerCase();
  const service = m.CauseMetadata?.Service?.toLowerCase();
  return {
    id: m.ID,
    name: title ? title : m.ID,
    shortDescription: { text: full.slice(0, MAX_DESCRIPTION) },
    ...(m.PrimaryURL?.startsWith('https://') === true && { helpUri: m.PrimaryURL }),
    properties: {
      trivySeverity: severityOf(m.Severity),
      tags: [
        'iac',
        ...(provider ? [provider] : []),
        ...(service && service !== 'general' ? [service] : []),
      ],
    },
  };
}

/** The targets Qualor takes, in order: config files outside a packaged chart. */
function* configTargets(raw: readonly unknown[] | null | undefined): Generator<Target> {
  for (const rawTarget of raw ?? []) {
    const parsed = result.safeParse(rawTarget);
    if (!parsed.success) continue;
    const target = parsed.data;
    if (target.Class === 'config' && !PACKAGED_CHART.test(target.Target)) yield target;
  }
}

/** A target's failed checks, in order, without the `KCV-` Kubernetes cluster checks. */
function* failedChecks(target: Target): Generator<Misconfiguration> {
  for (const rawEntry of target.Misconfigurations ?? []) {
    const parsed = misconfiguration.safeParse(rawEntry);
    if (!parsed.success) continue;
    const m = parsed.data;
    if (m.Status === 'FAIL' && !m.ID.startsWith('KCV-')) yield m;
  }
}

/**
 * Where a failed check of `target` sits: its region, if any, and the note a message gets when a
 * Helm line is not mapped. `start` and `end` are Trivy's lines, 0 when it gave none.
 */
function placeOf(
  target: Target,
  start: number,
  end: number,
  causeLines: readonly CodeLine[] | null | undefined,
  read: ReadLines,
): { region: Region | null; note: string } {
  if (start <= 0 && target.Type === 'dockerfile') {
    // Absence checks (no USER, no HEALTHCHECK) have no line: they sit on the last non-empty
    // line, which a base-image bump on line 1 does not move.
    const last = lastNonEmptyLine(read(target.Target));
    return { region: last > 0 ? { startLine: last, endLine: last } : null, note: '' };
  }
  if (start <= 0) return { region: null, note: '' };
  const last = end >= start ? end : start;
  if (target.Type !== 'helm') return { region: { startLine: start, endLine: last }, note: '' };
  const region = helmRegion(start, last, causeLines ?? [], read(target.Target));
  return { region, note: region === null ? NOT_MAPPED : '' };
}

/** The SARIF result of a failed check, on `region` when there is one. */
function resultOf(
  target: Target,
  m: Misconfiguration,
  region: Region | null,
  note: string,
): SarifResult {
  const message = (m.Message?.trim() ? m.Message : (m.Title ?? m.ID)) + note;
  return {
    ruleId: m.ID,
    message: { text: message },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: target.Target },
          ...(region !== null && { region }),
        },
      },
    ],
    properties: {
      trivySeverity: severityOf(m.Severity),
      ...(target.Type !== undefined && { iacType: target.Type }),
      ...(m.CauseMetadata?.Resource ? { iacResource: m.CauseMetadata.Resource } : {}),
    },
  };
}

/**
 * Trivy's misconfiguration JSON as a SARIF 2.1.0 log: one result per failed check, `ruleId` the
 * check id (`AWS-0086`, `KSV-0001`), with the config type and the resource in `properties`, which
 * the shared mapping turns into severity and identity. Results Qualor does not take are dropped:
 * passed checks, the `KCV-` Kubernetes cluster checks, findings inside a packaged chart (a target
 * inside a `.tgz`/`.tar.gz`) and exact duplicates. `readLines` reads a repository file, for the Helm template
 * behind a rendered manifest. Throws on output that is not a JSON object (the runner then records
 * a fixed failure reason).
 */
export function trivyIacJsonToSarif(output: unknown, readLines: ReadLines): SarifLog {
  const report = trivyIacReportSchema.parse(output);
  const read = cached(readLines);
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];
  const seen = new Set<string>();
  for (const target of configTargets(report.Results)) {
    for (const m of failedChecks(target)) {
      const start = m.CauseMetadata?.StartLine ?? 0;
      const end = m.CauseMetadata?.EndLine ?? 0;
      const key = JSON.stringify([target.Target, m.ID, start, end, m.Message]);
      if (seen.has(key)) continue;
      seen.add(key);
      if (!rules.has(m.ID)) rules.set(m.ID, ruleOf(m));
      const { region, note } = placeOf(target, start, end, m.CauseMetadata?.Code?.Lines, read);
      results.push(resultOf(target, m, region, note));
    }
  }
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Trivy',
            informationUri: 'https://trivy.dev/',
            rules: [...rules.values()],
          },
        },
        results,
      },
    ],
  };
}
