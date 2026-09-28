import { lstatSync, type Stats } from 'node:fs';
import path from 'node:path';
import {
  normalizeSarifWithSecrets,
  REPORT_BOUNDS,
  SarifError,
  toolVersion,
  type NormalizeResult,
  type NormalizeWarning,
  type ReportEngine,
  type ReportFinding,
  type SourceRegion,
} from '@qualor/shared';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { readSourceLines } from '../discovery/source';
import type { Logger } from '../log';
import type { SarifCapture } from './types';

export interface NormalizeCapturesOptions {
  repoRoot: string;
  readLines(repoPath: string): readonly string[] | null;
  knownPaths: ReadonlySet<string>;
  log: Logger;
  /**
   * Receives the secret texts every engine found, and whether a secret engine's output could not
   * be read (so its secrets are unknown), for the GitLab report files (scm.md §9). Kept out of
   * the result, which feeds the report.
   */
  onSecrets?: (texts: readonly string[], unknown: boolean) => void;
}

export interface NormalizedEngines {
  engines: ReportEngine[];
  findings: ReportFinding[];
  warnings: NormalizeWarning[];
}

/**
 * Fix-round-3 finding 1: a SARIF result's path may point outside `knownPaths` (a secret's text is
 * now derived from such a file too, per fix-round-2 finding 4), and `discoverFiles` never vetted
 * it — so unlike an in-scope file, nothing has yet ruled out a symlink/junction escaping the repo,
 * a FIFO/device that could hang the CLI, or a huge file that could exhaust memory. Walks every
 * path segment from `root` with `lstat`, refusing any symlink or junction segment (reusing the
 * same detection `discoverFiles` relies on for `SYMLINK_SKIPPED`); the final entry must be a
 * regular file no larger than the same 1 MiB bound `analyzeFiles` applies to metrics/duplication.
 * A refusal simply yields no lines (never throws), same as any other unreadable file.
 */
function safeReadLines(root: string, repoPath: string): string[] | null {
  const segments = repoPath.split('/');
  let current = root;
  let stat: Stats | undefined;
  for (const segment of segments) {
    current = path.join(current, segment);
    try {
      stat = lstatSync(current);
    } catch {
      return null;
    }
    if (stat.isSymbolicLink()) return null;
  }
  if (stat === undefined || !stat.isFile() || stat.size > MAX_ANALYZED_BYTES) return null;
  return readSourceLines(current);
}

/** `readLines` over the repo (report-format §7.3: lines only via splitSourceLines). */
export function fileLines(root: string): (repoPath: string) => string[] | null {
  return (repoPath) => safeReadLines(root, repoPath);
}

interface Outcome {
  engine: ReportEngine;
  result: NormalizeResult | null;
  /** This engine's own secret text (finding 1), never copied into `engine`/`result`. */
  secretTexts: readonly string[];
  /** The subset that is the secret itself (fragments are scrubbed from messages). */
  fragmentTexts: readonly string[];
}

function normalizeOne(
  c: SarifCapture,
  o: NormalizeCapturesOptions,
  extraRegions: readonly SourceRegion[],
  extraTexts: readonly string[],
  extraFragments: readonly string[] = [],
): Outcome {
  const engine: ReportEngine = {
    id: c.engineId,
    kind: c.kind,
    version: toolVersion(c.version),
    status: c.status,
    reason: c.reason,
    durationMs: Math.max(0, Math.round(c.durationMs)),
    rules: [],
    ...(c.database !== undefined && { database: c.database }),
  };
  if (c.status !== 'ok') return { engine, result: null, secretTexts: [], fragmentTexts: [] };
  try {
    const { result, secrets } = normalizeSarifWithSecrets(c.sarif, {
      engineId: c.engineId,
      repoRoot: o.repoRoot,
      readLines: o.readLines,
      knownPaths: o.knownPaths,
      ...(c.sourceRoots !== undefined && { sourceRoots: c.sourceRoots }),
      ...(c.mapping !== undefined && { mapping: c.mapping }),
      ...(extraRegions.length > 0 && { extraSecretRegions: extraRegions }),
      ...(extraTexts.length > 0 && { extraSecretTexts: extraTexts }),
      ...(extraFragments.length > 0 && { extraFragmentTexts: extraFragments }),
    });
    return {
      engine: {
        ...engine,
        version: toolVersion(c.version) ?? result.version,
        rules: result.rules
          .slice(0, REPORT_BOUNDS.rulesPerEngine)
          .map((r) =>
            c.ruleLanguages === undefined || r.languages !== undefined
              ? r
              : { ...r, languages: [...c.ruleLanguages] },
          ),
      },
      result,
      secretTexts: secrets.texts,
      fragmentTexts: secrets.fragmentTexts,
    };
  } catch (err) {
    if (!(err instanceof SarifError)) {
      // Fix round 2 of tasks 5-6: anything else (a resource limit, a bug) fails this engine
      // only, with a fixed reason like every other analyzer failure; the detail is debug-only.
      o.log.debug(
        `${c.engineId}: normalisation failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}`,
      );
      return {
        engine: { ...engine, status: 'failed', reason: 'SARIF output could not be normalised' },
        result: null,
        secretTexts: [],
        fragmentTexts: [],
      };
    }
    // Fix-round-2 finding 1: a zod schema-validation message can quote fragments of the input it
    // rejected (e.g. a malformed result whose `ruleId` field holds a leaked token), so `reason`
    // stays a fixed string; the detailed message is available in the debug log only.
    o.log.debug(`${c.engineId}: invalid SARIF: ${err.message}`);
    return {
      engine: {
        ...engine,
        status: 'failed',
        reason: 'SARIF output does not match SARIF 2.1.0',
      },
      result: null,
      secretTexts: [],
      fragmentTexts: [],
    };
  }
}

/** An engine whose results can carry secret text (Gitleaks, Semgrep's secret rules). */
function redacting(c: SarifCapture): boolean {
  const r = c.mapping?.redactRegion;
  return r !== undefined && r !== false;
}

/**
 * Fail closed (report-format §7): the secrets of an engine whose output could not be normalised
 * are unknown, so another engine's snippet, message, secondary-location message, properties or
 * partial fingerprints could still quote one. They are dropped, and the message becomes the
 * rule's static text (its short description, else its id), which comes from the tool, not from
 * the scanned files. Locations and hashes are kept, so issues still track.
 */
function withoutFreeText(
  engine: ReportEngine,
  findings: readonly ReportFinding[],
): ReportFinding[] {
  const ruleText = new Map(engine.rules.map((r) => [r.id, r.shortDescription ?? r.id]));
  return findings.map((f) => {
    const out: ReportFinding = { ...f, message: ruleText.get(f.ruleId) ?? f.ruleId };
    delete out.snippet;
    delete out.properties;
    delete out.partialFingerprints;
    if (f.secondaryLocations !== undefined) {
      out.secondaryLocations = f.secondaryLocations.map((l) => {
        const copy = { ...l };
        delete copy.message;
        return copy;
      });
    }
    return out;
  });
}

/**
 * Pass 1 normalises every engine. Pass 2 (ruling C11, fix-round finding 1) re-normalises every
 * `ok` engine whenever *any* engine (including itself, harmlessly) found a secret region or
 * secret text, folding in the union of every *other* engine's secret regions and secret text.
 * Texts are scrubbed from snippets, messages, secondary-location messages and properties
 * wherever they occur — in any file, not only one gated by a matching region path — so a secret
 * literal copied into another file, into a message, or found on a file outside the scan scope
 * (e.g. a `.env` no engine's findings otherwise reference) never survives in another engine's
 * output either. When a secret engine's own output cannot be normalised, its secrets are unknown,
 * so every other engine's free text is dropped (fail closed, `withoutFreeText`).
 */
export function normalizeCaptures(
  captures: readonly SarifCapture[],
  o: NormalizeCapturesOptions,
): NormalizedEngines {
  const first = captures.map((capture) => ({ capture, outcome: normalizeOne(capture, o, [], []) }));
  const final = first.map(({ capture, outcome }, i) => {
    if (outcome.result === null) return outcome;
    const foreignRegions = first.flatMap((other, j) =>
      j === i ? [] : (other.outcome.result?.secretRegions ?? []),
    );
    const foreignTexts = first.flatMap((other, j) => (j === i ? [] : other.outcome.secretTexts));
    const foreignFragments = first.flatMap((other, j) =>
      j === i ? [] : other.outcome.fragmentTexts,
    );
    if (foreignRegions.length === 0 && foreignTexts.length === 0) return outcome;
    return normalizeOne(capture, o, foreignRegions, foreignTexts, foreignFragments);
  });
  const blind = first
    .filter(
      ({ capture, outcome }) =>
        redacting(capture) && capture.status === 'ok' && outcome.result === null,
    )
    .map(({ capture }) => capture.engineId);
  if (blind.length > 0) {
    o.log.warn(
      `${blind.join(', ')}: the secret scan output could not be read, so the other engines' snippets and messages are left out of the report`,
    );
  }
  o.onSecrets?.(
    [...new Set(first.flatMap((x) => [...x.outcome.secretTexts, ...x.outcome.fragmentTexts]))],
    blind.length > 0,
  );
  return {
    engines: final.map((x) => x.engine),
    findings: final.flatMap((x) =>
      blind.length === 0
        ? (x.result?.findings ?? [])
        : withoutFreeText(x.engine, x.result?.findings ?? []),
    ),
    warnings: [
      ...captures.flatMap((c) => c.warnings ?? []),
      ...final.flatMap((x) => x.result?.warnings ?? []),
    ],
  };
}
