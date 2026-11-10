import path from 'node:path';
import {
  cppcheckIsAddonResult,
  cppcheckIsFinding,
  type SarifLog,
  type SarifResult,
  type SarifRule,
} from '@qualor/shared';
import { SaxesParser, type SaxesTagPlain } from 'saxes';
import { redactForeignPaths } from './cfamily-common';

interface XmlLocation {
  file: string;
  line: number;
  column: number;
  info: string | undefined;
}
interface XmlError {
  id: string;
  severity: string;
  msg: string;
  cwe: string | undefined;
  locations: XmlLocation[];
}

const MAX_DEPTH = 16;

/** cppcheck `--output-format=xmlv2` (fact F5) as plain records; throws on anything else. */
function readErrors(xml: string): XmlError[] {
  const parser = new SaxesParser();
  const errors: XmlError[] = [];
  const stack: string[] = [];
  let failure: Error | null = null;
  let version: string | undefined;
  let current: XmlError | null = null;
  parser.on('error', (e: Error) => {
    failure ??= e;
  });
  parser.on('doctype', () => {
    failure ??= new Error('cppcheck XML has a DOCTYPE');
  });
  parser.on('opentag', (tag: SaxesTagPlain) => {
    if (failure !== null) return;
    if (stack.length >= MAX_DEPTH) {
      failure = new Error('cppcheck XML nests too deep');
      return;
    }
    const a = tag.attributes;
    if (tag.name === 'results' && stack.length === 0) version = a['version'];
    else if (tag.name === 'error' && stack.at(-1) === 'errors') {
      current = {
        id: a['id'] ?? '',
        severity: a['severity'] ?? '',
        msg: a['msg'] ?? '',
        cwe: a['cwe'],
        locations: [],
      };
    } else if (tag.name === 'location' && stack.at(-1) === 'error' && current !== null) {
      current.locations.push({
        file: a['file'] ?? '',
        line: Number(a['line'] ?? 0),
        column: Number(a['column'] ?? 0),
        info: a['info'],
      });
    }
    stack.push(tag.name);
  });
  parser.on('closetag', (tag: SaxesTagPlain) => {
    stack.pop();
    if (tag.name === 'error' && current !== null) {
      errors.push(current);
      current = null;
    }
  });
  parser.write(xml).close();
  if (failure !== null) throw failure;
  if (version !== '2') throw new Error('not cppcheck xmlv2 output');
  return errors;
}

/**
 * A file inside `base` (the checked copy, which holds only in-scope files) as a
 * repository-relative URI, percent-encoded by segment (the normaliser decodes relative URIs,
 * ruling F8's fix round); null for any other path, which never leaves the transform (ruling D9-9).
 */
function uri(file: string, base: string): string | null {
  if (file === '') return null;
  const rel = path.relative(base, path.resolve(base, file));
  if (rel === '' || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
    return null;
  }
  return rel.split(path.sep).map(encodeURIComponent).join('/');
}

type SarifLocation = NonNullable<SarifResult['locations']>[number];

function location(l: XmlLocation, base: string, withMessage: boolean): SarifLocation | null {
  const u = uri(l.file, base);
  if (u === null || !Number.isInteger(l.line) || l.line < 1) return null;
  return {
    physicalLocation: {
      artifactLocation: { uri: u },
      region: {
        startLine: l.line,
        ...(Number.isInteger(l.column) && l.column > 0 && { startColumn: l.column }),
      },
    },
    ...(withMessage &&
      l.info !== undefined &&
      l.info !== '' && { message: { text: redactForeignPaths(l.info, [base]) } }),
  };
}

const LEVEL: ReadonlyMap<string, 'error' | 'warning'> = new Map([
  ['error', 'error'],
  ['warning', 'warning'],
]);

/** The rule of an id, with its first result's severity and CWE. */
function ruleOf(e: XmlError): SarifRule {
  const cwe = e.cwe !== undefined && /^\d+$/.test(e.cwe) && e.cwe !== '0' ? e.cwe : null;
  return {
    id: e.id,
    properties: {
      cppcheckSeverity: e.severity,
      ...(cwe !== null && { tags: [`external/cwe/cwe-${cwe}`] }),
    },
  };
}

export interface CppcheckConversion {
  log: SarifLog;
  /** Results that are no finding (decision 6), by id, in first-seen order. */
  notAnalysed: Map<string, number>;
  /**
   * Ruling D9-9: results located outside the checked copy (a system or host header an absolute
   * `#include` reached), and related locations there, dropped with their notes.
   */
  outside: number;
  /** Issue #33: the addon runs that failed (a crash, or a rule-texts file it cannot read). */
  addonFailures: number;
}

const MISRA_WITHOUT_TEXTS = 'misra violation (use --rule-texts=<file> to get proper output)';

/** Issue #33: the misra addon's message without rule texts names an option Qualor does not have. */
function messageOf(e: XmlError): string {
  const rule = /^misra-c2012-(\d+\.\d+)$/.exec(e.id)?.[1];
  if (rule === undefined || e.msg !== MISRA_WITHOUT_TEXTS) return e.msg;
  return `Violation of MISRA C 2012 rule ${rule}. Set analyzers.cppcheck.misraRuleTexts for its text.`;
}

/** Addons need groups the project may not have enabled: cppcheck's own results stay within them. */
function outsideProjectGroups(e: XmlError, groups: ReadonlySet<string> | undefined): boolean {
  return (
    groups !== undefined &&
    e.severity !== 'error' &&
    !groups.has(e.severity) &&
    !cppcheckIsAddonResult(e.id)
  );
}

/** Issue #33: an addon run that failed, as cppcheck reports it (an `internalError`). */
function isAddonFailure(e: XmlError): boolean {
  return e.id === 'internalError' && e.msg.includes('Failed to execute');
}

/** One finding at its primary location, with the related locations that stay inside the copy. */
function resultOf(
  e: XmlError,
  primary: SarifLocation,
  related: SarifLocation[],
  base: string,
): SarifResult {
  return {
    ruleId: e.id,
    level: LEVEL.get(e.severity) ?? 'note',
    // Ruling D9-11: no host path in a kept message (paths in the copy become relative to it).
    message: { text: redactForeignPaths(messageOf(e), [base]) },
    properties: { cppcheckSeverity: e.severity },
    locations: [primary],
    ...(related.length > 0 && { relatedLocations: related }),
  };
}

/**
 * config.md §6.2: cppcheck's xmlv2 as SARIF 2.1.0. `base` is the directory cppcheck ran in (the
 * checked copy), against which its relative paths resolve. Ids and severities that are no
 * finding (decision 6) are counted in `notAnalysed` instead; a result or related location outside
 * the copy is counted in `outside` and never reaches the log (ruling D9-9). `projectGroups` is set
 * when addons ran.
 */
export function cppcheckXmlToSarif(
  xml: string,
  o: { version: string; base: string; projectGroups?: ReadonlySet<string> | undefined },
): CppcheckConversion {
  const base = path.resolve(o.base);
  const rules = new Map<string, SarifRule>();
  const results: SarifResult[] = [];
  const notAnalysed = new Map<string, number>();
  let outside = 0;
  let addonFailures = 0;
  for (const e of readErrors(xml)) {
    if (!cppcheckIsFinding(e.id, e.severity)) {
      notAnalysed.set(e.id, (notAnalysed.get(e.id) ?? 0) + 1);
      if (isAddonFailure(e)) addonFailures++;
      continue;
    }
    if (outsideProjectGroups(e, o.projectGroups)) continue;
    const [first, ...rest] = e.locations;
    if (first === undefined || e.id === '') continue;
    const primary = location(first, base, false);
    if (primary === null) {
      outside++;
      continue;
    }
    const placed = rest.map((l) => location(l, base, true));
    const related = placed.filter((r): r is SarifLocation => r !== null);
    outside += placed.length - related.length;
    if (!rules.has(e.id)) rules.set(e.id, ruleOf(e));
    results.push(resultOf(e, primary, related, base));
  }
  return {
    log: {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'cppcheck', version: o.version, rules: [...rules.values()] } },
          results,
        },
      ],
    },
    notAnalysed,
    outside,
    addonFailures,
  };
}
