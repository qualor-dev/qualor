import type { VexJustification } from '../decisions';
import { SEVERITIES } from '../summary';
import { productId, type ExportDocument } from './types';

/** One vulnerability of a target with its effective triage decision. */
export interface VexEntry {
  vulnerabilityId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'unknown';
  title: string | null;
  primaryUrl: string | null;
  fixedVersion: string | null;
  packageName: string;
  purls: string[];
  status: 'open' | 'false_positive' | 'wont_fix';
  reason: VexJustification | null;
  comment: string | null;
  decidedAt: Date | null;
  decidedBy: string | null;
}

/** E8: the OpenVEX reason names and the CycloneDX justification each one becomes. */
export const CYCLONEDX_JUSTIFICATION: Record<VexJustification, string> = {
  component_not_present: 'code_not_present',
  vulnerable_code_not_present: 'code_not_present',
  vulnerable_code_not_in_execute_path: 'code_not_reachable',
  vulnerable_code_cannot_be_controlled_by_adversary: 'requires_environment',
  inline_mitigations_already_exist: 'protected_by_mitigating_control',
};

/** E7: the CycloneDX `analysis.state` of each Qualor status. */
export const CYCLONEDX_STATE: Record<VexEntry['status'], string> = {
  open: 'in_triage',
  false_positive: 'not_affected',
  wont_fix: 'exploitable',
};

/** E7: the OpenVEX `status` of each Qualor status. */
export const OPENVEX_STATUS: Record<VexEntry['status'], string> = {
  open: 'under_investigation',
  false_positive: 'not_affected',
  wont_fix: 'affected',
};

const NO_REASON = 'No reason was recorded.';
const NO_ACTION = 'No action is planned.';
const TOOL = { name: 'Trivy' };

/**
 * The advisory database a vulnerability id belongs to. Dependency-Track looks a VEX entry up by
 * (source name, id), so the source follows the id prefix.
 */
function vulnerabilitySource(id: string): { name: string; url: string } {
  const enc = encodeURIComponent(id);
  if (id.startsWith('CVE-')) return { name: 'NVD', url: `https://nvd.nist.gov/vuln/detail/${enc}` };
  if (id.startsWith('GHSA-'))
    return { name: 'GITHUB', url: `https://github.com/advisories/${enc}` };
  return { name: 'OSV', url: `https://osv.dev/vulnerability/${enc}` };
}

/**
 * The version of a purl, decoded: without its qualifiers (`?…`) and subpath (`#…`), which may hold
 * an `@` themselves, the part after the last `@`.
 */
function purlVersion(purl: string): string | undefined {
  const base = purl.split(/[?#]/)[0] ?? '';
  const at = base.lastIndexOf('@');
  if (at < 0) return undefined;
  const raw = base.slice(at + 1);
  if (raw === '') return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** The CycloneDX `analysis` of an entry without its dates: what the merge (A16) compares. */
function analysisOf(e: VexEntry): {
  state: string;
  justification?: string;
  response?: string[];
  detail?: string;
} {
  const detail =
    e.comment ?? (e.status === 'false_positive' && e.reason === null ? NO_REASON : undefined);
  return {
    state: CYCLONEDX_STATE[e.status],
    ...(e.status === 'false_positive' && e.reason !== null
      ? { justification: CYCLONEDX_JUSTIFICATION[e.reason] }
      : {}),
    ...(e.status === 'wont_fix' ? { response: ['will_not_fix'] } : {}),
    ...(detail === undefined ? {} : { detail }),
  };
}

type EntryGroup = [VexEntry, ...VexEntry[]];

/**
 * A16: the entries in groups of one vulnerability id and one analysis, in the order of each
 * group's first entry. Trivy keeps one statement per id, so a vulnerability lists every package
 * its decision covers; Dependency-Track still applies it per affected component.
 */
function sameAnalysis(entries: readonly VexEntry[]): EntryGroup[] {
  const groups = new Map<string, EntryGroup>();
  for (const e of entries) {
    const key = JSON.stringify([e.vulnerabilityId, analysisOf(e)]);
    const group = groups.get(key);
    if (group) group.push(e);
    else groups.set(key, [e]);
  }
  return [...groups.values()];
}

/** The CycloneDX analysis states that Trivy applies; it ignores a statement in any other. */
const TRIVY_APPLIES = new Set(['not_affected', 'resolved']);

/**
 * The groups with each id's groups that Trivy applies after its others; the order is otherwise
 * kept. Trivy keeps the last statement of an id, so an open or exploitable group of a CVE on one
 * package must not come after a not_affected one on another.
 */
function trivyOrder(groups: readonly EntryGroup[]): EntryGroup[] {
  const rank = new Map<string, number>();
  for (const [first] of groups) {
    if (!rank.has(first.vulnerabilityId)) rank.set(first.vulnerabilityId, rank.size);
  }
  const applies = ([first]: EntryGroup): number =>
    TRIVY_APPLIES.has(analysisOf(first).state) ? 1 : 0;
  const rankOf = ([first]: EntryGroup): number => rank.get(first.vulnerabilityId) ?? 0;
  // A stable sort: groups that tie keep their order.
  return [...groups].sort((a, b) => rankOf(a) - rankOf(b) || applies(a) - applies(b));
}

/** `Upgrade to <fix>.` when all entries share one fix, else the fix of each package with one. */
function recommendationOf(group: EntryGroup): string | undefined {
  const fixed = group.filter((e) => e.fixedVersion !== null);
  const [first] = fixed;
  if (first === undefined) return undefined;
  if (fixed.length === group.length && fixed.every((e) => e.fixedVersion === first.fixedVersion)) {
    return `Upgrade to ${first.fixedVersion}.`;
  }
  return fixed.map((e) => `Upgrade ${e.packageName} to ${e.fixedVersion}.`).join(' ');
}

/**
 * The CycloneDX vulnerability of a group of entries with one id and one analysis: the worst
 * severity, every advisory, author and affected purl, and the earliest and latest decision dates.
 */
function cycloneDxVulnerability(group: EntryGroup, link: (purl: string) => string): object {
  const [first] = group;
  const distinct = <T>(values: (T | null)[]): T[] => [
    ...new Set(values.filter((v): v is T => v !== null)),
  ];
  const severity = group
    .map((e) => e.severity)
    .reduce((a, b) => (SEVERITIES.indexOf(b) < SEVERITIES.indexOf(a) ? b : a));
  const dates = group
    .flatMap((e) => (e.decidedAt === null ? [] : [e.decidedAt.toISOString()]))
    .sort();
  const advisories = distinct(group.map((e) => e.primaryUrl));
  const recommendation = recommendationOf(group);
  const authors = distinct(group.map((e) => e.decidedBy));
  return {
    'bom-ref': `${first.vulnerabilityId}:${first.packageName}`,
    id: first.vulnerabilityId,
    source: vulnerabilitySource(first.vulnerabilityId),
    ratings: [{ severity, source: TOOL }],
    ...(advisories.length === 0 ? {} : { advisories: advisories.map((url) => ({ url })) }),
    ...(recommendation === undefined ? {} : { recommendation }),
    analysis: {
      ...analysisOf(first),
      ...(dates.length === 0 ? {} : { firstIssued: dates[0], lastUpdated: dates.at(-1) }),
    },
    affects: distinct(group.flatMap((e) => e.purls)).map((purl) => ({ ref: link(purl) })),
    ...(authors.length === 0
      ? {}
      : { properties: authors.map((value) => ({ name: 'qualor:decided-by', value })) }),
  };
}

/**
 * A CycloneDX 1.6 VEX of a target: its components, and one vulnerability per id and analysis.
 * D8-1: every affects ref and component bom-ref is a BOM-Link `urn:cdx:<sbomSerial>/1#<purl>`
 * into the CycloneDX SBOM with that serial, which Trivy needs to apply the VEX to that SBOM. The
 * components carry the same string, so Dependency-Track resolves each ref to its component. The
 * VEX keeps its own serial, `doc.serial` (A15).
 */
export function buildCycloneDxVex(
  doc: ExportDocument,
  entries: readonly VexEntry[],
  sbomSerial: string,
): object {
  const root = productId(doc.project, doc.target);
  const link = (purl: string): string => `urn:cdx:${sbomSerial}/1#${purl}`;
  const components = new Map<string, object>();
  for (const e of entries) {
    for (const purl of e.purls) {
      if (components.has(purl)) continue;
      const version = purlVersion(purl);
      components.set(purl, {
        type: 'library',
        'bom-ref': link(purl),
        name: e.packageName,
        ...(version === undefined ? {} : { version }),
        purl,
      });
    }
  }
  const vulnerabilities = trivyOrder(sameAnalysis(entries)).map((group) =>
    cycloneDxVulnerability(group, link),
  );
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${doc.serial}`,
    version: 1,
    metadata: {
      timestamp: doc.generatedAt.toISOString(),
      tools: { components: [{ type: 'application', name: 'Qualor', version: doc.toolVersion }] },
      component: {
        type: 'application',
        name: doc.project.name,
        version: doc.target.name,
        'bom-ref': root,
        purl: root,
      },
    },
    components: [...components.values()],
    vulnerabilities,
  };
}

/** A false positive's OpenVEX impact statement: its comment, else NO_REASON without a reason. */
function openVexImpact(e: VexEntry): string | undefined {
  if (e.status !== 'false_positive') return undefined;
  return e.comment ?? (e.reason === null ? NO_REASON : undefined);
}

/**
 * The OpenVEX `status_notes`: who decided, after the comment of an Open decision (D8-3), which has
 * no other field to go in.
 */
function openVexNotes(e: VexEntry): string | undefined {
  const notes = [
    ...(e.status === 'open' && e.comment !== null ? [e.comment] : []),
    ...(e.decidedBy === null ? [] : [`Decided by ${e.decidedBy}.`]),
  ];
  return notes.length === 0 ? undefined : notes.join(' ');
}

/**
 * An OpenVEX 0.2.0 document of a target, one statement per entry. Each package purl is also a
 * product of its own: Trivy matches an SBOM's findings against the package purls, not against the
 * project product, which it cannot see in a scanned SBOM file.
 */
export function buildOpenVex(doc: ExportDocument, entries: readonly VexEntry[]): object {
  const product = productId(doc.project, doc.target);
  const statements = entries.map((e) => {
    const impact = openVexImpact(e);
    const notes = openVexNotes(e);
    return {
      vulnerability: { name: e.vulnerabilityId },
      ...(e.decidedAt === null ? {} : { timestamp: e.decidedAt.toISOString() }),
      products: [
        {
          '@id': product,
          ...(e.purls.length === 0 ? {} : { subcomponents: e.purls.map((p) => ({ '@id': p })) }),
        },
        ...e.purls.map((p) => ({ '@id': p })),
      ],
      status: OPENVEX_STATUS[e.status],
      ...(e.status === 'false_positive' && e.reason !== null ? { justification: e.reason } : {}),
      ...(impact === undefined ? {} : { impact_statement: impact }),
      ...(e.status === 'wont_fix' ? { action_statement: e.comment ?? NO_ACTION } : {}),
      ...(notes === undefined ? {} : { status_notes: notes }),
    };
  });
  return {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${doc.serial}`,
    author: doc.organization,
    timestamp: doc.generatedAt.toISOString(),
    version: 1,
    tooling: `Qualor ${doc.toolVersion}`,
    statements,
  };
}
