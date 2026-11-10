import type { VexJustification } from '../decisions';
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

/** The version of a purl: the part after the last `@`, without qualifiers, decoded. */
function purlVersion(purl: string): string | undefined {
  const at = purl.lastIndexOf('@');
  if (at < 0) return undefined;
  const raw = purl.slice(at + 1).split(/[?#]/)[0] ?? '';
  if (raw === '') return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

/** A CycloneDX 1.6 VEX of a target: its components, and one vulnerability per entry. */
export function buildCycloneDxVex(doc: ExportDocument, entries: readonly VexEntry[]): object {
  const root = productId(doc.project, doc.target);
  const components = new Map<string, object>();
  for (const e of entries) {
    for (const purl of e.purls) {
      if (components.has(purl)) continue;
      const version = purlVersion(purl);
      components.set(purl, {
        type: 'library',
        'bom-ref': purl,
        name: e.packageName,
        ...(version === undefined ? {} : { version }),
        purl,
      });
    }
  }
  const vulnerabilities = entries.map((e) => {
    const decided = e.decidedAt?.toISOString();
    const detail =
      e.comment ?? (e.status === 'false_positive' && e.reason === null ? NO_REASON : undefined);
    const analysis = {
      state: CYCLONEDX_STATE[e.status],
      ...(e.status === 'false_positive' && e.reason !== null
        ? { justification: CYCLONEDX_JUSTIFICATION[e.reason] }
        : {}),
      ...(e.status === 'wont_fix' ? { response: ['will_not_fix'] } : {}),
      ...(detail === undefined ? {} : { detail }),
      ...(decided === undefined ? {} : { firstIssued: decided, lastUpdated: decided }),
    };
    return {
      'bom-ref': `${e.vulnerabilityId}:${e.packageName}`,
      id: e.vulnerabilityId,
      source: TOOL,
      ratings: [{ severity: e.severity, source: TOOL }],
      ...(e.primaryUrl === null ? {} : { advisories: [{ url: e.primaryUrl }] }),
      ...(e.fixedVersion === null ? {} : { recommendation: `Upgrade to ${e.fixedVersion}.` }),
      analysis,
      affects: e.purls.map((ref) => ({ ref })),
      ...(e.decidedBy === null
        ? {}
        : { properties: [{ name: 'qualor:decided-by', value: e.decidedBy }] }),
    };
  });
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
      },
    },
    components: [...components.values()],
    vulnerabilities,
  };
}

/** An OpenVEX 0.2.0 document of a target, one statement per entry. */
export function buildOpenVex(doc: ExportDocument, entries: readonly VexEntry[]): object {
  const product = productId(doc.project, doc.target);
  const statements = entries.map((e) => {
    const impact =
      e.status === 'false_positive'
        ? (e.comment ?? (e.reason === null ? NO_REASON : undefined))
        : undefined;
    return {
      vulnerability: { name: e.vulnerabilityId },
      ...(e.decidedAt === null ? {} : { timestamp: e.decidedAt.toISOString() }),
      products: [
        {
          '@id': product,
          ...(e.purls.length === 0 ? {} : { subcomponents: e.purls.map((p) => ({ '@id': p })) }),
        },
      ],
      status: OPENVEX_STATUS[e.status],
      ...(e.status === 'false_positive' && e.reason !== null ? { justification: e.reason } : {}),
      ...(impact === undefined ? {} : { impact_statement: impact }),
      ...(e.status === 'wont_fix' ? { action_statement: e.comment ?? NO_ACTION } : {}),
      ...(e.decidedBy === null ? {} : { status_notes: `Decided by ${e.decidedBy}.` }),
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
