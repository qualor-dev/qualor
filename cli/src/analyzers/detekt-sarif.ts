import { pathToFileURL } from 'node:url';
import {
  detektRuleId,
  sarifLogSchema,
  type SarifLocation,
  type SarifLog,
  type SarifResult,
  type SarifRule,
} from '@qualor/shared';

/** The rule-id parser the `ext-detekt` pairing uses too (plan 8E ruling E5). */
export { detektRuleId };

/** The base id detekt 1.23 gives every location when `--base-path` is set. */
const SRCROOT = '%SRCROOT%';

function rule(r: SarifRule): SarifRule {
  const id = detektRuleId(r.id);
  return id === null
    ? r
    : { ...r, id: id.rule, properties: { ...r.properties, ruleset: id.ruleset } };
}

/** A URI with a scheme and an authority, which detekt never writes against `%SRCROOT%`. */
const ABSOLUTE_URI = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * detekt writes the path relative to `--base-path` unencoded (`src/A b.kt`, `100%.kt`), but the
 * normaliser decodes a relative URI: each segment is percent-encoded, so it decodes to the same
 * name.
 */
function encodedLocation(l: SarifLocation): SarifLocation {
  const artifact = l.physicalLocation?.artifactLocation;
  const uri = artifact?.uri;
  // Only detekt's relative paths; a `:` in a file name is encoded too, never read as a scheme.
  if (artifact?.uriBaseId !== SRCROOT || uri === undefined || ABSOLUTE_URI.test(uri)) return l;
  return {
    ...l,
    physicalLocation: {
      ...l.physicalLocation,
      artifactLocation: { ...artifact, uri: uri.split('/').map(encodeURIComponent).join('/') },
    },
  };
}

function result(r: SarifResult, rebase: boolean): SarifResult {
  const id = r.ruleId === undefined ? null : detektRuleId(r.ruleId);
  const out = id === null ? r : { ...r, ruleId: id.rule };
  if (!rebase) return out;
  return {
    ...out,
    ...(out.locations !== undefined && { locations: out.locations.map(encodedLocation) }),
    ...(out.relatedLocations !== undefined && {
      relatedLocations: out.relatedLocations.map(encodedLocation),
    }),
  };
}

/**
 * report-format.md §5: detekt's rule names are unique across its rule sets, so the rule key is
 * `detekt:<Rule>`; the rule set moves to `properties.ruleset`, which the shared mapping reads.
 *
 * With `root`, the locations are moved from the copy detekt read (its `--base-path`) onto the
 * repository: the `%SRCROOT%` base becomes the root's URI, and the copy mirrors the repository's
 * layout, so every relative path stays the same.
 */
export function detektSarif(output: unknown, root?: string): SarifLog {
  const log = sarifLogSchema.parse(output);
  const rebase = root !== undefined;
  return {
    ...log,
    runs: log.runs.map((run) => ({
      ...run,
      ...(rebase && {
        originalUriBaseIds: {
          ...run.originalUriBaseIds,
          [SRCROOT]: { uri: `${pathToFileURL(root).href.replace(/\/$/, '')}/` },
        },
      }),
      tool: {
        ...run.tool,
        driver: {
          ...run.tool.driver,
          ...(run.tool.driver.rules !== undefined && { rules: run.tool.driver.rules.map(rule) }),
        },
      },
      ...(run.results !== undefined && { results: run.results.map((r) => result(r, rebase)) }),
    })),
  };
}
