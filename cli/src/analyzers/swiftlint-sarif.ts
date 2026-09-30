import {
  sarifLogSchema,
  type SarifLocation,
  type SarifLog,
  type SarifResult,
} from '@qualor/shared';

/** A URI with a scheme and an authority (`file:///…`), which SwiftLint never writes for the copy. */
const ABSOLUTE_URI = /^[a-z][a-z0-9+.-]*:\/\//i;

/**
 * SwiftLint 0.65.1 writes the path relative to its working directory raw (`a b#ü.swift`,
 * `100%.swift`, `a:b.swift`), but the normaliser decodes a relative URI and reads `a:` as a
 * scheme: each segment is percent-encoded, so it decodes to the same name (fix round 1,
 * Important 1, as detekt-sarif.ts does). A leading `/` (a path outside the copy) is left alone.
 */
function encodedLocation(l: SarifLocation): SarifLocation {
  const artifact = l.physicalLocation?.artifactLocation;
  const uri = artifact?.uri;
  if (uri === undefined || uri.startsWith('/') || ABSOLUTE_URI.test(uri)) return l;
  return {
    ...l,
    physicalLocation: {
      ...l.physicalLocation,
      artifactLocation: { ...artifact, uri: uri.split('/').map(encodeURIComponent).join('/') },
    },
  };
}

function result(r: SarifResult): SarifResult {
  return {
    ...r,
    ...(r.locations !== undefined && { locations: r.locations.map(encodedLocation) }),
    ...(r.relatedLocations !== undefined && {
      relatedLocations: r.relatedLocations.map(encodedLocation),
    }),
  };
}

/** SwiftLint's SARIF with every relative location URI percent-encoded by segment. */
export function swiftlintSarif(output: unknown): SarifLog {
  const log = sarifLogSchema.parse(output);
  return {
    ...log,
    runs: log.runs.map((run) => ({
      ...run,
      ...(run.results !== undefined && { results: run.results.map(result) }),
    })),
  };
}
