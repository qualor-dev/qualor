// Fake `trivy` for tests: node fake-trivy.mjs <mode> sbom ... -o <out> <in>
// Modes: ok (recorded output), echo (reports its arguments and environment), sleep, garbage, fail,
// flood (writes 2 KiB of output, then keeps running). Its output is what the server's lean template
// (trivy.ts TRIVY_LEAN_TEMPLATE) makes Trivy write: one JSON object per line and vulnerability.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const [, , mode, ...args] = process.argv;
const out = args[args.indexOf('-o') + 1];
const input = args[args.length - 1];

/** The lean template's line for one entry of Trivy's JSON report. */
const lean = (v) =>
  JSON.stringify({
    VulnerabilityID: v.VulnerabilityID,
    PkgIdentifier: { BOMRef: v.PkgIdentifier?.BOMRef ?? '', PURL: v.PkgIdentifier?.PURL ?? '' },
    Severity: v.Severity ?? '',
    Title: v.Title ?? '',
    FixedVersion: v.FixedVersion ?? '',
    PrimaryURL: v.PrimaryURL ?? '',
    PublishedDate: v.PublishedDate ?? null,
    VendorIDs: v.VendorIDs ?? null,
  }) + '\n';
/** A Trivy JSON report as the lean template writes it. */
const leanReport = (doc) =>
  (doc.Results ?? []).flatMap((r) => (r.Vulnerabilities ?? []).map(lean)).join('');

if (mode === 'sleep') {
  setTimeout(() => {}, 60_000);
} else if (mode === 'flood') {
  writeFileSync(out, 'x'.repeat(2048));
  setTimeout(() => {}, 60_000);
} else if (mode === 'fail') {
  process.stderr.write('FATAL fake failure\n');
  process.exit(1);
} else if (mode === 'garbage') {
  writeFileSync(out, 'this is not json');
} else if (mode === 'echo') {
  const seen = {
    args,
    env: process.env,
    inputIsSbom: JSON.parse(readFileSync(input, 'utf8')).bomFormat === 'CycloneDX',
  };
  const doc = {
    SchemaVersion: 2,
    Results: [
      {
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-0000-0000',
            Severity: 'LOW',
            Title: JSON.stringify(seen),
            PkgIdentifier: { PURL: 'echo' },
          },
        ],
      },
    ],
  };
  writeFileSync(out, leanReport(doc));
} else {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const report = readFileSync(
    path.join(here, '../src/vulnerabilities/__fixtures__/trivy-sbom-output.json'),
    'utf8',
  );
  writeFileSync(out, leanReport(JSON.parse(report)));
}
