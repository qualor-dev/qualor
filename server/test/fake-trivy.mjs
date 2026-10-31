// Fake `trivy` for tests: node fake-trivy.mjs <mode> sbom ... -o <out> <in>
// Modes: ok (recorded output), echo (reports its arguments and environment), sleep, garbage, fail.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const [, , mode, ...args] = process.argv;
const out = args[args.indexOf('-o') + 1];
const input = args[args.length - 1];

if (mode === 'sleep') {
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
  writeFileSync(out, JSON.stringify(doc));
} else {
  const here = path.dirname(fileURLToPath(import.meta.url));
  writeFileSync(
    out,
    readFileSync(path.join(here, '../src/vulnerabilities/__fixtures__/trivy-sbom-output.json')),
  );
}
