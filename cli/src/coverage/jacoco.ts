import type { ParsedCoverage } from './lcov';
import { recordFor, type CoverageRecord } from './model';
import { parseXmlFile } from './xml';

function count(value: string | undefined): number {
  const n = Number(value ?? '0');
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * JaCoCo XML: `package@name` + `sourcefile@name` form the path (e.g. `com/acme/Calculator.java`,
 * resolved to `src/main/java/…` by suffix). A line is executable when it has instructions
 * (`mi + ci > 0`) and covered when `ci > 0`; branches are `mb + cb`, covered `cb`.
 */
export async function parseJacoco(absPath: string): Promise<ParsedCoverage> {
  const files = new Map<string, CoverageRecord>();
  let pkg = '';
  let record: CoverageRecord | null = null;
  await parseXmlFile(absPath, {
    open(name, attrs, parents) {
      if (name === 'package') {
        pkg = attrs['name'] ?? '';
      } else if (name === 'sourcefile') {
        const file = attrs['name'];
        record = file === undefined || file === '' ? null : recordFor(files, pkg === '' ? file : `${pkg}/${file}`);
      } else if (name === 'line' && parents.at(-1) === 'sourcefile' && record !== null) {
        const line = Number(attrs['nr']);
        const mi = count(attrs['mi']);
        const ci = count(attrs['ci']);
        const mb = count(attrs['mb']);
        const cb = count(attrs['cb']);
        if (mi + ci > 0) record.hit(line, ci);
        if (mb + cb > 0) record.branch(line, mb + cb, cb);
      }
    },
    close(name) {
      if (name === 'package') pkg = '';
      else if (name === 'sourcefile') record = null;
    },
  });
  return { files, sourceDirs: [] };
}
