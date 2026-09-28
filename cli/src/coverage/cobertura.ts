import type { ParsedCoverage } from './lcov';
import { recordFor, type CoverageRecord } from './model';
import { parseXmlFile } from './xml';

const CONDITIONS = /\((\d+)\/(\d+)\)/;

/**
 * Cobertura XML: `class@filename` names the file; only `class > lines > line` counts (method
 * lines repeat them). `condition-coverage="50% (1/2)"` gives covered/total conditions.
 */
export async function parseCobertura(absPath: string): Promise<ParsedCoverage> {
  const files = new Map<string, CoverageRecord>();
  const sourceDirs: string[] = [];
  let record: CoverageRecord | null = null;
  let source: string | null = null;
  await parseXmlFile(absPath, {
    open(name, attrs, parents) {
      const parent = parents.at(-1);
      if (name === 'source' && parent === 'sources') {
        source = '';
      } else if (name === 'class') {
        const filename = attrs['filename'];
        record = filename === undefined || filename === '' ? null : recordFor(files, filename);
      } else if (name === 'line' && parent === 'lines' && parents.at(-2) === 'class' && record !== null) {
        const line = Number(attrs['number']);
        record.hit(line, Number(attrs['hits'] ?? '0'));
        // Coverlet writes .NET's Boolean.ToString(): branch="True" (plan 2D).
        if (attrs['branch']?.toLowerCase() === 'true') {
          const m = CONDITIONS.exec(attrs['condition-coverage'] ?? '');
          if (m !== null) record.branch(line, Number(m[2]), Number(m[1]));
        }
      }
    },
    close(name) {
      if (name === 'source' && source !== null) {
        const dir = source.trim();
        if (dir !== '') sourceDirs.push(dir);
        source = null;
      } else if (name === 'class') {
        record = null;
      }
    },
    text(text, parents) {
      if (source !== null && parents.at(-1) === 'source') source += text;
    },
  });
  return { files, sourceDirs };
}
