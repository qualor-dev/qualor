import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { recordFor, type BranchCounts, type CoverageRecord } from './model';

/** A parsed report, keyed by the paths written in it. */
export interface ParsedCoverage {
  files: Map<string, CoverageRecord>;
  /** Base directories named by the report (Cobertura `<source>`); empty for LCOV and JaCoCo. */
  sourceDirs: string[];
  /** Set when a parser stopped early on a limit; what was read so far is kept. */
  truncated?: boolean;
}

interface Current {
  record: CoverageRecord;
  branches: Map<number, BranchCounts>;
}

function finish(current: Current | null): void {
  if (current === null) return;
  for (const [line, b] of current.branches) current.record.branch(line, b.total, b.covered);
}

/** LCOV tracefile: `SF`, `DA:line,hits`, `BRDA:line,block,branch,taken` ('-' = not taken), `end_of_record`. */
export async function parseLcov(absPath: string): Promise<ParsedCoverage> {
  const files = new Map<string, CoverageRecord>();
  let current: Current | null = null;
  const lines = createInterface({
    input: createReadStream(absPath, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const raw of lines) {
    const line = raw.trim();
    if (line.startsWith('SF:')) {
      finish(current);
      current = { record: recordFor(files, line.slice(3)), branches: new Map() };
    } else if (line === 'end_of_record') {
      finish(current);
      current = null;
    } else if (current !== null && line.startsWith('DA:')) {
      const [l, h] = line.slice(3).split(',');
      current.record.hit(Number(l), Number(h));
    } else if (current !== null && line.startsWith('BRDA:')) {
      const parts = line.slice(5).split(',');
      const l = Number(parts[0]);
      if (!Number.isInteger(l)) continue;
      const counts = current.branches.get(l) ?? { total: 0, covered: 0 };
      counts.total++;
      const taken = parts[3];
      if (taken !== undefined && taken !== '-' && Number(taken) > 0) counts.covered++;
      current.branches.set(l, counts);
    }
  }
  finish(current);
  return { files, sourceDirs: [] };
}
