import { contextHash, lineHash, splitSourceLines, type Report } from '@qualor/shared';

/**
 * Tracking stability fixtures (brief §7, data-model.md §8.3): one source file and the edits a
 * developer makes to it. Hashes are computed from the text exactly as the CLI does
 * (report-format.md §7.3), so these exercise the real fingerprint inputs, not made-up ones.
 */
export const BASE_SOURCE = `export interface Refund {
  amount: number;
  currency: string;
}

export function refundCap(orders: readonly Refund[]): number {
  let total = 0;
  for (const order of orders) {
    total += order.amount;
  }
  console.log(total);
  return total;
}

export function isLarge(refund: Refund): boolean {
  return refund.amount > 1000;
}
`;

/** The flagged line in {@link BASE_SOURCE}: `console.log(total);` (1-based). */
export const FLAGGED_LINE = 11;

/** A finding on `line` of `source` (text, or its lines already split), with the CLI's hashes. */
export function sourceFinding(
  path: string,
  source: string | readonly string[],
  line: number,
  rule: { engineId?: string; ruleId?: string; message?: string } = {},
): Report['findings'][number] {
  const lines = typeof source === 'string' ? splitSourceLines(source) : source;
  return {
    engineId: rule.engineId ?? 'eslint',
    ruleId: rule.ruleId ?? 'no-console',
    message: rule.message ?? 'Unexpected console statement.',
    severity: 'medium',
    location: { path, startLine: line, startColumn: 3, endLine: line, endColumn: 22 },
    lineHash: lineHash(lines, line, line),
    contextHash: contextHash(lines, line, line),
    snippet: {
      startLine: Math.max(1, line - 3),
      lines: lines.slice(Math.max(0, line - 4), line + 3),
    },
  };
}

function insertAbove(source: string, count: number): string {
  const inserted = Array.from({ length: count }, (_, i) => `// inserted line ${i + 1}`);
  return `${inserted.join('\n')}\n${source}`;
}

export interface StabilityCase {
  name: string;
  path: string;
  source: string;
  /** Where the flagged line is after the edit; null when the code was deleted. */
  line: number | null;
  renames?: Report['scm']['renames'];
  /** true: the issue keeps its id; false: it is closed. */
  keepsId: boolean;
}

export const STABILITY_CASES: readonly StabilityCase[] = [
  ...[1, 20, 500].map((n) => ({
    name: `${n} line(s) inserted above`,
    path: 'src/refunds.ts',
    source: insertAbove(BASE_SOURCE, n),
    line: FLAGGED_LINE + n,
    keepsId: true,
  })),
  {
    name: 'lines removed above (the Refund interface)',
    path: 'src/refunds.ts',
    source: BASE_SOURCE.split('\n').slice(5).join('\n'),
    line: FLAGGED_LINE - 5,
    keepsId: true,
  },
  {
    name: 'whitespace reformatted (4-space indent)',
    path: 'src/refunds.ts',
    source: BASE_SOURCE.replace(/^( +)/gm, (spaces) => ' '.repeat(spaces.length * 2)),
    line: FLAGGED_LINE,
    keepsId: true,
  },
  {
    name: 'file renamed',
    path: 'src/payments/refunds.ts',
    source: BASE_SOURCE,
    line: FLAGGED_LINE,
    renames: [{ from: 'src/refunds.ts', to: 'src/payments/refunds.ts' }],
    keepsId: true,
  },
  {
    name: 'flagged line edited in place (pass 3)',
    path: 'src/refunds.ts',
    source: BASE_SOURCE.replace('console.log(total);', "console.log('total', total);"),
    line: FLAGGED_LINE,
    keepsId: true,
  },
  {
    name: 'file renamed and the flagged line edited in the same analysis',
    path: 'src/payments/refunds.ts',
    source: BASE_SOURCE.replace('console.log(total);', 'console.log(total, orders);'),
    line: FLAGGED_LINE,
    renames: [{ from: 'src/refunds.ts', to: 'src/payments/refunds.ts' }],
    keepsId: true,
  },
  {
    name: 'flagged code deleted',
    path: 'src/refunds.ts',
    source: BASE_SOURCE.replace('  console.log(total);\n', ''),
    line: null,
    keepsId: false,
  },
];
