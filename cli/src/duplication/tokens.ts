import { createHash } from 'node:crypto';
import type { Node } from 'web-tree-sitter';
import { FAMILY_RULES, type SyntaxFamily } from '../metrics/rules';

/** One source line's tokens: the unit the duplication detector compares (ruling C4). */
export interface LineUnit {
  startLine: number;
  /** Last line touched by a token that starts on `startLine` (multi-line strings). */
  endLine: number;
  tokens: number;
  /** Opening minus closing brackets: `( [ { ${` count +1, `) ] }` count -1. */
  delta: number;
  /** First 16 hex characters of SHA-256 over the token texts joined with U+0000. */
  hash: string;
}

const OPENERS = new Set(['(', '[', '{', '${']);
const CLOSERS = new Set([')', ']', '}']);

interface PendingLine {
  line: number;
  endLine: number;
  texts: string[];
  delta: number;
}

/** report-format §8: tokens are tree-sitter leaves; comments removed; identifiers and literals verbatim. */
export function lineUnits(root: Node, family: SyntaxFamily): LineUnit[] {
  const comments = FAMILY_RULES[family].comments;
  const byLine = new Map<number, PendingLine>();
  const stack: Node[] = [root];
  for (let node = stack.pop(); node !== undefined; node = stack.pop()) {
    if (comments.has(node.type)) continue;
    const count = node.childCount;
    if (count > 0) {
      for (let i = count - 1; i >= 0; i--) {
        const child = node.child(i);
        if (child !== null) stack.push(child);
      }
      continue;
    }
    if (node.endIndex <= node.startIndex) continue;
    const text = node.text;
    if (text.trim() === '') continue;
    const line = node.startPosition.row + 1;
    let pending = byLine.get(line);
    if (pending === undefined) {
      pending = { line, endLine: line, texts: [], delta: 0 };
      byLine.set(line, pending);
    }
    pending.texts.push(text);
    pending.endLine = Math.max(pending.endLine, node.endPosition.row + 1);
    if (OPENERS.has(node.type)) pending.delta++;
    else if (CLOSERS.has(node.type)) pending.delta--;
  }
  return [...byLine.values()]
    .sort((a, b) => a.line - b.line)
    .map((p) => ({
      startLine: p.line,
      endLine: p.endLine,
      tokens: p.texts.length,
      delta: p.delta,
      hash: createHash('sha256').update(p.texts.join('\u0000'), 'utf8').digest('hex').slice(0, 16),
    }));
}
