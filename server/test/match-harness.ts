import type { Trackable } from '../src/tracking/match';

/**
 * A randomized model of "one file, analysed twice" for the matcher's property test
 * (match.property.test.ts; U5 fix round 4). A file is a list of lines of tokens; two token kinds
 * are "flagged" by two rules. Every token has a unique id that survives edits, so the true
 * identity of every finding is known: the ground truth the matcher is scored against.
 *
 * Hashes follow report-format.md §7.3 in spirit: whitespace-free line text (`lineHash`) and the
 * whitespace-free text of lines −2..+2 (`contextHash`), kept as plain strings (the matcher only
 * compares them for equality). A tiny vocabulary makes duplicate lines, same-line twins and
 * hash collisions common — exactly the cases where pairing order matters.
 */

export interface TruthFinding extends Trackable {
  /** Id of the flagged token: equal ids on both sides are the same finding. */
  token: number;
}

export interface HarnessCase {
  before: string[];
  after: string[];
  /** Findings of the edited file. */
  findings: TruthFinding[];
  /** Findings of the original file, as candidate issues (some randomly `closed`). */
  candidates: TruthFinding[];
}

/** A small deterministic LCG, so every seed always yields the same cases. `Math.imul` keeps the
 *  multiply in 32-bit integers (a plain `*` exceeds 2^53, loses low bits and cycles after ~10k). */
export function rng(seed: number): { next: () => number; int: (n: number) => number } {
  let state = seed;
  const next = (): number => {
    state = (Math.imul(state, 1103515245) + 12345) & 0x7fffffff;
    return state / 0x80000000;
  };
  return { next, int: (n) => Math.floor(next() * n) };
}

interface Token {
  id: number;
  text: string;
}

interface Line {
  indent: number;
  tokens: Token[];
  /** Whitespace before each token (the first entry is unused). */
  gaps: string[];
}

const FLAGGED = ['X', 'Y'];
const VOCABULARY = ['a', 'b', '(', ')', 'X', 'Y', 'X', ';'];
const TEMPLATES = [
  ['X', '(', 'a', ')'],
  ['X', ';'],
  ['a', 'X', 'b', 'X'],
  ['Y', 'X'],
  ['b', ';'],
  ['X', 'Y', 'X'],
  ['a'],
];

const textOf = (line: Line): string =>
  ' '.repeat(line.indent) +
  line.tokens.map((t, i) => (i > 0 ? line.gaps[i] : '') + t.text).join('');

const normalise = (s: string): string => s.replace(/\s/g, '');

function findingsOf(file: Line[]): TruthFinding[] {
  const texts = file.map(textOf);
  const out: TruthFinding[] = [];
  file.forEach((line, li) => {
    let column = line.indent + 1;
    line.tokens.forEach((token, i) => {
      if (i > 0) column += line.gaps[i]!.length;
      if (FLAGGED.includes(token.text)) {
        out.push({
          ruleKey: token.text === 'X' ? 'rule-x' : 'rule-y',
          path: 'a.ts',
          lineHash: normalise(texts[li]!),
          contextHash: texts
            .slice(Math.max(0, li - 2), li + 3)
            .map(normalise)
            .join('\n'),
          line: li + 1,
          column,
          message: `flagged ${token.text}`,
          closed: false,
          token: token.id,
        });
      }
      column += token.text.length;
    });
  });
  return out;
}

/** Generates `count` cases from `seed`: a random file, then 1–4 random edits to it (inserting,
 *  deleting or moving lines, re-indenting a line or a block, changing whitespace or tokens). */
export function generateCases(seed: number, count: number): HarnessCase[] {
  const { next, int } = rng(seed);
  const pick = <T>(items: readonly T[]): T => items[int(items.length)]!;
  let nextId = 1;
  const makeLine = (): Line => {
    const texts =
      next() < 0.7 ? pick(TEMPLATES) : Array.from({ length: 1 + int(4) }, () => pick(VOCABULARY));
    return {
      indent: pick([0, 2, 4]),
      tokens: texts.map((text) => ({ id: nextId++, text })),
      gaps: texts.map(() => ' '),
    };
  };
  const edit = (file: Line[]): Line[] => {
    const f = file.map((l) => ({ indent: l.indent, tokens: [...l.tokens], gaps: [...l.gaps] }));
    const edits = 1 + int(4);
    for (let e = 0; e < edits; e++) {
      const op = int(8);
      const at = int(f.length + 1);
      const line = (): Line => f[Math.min(at, f.length - 1)]!;
      if (op === 0 || f.length === 0) {
        f.splice(at, 0, ...Array.from({ length: 1 + int(3) }, makeLine)); // insert lines
      } else if (op === 1) {
        f.splice(Math.min(at, f.length - 1), 1 + int(2)); // delete lines
      } else if (op === 2) {
        line().indent = pick([0, 2, 4, 6, 8]); // re-indent a line
      } else if (op === 3) {
        const l = line();
        l.gaps[int(l.gaps.length)] = pick(['', ' ', '  ']); // change inner whitespace
      } else if (op === 4) {
        const l = line();
        const i = int(l.tokens.length + 1);
        l.tokens.splice(i, 0, { id: nextId++, text: pick(['a', 'b', ';']) }); // insert a token
        l.gaps.splice(i, 0, ' ');
      } else if (op === 5) {
        const l = line();
        const i = int(l.tokens.length);
        if (l.tokens.length > 1) {
          l.tokens.splice(i, 1); // delete a token (possibly a flagged one)
          l.gaps.splice(i, 1);
        }
      } else if (op === 6) {
        const from = Math.min(at, f.length - 1);
        const by = pick([2, 4, -2]);
        for (const l of f.slice(from, from + 2 + int(3))) l.indent = Math.max(0, l.indent + by); // re-indent a block
      } else {
        const block = f.splice(Math.min(at, f.length - 1), 1 + int(3)); // move a block
        f.splice(int(f.length + 1), 0, ...block);
      }
    }
    return f;
  };
  const cases: HarnessCase[] = [];
  for (let c = 0; c < count; c++) {
    const before = Array.from({ length: 4 + int(10) }, makeLine);
    const after = edit(before);
    const candidates = findingsOf(before);
    const findings = findingsOf(after);
    if (next() < 0.2) {
      for (const candidate of candidates) if (next() < 0.3) candidate.closed = true;
    }
    cases.push({ before: before.map(textOf), after: after.map(textOf), findings, candidates });
  }
  return cases;
}

/**
 * Identity errors: a finding matched to a candidate with a different token, while its own true
 * candidate exists, or the candidate's own true finding exists — a swap or a steal (pairing a
 * genuinely new finding with a genuinely gone issue is not counted: nothing better existed).
 */
export function identityErrors(
  findings: readonly TruthFinding[],
  candidates: readonly TruthFinding[],
  matched: ReadonlyMap<number, number>,
): number {
  const findingTokens = new Set(findings.map((f) => f.token));
  const candidateTokens = new Set(candidates.map((c) => c.token));
  let errors = 0;
  for (const [f, c] of matched) {
    const own = findings[f]!.token;
    const other = candidates[c]!.token;
    if (own !== other && (candidateTokens.has(own) || findingTokens.has(other))) errors++;
  }
  return errors;
}

/** The pass keys of data-model.md §5.2 (pass 0 included), for {@link strandedPairs}. */
const PASS_KEYS: readonly ((t: Trackable) => string)[] = [
  (t) => `${t.lineHash}|${t.contextHash}|${t.message}`,
  (t) => `${t.lineHash}|${t.contextHash}`,
  (t) => t.lineHash,
  (t) => `${t.line}|${t.message}`,
  (t) => t.contextHash,
];

/** Unmatched findings that share some pass's bucket with a still-unmatched candidate. */
export function strandedPairs(
  findings: readonly Trackable[],
  candidates: readonly Trackable[],
  matched: ReadonlyMap<number, number>,
): number {
  const taken = new Set(matched.values());
  let stranded = 0;
  for (const key of PASS_KEYS) {
    const open = new Set<string>();
    candidates.forEach((c, i) => {
      if (!taken.has(i)) open.add(`${c.ruleKey}|${c.path}|${key(c)}`);
    });
    findings.forEach((f, i) => {
      if (!matched.has(i) && open.has(`${f.ruleKey}|${f.path}|${key(f)}`)) stranded++;
    });
  }
  return stranded;
}
