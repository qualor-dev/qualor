import type { LineUnit } from './tokens';

export interface DuplicationInput {
  path: string;
  units: readonly LineUnit[];
}

export interface DuplicationOptions {
  minTokens: number;
  minLines: number;
}

export interface DuplicationBlock {
  path: string;
  startLine: number;
  endLine: number;
}

export interface DuplicationGroup {
  blocks: DuplicationBlock[];
}

/** Units per index window: the smallest block (its first and last line) has two units. */
const WINDOW_UNITS = 2;
/** Windows seen more often than this are boilerplate (`}` `}`) and never seed a comparison. */
const MAX_WINDOW_OCCURRENCES = 64;
/** report-format §9 / reportSchema bounds. */
const MAX_BLOCKS = 1_000;
const MAX_GROUPS = 100_000;

interface Occurrence {
  file: number;
  unit: number;
}

class UnionFind {
  private readonly parent = new Map<string, string>();

  find(x: string): string {
    let root = x;
    for (let p = this.parent.get(root); p !== undefined && p !== root; p = this.parent.get(root)) {
      root = p;
    }
    this.parent.set(x, root);
    return root;
  }

  union(a: string, b: string): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent.set(rb, ra);
  }

  keys(): string[] {
    return [...this.parent.keys()];
  }
}

const blockKey = (b: DuplicationBlock) => `${b.startLine}:${b.endLine}:${b.path}`;

function parseBlockKey(key: string): DuplicationBlock {
  const first = key.indexOf(':');
  const second = key.indexOf(':', first + 1);
  return {
    path: key.slice(second + 1),
    startLine: Number(key.slice(0, first)),
    endLine: Number(key.slice(first + 1, second)),
  };
}

const byPosition = (x: DuplicationBlock, y: DuplicationBlock) =>
  x.path < y.path ? -1 : x.path > y.path ? 1 : x.startLine - y.startLine || x.endLine - y.endLine;

const contains = (outer: DuplicationBlock, inner: DuplicationBlock) =>
  outer.path === inner.path && outer.startLine <= inner.startLine && inner.endLine <= outer.endLine;

/** Ruling C4; see the "Duplication algorithm" notes of Task 6. */
export function detectDuplications(
  files: readonly DuplicationInput[],
  o: DuplicationOptions,
): DuplicationGroup[] {
  const index = new Map<string, Occurrence[]>();
  files.forEach((f, file) => {
    for (let unit = 0; unit + WINDOW_UNITS <= f.units.length; unit++) {
      let key = '';
      for (let k = 0; k < WINDOW_UNITS; k++) key += f.units[unit + k]?.hash ?? '';
      const list = index.get(key);
      if (list === undefined) index.set(key, [{ file, unit }]);
      else list.push({ file, unit });
    }
  });

  const same = (fa: number, ua: number, fb: number, ub: number) => {
    const a = files[fa]?.units[ua];
    const b = files[fb]?.units[ub];
    return a !== undefined && b !== undefined && a.hash === b.hash;
  };

  // Maximal runs already handled, per diagonal (file pair + unit offset).
  const covered = new Map<string, [number, number][]>();
  const groups = new UnionFind();

  for (const occurrences of index.values()) {
    if (occurrences.length < 2 || occurrences.length > MAX_WINDOW_OCCURRENCES) continue;
    for (let x = 0; x < occurrences.length; x++) {
      for (let y = x + 1; y < occurrences.length; y++) {
        const a = occurrences[x];
        const b = occurrences[y];
        if (a === undefined || b === undefined) continue;
        const diagonal = `${a.file}:${b.file}:${a.unit - b.unit}`;
        const runs = covered.get(diagonal) ?? [];
        if (runs.some(([s, e]) => a.unit >= s && a.unit < e)) continue;

        let ua = a.unit;
        let ub = b.unit;
        while (ua > 0 && ub > 0 && same(a.file, ua - 1, b.file, ub - 1)) {
          ua--;
          ub--;
        }
        let length = 0;
        while (same(a.file, ua + length, b.file, ub + length)) length++;
        runs.push([ua, ua + length]);
        covered.set(diagonal, runs);
        // A run longer than its own offset overlaps itself: periodic code, not a copy.
        if (a.file === b.file && length > Math.abs(ua - ub)) continue;
        if (length < WINDOW_UNITS) continue;

        const units = files[a.file]?.units ?? [];
        let start = ua;
        let end = ua + length - 1;
        let net = 0;
        for (let i = start; i <= end; i++) net += units[i]?.delta ?? 0;
        for (;;) {
          const last = units[end]?.delta ?? 0;
          const first = units[start]?.delta ?? 0;
          if (start < end && net < 0 && last < 0) {
            net -= last;
            end--;
          } else if (start < end && net > 0 && first > 0) {
            net -= first;
            start++;
          } else break;
        }
        let tokens = 0;
        for (let i = start; i <= end; i++) tokens += units[i]?.tokens ?? 0;
        const startLine = units[start]?.startLine ?? 0;
        const endLine = units[end]?.endLine ?? 0;
        if (tokens < o.minTokens || endLine - startLine + 1 < o.minLines) continue;

        const other = files[b.file]?.units ?? [];
        groups.union(
          blockKey({ path: files[a.file]?.path ?? '', startLine, endLine }),
          blockKey({
            path: files[b.file]?.path ?? '',
            startLine: other[ub + (start - ua)]?.startLine ?? 0,
            endLine: other[ub + (end - ua)]?.endLine ?? 0,
          }),
        );
      }
    }
  }

  const members = new Map<string, DuplicationBlock[]>();
  for (const key of groups.keys()) {
    const root = groups.find(key);
    const list = members.get(root);
    if (list === undefined) members.set(root, [parseBlockKey(key)]);
    else list.push(parseBlockKey(key));
  }
  const all = [...members.values()];
  const byPath = new Map<string, { block: DuplicationBlock; group: number }[]>();
  all.forEach((blocks, group) => {
    for (const block of blocks) {
      const list = byPath.get(block.path);
      if (list === undefined) byPath.set(block.path, [{ block, group }]);
      else list.push({ block, group });
    }
  });
  // Drop a group when one other group has, for each of its blocks, a block containing it.
  const kept = all.filter((blocks, group) => {
    const first = blocks[0];
    if (first === undefined) return false;
    const candidates = new Set(
      (byPath.get(first.path) ?? [])
        .filter((e) => e.group !== group && contains(e.block, first))
        .map((e) => e.group),
    );
    return ![...candidates].some((h) =>
      blocks.every((b) => (all[h] ?? []).some((c) => contains(c, b))),
    );
  });
  return kept
    .map((blocks) => ({ blocks: blocks.sort(byPosition).slice(0, MAX_BLOCKS) }))
    .sort((g, h) => {
      const x = g.blocks[0];
      const y = h.blocks[0];
      return x === undefined || y === undefined ? 0 : byPosition(x, y);
    })
    .slice(0, MAX_GROUPS);
}
