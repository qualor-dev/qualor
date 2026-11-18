/**
 * Yarn classic lockfiles (`# yarn lockfile v1`) as lock entries, by a line parser of blocks that
 * refuses what Yarn 1 could read differently (duplicate fields, odd indents) and what Yarn 1 does
 * not write (a block of several packages).
 */
import {
  inSlot,
  resolvedKind,
  specKind,
  splitDescriptor,
  unreadable,
  withDependents,
  type RawEntry,
  type ReadLock,
} from './lock-read';
import type { LockEntryKind } from './types';

/** Yarn breaks lines at `\r\n`, `\r` and `\n`. */
const LINE_BREAK = /\r\n|\r|\n/;

/** A JSON string, as Yarn quotes, or a bare token without space, quote, comma or colon. */
const TOKEN = /^(?:"(?:[^"\\]|\\.)*"|[^\s",:]+)/;
const PATTERN_SEPARATOR = /^, */;
const SPACES = /^ +/;

function unquote(token: string): string {
  return token.startsWith('"') ? String(JSON.parse(token)) : token;
}

interface ClassicBlock {
  patterns: string[];
  fields: Map<string, string>;
  /** Nested maps (`dependencies:`), by key: the names they list. */
  maps: Map<string, string[]>;
  /** The nested map the next 4-space lines belong to. */
  open: string[] | null;
}

interface ClassicLine {
  indent: number;
  text: string;
}

/** A line's indent (spaces only: 0, 2 or 4) and text; null for a blank or comment line. */
function classicLine(raw: string): ClassicLine | null {
  const line = raw.trimEnd();
  const text = line.trimStart();
  if (text === '' || text.startsWith('#')) return null;
  const indent = line.length - text.length;
  if (!/^ *$/.test(line.slice(0, indent)) || indent % 2 !== 0 || indent > 4) unreadable(raw);
  return { indent, text };
}

/** A block header: comma-separated patterns, then `:`. */
function classicHeader(text: string): ClassicBlock {
  if (!text.endsWith(':')) unreadable(text);
  const header = text.slice(0, -1);
  const patterns: string[] = [];
  let rest = header;
  for (;;) {
    const token = TOKEN.exec(rest) ?? unreadable(header);
    patterns.push(unquote(token[0]));
    rest = rest.slice(token[0].length);
    if (rest === '') return { patterns, fields: new Map(), maps: new Map(), open: null };
    rest = rest.slice((PATTERN_SEPARATOR.exec(rest) ?? unreadable(header))[0].length);
  }
}

/** `key value`, or `key:` that opens a nested map (value null). */
function classicPair(text: string): { key: string; value: string | null } {
  const key = TOKEN.exec(text) ?? unreadable(text);
  const rest = text.slice(key[0].length);
  if (rest === ':') return { key: unquote(key[0]), value: null };
  const valueText = rest.slice((SPACES.exec(rest) ?? unreadable(text))[0].length);
  const value = TOKEN.exec(valueText);
  if (value?.[0] !== valueText) unreadable(text);
  return { key: unquote(key[0]), value: unquote(valueText) };
}

/** A 2-space field or nested-map line, or a 4-space line of the open nested map. */
function classicBody(block: ClassicBlock, line: ClassicLine): void {
  const { key, value } = classicPair(line.text);
  if (line.indent === 4) {
    if (block.open === null || value === null) unreadable(line.text);
    block.open.push(key);
    return;
  }
  // Yarn keeps the last of two equal keys; refusing them keeps both readings the same.
  if (block.fields.has(key) || block.maps.has(key)) unreadable(line.text);
  block.open = value === null ? [] : null;
  if (block.open !== null) block.maps.set(key, block.open);
  if (value !== null) block.fields.set(key, value);
}

function classicBlocks(source: string): ClassicBlock[] {
  const blocks: ClassicBlock[] = [];
  for (const raw of source.split(LINE_BREAK)) {
    const line = classicLine(raw);
    if (line === null) continue;
    if (line.indent === 0) blocks.push(classicHeader(line.text));
    else classicBody(blocks.at(-1) ?? unreadable(raw), line);
  }
  return blocks;
}

interface ClassicPattern {
  /** The name the pattern declares (the slot). */
  slot: string;
  /** The package it holds: the slot, or the target of an `npm:<name>@<range>` alias. */
  name: string;
  range: string;
}

/** `name@range`, or an alias `slot@npm:<name>@<range>`. */
function classicPattern(pattern: string): ClassicPattern {
  const parts = splitDescriptor(pattern) ?? unreadable(pattern);
  if (!parts.range.startsWith('npm:')) return { slot: parts.name, ...parts };
  const target = parts.range.slice('npm:'.length);
  // Fix round 1: `npm:<name>` without a range is an alias of that name too (fail closed).
  const aliased = splitDescriptor(target) ?? { name: target, range: '' };
  return { slot: parts.name, name: aliased.name, range: aliased.range };
}

/** A range's own kind; a GitHub shorthand (`user/repo`) is git. */
function classicRangeKind(range: string): LockEntryKind | null {
  return specKind(range) ?? (range.includes('/') ? 'git' : null);
}

/** The first non-registry kind among a block's ranges; null when all are registry ranges. */
function rangesKind(ranges: readonly string[]): LockEntryKind | null {
  for (const range of ranges) {
    const kind = classicRangeKind(range);
    if (kind !== null) return kind;
  }
  return null;
}

/** The dependency maps of a block (Rulings T3e and T3l follow them all). */
const BLOCK_EDGES = ['dependencies', 'optionalDependencies'];

/**
 * The one package a block's patterns name, alias targets included. Yarn writes one block per
 * package, so a block that names several is unreadable (fix round 4, R4-1): its entries would
 * share one dependencies map between different packages.
 */
function blockPackage(block: ClassicBlock, patterns: readonly ClassicPattern[]): string {
  const name = patterns[0]?.name ?? unreadable('an empty block header');
  if (patterns.some((p) => p.name !== name)) unreadable(block.patterns.slice(0, 2).join(', '));
  return name;
}

/**
 * One block's entries: its package, once per slot its patterns declare, an alias pattern in its
 * own slot (fix round 1, C1). The kind comes from the block's ranges, then from `resolved` (T3b),
 * once per block.
 */
function blockEntries(block: ClassicBlock): RawEntry[] {
  const patterns = block.patterns.map(classicPattern);
  const name = blockPackage(block, patterns);
  const version = block.fields.get('version') ?? unreadable(name);
  const source = block.fields.get('resolved') ?? null;
  const rangeKind = rangesKind(patterns.map((p) => p.range));
  const raw: RawEntry = {
    name,
    version,
    source,
    kind: rangeKind ?? (source === null ? 'registry' : resolvedKind(source, name, version)),
    integrity: block.fields.get('integrity') ?? null,
    dependencies: BLOCK_EDGES.flatMap((key) => block.maps.get(key) ?? []),
  };
  return [...new Set(patterns.map((p) => p.slot))].map((slot) => inSlot(raw, slot));
}

/** Yarn classic: the entries of every block. The format is `yarn-classic`. */
export function parseYarnClassic(source: string): ReadLock {
  const entries = classicBlocks(source).flatMap(blockEntries);
  return { format: 'yarn-classic', entries: withDependents(entries) };
}

/** As Yarn decides it: a `# yarn lockfile v1` line among the leading comment lines. */
export function isYarnClassic(source: string): boolean {
  for (const line of source.split(LINE_BREAK, 64)) {
    if (!line.startsWith('#')) return false;
    if (/^#\s+yarn\s+lockfile\s+v1$/i.test(line)) return true;
  }
  return false;
}
