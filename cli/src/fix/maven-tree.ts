import { sameVersion, scrubToolOutput } from '@qualor/shared/fix';
import type { FixStop } from './adapter';
import type { ToolResult } from './runner';

/**
 * The text of `mvn -B dependency:tree -Dincludes=… -DoutputType=text` (Ruling F16, T15k): the
 * trees of a reactor, one node's place in its tree, and the artifacts Maven reports missing.
 */

const INFO = '[INFO] ';
/** `--- dependency:3.8.1:tree (default-cli) @ app ---` (Maven 3.9; 3.8 names maven-dependency-plugin). */
const GOAL_HEADER = /^--- \S+:tree \([^)]*\) @ \S+ ---$/;
/** A module's own line, the tree's root: `groupId:artifactId:packaging:version`. */
const MODULE_LINE = /^[^\s:]+:[^\s:]+:[^\s:]+:\S+$/;
/** `|  +- g:a:type:version:scope`: three characters per level above, then `+- ` or `\- `. */
const NODE_LINE = /^((?:\| {2}| {3})*)[+\\]- (\S+)/;

/** One node of a module's tree (depth 1: a direct dependency). */
export interface TreeNode {
  ga: string;
  version: string;
  depth: number;
}

export interface ModuleTree {
  /** The module's `groupId:artifactId`. */
  module: string;
  nodes: TreeNode[];
}

/**
 * The tree output read line by line: after a goal header, Maven may log downloads and warnings
 * before the module's line; the tree's lines follow it without a break.
 */
interface TreeReader {
  modules: ModuleTree[];
  goals: number;
  state: 'idle' | 'module' | 'tree';
  /** The first line that looks like a tree line but cannot be one. */
  problem: string | null;
}

/** `g:a:type:version:scope` or `g:a:type:classifier:version:scope`. */
function nodeOf(coords: string, depth: number): TreeNode | null {
  const parts = coords.split(':');
  if (parts.length < 5 || parts.length > 6 || parts.some((p) => p === '')) return null;
  return { ga: `${parts[0]}:${parts[1]}`, version: parts.at(-2) ?? '', depth };
}

function readOther(r: TreeReader, body: string | null): void {
  if (r.state === 'module' && body !== null && MODULE_LINE.test(body)) {
    const [groupId, artifactId] = body.split(':');
    r.modules.push({ module: `${groupId}:${artifactId}`, nodes: [] });
    r.state = 'tree';
  } else if (r.state === 'tree') {
    r.state = 'idle';
  }
}

function readNode(r: TreeReader, match: RegExpExecArray, body: string): void {
  const node = nodeOf(match[2] ?? '', (match[1] ?? '').length / 3 + 1);
  const module = r.modules.at(-1);
  if (r.state !== 'tree' || module === undefined || node === null) {
    r.problem ??= body;
    return;
  }
  module.nodes.push(node);
}

function feed(r: TreeReader, line: string): void {
  const body = line.startsWith(INFO) ? line.slice(INFO.length) : null;
  if (body !== null && GOAL_HEADER.test(body)) {
    r.goals += 1;
    r.state = 'module';
    return;
  }
  const node = body === null ? null : NODE_LINE.exec(body);
  if (node === null || body === null) readOther(r, body);
  else readNode(r, node, body);
}

export const treeStop = (why: string): FixStop => ({
  kind: 'failure',
  code: 'package_manager',
  message: `\`mvn dependency:tree\` printed ${why}`,
});

/** Each module's tree in the output; a stop when it shows no tree or a line it cannot be. */
export function readTrees(stdout: string): ModuleTree[] | FixStop {
  const r: TreeReader = { modules: [], goals: 0, state: 'idle', problem: null };
  for (const line of stdout.split('\n')) feed(r, line.endsWith('\r') ? line.slice(0, -1) : line);
  if (r.problem !== null) {
    // B9: the line is tool output, scrubbed like a failure's tail.
    return treeStop(
      `a tree line Qualor cannot read: ${scrubToolOutput(r.problem.slice(0, 200), [])}`,
    );
  }
  if (r.goals === 0) {
    return treeStop(
      'no dependency tree; Qualor reads its [INFO] lines (does .mvn/maven.config pass -q?).',
    );
  }
  return r.modules;
}

/** A node of the package and the node that brings it (`g:a`; null for a direct one). */
export interface PackageNode {
  version: string;
  depth: number;
  parent: string | null;
}

export function packageNodes(tree: ModuleTree, ga: string): PackageNode[] {
  const found: PackageNode[] = [];
  tree.nodes.forEach((node, i) => {
    if (node.ga !== ga) return;
    const above = tree.nodes.slice(0, i).findLast((n) => n.depth === node.depth - 1);
    const parent = node.depth === 1 ? null : (above?.ga ?? null);
    found.push({ version: node.version, depth: node.depth, parent });
  });
  return found;
}

/** The `[ERROR]` lines up to the first empty one, which starts Maven's help text. */
function leadingErrors(lines: readonly string[]): string[] {
  const errors = lines.filter((l) => l.startsWith('[ERROR]'));
  const help = errors.findIndex((l, i) => i > 0 && l.trim() === '[ERROR]');
  return help < 0 ? errors : errors.slice(0, help);
}

/** What a failure message quotes: Maven's errors (else its warnings) and stderr; else all stdout. */
export function errorText(r: ToolResult): string {
  const lines = r.stdout.split(/\r?\n/);
  const errors = leadingErrors(lines);
  const own = errors.length > 0 ? errors : lines.filter((l) => l.startsWith('[WARNING]'));
  const text = [...own, r.stderr.trim()].filter((t) => t !== '').join('\n');
  return text === '' ? r.stdout : text;
}

/**
 * How Maven names an artifact it cannot find: a POM missing during the tree's collection (a
 * warning; the tree still shows the version), or a failed resolution.
 */
const MISSING: readonly { before: string; after: string }[] = [
  { before: 'The POM for ', after: ' is missing' },
  { before: 'Could not find artifact ', after: '' },
  { before: 'Failure to find ', after: '' },
];

/** The artifacts (`g:a:type[:classifier]:version`) the output reports missing. */
export function missingArtifacts(output: string): string[] {
  const found: string[] = [];
  for (const { before, after } of MISSING) {
    for (let at = output.indexOf(before); at >= 0; at = output.indexOf(before, at + 1)) {
      const start = at + before.length;
      let end = start;
      while (end < output.length && output.charCodeAt(end) > 0x20) end += 1;
      if (output.startsWith(after, end)) found.push(output.slice(start, end));
    }
  }
  return found;
}

/** Ruling F36: Maven reports a target version of the package itself missing. */
export function targetMissing(output: string, ga: string, targets: readonly string[]): boolean {
  return missingArtifacts(output).some((artifact) => {
    const parts = artifact.split(':');
    const version = parts.at(-1) ?? '';
    return (
      parts.length >= 4 &&
      `${parts[0]}:${parts[1]}` === ga &&
      targets.some((t) => sameVersion('maven', version, t))
    );
  });
}
