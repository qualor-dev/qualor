import type { PomElement } from '@qualor/shared/fix';
import { SaxesParser } from 'saxes';

/**
 * Formatting-keeping edits of a `pom.xml` (spec §6.5, §11.3): the text of one element is replaced
 * where it stands, and a managed `<dependency>` is inserted as text at the indentation and line
 * ending around it, so every other byte stays (comments, the property block, CRLF, a byte order
 * mark). Positions come from saxes, which expands no external entity and refuses a DOCTYPE, as
 * Task 4's `readPom` does.
 */

/** A span of the text: `start` inclusive, `end` exclusive (JavaScript string indexes). */
export interface XmlSpan {
  start: number;
  end: number;
}

/** One element and where it stands in the text (byte order mark excluded). */
interface Located {
  element: PomElement;
  name: string;
  /** Where its start tag begins. */
  tagStart: number;
  /** After its start tag's `>`. */
  contentStart: number;
  /** Where its end tag begins (`contentStart` for a self-closing element). */
  contentEnd: number;
  /** After its end tag (or its self-closing tag). */
  end: number;
  selfClosing: boolean;
  /** A child element, comment or processing instruction inside it: not plain text. */
  mixed: boolean;
  children: Located[];
}

const BOM = '﻿';

/** Java's `String.trim()`, as Task 4's reader trims an element's text. */
function javaTrim(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && text.charCodeAt(start) <= 0x20) start++;
  while (end > start && text.charCodeAt(end - 1) <= 0x20) end--;
  return text.slice(start, end);
}

function located(
  name: string,
  attributes: Record<string, string>,
  text: string,
  at: number,
  selfClosing: boolean,
): Located {
  return {
    element: { name, text: '', attributes: { ...attributes }, children: [] },
    name,
    tagStart: text.lastIndexOf('<', at - 1),
    contentStart: at,
    contentEnd: at,
    end: at,
    selfClosing,
    mixed: false,
    children: [],
  };
}

/** The elements of a text without a byte order mark; throws when it is not well formed. */
function locate(text: string): Located {
  const parser = new SaxesParser({ xmlns: false });
  const stack: Located[] = [];
  const texts: string[][] = [];
  let root: Located | null = null;
  const markMixed = () => {
    const top = stack.at(-1);
    if (top !== undefined) top.mixed = true;
  };
  parser.on('doctype', () => {
    throw new Error('a DOCTYPE in a pom');
  });
  parser.on('opentag', (tag) => {
    const at = parser.position;
    const node = located(tag.name, tag.attributes, text, at, tag.isSelfClosing);
    const parent = stack.at(-1);
    if (parent === undefined) root = node;
    else {
      parent.children.push(node);
      parent.element.children.push(node.element);
      parent.mixed = true;
    }
    stack.push(node);
    texts.push([]);
  });
  const addText = (t: string) => texts.at(-1)?.push(t);
  parser.on('text', addText);
  parser.on('cdata', addText);
  parser.on('comment', markMixed);
  parser.on('processinginstruction', markMixed);
  parser.on('closetag', () => {
    const node = stack.pop();
    const parts = texts.pop() ?? [];
    if (node === undefined) return;
    node.end = parser.position;
    node.contentEnd = node.selfClosing ? node.contentStart : text.lastIndexOf('</', node.end - 1);
    node.element.text = javaTrim(parts.join(''));
  });
  parser.write(text).close();
  if (root === null) throw new Error('no root element');
  return root;
}

/**
 * The first element at `path` (names from the root down) in document order whose parent `match`
 * accepts (any parent without `match`). The parent is read whole, so a `<dependency>` can be picked
 * by its `groupId` and `artifactId` in whatever order they come.
 */
function findAt(
  root: Located,
  path: readonly string[],
  match: ((el: PomElement) => boolean) | undefined,
): Located | undefined {
  if (root.name !== path[0]) return undefined;
  let level: { node: Located; parent: Located | null }[] = [{ node: root, parent: null }];
  for (const name of path.slice(1)) {
    level = level.flatMap(({ node }) =>
      node.children.filter((c) => c.name === name).map((c) => ({ node: c, parent: node })),
    );
  }
  return level.find(
    ({ parent }) => match === undefined || (parent !== null && match(parent.element)),
  )?.node;
}

/** The content of an element without white space up to U+0020 at either end. */
function trimmedContent(text: string, node: Located): XmlSpan {
  let start = node.contentStart;
  let end = node.contentEnd;
  while (start < end && text.charCodeAt(start) <= 0x20) start++;
  while (end > start && text.charCodeAt(end - 1) <= 0x20) end--;
  return { start, end };
}

/**
 * Where the text of the element at `path` stands (saxes positions, as indexes into `text`): its
 * content between its tags, trimmed as Java trims, a CDATA section included. `match` picks among
 * the candidates by the element's parent (see {@link findAt}). Null when no element matches, the
 * element is self-closing or holds a child element, a comment or a processing instruction (its text
 * cannot be replaced alone), or the text is not well-formed XML. A byte order mark is allowed.
 */
export function xmlTextSpan(
  text: string,
  path: readonly string[],
  match?: (el: PomElement) => boolean,
): XmlSpan | null {
  const bom = text.startsWith(BOM) ? BOM.length : 0;
  const body = text.slice(bom);
  let root: Located;
  try {
    root = locate(body);
  } catch {
    return null;
  }
  const found = findAt(root, path, match);
  if (found === undefined || found.selfClosing || found.mixed) return null;
  const span = trimmedContent(body, found);
  return { start: span.start + bom, end: span.end + bom };
}

const escapeXml = (value: string) =>
  value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');

/** `text` with the span replaced by `value`, escaped as XML text; nothing else changes. */
export function replaceXmlText(text: string, span: XmlSpan, value: string): string {
  return `${text.slice(0, span.start)}${escapeXml(value)}${text.slice(span.end)}`;
}

// ─── Adding a managed dependency ────────────────────────────────────────────

interface Entry {
  groupId: string;
  artifactId: string;
  version: string;
}

/** The line ending of the line at `at` (or of the last line), `\n` when the text has none. */
function lineEndingAt(text: string, at: number): string {
  let newline = text.indexOf('\n', at);
  if (newline < 0) newline = text.lastIndexOf('\n');
  return newline > 0 && text.charAt(newline - 1) === '\r' ? '\r\n' : '\n';
}

/** The white space before `at` on its line, or null when anything else comes before it there. */
function lineIndent(text: string, at: number): string | null {
  const lineStart = text.lastIndexOf('\n', at - 1) + 1;
  const before = text.slice(lineStart, at);
  return /^[ \t]*$/.test(before) ? before : null;
}

/** What one level of nesting adds: from the first child of `node` on a line of its own. */
function childUnit(text: string, node: Located): string | null {
  const outer = lineIndent(text, node.tagStart);
  for (const child of node.children) {
    const inner = lineIndent(text, child.tagStart);
    if (outer === null || inner === null) continue;
    if (inner.length > outer.length && inner.startsWith(outer)) return inner.slice(outer.length);
  }
  return null;
}

/** The file's indentation unit: the project's own, else that of its first nested level; else two spaces. */
function fileUnit(text: string, project: Located): string {
  const own = childUnit(text, project);
  if (own !== null) return own;
  for (const child of project.children) {
    const nested = childUnit(text, child);
    if (nested !== null) return nested;
  }
  return '  ';
}

const dependencyLines = (e: Entry, indent: string, unit: string): string[] => [
  `${indent}<dependency>`,
  `${indent}${unit}<groupId>${escapeXml(e.groupId)}</groupId>`,
  `${indent}${unit}<artifactId>${escapeXml(e.artifactId)}</artifactId>`,
  `${indent}${unit}<version>${escapeXml(e.version)}</version>`,
  `${indent}</dependency>`,
];

const listLines = (e: Entry, indent: string, unit: string): string[] => [
  `${indent}<dependencies>`,
  ...dependencyLines(e, indent + unit, unit),
  `${indent}</dependencies>`,
];

const sectionLines = (e: Entry, indent: string, unit: string): string[] => [
  `${indent}<dependencyManagement>`,
  ...listLines(e, indent + unit, unit),
  `${indent}</dependencyManagement>`,
];

type Block = (indent: string, unit: string) => string[];

/**
 * After an element: at the end of its line when only white space or one comment follows it there
 * (a comment stays with the element it follows), else right after it.
 */
function afterElement(text: string, node: Located): number {
  let lineEnd = text.indexOf('\n', node.end);
  if (lineEnd < 0) lineEnd = text.length;
  else if (text.charAt(lineEnd - 1) === '\r') lineEnd -= 1;
  const rest = text.slice(node.end, lineEnd).trim();
  const oneComment = rest.startsWith('<!--') && rest.indexOf('-->') === rest.length - 3;
  return rest === '' || oneComment ? lineEnd : node.end;
}

/** `block` as the last child of `parent`, at its last child's indentation. */
function appendChild(text: string, parent: Located, block: Block, fallbackUnit: string): string {
  const last = parent.children.at(-1);
  const parentIndent = lineIndent(text, parent.tagStart) ?? '';
  const nl = lineEndingAt(text, parent.contentStart);
  if (last !== undefined) {
    const indent = lineIndent(text, last.tagStart) ?? parentIndent + fallbackUnit;
    const unit = childUnit(text, last) ?? fallbackUnit;
    const at = afterElement(text, last);
    return `${text.slice(0, at)}${nl}${block(indent, unit).join(nl)}${text.slice(at)}`;
  }
  const lines = block(parentIndent + fallbackUnit, fallbackUnit).join(nl);
  if (parent.selfClosing) {
    // `<dependencies/>` or `<dependencies a="b" />`: the tag's last `/` is the one before `>`.
    const tag = text.slice(parent.tagStart, parent.end);
    const open = `${tag.slice(0, tag.lastIndexOf('/')).trimEnd()}>`;
    return `${text.slice(0, parent.tagStart)}${open}${nl}${lines}${nl}${parentIndent}</${parent.name}>${text.slice(parent.end)}`;
  }
  let at = parent.contentEnd;
  while (at > parent.contentStart && text.charCodeAt(at - 1) <= 0x20) at -= 1;
  return `${text.slice(0, at)}${nl}${lines}${nl}${parentIndent}${text.slice(parent.contentEnd)}`;
}

/** `block` before `node`: on lines of its own at the node's indentation when the node starts its line. */
function insertBefore(text: string, node: Located, block: Block, unit: string): string {
  const nl = lineEndingAt(text, node.tagStart);
  const indent = lineIndent(text, node.tagStart);
  if (indent === null) {
    return `${text.slice(0, node.tagStart)}${block('', unit).join(nl)}${nl}${text.slice(node.tagStart)}`;
  }
  const lineStart = node.tagStart - indent.length;
  return `${text.slice(0, lineStart)}${block(indent, unit).join(nl)}${nl}${text.slice(lineStart)}`;
}

const childNamed = (node: Located, name: string) => node.children.find((c) => c.name === name);

function insertManaged(text: string, project: Located, entry: Entry): string {
  const unit = fileUnit(text, project);
  const managed = childNamed(project, 'dependencyManagement');
  if (managed !== undefined) {
    const list = childNamed(managed, 'dependencies');
    if (list !== undefined) {
      return appendChild(text, list, (i, u) => dependencyLines(entry, i, u), unit);
    }
    return appendChild(text, managed, (i, u) => listLines(entry, i, u), unit);
  }
  const dependencies = childNamed(project, 'dependencies');
  const section: Block = (i, u) => sectionLines(entry, i, u);
  return dependencies === undefined
    ? appendChild(text, project, section, unit)
    : insertBefore(text, dependencies, section, unit);
}

/**
 * `text` with a managed `<dependency>` of `ga` (`groupId:artifactId`) at `version`: appended to the
 * project's `<dependencyManagement><dependencies>`, at the indentation of its last entry; the
 * missing `<dependencies>` or the whole section created (the section before the project's
 * `<dependencies>`, else after its last element), at the indentation and line ending around it. A
 * byte order mark is kept. Throws when the text is not a pom or `ga` is not `groupId:artifactId`.
 */
export function addManagedDependency(text: string, ga: string, version: string): string {
  const parts = ga.split(':');
  const [groupId = '', artifactId = ''] = parts;
  if (parts.length !== 2 || groupId === '' || artifactId === '') {
    throw new Error(`${ga} is not groupId:artifactId`);
  }
  const bom = text.startsWith(BOM) ? BOM : '';
  const body = text.slice(bom.length);
  const project = locate(body);
  if (project.name !== 'project') throw new Error('not a pom: the root element is not <project>');
  return `${bom}${insertManaged(body, project, { groupId, artifactId, version })}`;
}
