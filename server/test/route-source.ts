import { readdirSync, readFileSync } from 'node:fs';

/**
 * The route parser the sweeps share (rbac-audit.md §5): it finds every
 * `app.<method>('…')` of server/src/routes/ and reads it to the parenthesis that closes the call.
 */

const QUOTES = new Set(["'", '"']);
const BACKSLASH = '\\';
const BACKTICK = '`';

/**
 * The index just past the parenthesis that closes the call whose `(` is at `open`, or -1. Quoted
 * strings, template literals (with their `${…}` parts) and comments are skipped, so a bracket
 * inside them does not count (Task 8 M5).
 */
export function closingParen(source: string, open: number): number {
  let depth = 0;
  /** For each open `${` of a template literal: the bracket depth at which it started. */
  const templates: number[] = [];
  let i = open;
  /** Skips template text from `i` to its closing backtick, or into its next `${`. */
  const templateText = (): void => {
    while (i < source.length && source[i] !== BACKTICK) {
      if (source[i] === BACKSLASH) {
        i += 2;
      } else if (source[i] === '$' && source[i + 1] === '{') {
        templates.push(depth);
        depth += 1;
        i += 2;
        return;
      } else {
        i += 1;
      }
    }
    i += 1; // the closing backtick
  };
  while (i < source.length) {
    const c = source[i]!;
    const next = source[i + 1];
    if (c === '/' && next === '/') {
      const eol = source.indexOf('\n', i);
      if (eol < 0) return -1;
      i = eol;
    } else if (c === '/' && next === '*') {
      const end = source.indexOf('*/', i + 2);
      if (end < 0) return -1;
      i = end + 2;
    } else if (QUOTES.has(c)) {
      i += 1;
      while (i < source.length && source[i] !== c) i += source[i] === BACKSLASH ? 2 : 1;
      i += 1;
    } else if (c === BACKTICK) {
      i += 1;
      templateText();
    } else if (c === '}' && templates.at(-1) === depth - 1) {
      // The end of a `${…}`: back into the template's text.
      templates.pop();
      depth -= 1;
      i += 1;
      templateText();
    } else {
      if (c === '(' || c === '{' || c === '[') depth += 1;
      if (c === ')' || c === '}' || c === ']') {
        depth -= 1;
        if (depth === 0) return i + 1;
      }
      i += 1;
    }
  }
  return -1;
}

/**
 * The source of the top-level function `name`, up to its closing brace at column 0 (Prettier
 * formats every file), so a check never reads past the function into the code that follows it.
 */
export function body(source: string, name: string): string {
  const start = source.search(new RegExp(`^(export )?(async )?function ${name}\\b`, 'm'));
  if (start < 0) return '';
  const end = source.indexOf('\n}', start);
  return end < 0 ? source.slice(start) : source.slice(start, end + 2);
}

export interface RouteSource {
  /** `METHOD /path` as declared, e.g. `GET /issues/:id`. */
  id: string;
  file: string;
  /** From `app.<method>(` to the parenthesis that closes that call. */
  text: string;
}

export function routeSources(dir = 'server/src/routes'): {
  routes: RouteSource[];
  unclosed: string[];
} {
  const routes: RouteSource[] = [];
  const unclosed: string[] = [];
  for (const file of readdirSync(dir).filter((f) => f.endsWith('.ts') && !f.endsWith('.test.ts'))) {
    const source = readFileSync(`${dir}/${file}`, 'utf8');
    for (const m of source.matchAll(
      /app\.(get|post|put|patch|delete)(?:<[^>]*>)?\(\s*'([^']+)'/g,
    )) {
      const id = `${m[1]!.toUpperCase()} ${m[2]}`;
      // The route's own call only, up to its closing parenthesis: a helper declared after the
      // route never counts for it.
      const end = closingParen(source, source.indexOf('(', m.index));
      if (end < 0) unclosed.push(`${file}: ${id}`);
      routes.push({ id, file, text: source.slice(m.index, end < 0 ? source.length : end) });
    }
  }
  return { routes, unclosed };
}

/** The full text of every call `name(…)` in `text`, arguments included. */
export function callsOf(text: string, name: string): string[] {
  const calls: string[] = [];
  for (const m of text.matchAll(new RegExp(`\\b${name}\\(`, 'g'))) {
    const open = m.index + m[0].length - 1;
    const end = closingParen(text, open);
    calls.push(text.slice(m.index, end < 0 ? text.length : end));
  }
  return calls;
}
