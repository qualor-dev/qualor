import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = 'file:///fixture-root';
/** `plain` output: a path, not a URI (tools whose own output uses OS paths, e.g. ESLint JSON). */
const PLAIN_ROOT = '/fixture-root';

function canonical(p: string): string {
  let s = p.replaceAll('\\', '/');
  if (/^[A-Za-z]:\//.test(s)) s = s.slice(0, 1).toLowerCase() + s.slice(1);
  return s.replace(/\/+$/, '');
}

function toPath(value: string): string | null {
  if (value.startsWith('file://')) {
    let p = decodeURIComponent(value.slice('file://'.length));
    if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
    return p;
  }
  // Non-conformant single-slash form some tools emit (e.g. SpotBugs's originalUriBaseIds),
  // as opposed to `file://host/...` which has a (possibly empty) authority after the slashes.
  if (/^file:\/(?!\/)/.test(value)) {
    let p = decodeURIComponent(value.slice('file:'.length));
    if (/^\/[A-Za-z]:\//.test(p)) p = p.slice(1);
    return p;
  }
  if (value.startsWith('/') || /^[A-Za-z]:[\\/]/.test(value)) return value;
  return null;
}

/**
 * Rewrites every absolute path or `file:` URI under one of `prefixes` to `file:///fixture-root/…`.
 * With `plain`, a plain absolute path (not a URI) becomes `/fixture-root/…` instead.
 */
export function rebaseSarif(
  log: unknown,
  prefixes: readonly string[],
  o: { plain?: boolean } = {},
): unknown {
  const roots = prefixes.map(canonical);
  const visit = (v: unknown): unknown => {
    if (typeof v === 'string') {
      const p = toPath(v);
      if (p === null) return v;
      const base = o.plain === true && !v.startsWith('file:') ? PLAIN_ROOT : ROOT;
      // canonical() strips trailing slashes to compare paths; preserve one on the output
      // when the source URI had it (it usually marks a directory-style base URI).
      const trailingSlash = p.length > 1 && p.endsWith('/');
      const c = canonical(p);
      for (const r of roots) {
        if (c === r) return `${base}/`;
        if (c.startsWith(`${r}/`))
          return `${base}/${c.slice(r.length + 1)}${trailingSlash ? '/' : ''}`;
      }
      return v;
    }
    if (Array.isArray(v)) return v.map(visit);
    if (v !== null && typeof v === 'object') {
      return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, visit(x)]));
    }
    return v;
  };
  return visit(log);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const args = process.argv.slice(2);
  const plain = args[0] === '--plain';
  const [input, output, ...prefixes] = plain ? args.slice(1) : args;
  if (!input || !output || prefixes.length === 0) {
    console.error('usage: rebase.ts [--plain] <in.json> <out.json> <prefix>...');
    process.exit(2);
  }
  const log = JSON.parse(readFileSync(input, 'utf8')) as unknown;
  writeFileSync(output, `${JSON.stringify(rebaseSarif(log, prefixes, { plain }), null, 2)}\n`);
}
