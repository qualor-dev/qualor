/**
 * Pure checks of what the deployed server answers (plan 1G), shared by the smoke script and its
 * unit tests: the UI index must carry a fresh nonce in its CSP and in the page, and nothing else.
 */

/** The nonce of `script-src` in a Content-Security-Policy, or null. */
export function scriptNonce(csp: string): string | null {
  const directive = csp
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith('script-src '));
  return /'nonce-([A-Za-z0-9+/=_-]+)'/.exec(directive ?? '')?.[1] ?? null;
}

/** Problems with the UI index response; empty when it is served as api.md §4 requires. */
export function indexProblems(headers: Headers, body: string): string[] {
  const problems: string[] = [];
  const csp = headers.get('content-security-policy') ?? '';
  const nonce = scriptNonce(csp);
  if (!(headers.get('content-type') ?? '').startsWith('text/html')) {
    problems.push(`content-type is ${headers.get('content-type')}`);
  }
  if (nonce === null) problems.push('the CSP has no script nonce');
  else if (!body.includes(nonce)) problems.push('the page does not carry the CSP nonce');
  for (const required of ["default-src 'self'", "object-src 'none'", "frame-ancestors 'none'"]) {
    if (!csp.includes(required)) problems.push(`the CSP lacks ${required}`);
  }
  if (/unsafe-inline|unsafe-eval/.test(csp)) problems.push('the CSP allows unsafe-inline or eval');
  if (headers.get('x-frame-options') !== 'DENY') problems.push('X-Frame-Options is not DENY');
  if (headers.get('cache-control') !== 'no-store') problems.push('the index is cacheable');
  if (!body.includes('<q-root')) problems.push('the page is not the Qualor UI');
  if (body.includes('__QUALOR_CSP_NONCE__'))
    problems.push('the nonce placeholder was not replaced');
  return problems;
}

/** The first content-hashed script the index loads (`main-XXXXXXXX.js`), or null. */
export function mainScript(body: string): string | null {
  return /src="(main-[A-Za-z0-9_-]{8}\.js)"/.exec(body)?.[1] ?? null;
}

/**
 * enterprise.md §14.1 (final review A I-2): the ES module the smoke test runs inside the server
 * image with `node --input-type=module -e ENTERPRISE_PROBE <plugin file> <owner uid>`. It checks
 * the enterprise plugin the way the loader would find it (R-PLUGINPATH): the file and its
 * directory owned by `<owner uid>` and not group- or world-writable, then imports the file and
 * checks its name, apiVersion, features and register. It prints the problems as a JSON array
 * and exits 1 when there is one. It imports the plugin in its own process: the server itself
 * never loads it without a key.
 */
export const ENTERPRISE_PROBE = `
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
const [file, owner] = process.argv.slice(1);
const problems = [];
for (const [p, kind] of [[file, 'file'], [path.dirname(file), 'directory']]) {
  let st;
  try { st = fs.statSync(p); } catch (e) { problems.push(p + ': ' + e.code); continue; }
  if (kind === 'file' ? !st.isFile() : !st.isDirectory()) problems.push(p + ' is not a ' + kind);
  if (String(st.uid) !== owner) problems.push(p + ' is owned by uid ' + st.uid + ', not ' + owner);
  if ((st.mode & 0o022) !== 0) {
    problems.push(p + ' is group- or world-writable (mode ' + (st.mode & 0o777).toString(8) + ')');
  }
}
try {
  const plugin = (await import(pathToFileURL(file).href)).default ?? {};
  if (plugin.name !== 'qualor-enterprise') problems.push('name is ' + JSON.stringify(plugin.name));
  if (plugin.apiVersion !== 1) problems.push('apiVersion is ' + JSON.stringify(plugin.apiVersion));
  const f = plugin.features;
  if (!Array.isArray(f) || !f.every((x) => typeof x === 'string') || !f.includes('llm.fix-quota')) {
    problems.push('features are ' + JSON.stringify(f));
  }
  if (typeof plugin.register !== 'function') problems.push('register is not a function');
} catch (e) {
  problems.push('import failed: ' + (e instanceof Error ? e.message : String(e)));
}
process.stdout.write(JSON.stringify(problems));
process.exit(problems.length > 0 ? 1 : 0);
`;
