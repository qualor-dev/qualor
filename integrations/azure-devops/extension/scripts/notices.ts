import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

export interface Bundled {
  name: string;
  version: string;
  license: string;
  text: string;
}

/**
 * The npm package that holds a metafile input path (`…/node_modules/<name>/…`, the last
 * `node_modules` segment wins, so pnpm's `.pnpm/<id>/node_modules/<name>` layout works), or null
 * for a file of this repository.
 */
export function packageRootOf(input: string): { name: string; dir: string } | null {
  const parts = input.split(/[/\\]/);
  const at = parts.lastIndexOf('node_modules');
  if (at < 0) return null;
  const first = parts[at + 1];
  if (first === undefined) return null;
  const scoped = first.startsWith('@');
  const name = scoped ? `${first}/${parts[at + 2] ?? ''}` : first;
  const dir = parts.slice(0, at + (scoped ? 3 : 2)).join(path.sep);
  return { name, dir };
}

function licenseField(pkg: { license?: unknown; licenses?: unknown }): string {
  if (typeof pkg.license === 'string') return pkg.license;
  if (Array.isArray(pkg.licenses)) {
    return pkg.licenses
      .map((l: unknown) => (l as { type?: string }).type ?? '')
      .filter(Boolean)
      .join(' OR ');
  }
  return 'UNKNOWN';
}

/** The packages esbuild bundled (from its metafile `inputs`), with licence name and LICENSE text. */
export function bundledPackages(inputs: readonly string[], workingDir: string): Bundled[] {
  // Keyed by directory: pnpm gives every installed version of a package its own directory, so two
  // bundled versions of one name both get their notice.
  const dirs = new Map<string, string>();
  for (const input of inputs) {
    const root = packageRootOf(input);
    if (root) dirs.set(path.resolve(workingDir, root.dir), root.name);
  }
  const out: Bundled[] = [];
  for (const [dir, name] of [...dirs].sort(([, a], [, b]) => a.localeCompare(b))) {
    const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8')) as {
      version?: string;
      license?: unknown;
      licenses?: unknown;
    };
    const file = readdirSync(dir).find((f) => /^(licen[cs]e|copying)(\.|$)/i.test(f));
    if (file === undefined) {
      throw new Error(`${name} is bundled into the task but ships no licence file (${dir})`);
    }
    const text = readFileSync(path.join(dir, file), 'utf8').trim();
    out.push({ name, version: pkg.version ?? '', license: licenseField(pkg), text });
  }
  return out;
}

export function noticesText(packages: readonly Bundled[]): string {
  const head =
    'Third-party software bundled into tasks/qualor/index.js\n' +
    'The Qualor task contains the following packages. Their licence notices follow.\n';
  const body = packages.map((p) => {
    return `${'='.repeat(72)}\n${p.name} ${p.version} (${p.license})\n${'='.repeat(72)}\n\n${p.text}\n`;
  });
  return `${head}\n${body.join('\n')}`;
}
