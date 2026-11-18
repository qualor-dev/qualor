import { FIX_FAMILIES, fixFileKind, type FixFamily } from '@qualor/shared/fix';

/**
 * B7: the package manager each file needs, by basename: the lockfiles, and the files that stand in
 * for one (`go.mod`; `pom.xml`, Maven having no lockfile). A family is served only when every one
 * of these files it has can be regenerated.
 */
export const FIX_LOCKFILE_TOOLS: Readonly<Record<string, string>> = Object.freeze({
  'package-lock.json': 'npm',
  'npm-shrinkwrap.json': 'npm',
  'pnpm-lock.yaml': 'pnpm',
  'yarn.lock': 'yarn',
  'go.mod': 'go',
  'pom.xml': 'mvn',
  'uv.lock': 'uv',
  'poetry.lock': 'poetry',
});

const basename = (p: string): string => p.slice(p.lastIndexOf('/') + 1);

/** The tool a file needs, or null for a file that needs none (a manifest such as package.json). */
function toolOf(p: string): string | null {
  const name = basename(p);
  return Object.hasOwn(FIX_LOCKFILE_TOOLS, name) ? (FIX_LOCKFILE_TOOLS[name] ?? null) : null;
}

/**
 * The tracked manifests and lockfiles of each family (`FIX_FILES`, by basename, at any depth), in
 * the order given; a family without files has no entry. The map follows `FIX_FAMILIES`' order.
 */
export function familyFiles(tracked: readonly string[]): Map<FixFamily, string[]> {
  const out = new Map<FixFamily, string[]>();
  for (const family of FIX_FAMILIES) {
    const files = tracked.filter((p) => fixFileKind(family, p) !== null);
    if (files.length > 0) out.set(family, files);
  }
  return out;
}

/** The tools these files need, each once, sorted. */
export function familyTools(files: readonly string[]): string[] {
  const tools = new Set<string>();
  for (const p of files) {
    const tool = toolOf(p);
    if (tool !== null) tools.add(tool);
  }
  return [...tools].toSorted((a, b) => a.localeCompare(b));
}

/** The tools these files need that `resolve` does not find. */
export function missingTools(
  files: readonly string[],
  resolve: (tool: string) => string | null,
): string[] {
  return familyTools(files).filter((tool) => resolve(tool) === null);
}

/**
 * B7, ruling F6: the families this job can serve completely: those with a lockfile (or `go.mod`,
 * or `pom.xml`) whose every tool `resolve` finds. A family with manifests only has nothing a
 * package manager could regenerate.
 */
export function servedFamilies(
  files: Map<FixFamily, string[]>,
  resolve: (tool: string) => string | null,
): FixFamily[] {
  return [...files.entries()]
    .filter(
      ([, paths]) => familyTools(paths).length > 0 && missingTools(paths, resolve).length === 0,
    )
    .map(([family]) => family);
}
