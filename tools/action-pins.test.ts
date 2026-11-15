import { readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * Every `actions/checkout` and `actions/cache` reference Qualor ships or runs, in one place: the CI
 * templates, the guide and the Docker Hub page users copy from, and this repository's own
 * workflows. A commit pin is the node24 v5.1.0 with its tag in a comment; a tag in an example is
 * `@v5`. Only the GitHub Enterprise Server layout keeps `@v4` (no GHES instance checked v5).
 */
const CHECKOUT_SHA = 'fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09';
const CACHE_SHA = 'caa296126883cff596d87d8935842f9db880ef25';
const TAG_COMMENT = /^ # v5\.1\.0(?![\w.])/;

const read = (file: string): string =>
  readFileSync(new URL(`../${file}`, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const inDir = (dir: string, ext: string): string[] =>
  readdirSync(new URL(`../${dir}/`, import.meta.url))
    .filter((name) => name.endsWith(ext))
    .map((name) => `${dir}/${name}`);

/** The files that must hold such references (a renamed file or a lost step fails the test). */
const PINNED_FILES = [
  'README.md',
  'server/src/onboarding/ci-templates.ts',
  'integrations/github/qualor.yml',
  'integrations/github/qualor-dotnet.yml',
  'docs/guide/github.md',
  'docs/guide/dependency-licenses.md',
  'deploy/dockerhub/scanner.md',
  '.github/workflows/ci.yml',
  '.github/workflows/nightly.yml',
  '.github/workflows/release.yml',
];
const SOURCES = [
  ...new Set([
    ...PINNED_FILES,
    ...inDir('integrations/github', '.yml'),
    ...inDir('.github/workflows', '.yml'),
    ...inDir('docs/guide', '.md'),
    ...inDir('deploy/dockerhub', '.md'),
  ]),
];

/** The GHES layout: the only `@v4` tags, as whole lines of the templates. */
const GHES_TEMPLATE_LINES = [
  "const GHES_CACHE_RESTORE = 'actions/cache/restore@v4';",
  "const GHES_CACHE_SAVE = 'actions/cache/save@v4';",
  "  `      - uses: ${o.host === 'self-hosted' ? 'actions/checkout@v4' : CHECKOUT}`,",
];
const GHES_GUIDE_SECTION = /^### CI setup on GitHub Enterprise Server\n[\s\S]*?(?=^#)/m;

/** The text of a file without its GHES layout, which is checked on its own below. */
function outsideGhes(file: string): string {
  let text = read(file);
  if (file === 'server/src/onboarding/ci-templates.ts') {
    const lines = text.split('\n');
    for (const line of GHES_TEMPLATE_LINES) {
      expect(
        lines.filter((l) => l === line),
        line,
      ).toHaveLength(1);
    }
    text = lines.filter((l) => !GHES_TEMPLATE_LINES.includes(l)).join('\n');
  }
  if (file === 'docs/guide/github.md') {
    expect(text).toMatch(GHES_GUIDE_SECTION);
    text = text.replace(GHES_GUIDE_SECTION, '');
  }
  return text;
}

interface Ref {
  action: string;
  ref: string;
  rest: string;
}

/** The rest of the line is read ahead, not consumed: one line can hold two references. */
const REF = /actions\/(checkout|cache(?:\/restore|\/save)?)@([^\s'"`]+)(?=(.*)$)/gm;
const refs = (text: string): Ref[] =>
  [...text.matchAll(REF)].map((m) => ({ action: m[1]!, ref: m[2]!, rest: m[3]! }));

describe('actions/checkout and actions/cache pins', () => {
  it.each(PINNED_FILES)('%s references them', (file) => {
    expect(refs(read(file)).length).toBeGreaterThan(0);
  });

  it.each(SOURCES)('%s pins v5.1.0 by commit, or the v5 tag in an example', (file) => {
    for (const { action, ref, rest } of refs(outsideGhes(file))) {
      const where = `${file}: actions/${action}@${ref}${rest}`;
      if (/^[0-9a-f]{40}$/.test(ref)) {
        expect(ref, where).toBe(action === 'checkout' ? CHECKOUT_SHA : CACHE_SHA);
        expect(rest, where).toMatch(TAG_COMMENT);
      } else {
        expect(ref, where).toBe('v5');
      }
    }
  });

  it('keeps the GHES layout on the v4 tags, in the templates and the guide', () => {
    const template = read('server/src/onboarding/ci-templates.ts').split('\n');
    for (const line of GHES_TEMPLATE_LINES) expect(template).toContain(line);
    const section = GHES_GUIDE_SECTION.exec(read('docs/guide/github.md'))?.[0] ?? '';
    expect(refs(section).map((r) => `${r.action}@${r.ref}`)).toEqual(['checkout@v4', 'cache@v4']);
  });
});
