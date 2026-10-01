import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { RUBOCOP_DEFAULT_EXCLUDE } from '../../packages/shared/src/rules/rubocop-default';

/** The Docker Hub repositories, one description file each in deploy/dockerhub/. */
const REPOSITORIES = [
  'server',
  'scanner',
  'scanner-dotnet',
  'scanner-sources',
  'server-sources',
  'qualor', // the Helm chart
] as const;
const read = (repository: string): string =>
  readFileSync(`deploy/dockerhub/${repository}.md`, 'utf8');

/** Docker Hub's limit for a repository's short description. */
const SHORT_MAX = 100;

describe('the Docker Hub descriptions', () => {
  it('have a short description of at most 100 characters and an overview', () => {
    for (const repository of REPOSITORIES) {
      const text = read(repository);
      expect(text.startsWith(`# qualor/${repository}\n`), repository).toBe(true);
      const short = /^Short description: (.+)$/m.exec(text)?.[1] ?? '';
      expect(short.length, repository).toBeGreaterThan(20);
      expect(short.length, `${repository}: "${short}"`).toBeLessThanOrEqual(SHORT_MAX);
      expect(text, repository).toMatch(/^## Overview$/m);
      expect(text, repository).toContain('https://github.com/qualor-dev/qualor');
    }
  });

  it('carry the trademark notice of the README in the server and scanner descriptions', () => {
    const readme = readFileSync('README.md', 'utf8');
    const notice = /## Trademarks\n\n([\s\S]+?)(?:\n## |\n?$)/.exec(readme)?.[1]?.trim() ?? '';
    expect(notice).toContain('SonarSource');
    for (const repository of ['server', 'scanner', 'scanner-dotnet', 'qualor']) {
      expect(read(repository), repository).toContain(notice);
    }
  });

  it('name the same analyzer versions, entrypoint and user as the scanner image', () => {
    const text = read('scanner');
    const installSh = readFileSync('tools/analyzers/install.sh', 'utf8');
    for (const tool of [
      'PMD',
      'SPOTBUGS',
      'OPENGREP',
      'GITLEAKS',
      'DETEKT',
      'SWIFTLINT',
      'PHPSTAN',
    ]) {
      const version = new RegExp(`^${tool}_VERSION=(\\S+)$`, 'm').exec(installSh)?.[1] ?? '';
      expect(version, tool).not.toBe('');
      expect(text, tool).toContain(version);
    }
    const dockerfile = readFileSync('deploy/scanner/Dockerfile', 'utf8');
    expect(dockerfile).toContain('ENTRYPOINT ["qualor"]');
    expect(dockerfile).toMatch(/^USER node$/m);
    expect(text).toContain('entrypoint `qualor`');
    expect(text).toContain('`node` (uid 1000)');
  });

  it('name the same .NET SDK and Roslynator versions as the scanner-dotnet image', () => {
    const text = read('scanner-dotnet');
    const installSh = readFileSync('tools/analyzers/install-dotnet.sh', 'utf8');
    for (const tool of ['DOTNET8', 'DOTNET10', 'ROSLYNATOR']) {
      const version = new RegExp(`^${tool}_VERSION=(\\S+)$`, 'm').exec(installSh)?.[1] ?? '';
      expect(version, tool).not.toBe('');
      expect(text, tool).toContain(version);
    }
    // Its copyleft sources are the scanner's (release.md §5): it names that companion.
    expect(text).toContain('qualor/scanner-sources');
    expect(text).toContain('https://qualor.dev/docs/languages-and-analyzers');
  });

  it('name the same port and user as the server image', () => {
    const text = read('server');
    const dockerfile = readFileSync('deploy/server/Dockerfile', 'utf8');
    expect(dockerfile).toMatch(/^USER 65532:65532$/m);
    expect(dockerfile).toMatch(/^EXPOSE 8080$/m);
    expect(text).toContain('user 65532');
    expect(text).toContain('port 8080');
  });
});

describe('placeholder image names', () => {
  // This file names the patterns.
  const DELIBERATE = [/^tools\/deploy\/dockerhub\.test\.ts$/];
  const PLACEHOLDER = /registry\.example\.com|<namespace>|<registry>/;

  it('are gone from the repository', () => {
    const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    })
      .split('\n')
      .filter((file) => file !== '' && !DELIBERATE.some((re) => re.test(file)));
    expect(files.length).toBeGreaterThan(100);
    const found: string[] = [];
    for (const file of files) {
      let text: string;
      try {
        text = readFileSync(file, 'utf8');
      } catch {
        continue; // listed but deleted in the working tree
      }
      if (PLACEHOLDER.test(text)) found.push(file);
    }
    expect(found).toEqual([]);
  });
});

describe('the Ruby pass versions in the docs (plan 9B)', () => {
  const script = readFileSync('tools/analyzers/install-rubocop.sh', 'utf8');
  const pin = (name: string) => new RegExp(`^${name}=(\\S+)$`, 'm').exec(script)?.[1] ?? '';
  const ruby = pin('RUBY_VERSION');
  const rubocop = pin('RUBOCOP_VERSION');
  const rubocopMinor = rubocop.split('.').slice(0, 2).join('.');
  const json =
    /^json (\S+) /m.exec(readFileSync('tools/analyzers/rubocop/gems.lock', 'utf8'))?.[1] ?? '';
  const grammar = (
    JSON.parse(readFileSync('cli/package.json', 'utf8')) as { dependencies: Record<string, string> }
  ).dependencies['tree-sitter-ruby'];

  it('reads the pins', () => {
    for (const v of [ruby, rubocop, json, grammar ?? '']) expect(v).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('names them in the scanner description, NOTICE.md, the guide and the changelog', () => {
    expect(read('scanner')).toContain(`RuboCop ${rubocop} on Ruby ${ruby}`);
    const notice = readFileSync('deploy/scanner/NOTICE.md', 'utf8');
    for (const v of [ruby, rubocop, `json ${json}`, `tree-sitter-ruby ${grammar}`])
      expect(notice, v).toContain(v);
    expect(notice).toContain(`https://github.com/rubocop/rubocop/tree/v${rubocop}`);
    const guide = readFileSync('docs/guide/languages-and-analyzers.md', 'utf8');
    expect(guide).toContain(`RuboCop ${rubocopMinor}`);
    expect(readFileSync('CHANGELOG.md', 'utf8')).toContain(
      `RuboCop ${rubocopMinor} (MIT) on Ruby ${ruby}`,
    );
  });

  it("lists exactly qualor-default's left-out cops in the guide", () => {
    const guide = readFileSync('docs/guide/languages-and-analyzers.md', 'utf8');
    for (const cop of RUBOCOP_DEFAULT_EXCLUDE) expect(guide, cop).toContain(`\`${cop}\``);
    expect(guide).toContain(`the ${RUBOCOP_DEFAULT_EXCLUDE.length} cops`);
  });
});
