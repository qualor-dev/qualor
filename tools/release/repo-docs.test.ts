import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { VERIFY_OFFLINE } from './cosign';
import { REKOR_FOR_REAL_RELEASES } from './publish';

const read = (f: string): string => readFileSync(f, 'utf8');
const PLACEHOLDER = /\bTODO\b|\bTBD\b|<[a-z][a-z ]*>/;

function agentsCommands(): string[] {
  const agents = read('AGENTS.md');
  const section = agents.slice(agents.indexOf('## Commands'), agents.indexOf('## Rules'));
  return [...section.matchAll(/`(pnpm [a-z0-9:-]+)[^`]*`/g)].map((m) => m[1] ?? '');
}

describe('CONTRIBUTING.md and SECURITY.md (release.md §13)', () => {
  it('CONTRIBUTING.md names every command of AGENTS.md, the rules and the contribution terms', () => {
    const text = read('CONTRIBUTING.md');
    const commands = agentsCommands();
    expect(commands.length).toBeGreaterThan(10);
    for (const c of commands) expect(text, c).toContain(c);
    for (const must of ['Signed-off-by', 'enterprise/', 'MIT', 'docs/guide/'])
      expect(text).toContain(must);
  });

  it('SECURITY.md says where to report, what to expect and how releases are signed', () => {
    const text = read('SECURITY.md');
    for (const must of [
      'security@qualor.dev',
      'Supported versions',
      '3 working days',
      '90 days',
      'cosign verify',
    ]) {
      expect(text).toContain(must);
    }
  });

  it('ties every documented cosign verification to the Rekor switch (release.md §12)', () => {
    const guide = readdirSync('docs/guide')
      .filter((f) => f.endsWith('.md'))
      .map((f) => `docs/guide/${f}`);
    const files = [
      'SECURITY.md',
      'docs/spec/release.md',
      'deploy/README.md',
      'README.md',
      ...guide,
      // The design specs are kept outside the public repository.
    ].filter((f) => existsSync(f));
    const commands: string[] = [];
    for (const f of files) {
      // A command continued with "\" is one line.
      const text = read(f).replace(/\\\r?\n\s*/g, ' ');
      for (const line of text.split(/\r?\n/)) {
        for (const m of line.matchAll(/cosign\s+verify(?:-attestation|-blob)?\s[^`\n]*/g)) {
          // A command, not prose: it names its key.
          if (m[0].includes('--key')) commands.push(`${f}: ${m[0]}`);
        }
      }
    }
    for (const f of ['SECURITY.md', 'docs/spec/release.md', 'docs/guide/install-server.md'].filter(
      (f) => existsSync(f),
    )) {
      expect(
        commands.some((c) => c.startsWith(`${f}: `)),
        f,
      ).toBe(true);
    }
    for (const kind of ['verify ', 'verify-attestation ', 'verify-blob ']) {
      expect(
        commands.some((c) => c.includes(`cosign ${kind}`)),
        kind,
      ).toBe(true);
    }
    for (const c of commands) {
      if (REKOR_FOR_REAL_RELEASES) expect(c).not.toContain('--insecure-ignore-tlog');
      else expect(c).toContain(VERIFY_OFFLINE.join(' '));
    }
    // And each file says why.
    for (const f of ['SECURITY.md', 'docs/guide/install-server.md']) {
      expect(read(f), f).toMatch(/not recorded in the public Rekor transparency log/);
    }
    expect(read('docs/guide/install-server.md')).toMatch(/Signed releases are not published yet/);
  });

  it('neither has a placeholder left', () => {
    for (const f of ['CONTRIBUTING.md', 'SECURITY.md']) expect(read(f), f).not.toMatch(PLACEHOLDER);
  });
});
