import { describe, expect, it } from 'vitest';
import { contextHash, filelessHash, lineHash } from '../hash';
import {
  levelToSeverity,
  normalizeSarif,
  normalizeSarifWithSecrets,
  parseCwe,
  REDACTED,
  toolVersion,
  type NormalizeOptions,
} from './normalize';
import { REPORT_BOUNDS, reportSchema } from '../report/schema';
import { budgetMs } from '../../test/perf';

const FILES: Record<string, string[]> = {
  'src/a.ts': Array.from({ length: 30 }, (_, i) => `line ${i + 1};`),
  'src/secret.ts': ['const x = 1;', 'const token = "AKIAABCDEFGHIJKLMNOP";', 'export {};'],
  'src/multiline-secret.ts': ['line1 SECRETSTART', 'MIDDLE SECRET LINE', 'line3 SECRETEND rest'],
  'src/two-secrets.ts': [
    'const a = 1;',
    'const k1 = "Zq8XwV3mN7pL2rT5";',
    'call(k1, k2);',
    'const k2 = "Hj4Kd9Fs6Gb1Yt0P";',
    'export {};',
  ],
  'src/repeated-secret.ts': [
    'const a = 1;',
    'const k1 = "Zq8XwV3mN7pL2rT5";',
    'const b = 2;',
    '// copy: Zq8XwV3mN7pL2rT5 and short',
    'export {};',
  ],
};

function opts(extra: Partial<NormalizeOptions> = {}): NormalizeOptions {
  return {
    engineId: 'eslint',
    repoRoot: '/repo',
    readLines: (p) => FILES[p] ?? null,
    ...extra,
  };
}

function log(
  results: unknown[],
  driver: Record<string, unknown> = {},
  run: Record<string, unknown> = {},
) {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ESLint',
            version: '9.1.0',
            rules: [
              {
                id: 'no-console',
                name: 'NoConsole',
                shortDescription: { text: 'Disallow console' },
                helpUri: 'https://eslint.org/docs/latest/rules/no-console',
                defaultConfiguration: { level: 'warning' },
                properties: { tags: ['CWE-532', 'best-practice'] },
              },
            ],
            ...driver,
          },
        },
        results,
        ...run,
      },
    ],
  };
}

const loc = (uri: string, startLine = 5, extra: Record<string, unknown> = {}) => ({
  physicalLocation: { artifactLocation: { uri }, region: { startLine, ...extra } },
});

describe('levelToSeverity / parseCwe', () => {
  it('maps SARIF levels', () => {
    expect(['error', 'warning', 'note', 'none'].map((l) => levelToSeverity(l as never))).toEqual([
      'high',
      'medium',
      'low',
      'info',
    ]);
  });
  it('parses CWE notations', () => {
    expect(
      parseCwe(['CWE-798', 'cwe-79', 'external/cwe/cwe-89', 'CWE-22: Path traversal', 798, 'nope']),
    ).toEqual([22, 79, 89, 798]);
  });
});

describe('normalizeSarif', () => {
  it('rejects non-SARIF input', () => {
    expect(() => normalizeSarif({ version: '1.0' }, opts())).toThrow(/SARIF/);
  });

  it('normalises a basic result', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          level: 'error',
          message: { text: 'Unexpected console.' },
          locations: [loc('src/a.ts', 5, { startColumn: 3, endColumn: 14 })],
        },
      ]),
      opts(),
    );
    expect(out.version).toBe('9.1.0');
    expect(out.warnings).toEqual([]);
    expect(out.findings).toEqual([
      {
        engineId: 'eslint',
        ruleId: 'no-console',
        message: 'Unexpected console.',
        severity: 'high',
        location: { path: 'src/a.ts', startLine: 5, startColumn: 3, endLine: 5, endColumn: 13 },
        lineHash: lineHash(FILES['src/a.ts']!, 5, 5),
        contextHash: contextHash(FILES['src/a.ts']!, 5, 5),
        snippet: { startLine: 2, lines: FILES['src/a.ts']!.slice(1, 8) },
      },
    ]);
    expect(out.rules).toEqual([
      {
        id: 'no-console',
        name: 'NoConsole',
        shortDescription: 'Disallow console',
        helpUri: 'https://eslint.org/docs/latest/rules/no-console',
        defaultSeverity: 'medium',
        quality: 'maintainability',
        kind: 'issue',
        tags: ['CWE-532', 'best-practice'],
        cwe: [532],
      },
    ]);
  });

  it('falls back to the rule default level, then warning', () => {
    const r = (ruleId: string) => ({
      ruleId,
      message: { text: 'm' },
      locations: [loc('src/a.ts')],
    });
    const out = normalizeSarif(log([r('no-console'), r('unknown-rule')]), opts());
    expect(out.findings.map((f) => f.severity)).toEqual(['medium', 'medium']);
  });

  it('resolves the rule id via rule.id and ruleIndex, drops unresolvable', () => {
    const out = normalizeSarif(
      log([
        { rule: { id: 'no-console' }, message: { text: 'a' }, locations: [loc('src/a.ts')] },
        { ruleIndex: 0, message: { text: 'b' }, locations: [loc('src/a.ts')] },
        { message: { text: 'c' }, locations: [loc('src/a.ts')] },
      ]),
      opts(),
    );
    expect(out.findings.map((f) => f.ruleId)).toEqual(['no-console', 'no-console']);
    expect(out.warnings).toEqual([
      expect.objectContaining({ code: 'RESULT_WITHOUT_RULE', count: 1 }),
    ]);
  });

  it('drops pass/notApplicable and suppressed results', () => {
    const base = { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts')] };
    const out = normalizeSarif(
      log([
        { ...base, kind: 'pass' },
        { ...base, kind: 'notApplicable' },
        { ...base, suppressions: [{ kind: 'inSource' }] },
        { ...base, suppressions: [{ kind: 'external', status: 'rejected' }] },
      ]),
      opts(),
    );
    expect(out.findings).toHaveLength(1);
  });

  it('resolves file URIs, uriBaseIds and Windows paths', () => {
    const results = [
      { ruleId: 'no-console', message: { text: '1' }, locations: [loc('file:///repo/src/a.ts')] },
      {
        ruleId: 'no-console',
        message: { text: '2' },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: 'a.ts', uriBaseId: 'SRC' },
              region: { startLine: 1 },
            },
          },
        ],
      },
      {
        ruleId: 'no-console',
        message: { text: '3' },
        locations: [loc('file:///C:/repo/src/a.ts')],
      },
      { ruleId: 'no-console', message: { text: '4' }, locations: [loc('src/a.ts')] },
    ];
    const posix = normalizeSarif(
      log(results.slice(0, 2), {}, { originalUriBaseIds: { SRC: { uri: 'file:///repo/src/' } } }),
      opts(),
    );
    expect(posix.findings.map((f) => f.location?.path)).toEqual(['src/a.ts', 'src/a.ts']);
    const win = normalizeSarif(log(results.slice(2)), opts({ repoRoot: 'C:\\repo' }));
    expect(win.findings.map((f) => f.location?.path)).toEqual(['src/a.ts', 'src/a.ts']);
  });

  it('drops invalid and out-of-scope paths with warnings', () => {
    const out = normalizeSarif(
      log([
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('../outside.ts')] },
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/secret.ts', 1)] },
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts')] },
      ]),
      opts({ knownPaths: new Set(['src/a.ts']) }),
    );
    expect(out.findings).toHaveLength(1);
    expect(out.warnings.map((w) => [w.code, w.count])).toEqual([
      ['FINDING_PATH_INVALID', 1],
      ['FINDING_OUT_OF_SCOPE', 1],
    ]);
  });

  it('creates file-less findings when there is no location', () => {
    const out = normalizeSarif(
      log([{ ruleId: 'no-console', message: { text: 'project note' } }]),
      opts(),
    );
    expect(out.findings[0]).toMatchObject({
      location: null,
      lineHash: filelessHash('eslint:no-console', 'project note'),
      contextHash: filelessHash('eslint:no-console', 'project note'),
    });
    expect(out.findings[0]).not.toHaveProperty('snippet');
  });

  it('falls back to fileless hashes when the file is unreadable or the region is outside it', () => {
    const out = normalizeSarif(
      log([
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/gone.ts', 1)] },
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts', 99)] },
      ]),
      opts(),
    );
    // The path is part of the fallback, so the same message in two files stays two identities.
    expect(out.findings.map((f) => [f.lineHash, f.contextHash])).toEqual([
      [
        filelessHash('eslint:no-console', 'm', 'src/gone.ts'),
        filelessHash('eslint:no-console', 'm', 'src/gone.ts'),
      ],
      [
        filelessHash('eslint:no-console', 'm', 'src/a.ts'),
        filelessHash('eslint:no-console', 'm', 'src/a.ts'),
      ],
    ]);
    expect(out.warnings).toEqual([expect.objectContaining({ code: 'HASH_FALLBACK', count: 2 })]);
  });

  it('hashes the identity a mapping gives instead of the lines, readable file or not (plan 2B)', () => {
    const identity = (result: { properties?: Record<string, unknown> }) =>
      typeof result.properties?.['pkg'] === 'string' ? result.properties['pkg'] : undefined;
    const vuln = (uri: string, line: number, pkg?: string) => ({
      ruleId: 'no-console',
      message: { text: `m ${line}` },
      locations: [loc(uri, line)],
      ...(pkg !== undefined && { properties: { pkg } }),
    });
    const out = normalizeSarif(
      log([
        vuln('src/a.ts', 3, 'minimist@1.2.5'),
        vuln('src/a.ts', 20, 'minimist@1.2.5'),
        vuln('src/gone.ts', 1, 'minimist@1.2.5'),
        vuln('src/a.ts', 5),
      ]),
      opts({ mapping: { identity } }),
    );
    const key = filelessHash('eslint:no-console', 'minimist@1.2.5', 'src/a.ts');
    // The same package on another line of the same file hashes the same: the lines around it
    // (a lockfile's neighbours) never change its identity, and neither does the message.
    expect(out.findings.map((f) => [f.lineHash, f.contextHash])).toEqual([
      [key, key],
      [key, key],
      [
        filelessHash('eslint:no-console', 'minimist@1.2.5', 'src/gone.ts'),
        filelessHash('eslint:no-console', 'minimist@1.2.5', 'src/gone.ts'),
      ],
      [lineHash(FILES['src/a.ts']!, 5, 5), contextHash(FILES['src/a.ts']!, 5, 5)],
    ]);
    // A readable file still gives a snippet; an unreadable one is no fallback.
    expect(out.findings[0]!.snippet).toEqual({
      startLine: 1,
      lines: FILES['src/a.ts']!.slice(0, 6),
    });
    expect(out.findings[2]!.snippet).toBeUndefined();
    expect(out.warnings).toEqual([]);
  });

  it('truncates long messages and snippet lines', () => {
    const long = 'x'.repeat(5000);
    const out = normalizeSarif(
      log([{ ruleId: 'no-console', message: { text: long }, locations: [loc('src/wide.ts', 1)] }]),
      opts({ readLines: () => ['y'.repeat(1000)] }),
    );
    expect(out.findings[0]!.message).toHaveLength(4000);
    expect(out.findings[0]!.message.endsWith('…')).toBe(true);
    expect(out.findings[0]!.snippet!.lines[0]).toHaveLength(400);
  });

  it('bounds tool rule metadata to the report schema (fix round 1)', () => {
    const longId = `plugin/${'r'.repeat(600)}`;
    const out = normalizeSarif(
      log(
        [
          { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts', 1)] },
          { ruleId: longId, message: { text: 'm' }, locations: [loc('src/a.ts', 2)] },
        ],
        {
          version: `9.${'9'.repeat(200)}`,
          rules: [
            {
              id: 'no-console',
              name: 'n'.repeat(600),
              shortDescription: { text: 'd'.repeat(5000) },
              helpUri: `https://example.com/${'u'.repeat(3000)}`,
              properties: {
                tags: ['ok', 't'.repeat(200), ...Array.from({ length: 100 }, (_, i) => `t${i}`)],
                cwe: Array.from({ length: 100 }, (_, i) => i + 1),
              },
            },
            { id: longId, shortDescription: { text: 'long id' } },
          ],
        },
      ),
      opts(),
    );
    expect(out.version).toBeNull();
    expect(out.rules.map((r) => r.id)).toEqual(['no-console']);
    const rule = out.rules[0]!;
    expect(rule.name).toHaveLength(REPORT_BOUNDS.ruleNameChars);
    expect(rule.shortDescription).toHaveLength(REPORT_BOUNDS.ruleDescriptionChars);
    expect(rule.shortDescription!.endsWith('…')).toBe(true);
    expect(rule).not.toHaveProperty('helpUri');
    expect(rule.tags).toHaveLength(REPORT_BOUNDS.ruleTags);
    expect(rule.tags).not.toContain('t'.repeat(200));
    expect(rule.cwe).toHaveLength(REPORT_BOUNDS.ruleCwes);
    expect(out.findings.map((f) => f.ruleId)).toEqual(['no-console']);
    expect(out.warnings).toContainEqual(
      expect.objectContaining({ code: 'RULE_ID_TOO_LONG', count: 1 }),
    );
    // The bounded engine now fits the report schema, so one plugin cannot fail the whole scan.
    const engine = {
      id: 'eslint',
      kind: 'builtin',
      version: out.version,
      status: 'ok',
      durationMs: 1,
      rules: out.rules,
    };
    expect(reportSchema.shape.engines.element.safeParse(engine).success).toBe(true);
  });

  it('keeps a bounded tool version and rejects control characters', () => {
    expect(toolVersion(' 9.1.0 ')).toBe('9.1.0');
    expect(toolVersion('x'.repeat(128))).toHaveLength(128);
    expect(toolVersion('x'.repeat(129))).toBeNull();
    expect(toolVersion('9.1.0\n\u001b[31m')).toBeNull();
    expect(toolVersion('')).toBeNull();
    expect(toolVersion(null)).toBeNull();
  });

  it('collects secondary locations from extra and related locations (max 20)', () => {
    const related = Array.from({ length: 25 }, (_, i) => ({
      ...loc('src/a.ts', i + 1),
      message: { text: `r${i}` },
    }));
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('src/a.ts'), loc('src/a.ts', 9)],
          relatedLocations: related,
        },
      ]),
      opts(),
    );
    const sec = out.findings[0]!.secondaryLocations!;
    expect(sec).toHaveLength(20);
    expect(sec[0]).toEqual({ path: 'src/a.ts', startLine: 9, endLine: 9 });
    expect(sec[1]).toEqual({ path: 'src/a.ts', startLine: 1, endLine: 1, message: 'r0' });
  });

  it('copies partial fingerprints and small properties', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'a' },
          locations: [loc('src/a.ts')],
          partialFingerprints: { k: 'v' },
          properties: { cwe: ['CWE-1'] },
        },
        {
          ruleId: 'no-console',
          message: { text: 'b' },
          locations: [loc('src/a.ts')],
          properties: { blob: 'x'.repeat(5000) },
        },
      ]),
      opts(),
    );
    expect(out.findings[0]).toMatchObject({
      partialFingerprints: { k: 'v' },
      properties: { cwe: ['CWE-1'] },
    });
    expect(out.findings[1]).not.toHaveProperty('properties');
    expect(out.warnings).toEqual([
      expect.objectContaining({ code: 'PROPERTIES_TOO_LARGE', count: 1 }),
    ]);
  });

  it('applies mapping rule metadata and severity', () => {
    const out = normalizeSarif(
      log([{ ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts')] }]),
      opts({
        mapping: {
          rule: () => ({ quality: 'security', defaultSeverity: 'blocker', kind: 'hotspot' }),
          severity: () => 'low',
        },
      }),
    );
    expect(out.rules[0]).toMatchObject({
      quality: 'security',
      defaultSeverity: 'blocker',
      kind: 'hotspot',
    });
    expect(out.findings[0]!.severity).toBe('low');
  });

  it('honours properties.qualor.quality for external tools', () => {
    const out = normalizeSarif(
      log([], { rules: [{ id: 'X1', properties: { qualor: { quality: 'reliability' } } }] }),
      opts({ engineId: 'mytool' }),
    );
    expect(out.rules[0]!.quality).toBe('reliability');
  });

  it('redacts the secret region from snippet and hashes', () => {
    const out = normalizeSarif(
      log(
        [
          {
            ruleId: 'aws-access-token',
            message: { text: 'aws-access-token has detected secret' },
            locations: [loc('src/secret.ts', 2, { startColumn: 16, endColumn: 36 })],
          },
        ],
        { name: 'gitleaks', rules: [{ id: 'aws-access-token' }] },
      ),
      opts({ engineId: 'gitleaks', mapping: { redactRegion: true } }),
    );
    const f = out.findings[0]!;
    expect(JSON.stringify(out)).not.toContain('AKIAABCDEFGHIJKLMNOP');
    expect(f.snippet!.lines[1]).toBe(`const token = "${REDACTED}";`);
    const redacted = ['const x = 1;', `const token = "${REDACTED}";`, 'export {};'];
    expect(f.lineHash).toBe(lineHash(redacted, 2, 2));
  });

  it('aggregates rules from extensions and deduplicates by id', () => {
    const l = log([]);
    (l.runs[0]!.tool as Record<string, unknown>)['extensions'] = [
      { name: 'plugin', rules: [{ id: 'no-console', name: 'dup' }, { id: 'plugin/x' }] },
    ];
    const out = normalizeSarif(l, opts());
    expect(out.rules.map((r) => [r.id, r.name])).toEqual([
      ['no-console', 'NoConsole'],
      ['plugin/x', undefined],
    ]);
  });

  it('redacts a multi-line region with columns (first line to end, middle lines whole, last line up to endColumn)', () => {
    const out = normalizeSarif(
      log(
        [
          {
            ruleId: 'aws-access-token',
            message: { text: 'aws-access-token has detected secret' },
            locations: [
              loc('src/multiline-secret.ts', 1, { startColumn: 7, endLine: 3, endColumn: 16 }),
            ],
          },
        ],
        { name: 'gitleaks', rules: [{ id: 'aws-access-token' }] },
      ),
      opts({ engineId: 'gitleaks', mapping: { redactRegion: true } }),
    );
    const f = out.findings[0]!;
    const json = JSON.stringify(out);
    expect(json).not.toContain('SECRETSTART');
    expect(json).not.toContain('MIDDLE SECRET LINE');
    expect(json).not.toContain('SECRETEND');
    const redacted = [`line1 ${REDACTED}`, REDACTED, `${REDACTED} rest`];
    expect(f.lineHash).toBe(lineHash(redacted, 1, 3));
    expect(f.snippet!.lines).toEqual(redacted);
  });

  it('redacts whole lines when no columns are given', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('src/a.ts', 5)],
        },
      ]),
      opts({ mapping: { redactRegion: true } }),
    );
    const f = out.findings[0]!;
    const redacted = [...FILES['src/a.ts']!];
    redacted[4] = REDACTED;
    expect(f.lineHash).toBe(lineHash(redacted, 5, 5));
    expect(JSON.stringify(out)).not.toContain('line 5;');
  });

  it('applies redactRegion per rule when given as a function', () => {
    const out = normalizeSarif(
      log(
        [
          {
            ruleId: 'secret-rule',
            message: { text: 'has a secret' },
            locations: [loc('src/secret.ts', 2, { startColumn: 16, endColumn: 36 })],
          },
          {
            ruleId: 'no-console',
            message: { text: 'no secret here' },
            locations: [loc('src/a.ts', 5)],
          },
        ],
        { rules: [{ id: 'secret-rule' }, { id: 'no-console' }] },
      ),
      opts({ mapping: { redactRegion: (rule) => rule?.id === 'secret-rule' } }),
    );
    const redactedSecretLine = ['const x = 1;', `const token = "${REDACTED}";`, 'export {};'];
    expect(out.findings[0]!.lineHash).toBe(lineHash(redactedSecretLine, 2, 2));
    expect(JSON.stringify(out)).not.toContain('AKIAABCDEFGHIJKLMNOP');
    expect(out.findings[1]!.lineHash).toBe(lineHash(FILES['src/a.ts']!, 5, 5));
  });

  it('normalises multiple runs under the same engineId, using the first run version', () => {
    const doc = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'ESLint', version: '9.1.0', rules: [{ id: 'no-console' }] } },
          results: [
            {
              ruleId: 'no-console',
              message: { text: 'from run 1' },
              locations: [loc('src/a.ts', 1)],
            },
          ],
        },
        {
          tool: { driver: { name: 'ESLint', version: '9.2.0', rules: [{ id: 'no-alert' }] } },
          results: [
            {
              ruleId: 'no-alert',
              message: { text: 'from run 2' },
              locations: [loc('src/a.ts', 2)],
            },
          ],
        },
      ],
    };
    const out = normalizeSarif(doc, opts());
    expect(out.version).toBe('9.1.0');
    expect(out.findings.map((f) => [f.engineId, f.ruleId, f.message])).toEqual([
      ['eslint', 'no-console', 'from run 1'],
      ['eslint', 'no-alert', 'from run 2'],
    ]);
    expect(out.rules.map((r) => r.id)).toEqual(['no-console', 'no-alert']);
  });

  it('falls back to semanticVersion when version is absent', () => {
    const doc = {
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: { name: 'ESLint', semanticVersion: '1.2.3', rules: [{ id: 'no-console' }] },
          },
          results: [],
        },
      ],
    };
    const out = normalizeSarif(doc, opts());
    expect(out.version).toBe('1.2.3');
  });

  it('decodes percent-encoded characters in relative URIs', () => {
    const out = normalizeSarif(
      log([{ ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/my%20file.ts')] }]),
      opts(),
    );
    expect(out.findings[0]!.location?.path).toBe('src/my file.ts');
  });

  it('resolves a uriBaseId with no matching originalUriBaseIds entry as a plain relative path', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'src/a.ts', uriBaseId: 'MISSING' },
                region: { startLine: 1 },
              },
            },
          ],
        },
      ]),
      opts(),
    );
    expect(out.findings[0]!.location?.path).toBe('src/a.ts');
  });

  it('includes CWEs from rule properties.cwe alongside tags', () => {
    const out = normalizeSarif(
      log([], { rules: [{ id: 'X2', properties: { cwe: ['CWE-79'], tags: ['CWE-89'] } }] }),
      opts({ engineId: 'mytool' }),
    );
    expect(out.rules[0]!.cwe).toEqual([79, 89]);
  });

  it('reads CWEs from relationships to the CWE taxonomy (SpotBugs) and ignores malformed ones', () => {
    const cweTarget = (id: string, name = 'CWE') => ({
      target: { id, toolComponent: { name } },
      kinds: ['superset'],
    });
    const out = normalizeSarif(
      log([], {
        rules: [
          {
            id: 'X3',
            relationships: [cweTarget('595'), cweTarget('12', 'OWASP'), { target: {} }],
          },
          { id: 'X4', relationships: 'not an array' },
        ],
      }),
      opts({ engineId: 'mytool' }),
    );
    expect(out.rules.map((r) => [r.id, r.cwe])).toEqual([
      ['X3', [595]],
      ['X4', undefined],
    ]);
  });

  it('bounds CWEs from relationships: plain numbers of at most 7 digits, at most the CWE limit', () => {
    const rel = (id: unknown) => ({ target: { id, toolComponent: { name: 'cwe' } } });
    const out = normalizeSarif(
      log([], {
        rules: [
          {
            id: 'X5',
            relationships: [
              rel('99999999999999999999'),
              rel('CWE-79'),
              rel('7 CWE-89'),
              rel(' 22'),
              rel(22),
              rel('0'),
              rel('1234567'),
            ],
          },
          {
            id: 'X6',
            relationships: Array.from({ length: 1000 }, (_, i) => rel(String(i + 1))),
          },
        ],
      }),
      opts({ engineId: 'mytool' }),
    );
    expect(out.rules[0]!.cwe).toEqual([1234567]);
    expect(out.rules[1]!.cwe).toHaveLength(REPORT_BOUNDS.ruleCwes);
  });

  it('drops findings whose URI has a non-file scheme', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('https://example.com/x.ts')],
        },
      ]),
      opts(),
    );
    expect(out.findings).toHaveLength(0);
    expect(out.warnings).toEqual([
      expect.objectContaining({ code: 'FINDING_PATH_INVALID', count: 1 }),
    ]);
  });

  it('drops findings whose file: URI has a non-empty host (UNC path)', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('file://server/share/src/a.ts')],
        },
      ]),
      opts(),
    );
    expect(out.findings).toHaveLength(0);
    expect(out.warnings).toEqual([
      expect.objectContaining({ code: 'FINDING_PATH_INVALID', count: 1 }),
    ]);
  });

  it('resolves tool paths relative to source roots', () => {
    const files = { 'src/main/java/com/acme/A.java': ['class A {}', 'int x;'] } as Record<
      string,
      string[]
    >;
    const out = normalizeSarif(
      log([
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('com/acme/A.java', 2)] },
      ]),
      opts({ readLines: (p) => files[p] ?? null, sourceRoots: ['src/main/java'] }),
    );
    expect(out.findings[0]!.location!.path).toBe('src/main/java/com/acme/A.java');
    expect(out.warnings).toEqual([]);
  });

  it('treats empty or whitespace-only text as absent in the message fallback chain', () => {
    const out = normalizeSarif(
      log([
        { ruleId: 'no-console', message: { text: '' }, locations: [loc('src/a.ts')] },
        { ruleId: 'no-console', message: { text: '   ' }, locations: [loc('src/a.ts')] },
        {
          ruleId: 'no-console',
          message: { markdown: 'from markdown' },
          locations: [loc('src/a.ts')],
        },
      ]),
      opts(),
    );
    expect(out.findings.map((f) => f.message)).toEqual([
      'Disallow console',
      'Disallow console',
      'from markdown',
    ]);
  });

  it('falls back to level none for a non-fail kind without a level (SARIF §3.27.10)', () => {
    const r = (ruleId: string, extra: Record<string, unknown>) => ({
      ruleId,
      message: { text: 'm' },
      locations: [loc('src/a.ts')],
      ...extra,
    });
    const out = normalizeSarif(
      log([
        r('no-console', { kind: 'informational' }),
        r('no-console', { kind: 'review' }),
        r('no-console', { kind: 'open' }),
        r('no-console', { kind: 'fail' }),
        r('unknown-rule', { kind: 'fail' }),
        r('no-console', { kind: 'review', level: 'error' }),
      ]),
      opts(),
    );
    expect(out.findings.map((f) => f.severity)).toEqual([
      'info',
      'info',
      'info',
      'medium',
      'medium',
      'high',
    ]);
  });

  it('drops partial fingerprints when the mapping says so', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'a' },
          locations: [loc('src/a.ts')],
          partialFingerprints: { author: 'Jane', email: 'jane@example.com' },
        },
      ]),
      opts({ mapping: { dropPartialFingerprints: true } }),
    );
    expect(out.findings[0]).not.toHaveProperty('partialFingerprints');
  });

  it('drops partial fingerprints that exceed the report bounds, with a warning', () => {
    const many = Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`k${i}`, 'v']));
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: 'a' },
          locations: [loc('src/a.ts')],
          partialFingerprints: many,
        },
        {
          ruleId: 'no-console',
          message: { text: 'b' },
          locations: [loc('src/a.ts')],
          partialFingerprints: { ['k'.repeat(129)]: 'v' },
        },
        {
          ruleId: 'no-console',
          message: { text: 'c' },
          locations: [loc('src/a.ts')],
          partialFingerprints: { k: 'v'.repeat(257) },
        },
      ]),
      opts(),
    );
    expect(out.findings.some((f) => 'partialFingerprints' in f)).toBe(false);
    expect(out.warnings).toEqual([
      expect.objectContaining({ code: 'PARTIAL_FINGERPRINTS_DROPPED', count: 3 }),
    ]);
  });
});

describe('normalizeSarif secret redaction across findings', () => {
  const S1 = 'Zq8XwV3mN7pL2rT5';
  const S2 = 'Hj4Kd9Fs6Gb1Yt0P';
  const secretLoc = (uri: string, line: number, snippetText?: string) => ({
    physicalLocation: {
      artifactLocation: { uri },
      region: {
        startLine: line,
        startColumn: 13,
        endColumn: 29,
        ...(snippetText !== undefined && { snippet: { text: snippetText } }),
      },
    },
  });
  const gitleaks = (results: unknown[]) =>
    log(results, { name: 'gitleaks', rules: [{ id: 'generic-api-key' }, { id: 'no-console' }] });
  const leak = (uri: string, line: number, snippetText?: string, extra = {}) => ({
    ruleId: 'generic-api-key',
    message: { text: 'generic-api-key has detected secret' },
    locations: [secretLoc(uri, line, snippetText)],
    ...extra,
  });
  const secretOpts = opts({
    engineId: 'gitleaks',
    mapping: { redactRegion: (rule) => rule?.id === 'generic-api-key' },
  });

  it('redacts neighbouring secrets in every snippet of the log', () => {
    const out = normalizeSarif(
      gitleaks([leak('src/two-secrets.ts', 2), leak('src/two-secrets.ts', 4)]),
      secretOpts,
    );
    const json = JSON.stringify(out);
    expect(json).not.toContain(S1);
    expect(json).not.toContain(S2);
    expect(out.findings[0]!.snippet!.lines).toEqual([
      'const a = 1;',
      `const k1 = "${REDACTED}";`,
      'call(k1, k2);',
      `const k2 = "${REDACTED}";`,
      'export {};',
    ]);
    // Each finding's own hashes only redact its own region.
    const own = [...FILES['src/two-secrets.ts']!];
    own[1] = `const k1 = "${REDACTED}";`;
    expect(out.findings[0]!.contextHash).toBe(contextHash(own, 2, 2));
  });

  it('redacts the snippet of a non-redacting finding but hashes its unredacted lines', () => {
    const raw = FILES['src/two-secrets.ts']!;
    const out = normalizeSarif(
      gitleaks([
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/two-secrets.ts', 3)] },
        leak('src/two-secrets.ts', 2),
      ]),
      secretOpts,
    );
    const f = out.findings[0]!;
    expect(f.ruleId).toBe('no-console');
    expect(f.snippet!.lines[1]).toBe(`const k1 = "${REDACTED}";`);
    expect(f.lineHash).toBe(lineHash(raw, 3, 3));
    expect(f.contextHash).toBe(contextHash(raw, 3, 3));
    expect(JSON.stringify(out)).not.toContain(S1);
  });

  it('scrubs region.snippet.text wherever it appears in snippets and messages', () => {
    const out = normalizeSarif(
      gitleaks([
        leak('src/repeated-secret.ts', 2, S1),
        {
          ruleId: 'no-console',
          message: { text: `found ${S1} again` },
          locations: [loc('src/a.ts', 1)],
          relatedLocations: [{ ...loc('src/a.ts', 2), message: { text: `see ${S1}` } }],
        },
      ]),
      secretOpts,
    );
    expect(JSON.stringify(out)).not.toContain(S1);
    expect(out.findings[0]!.snippet!.lines[3]).toBe(`// copy: ${REDACTED} and short`);
    expect(out.findings[1]!.message).toBe(`found ${REDACTED} again`);
    expect(out.findings[1]!.secondaryLocations![0]!.message).toBe(`see ${REDACTED}`);
  });

  it('does not scrub snippet texts shorter than 8 characters', () => {
    const out = normalizeSarif(
      gitleaks([leak('src/a.ts', 5, 'line')]),
      opts({ engineId: 'gitleaks', mapping: { redactRegion: true } }),
    );
    expect(out.findings[0]!.snippet!.lines[0]).toBe('line 2;');
  });

  it('redacts regions of suppressed secret results in other snippets', () => {
    const out = normalizeSarif(
      gitleaks([
        leak('src/two-secrets.ts', 2, undefined, { suppressions: [{ kind: 'inSource' }] }),
        leak('src/two-secrets.ts', 4),
      ]),
      secretOpts,
    );
    expect(out.findings).toHaveLength(1);
    expect(JSON.stringify(out.findings)).not.toContain(S1);
  });

  it("replaces a redacting result's message with the rule's static text (a metavariable can interpolate part of the match)", () => {
    const semgrepLog = (rule: Record<string, unknown>) =>
      log(
        [
          {
            ruleId: 'k',
            // `message: "key $K in $N"` with only the secret bound to $K: the whole-match text
            // (region.snippet.text) never occurs in it, so a text scrub cannot find it.
            message: { text: `key ${S1} in k1` },
            locations: [secretLoc('src/two-secrets.ts', 2, `const k1 = "${S1}";`)],
          },
        ],
        { name: 'Semgrep OSS', rules: [{ id: 'k', ...rule }] },
      );
    const secretRule = { redactRegion: true } as const;
    const run = (rule: Record<string, unknown>) =>
      normalizeSarif(semgrepLog(rule), opts({ engineId: 'semgrep', mapping: secretRule }));
    const full = run({
      fullDescription: { text: 'key $K in $N' },
      shortDescription: { text: 'Semgrep Finding: k' },
    });
    expect(full.findings[0]!.message).toBe('key $K in $N');
    expect(JSON.stringify(full)).not.toContain(S1);
    expect(run({ shortDescription: { text: 'Semgrep Finding: k' } }).findings[0]!.message).toBe(
      'Semgrep Finding: k',
    );
    expect(run({ fullDescription: { text: '  ' } }).findings[0]!.message).toBe('k');
    // A malformed fullDescription is ignored, never a reason to reject the log.
    expect(run({ fullDescription: 7 }).findings[0]!.message).toBe('k');
    // The rule's own static text is still scrubbed of the secret text (here the whole match).
    // A Semgrep snippet is the whole match, not the secret, so it feeds no fragments (fix round 2);
    // a rule quoting only part of it is the repository's own doing (config.md, code-equivalent).
    expect(
      run({ fullDescription: { text: `never const k1 = "${S1}";` } }).findings[0]!.message,
    ).toBe(`never ${REDACTED}`);
  });

  // Fix round 2 of tasks 5-6: fragments come only from texts that are the secret itself.
  const exactOpts = opts({
    engineId: 'gitleaks',
    mapping: { exactSecretText: true, redactRegion: (rule) => rule?.id === 'generic-api-key' },
  });

  it('scrubs every fragment of at least 8 characters of an exact secret text from messages', () => {
    const { result: out, secrets } = normalizeSarifWithSecrets(
      gitleaks([
        leak('src/two-secrets.ts', 2, S1),
        {
          ruleId: 'no-console',
          message: { text: `a ${S1} b ${S1.slice(3, 11)} c ${S1.slice(0, 7)} d` },
          locations: [loc('src/a.ts', 1)],
          relatedLocations: [{ ...loc('src/a.ts', 2), message: { text: `see ${S1.slice(2)}` } }],
        },
      ]),
      exactOpts,
    );
    const f = out.findings.find((x) => x.ruleId === 'no-console')!;
    expect(f.message).toBe(`a ${REDACTED} b ${REDACTED} c ${S1.slice(0, 7)} d`);
    expect(f.secondaryLocations![0]!.message).toBe(`see ${REDACTED}`);
    expect(JSON.stringify(out)).not.toContain(S1);
    expect(secrets.fragmentTexts).toEqual([S1]);
  });

  it('takes no fragments from the code of a whole-match snippet or from a region-derived text, so code words stay readable', () => {
    const message = `const k1 = is fine, ${S1.slice(3, 11)} too`;
    const other = {
      ruleId: 'no-console',
      message: { text: message },
      locations: [loc('src/a.ts', 1)],
    };
    // A Semgrep-style snippet: the whole match. Only its quoted literal (the secret) feeds
    // fragments; `const k1 = ` is never blanked (round 1 blanked it).
    const whole = normalizeSarifWithSecrets(
      gitleaks([leak('src/two-secrets.ts', 2, `const k1 = "${S1}";`), other]),
      secretOpts,
    );
    expect(whole.result.findings.find((x) => x.ruleId === 'no-console')!.message).toBe(
      `const k1 = is fine, ${REDACTED} too`,
    );
    expect(whole.secrets.fragmentTexts).toEqual([S1]);
    // Without a quoted literal, a whole match feeds no fragments at all.
    const bare = normalizeSarifWithSecrets(
      gitleaks([leak('src/two-secrets.ts', 2, `const k1 = ${S1};`), other]),
      secretOpts,
    );
    expect(bare.result.findings.find((x) => x.ruleId === 'no-console')!.message).toBe(message);
    expect(bare.secrets.fragmentTexts).toEqual([]);
    // Gitleaks without snippet text: the region columns cover the match, so exact text only.
    const derived = normalizeSarifWithSecrets(
      gitleaks([leak('src/two-secrets.ts', 2), other]),
      exactOpts,
    );
    expect(derived.secrets.texts).toEqual([S1]);
    expect(derived.secrets.fragmentTexts).toEqual([]);
  });

  it("takes the quoted literals of a secret rule's whole-match snippet as the secret itself", () => {
    const other = (text: string) => ({
      ruleId: 'no-console',
      message: { text },
      locations: [loc('src/a.ts', 1)],
    });
    const { result, secrets } = normalizeSarifWithSecrets(
      gitleaks([
        leak('src/two-secrets.ts', 2, `const k1 = "${S1}"; const short = 'abc'; x(\`${S2}\`)`),
        other(`value ${S1}`),
        other(`part ${S2.slice(1, 10)} and const k1 = kept`),
      ]),
      secretOpts,
    );
    expect(result.findings.filter((f) => f.ruleId === 'no-console').map((f) => f.message)).toEqual([
      `value ${REDACTED}`,
      `part ${REDACTED} and const k1 = kept`,
    ]);
    expect(secrets.fragmentTexts).toEqual([S1, S2]);
  });

  it('applies extraFragmentTexts from other engines to messages', () => {
    const out = normalizeSarif(
      log([
        {
          ruleId: 'no-console',
          message: { text: `part ${S1.slice(0, 9)} end` },
          locations: [loc('src/a.ts', 5)],
        },
      ]),
      opts({ extraSecretTexts: [S1], extraFragmentTexts: [S1] }),
    );
    expect(out.findings[0]!.message).toBe(`part ${REDACTED} end`);
  });

  it(
    'stays bounded with thousands of long secrets: never throws, exact scrubbing past the fragment cap',
    { timeout: 30_000 },
    () => {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let seed = 7;
      const next = () => {
        seed = (seed * 48271) % 2147483647;
        return chars[seed % chars.length];
      };
      const texts = Array.from({ length: 4200 }, () => Array.from({ length: 4096 }, next).join(''));
      const last = texts[texts.length - 1]!;
      const started = performance.now();
      const out = normalizeSarif(
        gitleaks([
          ...texts.map((t) => leak('src/a.ts', 1, t)),
          {
            ruleId: 'no-console',
            message: { text: `whole ${last} and part ${texts[0]!.slice(5, 20)}` },
            locations: [loc('src/a.ts', 2)],
          },
        ]),
        exactOpts,
      );
      expect(performance.now() - started).toBeLessThan(budgetMs(4000));
      const f = out.findings.find((x) => x.ruleId === 'no-console')!;
      // The last text is past the cap: still scrubbed exactly. The first one's fragment is caught.
      expect(f.message).toBe(`whole ${REDACTED} and part ${REDACTED}`);
    },
  );

  it('scrubs the union of overlapping secret texts, so no tail of an overlap survives', () => {
    const a = 'AAAABBBBCCCC1234';
    const b = 'CCCC1234DDDDEEEE';
    const out = normalizeSarif(
      gitleaks([
        leak('src/two-secrets.ts', 2, a),
        leak('src/two-secrets.ts', 4, b),
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('src/a.ts', 5)],
          properties: { overlap: `x ${a.slice(0, 8)}${b} y`, adjacent: `${b}${a}` },
        },
      ]),
      secretOpts,
    );
    const f = out.findings.find((x) => x.ruleId === 'no-console')!;
    expect(f.properties).toEqual({
      overlap: `x ${REDACTED} y`,
      adjacent: `${REDACTED}${REDACTED}`,
    });
  });

  const randomText = (seed: number, alphabet: string) => {
    let state = seed;
    return (length: number) =>
      Array.from({ length }, () => {
        state = (state * 48271) % 2147483647;
        return alphabet[state % alphabet.length];
      }).join('');
  };

  it(
    'stays near-linear when thousands of secrets share one 8-character prefix',
    { timeout: 60_000 },
    () => {
      const next = randomText(11, 'BCDEFGHIJKLMNOPQRSTUVWXYZbcdefghijklmnopqrstuvwxyz0123456789');
      const texts = Array.from({ length: 5000 }, () => `AAAAAAAA${next(24)}`);
      const flood = 'A'.repeat(200_000);
      const started = performance.now();
      const out = normalizeSarif(
        gitleaks([
          ...texts.map((t) => leak('src/a.ts', 1, t)),
          {
            ruleId: 'no-console',
            message: { text: `${texts[4999]!}${flood}${texts[0]!}` },
            locations: [loc('src/a.ts', 2)],
          },
        ]),
        secretOpts,
      );
      expect(performance.now() - started).toBeLessThan(budgetMs(2000));
      const f = out.findings.find((x) => x.ruleId === 'no-console')!;
      expect(f.message.startsWith(`${REDACTED}AAAAAAAA`)).toBe(true);
    },
  );

  it('indexes foreign and shortest fragment texts first when the fragment cap is reached', () => {
    const next = randomText(23, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
    // Own texts that fill the 250 000-fragment cap to within 5: 61 × 4 089 + 566 = 249 995.
    const fill = [...Array.from({ length: 61 }, () => next(4096)), next(573)];
    const ownShort = next(20);
    const foreign = next(20);
    const out = normalizeSarif(
      gitleaks([
        ...fill.map((t) => leak('src/a.ts', 1, t)),
        leak('src/a.ts', 1, ownShort),
        {
          ruleId: 'no-console',
          message: { text: `own ${ownShort.slice(2, 12)} foreign ${foreign.slice(3, 13)}` },
          locations: [loc('src/a.ts', 2)],
        },
      ]),
      { ...exactOpts, extraSecretTexts: [foreign], extraFragmentTexts: [foreign] },
    );
    const f = out.findings.find((x) => x.ruleId === 'no-console')!;
    expect(f.message).toBe(`own ${REDACTED} foreign ${REDACTED}`);
  });

  it('exports the resolved secret regions', () => {
    const out = normalizeSarif(
      gitleaks([
        leak('src/two-secrets.ts', 2),
        { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/a.ts', 3)] },
        leak('src/two-secrets.ts', 4),
      ]),
      secretOpts,
    );
    expect(out.secretRegions).toEqual([
      { path: 'src/two-secrets.ts', startLine: 2, startColumn: 13, endLine: 2, endColumn: 28 },
      { path: 'src/two-secrets.ts', startLine: 4, startColumn: 13, endLine: 4, endColumn: 28 },
    ]);
    expect(normalizeSarif(log([]), opts()).secretRegions).toEqual([]);
  });

  it('applies extraSecretRegions to snippets but never to hashes (cross-engine redaction)', () => {
    const results = [
      { ruleId: 'no-console', message: { text: 'm' }, locations: [loc('src/two-secrets.ts', 3)] },
    ];
    const region = {
      path: 'src/two-secrets.ts',
      startLine: 2,
      startColumn: 13,
      endLine: 2,
      endColumn: 28,
    };
    const plain = normalizeSarif(log(results), opts());
    const out = normalizeSarif(log(results), opts({ extraSecretRegions: [region] }));
    expect(plain.findings[0]!.snippet!.lines[1]).toContain(S1);
    expect(out.findings[0]!.snippet!.lines[1]).toBe(`const k1 = "${REDACTED}";`);
    expect(JSON.stringify(out)).not.toContain(S1);
    expect(out.findings[0]!.lineHash).toBe(plain.findings[0]!.lineHash);
    expect(out.findings[0]!.contextHash).toBe(plain.findings[0]!.contextHash);
    expect(out.secretRegions).toEqual([]);
  });

  it('applies extraSecretTexts to snippets and messages, alongside extraSecretRegions', () => {
    const { result, secrets } = normalizeSarifWithSecrets(
      log([
        { ruleId: 'no-console', message: { text: `see ${S1}` }, locations: [loc('src/a.ts', 5)] },
      ]),
      opts({ extraSecretTexts: [S1] }),
    );
    expect(result.findings[0]!.message).toBe(`see ${REDACTED}`);
    expect(secrets.texts).toEqual([]);
    expect(JSON.stringify(result)).not.toContain(S1);
  });

  it('exports region.snippet.text alongside secretRegions for the CLI to scrub cross-engine, kept out of the serialisable result (finding 5)', () => {
    const { result, secrets } = normalizeSarifWithSecrets(
      gitleaks([leak('src/two-secrets.ts', 2, S1)]),
      secretOpts,
    );
    expect(secrets.texts).toEqual([S1]);
    expect(secrets.regions).toEqual(result.secretRegions);
    expect(result).not.toHaveProperty('secretTexts');
    expect(JSON.stringify(result)).not.toContain(S1);
  });

  it('derives the secret text from a redacting result’s own region when it has no snippet.text, so its message is still scrubbed (finding 2)', () => {
    const out = normalizeSarif(
      gitleaks([
        {
          ruleId: 'generic-api-key',
          message: { text: `generic-api-key found ${S1}` },
          locations: [secretLoc('src/two-secrets.ts', 2)],
        },
      ]),
      secretOpts,
    );
    // Fix round 1 of tasks 5-6: a redacting result's own message is replaced by its rule's static
    // text (here only the id), so neither the secret nor the text around it survives.
    expect(out.findings[0]!.message).toBe('generic-api-key');
    expect(JSON.stringify(out)).not.toContain(S1);
  });

  it('derives the secret text even when the redacting result’s own file is out of scope, e.g. a .env (fix-round-2 finding 4)', () => {
    const { result, secrets } = normalizeSarifWithSecrets(
      gitleaks([leak('src/two-secrets.ts', 2)]),
      opts({
        engineId: 'gitleaks',
        mapping: { redactRegion: (rule) => rule?.id === 'generic-api-key' },
        knownPaths: new Set(['src/a.ts']), // src/two-secrets.ts is readable but not in scope
      }),
    );
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual([expect.objectContaining({ code: 'FINDING_OUT_OF_SCOPE' })]);
    expect(secrets.texts).toEqual([S1]);
    expect(JSON.stringify(result)).not.toContain(S1);
  });

  it('drops properties and partialFingerprints entirely for a redacting result (finding 2)', () => {
    const out = normalizeSarif(
      gitleaks([
        {
          ...leak('src/two-secrets.ts', 2),
          properties: { note: 'x' },
          partialFingerprints: { k: 'v' },
        },
      ]),
      secretOpts,
    );
    expect(out.findings[0]).not.toHaveProperty('properties');
    expect(out.findings[0]).not.toHaveProperty('partialFingerprints');
  });

  it('scrubs secret text from properties, and drops a partialFingerprints value containing one, for a non-redacting result (finding 2)', () => {
    const out = normalizeSarif(
      gitleaks([
        leak('src/two-secrets.ts', 2), // establishes S1 as a known secret text
        {
          ruleId: 'no-console',
          message: { text: 'm' },
          locations: [loc('src/a.ts', 5)],
          properties: { note: `copy: ${S1}`, nested: { list: [S1, 'safe'] } },
          partialFingerprints: { hash: `sha:${S1}`, stable: 'unrelated' },
        },
      ]),
      secretOpts,
    );
    const f = out.findings[1]!;
    expect(f.properties).toEqual({
      note: `copy: ${REDACTED}`,
      nested: { list: [REDACTED, 'safe'] },
    });
    expect(f.partialFingerprints).toEqual({ stable: 'unrelated' });
    expect(JSON.stringify(out)).not.toContain(S1);
  });

  it(
    'finds a secret text occurrence directly on the raw line, so a byte-based column that ' +
      'understates its start (non-ASCII text before the secret) cannot leave a leading fragment ' +
      'visible in the snippet or the hash (ruling R18, finding 6)',
    () => {
      const files: Record<string, string[]> = {
        'src/nonascii-secret.ts': ['const ééé = "Zq8XwV3mN7pL2rT5";'],
      };
      // A byte-based column: 3 leading 2-byte 'é' characters push the true UTF-8 byte offset of
      // the secret 6 bytes past its actual (UTF-16) string index, understating where it starts.
      const results = [
        {
          ruleId: 'generic-api-key',
          message: { text: 'generic-api-key has detected secret' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: 'src/nonascii-secret.ts' },
                region: {
                  startLine: 1,
                  startColumn: 17,
                  endLine: 1,
                  endColumn: 33,
                  snippet: { text: S1 },
                },
              },
            },
          ],
        },
      ];
      const out = normalizeSarif(
        gitleaks(results),
        opts({
          engineId: 'gitleaks',
          mapping: { redactRegion: true },
          readLines: (p) => files[p] ?? null,
        }),
      );
      const json = JSON.stringify(out);
      expect(json).not.toContain(S1);
      expect(json).not.toContain('Zq8');
      expect(out.findings[0]!.snippet!.lines[0]).toBe(`const ééé = "${REDACTED}`);
      const redactedLine = [`const ééé = "${REDACTED}`];
      expect(out.findings[0]!.lineHash).toBe(lineHash(redactedLine, 1, 1));
      expect(out.findings[0]!.contextHash).toBe(contextHash(redactedLine, 1, 1));
    },
  );
});
