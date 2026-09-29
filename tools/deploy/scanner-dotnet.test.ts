import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { expectedContent, imageProblems, PROBE } from './scanner-dotnet';

const INSTALL = readFileSync('tools/analyzers/install-dotnet.sh', 'utf8');

/** What `ls /opt/qualor/dotnet/analyzers` printed in the image built in plan 2D. */
const ROSLYNATOR = [
  'Roslynator.CSharp.Analyzers.CodeFixes.dll',
  'Roslynator.CSharp.Analyzers.dll',
  'Roslynator_Analyzers_Roslynator.CSharp.Workspaces.dll',
  'Roslynator_Analyzers_Roslynator.CSharp.dll',
  'Roslynator_Analyzers_Roslynator.Common.dll',
  'Roslynator_Analyzers_Roslynator.Core.dll',
  'Roslynator_Analyzers_Roslynator.Workspaces.Common.dll',
  'Roslynator_Analyzers_Roslynator.Workspaces.Core.dll',
];

/** What `ls /opt/qualor/dotnet/analyzers/sonar` printed in the image built for Task 3. */
const SONAR = [
  'Google.Protobuf.dll',
  'SonarAnalyzer.CFG.dll',
  'SonarAnalyzer.CSharp.dll',
  'SonarAnalyzer.dll',
  'SonarAnalyzer.ShimLayer.dll',
];

function output(
  o: {
    sdks?: string[];
    analyzers?: string[];
    sonar?: string[];
    licenses?: string[];
    version?: string;
  } = {},
) {
  return [
    '== sdks',
    ...(o.sdks ?? [
      '8.0.425 [/opt/qualor/share/dotnet/sdk]',
      '10.0.401 [/opt/qualor/share/dotnet/sdk]',
    ]),
    '== analyzers',
    ...(o.analyzers ?? ROSLYNATOR),
    '== sonar',
    ...(o.sonar ?? SONAR),
    '== licenses',
    ...(o.licenses ?? [
      'DOTNET-10.0.401-ThirdPartyNotices.txt',
      'DOTNET-8.0.425-ThirdPartyNotices.txt',
      'DOTNET-LICENSE.txt',
      'GITLEAKS-LICENSE.txt',
      'ROSLYNATOR-LICENSE.txt',
      'SONARANALYZER-CSHARP-LICENSE.txt',
      'TREE-SITTER-C-SHARP-LICENSE.txt',
    ]),
    '== version',
    o.version ?? 'qualor 0.0.0 (linux-x64)\ngrammars: java (ABI 14), csharp (ABI 15)',
    '== end',
    '',
  ].join('\n');
}

describe('the qualor/scanner-dotnet content check (deploy/README.md)', () => {
  it('reads the SDK versions from install-dotnet.sh, not from a second copy', () => {
    const expected = expectedContent(INSTALL);
    expect(expected.sdks).toEqual([
      INSTALL.match(/^DOTNET8_VERSION=(\S+)$/m)?.[1],
      INSTALL.match(/^DOTNET10_VERSION=(\S+)$/m)?.[1],
    ]);
    expect(expected.licenses).toEqual([
      'DOTNET-LICENSE.txt',
      ...expected.sdks.map((v) => `DOTNET-${v}-ThirdPartyNotices.txt`),
      'ROSLYNATOR-LICENSE.txt',
      'SONARANALYZER-CSHARP-LICENSE.txt',
      'TREE-SITTER-C-SHARP-LICENSE.txt',
    ]);
    expect(expected.analyzers).toBe(8);
    expect(expected.sonarAnalyzers).toBe(5);
    expect(() => expectedContent('#!/bin/sh\n')).toThrow(/DOTNET8_VERSION/);
  });

  it('probes every section in one shell, which never stops at the first failure', () => {
    for (const part of [
      'dotnet --list-sdks',
      '/opt/qualor/dotnet/analyzers',
      '/opt/qualor/dotnet/analyzers/sonar',
      '/opt/qualor/licenses',
      'qualor version',
    ]) {
      expect(PROBE).toContain(part);
    }
    expect(PROBE).not.toMatch(/set -e/);
  });

  it('passes an image with everything, and names each missing piece', () => {
    const expected = expectedContent(INSTALL);
    expect(imageProblems(output(), expected)).toEqual([]);
    expect(
      imageProblems(
        output({
          sdks: ['8.0.425 [/opt/qualor/share/dotnet/sdk]'],
          analyzers: ROSLYNATOR.slice(1),
          licenses: ['DOTNET-LICENSE.txt'],
          version: 'grammars: java (ABI 14)',
        }),
        expected,
      ),
    ).toEqual([
      'dotnet --list-sdks does not list 10.0.401',
      '/opt/qualor/dotnet/analyzers holds 7 Roslynator*.dll, not 8',
      '/opt/qualor/licenses/ has no DOTNET-8.0.425-ThirdPartyNotices.txt',
      '/opt/qualor/licenses/ has no DOTNET-10.0.401-ThirdPartyNotices.txt',
      '/opt/qualor/licenses/ has no ROSLYNATOR-LICENSE.txt',
      '/opt/qualor/licenses/ has no SONARANALYZER-CSHARP-LICENSE.txt',
      '/opt/qualor/licenses/ has no TREE-SITTER-C-SHARP-LICENSE.txt',
      'qualor version does not list the csharp grammar',
    ]);
    // A command that is missing altogether leaves its error text, not a match.
    expect(
      imageProblems(output({ sdks: ['sh: 1: dotnet: not found'] }), expected).slice(0, 2),
    ).toEqual([
      'dotnet --list-sdks does not list 8.0.425',
      'dotnet --list-sdks does not list 10.0.401',
    ]);
    expect(imageProblems('', expected)).toContain('the probe printed no "== end" line');
  });

  it('names it when the sonar directory is short a SonarAnalyzer DLL', () => {
    const expected = expectedContent(INSTALL);
    expect(imageProblems(output({ sonar: SONAR.slice(1) }), expected)).toEqual([
      'expected 5 SonarAnalyzer DLLs in /opt/qualor/dotnet/analyzers/sonar, found 4',
    ]);
  });
});
