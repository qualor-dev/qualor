/**
 * The content check of the qualor/scanner-dotnet image (`pnpm deploy:scanner-dotnet-check`,
 * deploy/README.md): what `tools/analyzers/install-dotnet.sh` and the licence files promise, and
 * whether one probe of a built image finds it. Pure, so the parsing is tested without Docker.
 */

export interface ExpectedContent {
  /** The .NET SDK versions `dotnet --list-sdks` must list. */
  sdks: string[];
  /** How many `Roslynator*.dll` the analyzers directory holds (Roslynator.Analyzers' roslyn4.7/cs). */
  analyzers: number;
  /** How many SonarAnalyzer DLLs the analyzers/sonar directory holds (sonaranalyzer.csharp's analyzers/). */
  sonarAnalyzers: number;
  /** Files `/opt/qualor/licenses/` must have for the .NET SDKs, Roslynator, SonarAnalyzer.CSharp and C# parsing. */
  licenses: string[];
}

const ANALYZERS_DIR = '/opt/qualor/dotnet/analyzers';
const SONAR_DIR = `${ANALYZERS_DIR}/sonar`;
const LICENSES_DIR = '/opt/qualor/licenses';
const ROSLYNATOR_DLLS = 8;
const SONAR_DLLS = 5;

/** The SDK versions come from install-dotnet.sh itself, so they are written down once. */
export function expectedContent(installScript: string): ExpectedContent {
  const version = (name: string): string => {
    const found = new RegExp(`^${name}=(\\S+)$`, 'm').exec(installScript)?.[1];
    if (found === undefined) throw new Error(`install-dotnet.sh sets no ${name}`);
    return found;
  };
  const sdks = [version('DOTNET8_VERSION'), version('DOTNET10_VERSION')];
  return {
    sdks,
    analyzers: ROSLYNATOR_DLLS,
    sonarAnalyzers: SONAR_DLLS,
    licenses: [
      'DOTNET-LICENSE.txt',
      ...sdks.map((v) => `DOTNET-${v}-ThirdPartyNotices.txt`),
      'ROSLYNATOR-LICENSE.txt',
      'SONARANALYZER-CSHARP-LICENSE.txt',
      'SONARANALYZER-CSHARP-THIRD-PARTY-NOTICES.txt',
      'TREE-SITTER-C-SHARP-LICENSE.txt',
    ],
  };
}

/**
 * One `sh -c` inside the image, as its default user: each section's output follows its `== name`
 * line, errors included (no `set -e`), and `== end` proves the shell got to the end.
 */
export const PROBE = [
  'echo "== sdks"; dotnet --list-sdks 2>&1',
  `echo "== analyzers"; ls ${ANALYZERS_DIR} 2>&1`,
  `echo "== sonar"; ls ${SONAR_DIR} 2>&1`,
  `echo "== licenses"; ls ${LICENSES_DIR} 2>&1`,
  'echo "== version"; qualor version 2>&1',
  'echo "== end"',
].join('; ');

function sections(output: string): Map<string, string[]> {
  const result = new Map<string, string[]>();
  let current: string[] | undefined;
  for (const line of output.split(/\r?\n/)) {
    const header = /^== (\S+)$/.exec(line);
    if (header?.[1] !== undefined) {
      current = [];
      result.set(header[1], current);
    } else if (current !== undefined && line.trim() !== '') {
      current.push(line.trim());
    }
  }
  return result;
}

/** What the probe's output lacks, one line each; empty when the image is complete. */
export function imageProblems(output: string, expected: ExpectedContent): string[] {
  const found = sections(output);
  const problems: string[] = [];
  if (!found.has('end')) problems.push('the probe printed no "== end" line');
  const sdks = new Set((found.get('sdks') ?? []).map((line) => line.split(/\s+/)[0]));
  for (const v of expected.sdks) {
    if (!sdks.has(v)) problems.push(`dotnet --list-sdks does not list ${v}`);
  }
  const dlls = (found.get('analyzers') ?? []).filter((n) => /^Roslynator.*\.dll$/.test(n)).length;
  if (dlls !== expected.analyzers) {
    problems.push(`${ANALYZERS_DIR} holds ${dlls} Roslynator*.dll, not ${expected.analyzers}`);
  }
  // `SonarAnalyzer.dll` itself is one of the five bundled DLLs (no second dot before `.dll`), so
  // the SonarAnalyzer alternative can't require one.
  const sonarDlls = (found.get('sonar') ?? []).filter((n) =>
    /^(SonarAnalyzer.*|Google\.Protobuf)\.dll$/.test(n),
  ).length;
  if (sonarDlls !== expected.sonarAnalyzers) {
    problems.push(
      `expected ${expected.sonarAnalyzers} SonarAnalyzer DLLs in ${SONAR_DIR}, found ${sonarDlls}`,
    );
  }
  const licenses = new Set(found.get('licenses') ?? []);
  for (const file of expected.licenses) {
    if (!licenses.has(file)) problems.push(`${LICENSES_DIR}/ has no ${file}`);
  }
  const grammars = (found.get('version') ?? []).find((line) => line.startsWith('grammars:'));
  if (grammars === undefined || !/\bcsharp\b/.test(grammars)) {
    problems.push('qualor version does not list the csharp grammar');
  }
  return problems;
}
