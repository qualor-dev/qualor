import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { REPO_ROOT } from './stack';

/**
 * `pnpm deploy:scanner-dotnet-sonar-check [image]` (Task 4, Review Focus 1): proves, inside a
 * real `qualor/scanner-dotnet` image (default `qualor/scanner-dotnet:dev`), that a project's own
 * `SonarAnalyzer.CSharp` reference wins over the bundled one: `qualor dotnet begin`, then the
 * project's own `dotnet build` of a copy of `fixtures/csharp-basic` whose main project also
 * references SonarAnalyzer.CSharp 9.32.0.97167 (config.md §3, global constraints). The image's
 * `qualor` CLI must already carry this task's begin/session/hook changes — rebuild it from this
 * checkout first (deploy/README.md "Building") — and the run needs network access for the NuGet
 * restore, so it is not part of `pnpm test`; run it by hand after a rebuild.
 *
 * Fails unless: the build succeeds; its output has no CS8032 or AD0001 (the duplicate-analyzer
 * diagnostics); `session.props` (written by `begin`, before `dotnet end` would remove it) still
 * lists the bundled Sonar DLLs; and the diagnostic-verbosity build log shows the compiler loading
 * only the project's own restored SonarAnalyzer.CSharp copy, never the bundled one.
 */
const SONAR_VERSION = '9.32.0.97167';
const DUPLICATE_ANALYZER_CODES = ['CS8032', 'AD0001'];

function fail(message: string): never {
  throw new Error(message);
}

function main(): void {
  const args = process.argv.slice(2);
  if (args.length > 1 || args[0]?.startsWith('-')) {
    throw new Error('usage: pnpm deploy:scanner-dotnet-sonar-check [image]');
  }
  const image = args[0] ?? 'qualor/scanner-dotnet:dev';

  const work = mkdtempSync(path.join(os.tmpdir(), 'qualor-dotnet-sonar-'));
  try {
    const repo = path.join(work, 'repo');
    cpSync(path.join(REPO_ROOT, 'fixtures', 'csharp-basic'), repo, { recursive: true });
    rmSync(path.join(repo, 'coverage'), { recursive: true, force: true });
    const csproj = path.join(repo, 'src', 'Acme.Store', 'Acme.Store.csproj');
    const original = readFileSync(csproj, 'utf8');
    if (!original.includes('</PropertyGroup>')) fail(`unexpected ${csproj}`);
    writeFileSync(
      csproj,
      original.replace(
        '</PropertyGroup>',
        '</PropertyGroup>\n' +
          '  <ItemGroup>\n' +
          `    <PackageReference Include="SonarAnalyzer.CSharp" Version="${SONAR_VERSION}" PrivateAssets="all" />\n` +
          '  </ItemGroup>',
      ),
    );

    // A diagnostic-verbosity file logger (separate from the console logger, which stays at its
    // default verbosity so docker run's own output stays readable) so the Csc task's full
    // command line, with every /analyzer: switch, ends up in a file this script can read back
    // from the bind mount after the container exits.
    const diagLog = 'build.diag.log';
    const script = [
      'set -e',
      'git init -q .',
      'git add -A',
      'git -c user.email=t@t.example -c user.name=t commit -q -m fixture --no-verify',
      'qualor dotnet begin',
      `dotnet build --no-incremental -nologo Fixture.slnx '-flp:v=diag;logfile=${diagLog}'`,
    ].join(' && ');

    const r = spawnSync(
      'docker',
      [
        'run',
        '--rm',
        '-v',
        `${repo}:/work`,
        '-w',
        '/work',
        '--entrypoint',
        'sh',
        image,
        '-c',
        script,
      ],
      { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 },
    );
    process.stdout.write(r.stdout);
    process.stderr.write(r.stderr);
    if (r.status !== 0) {
      throw new Error(`the build failed (exit ${r.status ?? r.signal}); see the output above`);
    }
    const combined = `${r.stdout}\n${r.stderr}`;
    for (const code of DUPLICATE_ANALYZER_CODES) {
      if (combined.includes(code)) fail(`the build reported ${code}: a duplicate-analyzer warning`);
    }

    const props = readFileSync(path.join(repo, '.qualor', 'dotnet', 'session.props'), 'utf8');
    if (!props.includes('<QualorBundledSonarAnalyzer Include=')) {
      fail('session.props does not list the bundled Sonar analyzers');
    }
    if (
      !/QualorBundledSonarAnalyzer Include="\/opt\/qualor\/dotnet\/analyzers\/sonar\//.test(props)
    ) {
      fail(
        'session.props does not point QualorBundledSonarAnalyzer at /opt/qualor/dotnet/analyzers/sonar/',
      );
    }

    // The diagnostic-verbosity log lists the Csc task's own `Analyzers=` parameter, the
    // authoritative "what the compiler actually loaded" list, once per Csc invocation (one per
    // project, per target framework). Each block also carries that invocation's `ProjectName=`,
    // so the check only looks at Acme.Store's own invocations: Acme.Store.Tests has no
    // SonarAnalyzer.CSharp reference of its own, so it is *supposed* to get the bundled one, and
    // must not be mistaken for a duplicate on Acme.Store's build.
    const lines = readFileSync(path.join(repo, diagLog), 'utf8').split(/\r?\n/);
    const cscStarts = lines
      .map((line, i) => (/Task "Csc" \(TaskId:\d+\)/.test(line) ? i : -1))
      .filter((i) => i >= 0);
    if (cscStarts.length === 0) fail('the diagnostic log has no Csc task invocation');
    const storeInvocations: string[][] = [];
    for (const [i, start] of cscStarts.entries()) {
      const end = cscStarts[i + 1] ?? lines.length;
      const block = lines.slice(start, end);
      const project = block.find((l) => /Task Parameter:ProjectName=/.test(l))?.trim();
      if (project === undefined || !project.startsWith('Task Parameter:ProjectName=Acme.Store ('))
        continue;
      const analyzersAt = block.findIndex((l) => l.trim() === 'Analyzers=');
      if (analyzersAt === -1) fail(`Csc invocation for ${project} has no Analyzers= parameter`);
      const analyzers: string[] = [];
      for (const line of block.slice(analyzersAt + 1)) {
        if (/^\s*Task Parameter:/.test(line)) break;
        const trimmed = line.trim();
        if (trimmed.endsWith('.dll')) analyzers.push(trimmed);
      }
      storeInvocations.push(analyzers);
    }
    if (storeInvocations.length !== 2) {
      fail(
        `expected 2 Csc invocations for Acme.Store (net8.0 and net10.0), found ${storeInvocations.length}`,
      );
    }
    for (const analyzers of storeInvocations) {
      const bundledSonar = analyzers.filter((p) =>
        p.includes('/opt/qualor/dotnet/analyzers/sonar/'),
      );
      const ownSonar = analyzers.filter(
        (p) =>
          /sonaranalyzer\.csharp/i.test(p) && !p.includes('/opt/qualor/dotnet/analyzers/sonar/'),
      );
      if (bundledSonar.length > 0) {
        fail(
          `Acme.Store's compiler invocation loaded the bundled SonarAnalyzer as well as its own: ${bundledSonar.join(', ')}`,
        );
      }
      if (ownSonar.length === 0) {
        fail(
          "Acme.Store's compiler invocation never loaded its own SonarAnalyzer.CSharp (restore or hook problem)",
        );
      }
    }

    // S2930 ("Dispose" should be called on objects created with "new", of which Reader.FirstLine
    // is a real instance) must appear exactly once per SARIF result, never duplicated by a
    // second, bundled copy of the analyzer running alongside the project's own.
    const sarifDir = path.join(repo, '.qualor', 'dotnet', 'sarif');
    const sarifFiles = readdirSync(sarifDir).filter((f) => f.endsWith('.sarif'));
    if (sarifFiles.length === 0) fail('no SARIF log was written');
    let s2930 = 0;
    for (const file of sarifFiles) {
      const sarif = JSON.parse(readFileSync(path.join(sarifDir, file), 'utf8')) as {
        runs?: { results?: { ruleId?: string }[] }[];
      };
      for (const run of sarif.runs ?? []) {
        for (const result of run.results ?? []) if (result.ruleId === 'S2930') s2930++;
      }
    }
    if (s2930 === 0) fail('S2930 was not found at all (the fixture no longer triggers it?)');
    // One result per target framework build (net8.0 and net10.0 each write their own SARIF file
    // for the same source line); never more than one per file.
    for (const file of sarifFiles) {
      const sarif = JSON.parse(readFileSync(path.join(sarifDir, file), 'utf8')) as {
        runs?: { results?: { ruleId?: string }[] }[];
      };
      const count = (sarif.runs ?? [])
        .flatMap((run) => run.results ?? [])
        .filter((r) => r.ruleId === 'S2930').length;
      if (count > 1) fail(`${file} has S2930 ${count} times (expected at most once per file)`);
    }

    process.stdout.write(
      `ok ${image}: build succeeded, no CS8032/AD0001, S2930 found ${s2930} time(s) (once per file), ` +
        `only the project's own SonarAnalyzer.CSharp was loaded by the compiler\n`,
    );
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error: unknown) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
