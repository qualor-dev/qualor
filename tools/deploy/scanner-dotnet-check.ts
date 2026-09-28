import { readFileSync } from 'node:fs';
import path from 'node:path';
import { expectedContent, imageProblems, PROBE } from './scanner-dotnet';
import { REPO_ROOT, run } from './stack';

/**
 * `pnpm deploy:scanner-dotnet-check [image]` (deploy/README.md): runs one probe in a built
 * qualor/scanner-dotnet image (default `qualor/scanner-dotnet:dev`) and fails unless it has the
 * .NET SDKs of tools/analyzers/install-dotnet.sh, the Roslynator analyzers, their licence files
 * and a CLI that parses C#. It starts nothing else and needs no network.
 */
function main(): void {
  const args = process.argv.slice(2);
  if (args.length > 1 || args[0]?.startsWith('-')) {
    throw new Error('usage: pnpm deploy:scanner-dotnet-check [image]');
  }
  const image = args[0] ?? 'qualor/scanner-dotnet:dev';
  const expected = expectedContent(
    readFileSync(path.join(REPO_ROOT, 'tools', 'analyzers', 'install-dotnet.sh'), 'utf8'),
  );
  const result = run('docker', ['run', '--rm', '--entrypoint', 'sh', image, '-c', PROBE]);
  process.stdout.write(result.stdout);
  if (result.code !== 0) {
    throw new Error(`docker run ${image} failed (exit ${result.code}):\n${result.stderr}`);
  }
  const problems = imageProblems(result.stdout, expected);
  if (problems.length > 0) {
    throw new Error(`${image} is incomplete:\n  ${problems.join('\n  ')}`);
  }
  process.stdout.write(
    `ok ${image}: .NET SDK ${expected.sdks.join(' and ')}, ${expected.analyzers} Roslynator ` +
      `analyzers, ${expected.licenses.length} licence files, csharp grammar\n`,
  );
}

try {
  main();
} catch (error: unknown) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
