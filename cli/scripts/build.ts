import { bun, BUN_VERSION, bunBuildArgs, CLI_DIR, parseTargets } from './targets';

function build(): number {
  const version = bun(['--version'], { encoding: 'utf8' });
  const found = String(version.stdout ?? '').trim();
  if (version.status !== 0) {
    console.error(`bun ${BUN_VERSION} is required to build the binary (https://bun.sh)`);
    return 1;
  }
  if (found !== BUN_VERSION) {
    console.error(`bun ${BUN_VERSION} is required, found ${found}`);
    return 1;
  }
  for (const target of parseTargets(process.argv.slice(2))) {
    const result = bun(bunBuildArgs(target), { cwd: CLI_DIR, stdio: 'inherit' });
    if (result.status !== 0) return result.status ?? 1;
  }
  return 0;
}

process.exitCode = build();
