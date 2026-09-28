import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { ELF_MACHINE, elfMachine } from './elf';
import { outputPath, parseTargets } from './targets';

function smoke(): number {
  let failed = false;
  for (const target of parseTargets(process.argv.slice(2))) {
    const file = outputPath(target);
    if (!existsSync(file)) {
      console.error(`✗ ${target}: ${file} missing; run pnpm --filter @qualor/cli build`);
      failed = true;
      continue;
    }
    const machine = elfMachine(readFileSync(file).subarray(0, 64));
    if (machine !== ELF_MACHINE[target]) {
      console.error(`✗ ${target}: not a ${target} ELF executable (e_machine ${machine})`);
      failed = true;
      continue;
    }
    const native = `${process.platform}-${process.arch}` === target;
    if (!native) {
      console.log(`✓ ${target}: ELF header ok (not executed on this host)`);
      continue;
    }
    const run = spawnSync(file, ['version'], { encoding: 'utf8' });
    if (run.status !== 0 || !/^grammars: typescript \(ABI 1[3-5]\)/m.test(run.stdout)) {
      console.error(`✗ ${target}: 'qualor version' failed:\n${run.stdout}${run.stderr}`);
      failed = true;
      continue;
    }
    console.log(`✓ ${target}: ${run.stdout.trim().replaceAll('\n', ' | ')}`);
  }
  return failed ? 1 : 0;
}

process.exitCode = smoke();
