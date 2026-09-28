// Entry point of the process-tree smoke binary (`pnpm --filter @qualor/cli smoke:process`).
// It is compiled with the same pinned bun as the shipped `qualor` binary, so it checks that
// `runProcess` kills a hung analyzer's whole process group under the bun runtime, without the
// shipped binary needing a hidden test flag.
import { checkProcessGroupKill } from './process-smoke-check';

const failure = await checkProcessGroupKill();
if (failure === null) {
  console.log('✓ a hung analyzer and its grandchild were killed on timeout');
} else {
  console.error(`✗ ${failure}`);
  process.exitCode = 1;
}
