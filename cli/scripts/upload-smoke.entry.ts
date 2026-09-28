// Entry point of the upload smoke binary (`pnpm --filter @qualor/cli smoke:upload`). It is
// compiled with the same pinned bun as the shipped `qualor` binary, so the upload path (ruling
// E5: private gzip file, `Expect: 100-continue`, early refusal, reset, slow reader, 503 retry)
// is checked on the bun runtime, without the shipped binary needing a hidden test flag.
import { checkUploadPath, lingerProbe } from './upload-smoke-check';

if (process.argv.includes('--linger-probe')) {
  await lingerProbe();
} else {
  const { passed, failed } = await checkUploadPath();
  for (const name of passed) console.log(`✓ ${name}`);
  for (const failure of failed) console.error(`✗ ${failure}`);
  process.exitCode = failed.length === 0 ? 0 : 1;
}
