import { fixToolEnv } from '../../src/fix/env';
import { resolveTool } from '../../src/fix/shim';

/**
 * R26, ruling T12a: whether the fix job's runner can start `name` here, by its own lookup
 * (`resolveTool` on the tool environment's `PATH`, npm's node shims on Windows included). The
 * adapters' real-manager tests run only then: `describe.runIf(toolInstalled('npm'))`. Not
 * `cli/test/analyzers.ts`' `toolInstalled`, which looks for analyzers, never for shims.
 */
export function toolInstalled(name: string): boolean {
  const found = resolveTool(name, { root: process.cwd(), env: fixToolEnv(process.env) });
  return found !== null && !('problem' in found);
}
