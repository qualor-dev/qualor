import { describe, expect, it } from 'vitest';
import { liveEnabled, readLiveEnv, runLiveCheck } from './ollama-live';

/**
 * Plan 3B Task 20, llm.md §17: the opt-in live check of the `openai` adapter against a local
 * Ollama. Never collected by `pnpm test` or CI: vitest.config.ts defines its project (`llm-live`)
 * only when `QUALOR_LIVE_LLM_URL` and `QUALOR_LIVE_LLM_MODEL` are set, and only `pnpm llm:live`
 * runs it, by hand. Loopback only unless `QUALOR_LIVE_LLM_ALLOWED_HOSTS` lists the host; no API
 * key; the fixture's synthetic cases only; aggregates only.
 */
describe.skipIf(!liveEnabled(process.env))(
  'live: a local Ollama through the openai adapter',
  () => {
    it('answers every feature of the fixture, and prints aggregates only', async () => {
      const { summary, text } = await runLiveCheck(readLiveEnv(process.env));
      // runLiveCheck has already refused a text holding an answer or a line of the fixture.
      console.log(text);
      expect(summary.features.explain.answered).toBeGreaterThan(0);
    });
  },
);
