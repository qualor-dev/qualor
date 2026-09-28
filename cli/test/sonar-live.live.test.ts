import { writeFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { request } from '../src/server/http';
import { liveEnabled, readLiveEnv, runLiveCheck } from './sonar-live';

/**
 * Plan 3A Task 17, import-sonarqube.md §17.1: the opt-in live check of a real SonarQube Server or
 * SonarQube Cloud organisation. Never collected by `pnpm test` or CI: vitest.config.ts defines
 * its project (`sonar-live`) only when `QUALOR_LIVE_SONAR_URL` and `QUALOR_LIVE_SONAR_TOKEN` are
 * set, and only `pnpm sonar:live` runs it, by hand. SonarQube Cloud also needs
 * `QUALOR_LIVE_SONAR_ORG`. GET only, allow-listed paths, a capped request budget
 * (`QUALOR_LIVE_SONAR_MAX_REQUESTS`, default 200); no Qualor server; nothing written but, when
 * `QUALOR_LIVE_SONAR_SUMMARY` names a path outside the repository, the aggregate JSON it prints.
 * The token is read from the environment at run time and never written anywhere.
 */
describe.skipIf(!liveEnabled(process.env))('live SonarQube, GET only (§17.1)', () => {
  it('reads and maps the organisation, and prints aggregates only', async () => {
    const o = readLiveEnv(process.env);
    const { summary, text } = await runLiveCheck({ ...o, transport: request });
    expect(Object.keys(summary.endpoints).length).toBeGreaterThan(0);
    // runLiveCheck has already refused a text holding anything of the organisation.
    console.log(text);
    if (o.summaryPath !== null) {
      writeFileSync(o.summaryPath, `${text}\n`, { mode: 0o600, flag: 'wx' });
    }
  });
});
