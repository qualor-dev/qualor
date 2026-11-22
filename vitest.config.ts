import { defineConfig } from 'vitest/config';

const ignored = ['**/node_modules/**', 'fixtures/**', 'ui/**'];
/**
 * scm.md §11: the opt-in real-GitLab checks (`pnpm gitlab:real`) are never part of `pnpm test`:
 * GitLab CE in Docker, or (`--url`, `--project`) a GitLab that is already running.
 */
const realGitLab = process.env.QUALOR_GITLAB_REAL === '1';
const liveGitLab = process.env.QUALOR_GITLAB_LIVE === '1';
/**
 * Plan 3A Task 17: the opt-in live SonarQube check (import-sonarqube.md §17.1). Never part of
 * `pnpm test` or CI (the unit project excludes `*.live.test.ts`): it exists only when the
 * coordinator sets both variables by hand, and runs through `pnpm sonar:live`.
 */
const liveSonar =
  (process.env.QUALOR_LIVE_SONAR_URL ?? '') !== '' &&
  (process.env.QUALOR_LIVE_SONAR_TOKEN ?? '') !== '';
/**
 * Plan 3B Task 20: the opt-in check against a local Ollama (llm.md §17). Never part of
 * `pnpm test` or CI (the unit project excludes `*.live.test.ts`): it exists only when both
 * variables are set by hand, and runs through `pnpm llm:live`.
 */
const liveLlm =
  (process.env.QUALOR_LIVE_LLM_URL ?? '') !== '' &&
  (process.env.QUALOR_LIVE_LLM_MODEL ?? '') !== '';

/**
 * Plan 6I-3 Task 14 (spec §12): the opt-in evaluation of the AI review against a real provider,
 * which scores the evaluation set (fixtures/review-eval) and costs real tokens. Never part of
 * `pnpm test` or CI (the unit project excludes `*.live.test.ts`): it exists only when both
 * variables are set by hand, and runs through `pnpm review:live`.
 */
const liveReview =
  (process.env.QUALOR_LIVE_REVIEW_URL ?? '') !== '' &&
  (process.env.QUALOR_LIVE_REVIEW_MODEL ?? '') !== '';

/** 6G: the opt-in check against a real Slack and/or Teams channel (`pnpm chat:live`). */
const liveChat =
  (process.env.QUALOR_SLACK_WEBHOOK_URL ?? '') !== '' ||
  (process.env.QUALOR_TEAMS_WEBHOOK_URL ?? '') !== '';

/**
 * 0.16 Jira (spec §9): the opt-in check against a real Jira site (`pnpm jira:live`). Never part of
 * `pnpm test` or CI, whatever variables are set: the unit project excludes `*.live.test.ts`, and
 * the project exists only when the command line names it. Without QUALOR_LIVE_JIRA_* the file
 * skips with a message.
 */
const JIRA_LIVE_FILE = 'server/src/jira/live.live.test.ts';
const liveJira = process.argv.some(
  (arg, i, all) =>
    arg === '--project=jira-live' || (arg === '--project' && all[i + 1] === 'jira-live'),
);

/**
 * Azure DevOps connection: the opt-in check against a real organisation
 * (`pnpm azure:live`). Never part of `pnpm test` or CI: the unit project excludes
 * `*.live.test.ts`, and the project exists only when `QUALOR_LIVE_AZURE_ENV_FILES` is set and the
 * command line names it. The file loads the env files itself.
 */
const AZURE_LIVE_FILE = 'server/src/scm/azure/live.live.test.ts';
const liveAzure =
  (process.env.QUALOR_LIVE_AZURE_ENV_FILES ?? '') !== '' &&
  process.argv.some(
    (arg, i, all) =>
      arg === '--project=azure-live' || (arg === '--project' && all[i + 1] === 'azure-live'),
  );

/**
 * 0.16 fix MRs (spec §9, R26): the opt-in live checks of the fix adapters (`pnpm fix:live`), which
 * run the real package managers against the public registries. Never part of `pnpm test` or CI:
 * the unit project excludes `*.live.test.ts`, and the project exists only when the command line
 * names it. Each file skips without what it needs.
 */
const FIX_LIVE_FILES = 'cli/src/fix/**/*.live.test.ts';
const liveFix = process.argv.some(
  (arg, i, all) =>
    arg === '--project=fix-live' || (arg === '--project' && all[i + 1] === 'fix-live'),
);

/**
 * Plan 4A (ruling RE5): tests that run Helm, cosign or Syft in the release toolbox (Docker). Never
 * part of `pnpm test`: the project exists only when `pnpm helm:test` or `pnpm release:test` sets
 * QUALOR_RELEASE_TOOLS=1 (tools/release/test-tools.ts), after building the toolbox image.
 */
const releaseTools = process.env.QUALOR_RELEASE_TOOLS === '1';

/**
 * Plan 4D Task 20 (sso-scim.md §19.4): the live check against Keycloak in Docker. Never part of
 * `pnpm test` or CI: the unit project excludes its file, and its project exists only when the
 * command line names it, which only `pnpm sso:keycloak` (`vitest run --project keycloak`) does.
 */
const KEYCLOAK_FILE = 'tools/sso/keycloak.test.ts';
const keycloak = process.argv.some(
  (arg, i, all) =>
    arg === '--project=keycloak' || (arg === '--project' && all[i + 1] === 'keycloak'),
);

// Wall-clock budgets of performance tests scale by this (server/test/perf.ts): v8 coverage
// instrumentation slows hot loops several-fold. Workers inherit the environment.
const coverage = process.argv.some((arg) => arg === '--coverage' || arg.startsWith('--coverage.'));
process.env.QUALOR_TEST_TIME_SCALE ??= coverage ? '5' : '1';
process.env.QUALOR_TEST_COVERAGE ??= coverage ? '1' : '0';

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      // text for the CI log (GitLab reads its total), lcov for the dogfood scan (qualor.yml).
      reporter: ['text', 'lcov'],
      include: ['packages/*/src/**', 'cli/src/**', 'server/src/**'],
      exclude: [
        '**/*.test.ts',
        '**/*.d.ts',
        'cli/src/entry.bun.ts',
        'cli/src/cli.ts',
        'cli/scripts/**',
      ],
    },
    projects: [
      {
        test: {
          name: 'unit',
          // The analyzers' *-real tests run here too and load a CI runner's CPU: with Vitest's
          // 5 s default, light tests in other files timed out at random (PR #13). 30 s, as db.
          testTimeout: 30_000,
          include: ['**/*.test.ts'],
          exclude: [
            ...ignored,
            '**/*.db.test.ts',
            '**/*.real.test.ts',
            '**/*.live.test.ts',
            '**/*.helm.test.ts',
            '**/*.tools.test.ts',
            KEYCLOAK_FILE,
          ],
        },
      },
      {
        // Plan 1F: checks of the UI's sources (i18n, no HTML injection) that need no browser.
        test: { name: 'ui-tools', include: ['ui/tools/**/*.test.ts'] },
      },
      {
        test: {
          name: 'db',
          include: ['server/**/*.db.test.ts', 'enterprise/**/*.db.test.ts'],
          exclude: ignored,
          globalSetup: ['server/test/global-setup.ts'],
          testTimeout: 30_000,
          hookTimeout: 120_000,
        },
      },
      ...(realGitLab
        ? [
            {
              test: {
                name: 'gitlab-real',
                include: ['server/test/**/*.real.test.ts'],
                globalSetup: ['server/test/global-setup.ts', 'server/test/gitlab-real-setup.ts'],
                testTimeout: 600_000,
                hookTimeout: 1_200_000,
              },
            },
          ]
        : []),
      ...(liveGitLab
        ? [
            {
              test: {
                name: 'gitlab-live',
                include: ['server/test/**/*.live.test.ts'],
                globalSetup: ['server/test/global-setup.ts'],
                testTimeout: 900_000,
                hookTimeout: 300_000,
              },
            },
          ]
        : []),
      ...(liveSonar
        ? [
            {
              test: {
                name: 'sonar-live',
                include: ['cli/test/sonar-live.live.test.ts'],
                testTimeout: 900_000,
              },
            },
          ]
        : []),
      ...(liveLlm
        ? [
            {
              test: {
                name: 'llm-live',
                include: ['tools/llm/ollama.live.test.ts'],
                // Up to 10 runs × 3 features × the fixture's cases, a slow CPU model each.
                testTimeout: 3_600_000,
              },
            },
          ]
        : []),
      ...(liveReview
        ? [
            {
              test: {
                name: 'review-live',
                include: ['tools/review/review.live.test.ts'],
                // Up to 5 runs of every case: about five calls and their tool turns each, with a
                // slow model.
                testTimeout: 7_200_000,
              },
            },
          ]
        : []),
      ...(liveChat
        ? [
            {
              test: {
                name: 'chat-live',
                include: ['server/src/webhooks/chat/live.live.test.ts'],
                testTimeout: 60_000,
              },
            },
          ]
        : []),
      ...(liveJira
        ? [
            {
              test: {
                name: 'jira-live',
                include: [JIRA_LIVE_FILE],
                testTimeout: 300_000,
                hookTimeout: 120_000,
              },
            },
          ]
        : []),
      ...(liveAzure
        ? [
            {
              test: {
                name: 'azure-live',
                include: [AZURE_LIVE_FILE],
                // Entra token requests and a few Azure DevOps calls per credential.
                testTimeout: 120_000,
              },
            },
          ]
        : []),
      ...(liveFix
        ? [
            {
              test: {
                name: 'fix-live',
                include: [FIX_LIVE_FILES],
                // A package manager resolving and fetching against a real registry, per adapter.
                testTimeout: 600_000,
              },
            },
          ]
        : []),
      ...(releaseTools
        ? [
            {
              test: {
                name: 'release-tools',
                include: ['tools/**/*.helm.test.ts', 'tools/**/*.tools.test.ts'],
                // One container per Helm or cosign call; the dry run builds binaries.
                testTimeout: 900_000,
                hookTimeout: 900_000,
                fileParallelism: false,
              },
            },
          ]
        : []),
      ...(keycloak
        ? [
            {
              test: {
                name: 'keycloak',
                include: [KEYCLOAK_FILE],
                // The server's PostgreSQL, as the db project starts it (Testcontainers).
                globalSetup: ['server/test/global-setup.ts'],
                testTimeout: 300_000,
                // The first run pulls the pinned Keycloak image; bundles are built in beforeAll.
                hookTimeout: 900_000,
                fileParallelism: false,
              },
            },
          ]
        : []),
    ],
  },
});
