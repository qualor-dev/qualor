import { describe, expect, it } from 'vitest';
import { detectCi } from './ci';

const noFile = () => {
  throw new Error('no file');
};

describe('detectCi', () => {
  it('returns provider none without CI variables', () => {
    expect(detectCi({}, noFile)).toEqual({
      provider: 'none',
      revision: null,
      branch: null,
      mergeRequest: null,
      mainBranch: null,
      projectPath: null,
      gitlab: null,
      github: null,
      pullRequestHead: null,
    });
  });

  it('reads a GitLab merge request pipeline', () => {
    expect(
      detectCi(
        {
          GITLAB_CI: 'true',
          CI_COMMIT_SHA: 'a'.repeat(40),
          CI_COMMIT_REF_NAME: 'feature/x',
          CI_MERGE_REQUEST_IID: '482',
          CI_MERGE_REQUEST_TARGET_BRANCH_NAME: 'main',
          CI_DEFAULT_BRANCH: 'main',
          CI_PROJECT_PATH: 'acme/payments-api',
          CI_PROJECT_ID: '4711',
          CI_PIPELINE_ID: '99001',
          CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
        },
        noFile,
      ),
    ).toEqual({
      provider: 'gitlab',
      revision: 'a'.repeat(40),
      branch: 'feature/x',
      mergeRequest: { id: '482', targetBranch: 'main' },
      mainBranch: 'main',
      projectPath: 'acme/payments-api',
      gitlab: { projectId: '4711', pipelineId: '99001', mergeRequestEventType: 'detached' },
      github: null,
      pullRequestHead: null,
    });
  });

  it('leaves out malformed GitLab ids and unknown merge request event types (scm.md §3)', () => {
    expect(
      detectCi(
        {
          GITLAB_CI: 'true',
          CI_PROJECT_ID: '47 11',
          CI_PIPELINE_ID: '-1',
          CI_MERGE_REQUEST_EVENT_TYPE: 'merge_everything',
        },
        noFile,
      ).gitlab,
    ).toEqual({});
    expect(
      detectCi({ GITLAB_CI: 'true', CI_MERGE_REQUEST_EVENT_TYPE: 'merged_result' }, noFile).gitlab,
    ).toEqual({ mergeRequestEventType: 'merged_result' });
    for (const bad of ['1'.repeat(21), '0x1F', '1e3', '\u0661\u0662', '12\n34', '']) {
      expect(detectCi({ GITLAB_CI: 'true', CI_PIPELINE_ID: bad }, noFile).gitlab).toEqual({});
    }
  });

  it('never copies a secret CI variable into what reaches the report (scm.md §3)', () => {
    // Every value is a unique sentinel; the ones named like secrets must not appear anywhere.
    const secrets: Record<string, string> = {
      CI_JOB_TOKEN: 'S1-job-token',
      CI_JOB_JWT: 'S2-jwt',
      CI_JOB_JWT_V2: 'S3-jwt',
      CI_REGISTRY_PASSWORD: 'S4-registry',
      CI_DEPLOY_PASSWORD: 'S5-deploy',
      CI_DEPENDENCY_PROXY_PASSWORD: 'S6-proxy',
      CI_REPOSITORY_URL: 'https://gitlab-ci-token:S7-in-url@gitlab.example/acme/api.git',
      GITLAB_TOKEN: 'S8-token',
      QUALOR_TOKEN: 'S9-qualor',
      MY_SECRET: 'S10-secret',
      ID_TOKEN_1: 'S11-oidc',
      CI_SERVER_TLS_KEY_FILE: 'S12-key',
      GITHUB_TOKEN: 'S13-gh',
      ACTIONS_RUNTIME_TOKEN: 'S14-actions',
    };
    const env = {
      GITLAB_CI: 'true',
      CI_COMMIT_SHA: 'a'.repeat(40),
      CI_PROJECT_ID: '4711',
      CI_PIPELINE_ID: '99001',
      CI_MERGE_REQUEST_EVENT_TYPE: 'detached',
      ...secrets,
    };
    const seen = [
      JSON.stringify(detectCi(env, noFile)),
      JSON.stringify(detectCi({ ...env, GITLAB_CI: undefined, GITHUB_ACTIONS: 'true' }, noFile)),
    ].join('\n');
    for (const [name, value] of Object.entries(secrets)) {
      expect(seen, name).not.toContain(value);
      expect(seen, name).not.toContain(name);
    }
    // And the GitLab context holds exactly the three non-secret fields.
    expect(Object.keys(detectCi(env, noFile).gitlab ?? {}).sort()).toEqual([
      'mergeRequestEventType',
      'pipelineId',
      'projectId',
    ]);
  });

  it('treats a GitLab tag pipeline as having no branch', () => {
    const ci = detectCi(
      { GITLAB_CI: 'true', CI_COMMIT_REF_NAME: 'v1.2.0', CI_COMMIT_TAG: 'v1.2.0' },
      noFile,
    );
    expect(ci.branch).toBeNull();
    expect(ci.mergeRequest).toBeNull();
  });

  it('reads a GitHub pull request from the event payload', () => {
    const event = JSON.stringify({
      pull_request: { number: 17, head: { sha: 'b'.repeat(40) }, base: { ref: 'main' } },
      repository: { default_branch: 'main' },
    });
    expect(
      detectCi(
        {
          GITHUB_ACTIONS: 'true',
          GITHUB_SHA: 'c'.repeat(40),
          GITHUB_HEAD_REF: 'feature/y',
          GITHUB_REF_NAME: '17/merge',
          GITHUB_BASE_REF: 'main',
          GITHUB_EVENT_PATH: '/github/event.json',
          GITHUB_REPOSITORY: 'acme/web',
        },
        (p) => (p === '/github/event.json' ? event : noFile()),
      ),
    ).toEqual({
      provider: 'github',
      revision: 'b'.repeat(40),
      branch: 'feature/y',
      mergeRequest: { id: '17', targetBranch: 'main' },
      mainBranch: 'main',
      projectPath: 'acme/web',
      gitlab: null,
      github: {},
      pullRequestHead: 'b'.repeat(40),
    });
  });

  it('reads a GitHub push and survives a missing or malformed event file', () => {
    const ci = detectCi(
      {
        GITHUB_ACTIONS: 'true',
        GITHUB_SHA: 'c'.repeat(40),
        GITHUB_HEAD_REF: '',
        GITHUB_REF_NAME: 'main',
        GITHUB_EVENT_PATH: '/nope.json',
        GITHUB_REPOSITORY: 'acme/web',
      },
      noFile,
    );
    expect(ci).toMatchObject({
      provider: 'github',
      revision: 'c'.repeat(40),
      branch: 'main',
      mergeRequest: null,
      mainBranch: null,
    });
    expect(
      detectCi({ GITHUB_ACTIONS: 'true', GITHUB_EVENT_PATH: '/e' }, () => '{ not json').provider,
    ).toBe('github');
  });
});

describe('GitHub Actions context (github.md §3)', () => {
  const event = JSON.stringify({
    pull_request: { number: 7, head: { sha: 'a'.repeat(40) }, base: { ref: 'main' } },
    repository: { default_branch: 'main' },
  });
  const env = {
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_PATH: '/event.json',
    GITHUB_REPOSITORY: 'acme/api',
    GITHUB_REPOSITORY_ID: '123456',
    GITHUB_RUN_ID: '987',
    GITHUB_TOKEN: 'ghs_secret',
  };

  it('reads the repository and run ids by name, and the PR head', () => {
    const ci = detectCi(env, () => event);
    expect(ci.github).toEqual({ repositoryId: '123456', runId: '987' });
    expect(ci.pullRequestHead).toBe('a'.repeat(40));
    expect(JSON.stringify(ci)).not.toContain('ghs_secret');
  });

  it('leaves out malformed ids, and has no GitHub context in GitLab CI', () => {
    const ci = detectCi({ ...env, GITHUB_REPOSITORY_ID: '12a', GITHUB_RUN_ID: '' }, () => event);
    expect(ci.github).toEqual({});
    expect(detectCi({ GITLAB_CI: 'true' }).github).toBeNull();
  });

  it('has no PR head for a push, nor for a head that is not a full SHA', () => {
    expect(detectCi({ ...env, GITHUB_EVENT_PATH: '' }, () => event).pullRequestHead).toBeNull();
    const bad = JSON.stringify({ pull_request: { number: 7, head: { sha: 'abc' } } });
    expect(detectCi(env, () => bad).pullRequestHead).toBeNull();
  });
});
