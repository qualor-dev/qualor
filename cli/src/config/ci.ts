import { readFileSync } from 'node:fs';
import {
  GITHUB_ID,
  GITLAB_ID,
  GITLAB_MR_EVENT_TYPES,
  type GitLabMergeRequestEventType,
} from '@qualor/shared';
import { z } from 'zod';

export type CiProvider = 'gitlab' | 'github' | 'none';

/** CI values of config.md §4 (read-only, never required). */
export interface CiInfo {
  provider: CiProvider;
  revision: string | null;
  branch: string | null;
  mergeRequest: { id: string; targetBranch: string } | null;
  mainBranch: string | null;
  projectPath: string | null;
  /** GitLab CI only (report `scm.gitlab`, scm.md §3); a malformed value is left out. */
  gitlab: GitLabCi | null;
  /** GitHub Actions only (report `scm.github`, github.md §3); a malformed value is left out. */
  github: GitHubCi | null;
  /** The pull request's head SHA from the event payload (full, lower-case hex), else null. */
  pullRequestHead: string | null;
}

export interface GitLabCi {
  projectId?: string;
  pipelineId?: string;
  mergeRequestEventType?: GitLabMergeRequestEventType;
}

export interface GitHubCi {
  repositoryId?: string;
  runId?: string;
}

type Env = Readonly<Record<string, string | undefined>>;

function get(env: Env, name: string): string | null {
  const v = env[name]?.trim();
  return v === undefined || v === '' ? null : v;
}

const githubEvent = z.looseObject({
  pull_request: z
    .looseObject({
      number: z.number().int(),
      head: z.looseObject({ sha: z.string() }).optional(),
      base: z.looseObject({ ref: z.string() }).optional(),
    })
    .optional(),
  repository: z.looseObject({ default_branch: z.string() }).optional(),
});

function readEvent(
  file: string | null,
  readFile: (path: string) => string,
): z.infer<typeof githubEvent> {
  if (file === null) return {};
  try {
    const parsed = githubEvent.safeParse(JSON.parse(readFile(file)));
    return parsed.success ? parsed.data : {};
  } catch {
    // A missing or malformed payload only loses the PR details; the scan still works.
    return {};
  }
}

/**
 * `CI_PROJECT_ID`, `CI_PIPELINE_ID` and `CI_MERGE_REQUEST_EVENT_TYPE`, each only when well
 * formed. These three are read by name and nothing else is: no token, password or other secret
 * CI variable (`CI_JOB_TOKEN`, `CI_REGISTRY_PASSWORD`, ...) can reach the report.
 */
function gitlabCi(env: Env): GitLabCi {
  const id = (name: string) => {
    const v = get(env, name);
    return v !== null && GITLAB_ID.test(v) ? v : undefined;
  };
  const projectId = id('CI_PROJECT_ID');
  const pipelineId = id('CI_PIPELINE_ID');
  const eventType = get(env, 'CI_MERGE_REQUEST_EVENT_TYPE');
  const mergeRequestEventType = GITLAB_MR_EVENT_TYPES.find((t) => t === eventType);
  return {
    ...(projectId === undefined ? {} : { projectId }),
    ...(pipelineId === undefined ? {} : { pipelineId }),
    ...(mergeRequestEventType === undefined ? {} : { mergeRequestEventType }),
  };
}

/**
 * `GITHUB_REPOSITORY_ID` and `GITHUB_RUN_ID`, each only when well formed. Read by name: no token
 * (`GITHUB_TOKEN`, `ACTIONS_RUNTIME_TOKEN`, ...) can reach the report.
 */
function githubCi(env: Env): GitHubCi {
  const id = (name: string) => {
    const v = get(env, name);
    return v !== null && GITHUB_ID.test(v) ? v : undefined;
  };
  const repositoryId = id('GITHUB_REPOSITORY_ID');
  const runId = id('GITHUB_RUN_ID');
  return {
    ...(repositoryId === undefined ? {} : { repositoryId }),
    ...(runId === undefined ? {} : { runId }),
  };
}

const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

export function detectCi(
  env: Env,
  readFile: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): CiInfo {
  if (get(env, 'GITLAB_CI') === 'true') {
    const iid = get(env, 'CI_MERGE_REQUEST_IID');
    const target = get(env, 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME');
    return {
      provider: 'gitlab',
      revision: get(env, 'CI_COMMIT_SHA'),
      branch: get(env, 'CI_COMMIT_TAG') !== null ? null : get(env, 'CI_COMMIT_REF_NAME'),
      mergeRequest: iid !== null && target !== null ? { id: iid, targetBranch: target } : null,
      mainBranch: get(env, 'CI_DEFAULT_BRANCH'),
      projectPath: get(env, 'CI_PROJECT_PATH'),
      gitlab: gitlabCi(env),
      github: null,
      pullRequestHead: null,
    };
  }
  if (get(env, 'GITHUB_ACTIONS') === 'true') {
    const event = readEvent(get(env, 'GITHUB_EVENT_PATH'), readFile);
    const pr = event.pull_request;
    const target = get(env, 'GITHUB_BASE_REF') ?? pr?.base?.ref ?? null;
    return {
      provider: 'github',
      revision: pr?.head?.sha ?? get(env, 'GITHUB_SHA'),
      branch:
        get(env, 'GITHUB_REF_TYPE') === 'tag'
          ? null
          : (get(env, 'GITHUB_HEAD_REF') ?? get(env, 'GITHUB_REF_NAME')),
      mergeRequest:
        pr !== undefined && target !== null
          ? { id: String(pr.number), targetBranch: target }
          : null,
      mainBranch: event.repository?.default_branch ?? null,
      projectPath: get(env, 'GITHUB_REPOSITORY'),
      gitlab: null,
      github: githubCi(env),
      pullRequestHead:
        pr?.head?.sha !== undefined && FULL_SHA.test(pr.head.sha) ? pr.head.sha : null,
    };
  }
  return {
    provider: 'none',
    revision: null,
    branch: null,
    mergeRequest: null,
    mainBranch: null,
    projectPath: null,
    gitlab: null,
    github: null,
    pullRequestHead: null,
  };
}
