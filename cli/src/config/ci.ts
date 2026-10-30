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
  /** The git tag of a tag pipeline (GitLab `CI_COMMIT_TAG`, GitHub `GITHUB_REF_TYPE=tag`), else null. */
  tag: string | null;
  mergeRequest: CiMergeRequest | null;
  mainBranch: string | null;
  projectPath: string | null;
  /** GitLab CI only (report `scm.gitlab`, scm.md §3); a malformed value is left out. */
  gitlab: GitLabCi | null;
  /** GitHub Actions only (report `scm.github`, github.md §3); a malformed value is left out. */
  github: GitHubCi | null;
  /** The pull request's head SHA from the event payload (full, lower-case hex), else null. */
  pullRequestHead: string | null;
}

/**
 * The merge request a CI pipeline runs for. `id` and `targetBranch` go to the report; the rest is
 * only for the AI review's repository snapshot (6I-2) and never reaches the report.
 */
export interface CiMergeRequest {
  id: string;
  targetBranch: string;
  /**
   * The merge request's head commit (full, lower-case hex): its source branch's head, which a
   * merged-result or merge-train pipeline does not check out (ruling R12); null when CI does not
   * name it.
   */
  headSha: string | null;
  /** Its title and description as CI gives them (ruling R9); null when absent or blank. */
  title: string | null;
  description: string | null;
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

/** A text as its author wrote it (a description keeps its indentation); null when blank. */
function text(value: string | null | undefined): string | null {
  return value === null || value === undefined || value.trim() === '' ? null : value;
}

const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

/** A full commit id, else null. */
function fullSha(value: string | null | undefined): string | null {
  return value !== null && value !== undefined && FULL_SHA.test(value) ? value : null;
}

/** A text field of the event read leniently: of another type it is absent, never the PR lost. */
const eventText = z.string().nullish().catch(null);

const githubEvent = z.looseObject({
  pull_request: z
    .looseObject({
      number: z.number().int(),
      head: z.looseObject({ sha: z.string() }).optional(),
      base: z.looseObject({ ref: z.string() }).optional(),
      title: eventText,
      body: eventText,
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

/**
 * A GitLab merge request's head: in a merged-result or merge-train pipeline the commit is the
 * merge GitLab made, and `CI_MERGE_REQUEST_SOURCE_BRANCH_SHA` names the source branch's head; in
 * any other the commit is that head.
 */
function gitlabHead(env: Env, eventType: GitLabMergeRequestEventType | undefined): string | null {
  const merged = eventType === 'merged_result' || eventType === 'merge_train';
  return fullSha(get(env, merged ? 'CI_MERGE_REQUEST_SOURCE_BRANCH_SHA' : 'CI_COMMIT_SHA'));
}

export function detectCi(
  env: Env,
  readFile: (path: string) => string = (p) => readFileSync(p, 'utf8'),
): CiInfo {
  if (get(env, 'GITLAB_CI') === 'true') {
    const iid = get(env, 'CI_MERGE_REQUEST_IID');
    const target = get(env, 'CI_MERGE_REQUEST_TARGET_BRANCH_NAME');
    const gitlab = gitlabCi(env);
    return {
      provider: 'gitlab',
      revision: get(env, 'CI_COMMIT_SHA'),
      branch: get(env, 'CI_COMMIT_TAG') !== null ? null : get(env, 'CI_COMMIT_REF_NAME'),
      tag: get(env, 'CI_COMMIT_TAG'),
      mergeRequest:
        iid !== null && target !== null
          ? {
              id: iid,
              targetBranch: target,
              headSha: gitlabHead(env, gitlab.mergeRequestEventType),
              title: text(env['CI_MERGE_REQUEST_TITLE']),
              description: text(env['CI_MERGE_REQUEST_DESCRIPTION']),
            }
          : null,
      mainBranch: get(env, 'CI_DEFAULT_BRANCH'),
      projectPath: get(env, 'CI_PROJECT_PATH'),
      gitlab,
      github: null,
      pullRequestHead: null,
    };
  }
  if (get(env, 'GITHUB_ACTIONS') === 'true') {
    const event = readEvent(get(env, 'GITHUB_EVENT_PATH'), readFile);
    const pr = event.pull_request;
    const target = get(env, 'GITHUB_BASE_REF') ?? pr?.base?.ref ?? null;
    const head = fullSha(pr?.head?.sha);
    return {
      provider: 'github',
      revision: pr?.head?.sha ?? get(env, 'GITHUB_SHA'),
      branch:
        get(env, 'GITHUB_REF_TYPE') === 'tag'
          ? null
          : (get(env, 'GITHUB_HEAD_REF') ?? get(env, 'GITHUB_REF_NAME')),
      tag: get(env, 'GITHUB_REF_TYPE') === 'tag' ? get(env, 'GITHUB_REF_NAME') : null,
      mergeRequest:
        pr !== undefined && target !== null
          ? {
              id: String(pr.number),
              targetBranch: target,
              headSha: head,
              title: text(pr.title),
              description: text(pr.body),
            }
          : null,
      mainBranch: event.repository?.default_branch ?? null,
      projectPath: get(env, 'GITHUB_REPOSITORY'),
      gitlab: null,
      github: githubCi(env),
      pullRequestHead: head,
    };
  }
  return {
    provider: 'none',
    revision: null,
    branch: null,
    tag: null,
    mergeRequest: null,
    mainBranch: null,
    projectPath: null,
    gitlab: null,
    github: null,
    pullRequestHead: null,
  };
}
