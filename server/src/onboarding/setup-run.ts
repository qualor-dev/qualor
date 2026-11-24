// The repository-setup run (onboarding): each repository of a run gets its project (created, or an
// existing one adopted) mapped to it, then its CI: a merge request that adds the Qualor job and
// keeps the project's token in the repository's CI secrets, or a snippet and the token to copy.
// Every step's outcome is saved as soon as it is known, so a retried job resumes where it stopped.
import { assertNever, type ScmProvider } from '@qualor/shared';
import { and, asc, eq, inArray, isNull, sql } from 'drizzle-orm';
import { z } from 'zod';
import { canonicalJson } from '../audit/canonical';
import { PROJECT_CHANGE_FIELDS } from '../audit/catalogue';
import { SYSTEM_ACTOR, type AuditActorContext, type AuditRecorder } from '../audit/recorder';
import { projectRefs } from '../audit/refs';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db, Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import {
  apiTokens,
  projects,
  repositorySetupItems,
  repositorySetupRuns,
  scmConnections,
  users,
  type EncryptedValue,
  type SetupAzureQueue,
  type SetupCiOutcome,
  type SetupProjectOutcome,
} from '../db/schema';
import { VERSION } from '../index';
import { PROJECT_KEY_PATTERN } from '../patterns';
import type { ProjectRow } from '../projects/access';
import { createProject, type AuditedActor } from '../projects/create';
import { createProjectToken, revokeProjectToken } from '../projects/tokens';
import { enqueue } from '../queue/queue';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import { queueRemapPurgeIfCopies } from '../review/jobs';
import { readCiSetupStatus, type CiSetupStatus } from '../scm/ci-setup-status';
import {
  forgetForeignMergeRequestUrls,
  gitlabClientFor,
  type ScmConnectionRow,
  type ScmDeps,
} from '../scm/connections';
import type { InstallationTokenCache, MutationPacer } from '../scm/github/app-auth';
import type { GitHubClient } from '../scm/github/client';
import { githubClientFor } from '../scm/github/connections';
import { githubHostKind, parseRepoRef } from '../scm/github/url';
import type { GitLabClient } from '../scm/gitlab/client';
import { gitlabHostKind } from '../scm/gitlab/url';
import {
  AZURE_SECRET_VARIABLE,
  type AzureDefinition,
  type AzureDefinitionVariable,
  type AzureDevOpsClient,
  type AzureQueue,
  type AzureRepository,
} from '../scm/azure/client';
import { azureClientFor } from '../scm/azure/connections';
import { azureDeployment } from '../scm/azure/url';
import { MAX_VALUE_CHARS, plainValue } from '../scm/markdown';
import { ScmError } from '../scm/provider';
import {
  AZURE_FILE,
  azurePipelineNamed,
  azureSnippet,
  planCiSetup,
  type CiPlan,
  type CiSetupInput,
  type CiSnippetReason,
} from './ci-setup';
import type { AzurePool } from './ci-templates';

export const REPOSITORY_SETUP_QUEUE = 'repository-setup';
/** Repositories one run takes at most. */
export const MAX_SETUP_REPOSITORIES = 50;
export const SETUP_BRANCH = 'qualor/setup';
/** The merge request's title, and the message of its commit. */
export const SETUP_TITLE = 'Add Qualor code analysis';
/** The name of the project analysis token a run makes. */
export const SETUP_TOKEN_NAME = 'CI setup';
/** The AAD of `repository_setup_items.token_enc`. */
export const SETUP_TOKEN_AAD = 'repository_setup_items.token_enc';
/**
 * A repository's name (on Azure DevOps made a key) is its project's key; when taken, `-2` … `-20`
 * are tried.
 */
const MAX_KEY_SUFFIX = 20;
/** Where a snippet points while the server has no public URL: the address the guide uses. */
const URL_PLACEHOLDER = 'https://qualor.example.com';
const PROJECT_NAME_MAX = 255;
/**
 * A rate-limited provider, or a failed read of the connection's CI-setup status, pauses the run:
 * its job is queued again for when the provider says (a minute when it does not), at most this
 * many times; after that the error fails the repository's CI.
 */
const MAX_PAUSES = 5;
const DEFAULT_PAUSE_SECONDS = 60;

/**
 * Why a repository got a snippet instead of a merge request: the planner's reasons, the
 * connection's CI-setup status when it changed after the run started (`not_allowed`,
 * `missing_permissions` for the repository's own installation, `no_public_url`), or a repository
 * without a commit to branch from.
 */
export const SETUP_CI_REASONS = [
  'already_set_up',
  'yaml_unsupported',
  'custom_ci_path',
  'no_public_url',
  'not_allowed',
  'missing_permissions',
  'empty_repository',
] as const;
export type SetupCiReason = (typeof SETUP_CI_REASONS)[number];

export const SETUP_ERROR_CODES = [
  'not_found',
  'key_taken',
  'connection_gone',
  'connection_unusable',
  'project_gone',
  'permission',
  'rate_limited',
  'unavailable',
  'refused',
  'bad_answer',
  'budget',
  'internal',
  'abandoned',
  // Azure DevOps: the run's agent pool has no queue in the repository's project, checked before
  // anything is written; both names Qualor gives a pipeline are taken in the project.
  'no_agent_pool',
  'pipeline_name_taken',
] as const;
export type SetupErrorCode = (typeof SETUP_ERROR_CODES)[number];

/** The fixed texts of the item errors: never the provider's words, which could quote a secret. */
const ERROR_TEXT: Record<Exclude<SetupErrorCode, 'permission' | 'no_agent_pool'>, string> = {
  not_found: 'The repository was not found, or the connection cannot reach it',
  key_taken: 'Every project key Qualor would give this repository is taken',
  connection_gone: 'The SCM connection was deleted',
  connection_unusable: 'The SCM connection cannot be used; test it in the settings',
  project_gone: 'The project was deleted',
  rate_limited: 'The provider is rate limiting Qualor; try again later',
  unavailable: 'The provider could not be reached; try again later',
  refused: 'The provider refused the change',
  bad_answer: "The provider's answer was not understood",
  budget: 'Too many provider requests for one repository',
  internal: 'Something went wrong; the server log has the details',
  abandoned: 'The run stopped before this repository',
  pipeline_name_taken: 'A pipeline named Qualor already exists in this project',
};
/** The agent pool named for the run has no queue in the Azure DevOps project. */
function noAgentPool(pool: string): ItemError {
  return {
    code: 'no_agent_pool',
    message: `No agent pool named "${plainValue(pool, MAX_VALUE_CHARS)}" in this project`,
  };
}
/** A refused permission while reading the repository, or while changing it for CI setup. */
const PERMISSION_TEXT = {
  read: 'The connection was refused access to the repository',
  github: 'The GitHub App needs Contents, Workflows and Secrets write',
  gitlab: 'The GitLab token needs the api scope and the Maintainer role',
} as const;
/** A refusal (`refused`) of a request that only reads, before CI setup changes anything. */
const REFUSED_READ_TEXT = 'The provider refused a request to read the repository';

/**
 * What CI setup was doing when the provider failed, for the log line: reading the repository,
 * the branch, the files, the token's secret, the variables (GitLab; on Azure DevOps the pipeline's
 * address and its agent pool), the merge request.
 */
type CiStep = 'read' | 'branch' | 'files' | 'secret' | 'variables' | 'merge_request';

/**
 * Azure DevOps rights are found per step (Ruling 2): a refusal names the right that step needs.
 * A refused read says what any read says ({@link PERMISSION_TEXT}`.read`).
 */
const AZURE_PERMISSION_TEXT: Record<Exclude<CiStep, 'read'>, string> = {
  branch: 'The Azure DevOps identity needs Contribute and Create branch on the repository',
  files: 'The Azure DevOps identity needs Contribute and Create branch on the repository',
  secret: 'The Azure DevOps identity needs Edit build pipeline in the project',
  variables: 'The Azure DevOps identity needs Edit build pipeline in the project',
  merge_request: 'The Azure DevOps identity needs Contribute to pull requests',
};

/** What a refused permission tells: the read, else what CI setup needs on the provider. */
function permissionText(provider: ScmProvider, stage: 'open' | 'ci_read' | 'change', step: CiStep) {
  if (stage === 'open') return PERMISSION_TEXT.read;
  switch (provider) {
    case 'github':
    case 'gitlab':
      return PERMISSION_TEXT[provider];
    case 'azure':
      return step === 'read' ? PERMISSION_TEXT.read : AZURE_PERMISSION_TEXT[step];
    default:
      return assertNever(provider, 'provider');
  }
}

/**
 * Where a provider's refusal happened, for the page, which never reads the message (Ruling 9):
 * `read` while Qualor opened or read the repository, `change` while CI setup wrote to it. No
 * column keeps the stage: the fixed texts above tell it (a refused permission while reading for
 * GitHub or GitLab CI setup names what the change needs, so it counts as `change`). Null for the
 * other codes.
 */
export function setupErrorStage(code: string, message: string): 'read' | 'change' | null {
  switch (code) {
    case 'permission':
      return message === PERMISSION_TEXT.read ? 'read' : 'change';
    case 'refused':
      return message === REFUSED_READ_TEXT ? 'read' : 'change';
    default:
      return null;
  }
}

export interface SetupRunDeps {
  db: Db;
  scm: ScmDeps;
  /** The `scm` worker's GitHub token cache and mutation pacer (scm/runtime.ts). */
  runtime?: {
    githubTokens: InstallationTokenCache;
    githubPacer: MutationPacer;
    /** Microsoft Entra tokens of Azure DevOps service principals. */
    azureTokens: InstallationTokenCache;
  };
  publicUrl: string | null;
  audit: AuditRecorder;
  logger?: WorkerLogger;
  /** Where the connection's CI runs; {@link ciHostOf} unless a test stands a fake for github.com. */
  host?: (row: ScmConnectionRow) => 'cloud' | 'self-hosted';
}

/**
 * github.com, GHE.com and gitlab.com run the Qualor Action or CI/CD component; GitHub Enterprise
 * Server and self-managed GitLab get the plain job on the scanner image.
 */
export function ciHostOf(row: { provider: ScmProvider; baseUrl: string }): 'cloud' | 'self-hosted' {
  switch (row.provider) {
    case 'github':
      return githubHostKind(row.baseUrl) === 'cloud' ? 'cloud' : 'self-hosted';
    case 'gitlab':
      return gitlabHostKind(row.baseUrl) === 'gitlab.com' ? 'cloud' : 'self-hosted';
    case 'azure':
      return azureDeployment(row.baseUrl) === 'services' ? 'cloud' : 'self-hosted';
    default:
      return assertNever(row.provider, 'provider');
  }
}

const payloadSchema = z.object({
  runId: z.uuid(),
  /** How often the run paused already ({@link MAX_PAUSES}). */
  pauses: z.number().int().min(0).default(0),
});

/**
 * The connection's credentials no longer decrypt, or its address is no longer allowed: every
 * repository of the run fails alike (the connection test says why).
 */
class UnusableConnection extends Error {
  constructor() {
    super('unusable SCM connection');
  }
}

/** The provider is rate limiting: the run stops here and its job comes back in `seconds`. */
class RateLimitPause extends Error {
  constructor(readonly seconds: number) {
    super('rate limited');
  }
}

type RunRow = typeof repositorySetupRuns.$inferSelect;
type ItemRow = typeof repositorySetupItems.$inferSelect;
interface ItemError {
  code: SetupErrorCode;
  message: string;
}

/**
 * CI setup stops for a reason in Qualor's own words, not a provider error: the Azure DevOps agent
 * pool has no queue, or the pipeline's names are taken. Nothing it was about to write was written.
 */
class SetupFailure extends Error {
  constructor(readonly error: ItemError) {
    super(error.code);
  }
}

function errorOf(code: Exclude<SetupErrorCode, 'permission' | 'no_agent_pool'>): ItemError {
  return { code, message: ERROR_TEXT[code] };
}

/**
 * An SCM failure as an item error: a fixed text per kind. `stage`: opening the repository, reading
 * it for CI setup, or changing it; `step`: the CI step, for the right Azure DevOps refused. A
 * refused permission names what CI setup needs once the repository is open; a refusal says
 * whether a read or the change was refused.
 */
function scmErrorOf(
  err: ScmError,
  provider: ScmProvider,
  stage: 'open' | 'ci_read' | 'change',
  step: CiStep = 'read',
): ItemError {
  switch (err.kind) {
    case 'not_found':
      return errorOf('not_found');
    case 'auth':
      return { code: 'permission', message: permissionText(provider, stage, step) };
    case 'rate_limited':
      return errorOf('rate_limited');
    case 'transient':
      return errorOf('unavailable');
    case 'refused':
      return stage === 'change'
        ? errorOf('refused')
        : { code: 'refused', message: REFUSED_READ_TEXT };
    case 'bad_answer':
      return errorOf('bad_answer');
    case 'budget':
      return errorOf('budget');
  }
}

/** Whether the provider answered a refusal (4xx): then the write it refused stored nothing. */
function definitelyRefused(err: unknown): boolean {
  return err instanceof ScmError && err.status !== null && err.status >= 400 && err.status < 500;
}

async function updateItem(
  db: Executor,
  item: Pick<ItemRow, 'runId' | 'position'>,
  values: Partial<typeof repositorySetupItems.$inferInsert>,
): Promise<void> {
  await db
    .update(repositorySetupItems)
    .set(values)
    .where(
      and(
        eq(repositorySetupItems.runId, item.runId),
        eq(repositorySetupItems.position, item.position),
      ),
    );
}

/** The item failed as a whole: no project, so no CI either. */
function failItem(db: Executor, item: ItemRow, error: ItemError): Promise<void> {
  return updateItem(db, item, {
    projectOutcome: item.projectOutcome === 'pending' ? 'failed' : item.projectOutcome,
    ciOutcome: 'failed',
    errorCode: error.code,
    errorMessage: error.message,
  });
}

/** Whom the run's events name: its creator, as a user; the system once the user is gone. */
async function actorOf(db: Executor, userId: string | null): Promise<AuditActorContext> {
  if (userId === null) return SYSTEM_ACTOR;
  const [user] = await db
    .select({ id: users.id, username: users.username })
    .from(users)
    .where(eq(users.id, userId));
  return user
    ? {
        actor: { type: 'user', userId: user.id, username: user.username, tokenId: null },
        ip: null,
        userAgent: null,
      }
    : SYSTEM_ACTOR;
}

// ─── The repository, as the provider names it ─────────────────────────────────────────────

/** What a CI change does on each provider, on the branch {@link SETUP_BRANCH}. */
interface CiRepository {
  /**
   * Whether the repository is C#: GitHub's main language or a .sln or .csproj at the root, GitLab's
   * main language, a .sln or .csproj at the root on Azure DevOps (Ruling 7).
   */
  csharp(): Promise<boolean>;
  /** What the planner needs, read from the default branch; `empty`: no commit to branch from. */
  read(): Promise<{
    csharp: boolean;
    empty: boolean;
    customCiPath: boolean;
    existing: CiSetupInput['existing'];
    azure?: CiSetupInput['azure'];
  }>;
  /**
   * Checks what the change needs besides the repository, before anything is written (Azure
   * DevOps: the agent pool's queue in the project). A {@link SetupFailure} says what is missing.
   */
  prepare?(): Promise<void>;
  branchExists(): Promise<boolean>;
  createBranch(): Promise<void>;
  /** Writes the files on the branch, skipping those it already holds as planned. */
  writeFiles(
    files: { path: string; content: string; update: boolean }[],
    reused: boolean,
  ): Promise<void>;
  storeToken(token: string): Promise<void>;
  /**
   * Sets the variables (an upsert). Azure DevOps keeps them in the pipeline, which the secret's
   * write made; here the pipeline is authorised on its agent pool, and a resumed setup's pipeline
   * gets its address again.
   */
  setVariables(variables: { key: string; value: string }[]): Promise<void>;
  findMergeRequest(): Promise<string | null>;
  openMergeRequest(description: string): Promise<string>;
}

interface OpenedRepository {
  /** `owner/repo`, the GitLab project's full path, `<project>/<repository>`: the project's name. */
  name: string;
  /**
   * The project's key, or the base of its `-2` … `-20` keys: the name (on Azure DevOps, the name
   * made a key).
   */
  key: string;
  /** What the project maps to: GitHub `owner/repo`, the GitLab project id, the Azure DevOps id. */
  mappingRef: string;
  /** Null: an empty GitLab project or Azure DevOps repository. */
  defaultBranch: string | null;
  /**
   * The GitHub installation grants what a CI change needs (always true on GitLab, and on Azure
   * DevOps, whose rights are found per step: Ruling 2).
   */
  mayChange: boolean;
  ci: CiRepository;
}

/**
 * The project key of an Azure DevOps repository (Ruling 8): `<project>/<repository>` with every
 * character a key may not hold made `-`, runs of `-` collapsed and trimmed. A name of other
 * scripts only leaves no letter or digit: the repository's id is the key then. The project's name
 * keeps the original.
 */
export function azureProjectKey(name: string, repositoryId: string): string {
  const key = [...name]
    .map((c) => (PROJECT_KEY_PATTERN.test(c) ? c : '-'))
    .join('')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '');
  return /[A-Za-z0-9]/.test(key) ? key : repositoryId.toLowerCase();
}

/** The key a repository's project gets before a `-2` … `-20` suffix: the one a run adopts. */
export function setupKeyOf(provider: ScmProvider, name: string, ref: string): string {
  switch (provider) {
    case 'github':
    case 'gitlab':
      return name;
    case 'azure':
      return azureProjectKey(name, ref);
    default:
      return assertNever(provider, 'provider');
  }
}

const WORKFLOWS = '.github/workflows';
/** Workflow files read at most for a Qualor step: one request each, within the job's budget. */
const MAX_WORKFLOW_FILES = 50;

/**
 * The texts of the repository's workflow files on the default branch (the first
 * {@link MAX_WORKFLOW_FILES} YAML files). A file GitHub serves without its content (over 1 MB) is
 * left out: it is no Qualor workflow.
 */
async function workflowTexts(client: GitHubClient, names: string[]): Promise<string[]> {
  const texts: string[] = [];
  for (const name of names.filter((n) => /\.ya?ml$/i.test(n)).slice(0, MAX_WORKFLOW_FILES)) {
    try {
      const text = await client.fileText(`${WORKFLOWS}/${name}`);
      if (text !== null) texts.push(text);
    } catch (err) {
      if (err instanceof ScmError && err.kind === 'bad_answer') continue;
      throw err;
    }
  }
  return texts;
}
const GITLAB_CI = '.gitlab-ci.yml';

function githubRepository(
  client: GitHubClient,
  found: { full_name: string; default_branch: string },
): OpenedRepository {
  const defaultBranch = found.default_branch;
  const granted = client.installationAccess?.permissions ?? {};
  let baseSha: string | null = null;
  // C#: the main language (the most bytes), or a solution or project file at the root.
  const csharp = async () => {
    if ((await client.languages())[0] === 'C#') return true;
    return (await client.listDirectory('')).some((f) => /\.(sln|csproj)$/i.test(f));
  };
  return {
    name: found.full_name,
    key: found.full_name,
    mappingRef: found.full_name,
    defaultBranch,
    mayChange: ['contents', 'workflows', 'secrets'].every((p) => granted[p] === 'write'),
    ci: {
      csharp,
      async read() {
        baseSha = await client.branchSha(defaultBranch);
        const workflowFiles = await client.listDirectory(WORKFLOWS);
        return {
          csharp: await csharp(),
          empty: baseSha === null,
          customCiPath: false,
          existing: {
            gitlabCi: null,
            workflowFiles,
            workflowTexts: await workflowTexts(client, workflowFiles),
            tokenSecretSet: await client.hasActionsSecret('QUALOR_TOKEN'),
            inheritedTokenSet: await client.hasOrganizationSecret('QUALOR_TOKEN'),
          },
        };
      },
      branchExists: async () => (await client.branchSha(SETUP_BRANCH)) !== null,
      async createBranch() {
        const from = baseSha ?? (await client.branchSha(defaultBranch));
        if (from === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        await client.createBranch(SETUP_BRANCH, from);
      },
      async writeFiles(files, reused) {
        for (const file of files) {
          let sha: string | null = null;
          if (reused || file.update) {
            sha = await client.fileSha(file.path, SETUP_BRANCH);
            if (sha !== null && (await client.fileText(file.path, SETUP_BRANCH)) === file.content) {
              continue;
            }
          }
          await client.putFile({
            path: file.path,
            branch: SETUP_BRANCH,
            content: file.content,
            message: SETUP_TITLE,
            ...(sha === null ? {} : { sha }),
          });
        }
      },
      storeToken: (token) => client.putActionsSecret('QUALOR_TOKEN', token),
      // The server address is in the workflow file: GitHub gets no variable.
      setVariables: async () => undefined,
      findMergeRequest: async () => (await client.findOpenPullRequest(SETUP_BRANCH))?.url ?? null,
      openMergeRequest: async (description) =>
        (
          await client.openPullRequest({
            head: SETUP_BRANCH,
            base: defaultBranch,
            title: SETUP_TITLE,
            body: description,
          })
        ).url,
    },
  };
}

function gitlabRepository(
  client: GitLabClient,
  found: {
    id: number;
    path_with_namespace: string;
    default_branch?: string | null;
    ci_config_path?: string | null;
  },
): OpenedRepository {
  const ref = String(found.id);
  const defaultBranch = found.default_branch ?? null;
  const configPath = found.ci_config_path ?? '';
  // C#: the main language only; the GitLab client lists no tree to look for a .sln or .csproj.
  const csharp = async () => (await client.languages(ref))[0] === 'C#';
  return {
    name: found.path_with_namespace,
    key: found.path_with_namespace,
    mappingRef: ref,
    defaultBranch,
    mayChange: true,
    ci: {
      csharp,
      async read() {
        return {
          csharp: await csharp(),
          empty: defaultBranch === null,
          // GitLab answers an empty path (or none) for its default file.
          customCiPath: configPath !== '' && configPath !== GITLAB_CI,
          existing: {
            gitlabCi:
              defaultBranch === null ? null : await client.fileText(ref, GITLAB_CI, defaultBranch),
            workflowFiles: [],
            workflowTexts: [],
            tokenSecretSet: (await client.variable(ref, 'QUALOR_TOKEN')) !== null,
            // A group's or the instance's variable: no API answers it for a project token (the
            // guide says to add such a repository by hand).
            inheritedTokenSet: false,
          },
        };
      },
      branchExists: () => client.branchExists(ref, SETUP_BRANCH),
      async createBranch() {
        if (defaultBranch === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        await client.createBranch(ref, SETUP_BRANCH, defaultBranch);
      },
      async writeFiles(files, reused) {
        const actions = [];
        for (const file of files) {
          const current =
            reused || file.update ? await client.fileText(ref, file.path, SETUP_BRANCH) : null;
          if (current === file.content) continue;
          actions.push({
            action: current === null ? ('create' as const) : ('update' as const),
            path: file.path,
            content: file.content,
          });
        }
        if (actions.length > 0) {
          await client.commitFiles(ref, { branch: SETUP_BRANCH, message: SETUP_TITLE, actions });
        }
      },
      // Masked, and not protected: merge request pipelines must read it.
      storeToken: (token) =>
        client.putVariable(ref, {
          key: 'QUALOR_TOKEN',
          value: token,
          masked: true,
          protected: false,
        }),
      async setVariables(variables) {
        for (const v of variables) {
          await client.putVariable(ref, {
            key: v.key,
            value: v.value,
            masked: false,
            protected: false,
          });
        }
      },
      findMergeRequest: async () =>
        (await client.findOpenMergeRequest(ref, SETUP_BRANCH))?.url ?? null,
      async openMergeRequest(description) {
        if (defaultBranch === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        return (
          await client.openMergeRequest(ref, {
            source: SETUP_BRANCH,
            target: defaultBranch,
            title: SETUP_TITLE,
            description,
          })
        ).url;
      },
    },
  };
}

/** The pipeline's name; `Qualor (<repository>)` when the project has a pipeline of that name. */
const AZURE_PIPELINE_NAME = 'Qualor';
/** The queue of the Microsoft-hosted agents on Azure DevOps Services (probe item 26). */
const AZURE_HOSTED_QUEUE = 'Azure Pipelines';
const AZURE_PIPELINES_YML = 'azure-pipelines.yml';

/** What an Azure DevOps CI setup needs of its run: where its outcomes go, the address, the pool. */
interface AzureSetup {
  db: Db;
  item: Pick<ItemRow, 'runId' | 'position'>;
  /** The pipeline's `QUALOR_URL`. */
  serverUrl: string;
  pool: AzurePool;
}

/**
 * The agent pool of a run's pipelines (Ruling 3): the pool named, else the Microsoft-hosted agents
 * of Services; a Server has none, so `Default` (which a run with CI setup on Server always names).
 */
function azurePoolOf(
  run: Pick<RunRow, 'azurePool'>,
  connection: Pick<ScmConnectionRow, 'baseUrl'>,
): AzurePool {
  if (run.azurePool !== null) return { name: run.azurePool };
  return azureDeployment(connection.baseUrl) === 'services'
    ? { vmImage: 'ubuntu-latest' }
    : { name: 'Default' };
}

/** A pipeline's file without the leading `/` Azure DevOps may keep. */
function yamlPathOf(definition: AzureDefinition): string | null {
  return definition.yamlPath?.replace(/^\/+/, '') ?? null;
}

/** Whether Azure DevOps refused a pipeline's create because the project has one of that name. */
function nameTaken(err: unknown): boolean {
  return err instanceof ScmError && err.kind === 'refused' && err.status === 409;
}

/**
 * Azure DevOps (spec §7.7, Ruling 4): the push of `.azure-pipelines/qualor.yml` on a new branch,
 * the pipeline with its secret and `QUALOR_URL`, its authorisation on the agent pool's queue, then
 * the pull request. Every build, queue and permission call goes to the project's GUID. The item
 * records the pipeline, the queue's state and the pending Build validation policy as they happen.
 */
function azureRepository(
  client: AzureDevOpsClient,
  found: AzureRepository,
  setup: AzureSetup,
): OpenedRepository {
  const { db, item, serverUrl, pool } = setup;
  const repositoryId = found.id;
  const projectId = found.projectId;
  const name = `${found.projectName}/${found.name}`;
  const defaultBranch = found.defaultBranch;
  /** The default branch's head, read once: undefined until then, null for an empty repository. */
  let base: string | null | undefined;
  /** The repository's pipeline for the file, as the read found it. */
  let listed: AzureDefinition | null = null;
  /** The pool's queue, found before anything is written. */
  let queue: AzureQueue | null = null;
  /** The pipeline this job wrote the secret to. */
  let written: AzureDefinition | null = null;

  const baseHead = async (): Promise<string | null> => {
    base ??= defaultBranch === null ? null : await client.branchHead(repositoryId, defaultBranch);
    return base;
  };
  const csharp = async () => {
    const head = await baseHead();
    if (head === null) return false;
    return (await client.rootItems(repositoryId, head)).some(
      (entry) => !entry.isFolder && /\.(sln|csproj)$/i.test(entry.path),
    );
  };
  /** The pool's queue: the hosted one, or the one named for the run. */
  const queueOfPool = async (): Promise<AzureQueue> => {
    if (queue !== null) return queue;
    const wanted = 'vmImage' in pool ? AZURE_HOSTED_QUEUE : pool.name;
    const same = (value: string) => value.toLowerCase() === wanted.toLowerCase();
    const match = (await client.queues(projectId, wanted)).find(
      (q) => same(q.name) || same(q.poolName),
    );
    if (!match) throw new SetupFailure(noAgentPool(wanted));
    queue = match;
    return match;
  };
  /**
   * The pipeline's queue permission: open to every pipeline (or to this one already), authorised
   * now, or a refusal, which the setup result names as the manual approval (Ruling 2).
   */
  const authorise = async (definitionId: number, queueId: number | null): Promise<void> => {
    if (queueId === null) return;
    let state: SetupAzureQueue;
    try {
      const permissions = await client.queuePermissions(projectId, queueId);
      if (permissions.open || permissions.pipelineIds.includes(definitionId)) {
        state = 'open';
      } else {
        await client.authorizeOnQueue(projectId, queueId, definitionId);
        state = 'authorized';
      }
    } catch (err) {
      const refused =
        err instanceof ScmError &&
        (err.kind === 'auth' || err.kind === 'refused' || err.kind === 'not_found');
      if (!refused) throw err;
      state = 'manual';
    }
    await updateItem(db, item, { azureQueue: state });
  };
  const createPipeline = async (
    target: AzureQueue,
    variables: Record<string, AzureDefinitionVariable>,
  ): Promise<AzureDefinition> => {
    const create = (pipelineName: string) =>
      client.createDefinition(projectId, {
        name: pipelineName,
        yamlPath: AZURE_FILE,
        repositoryId,
        repositoryName: found.name,
        defaultBranch: `refs/heads/${defaultBranch ?? 'main'}`,
        queueId: target.id,
        variables,
      });
    try {
      return await create(AZURE_PIPELINE_NAME);
    } catch (err) {
      if (!nameTaken(err)) throw err;
    }
    try {
      return await create(`${AZURE_PIPELINE_NAME} (${found.name})`);
    } catch (err) {
      if (!nameTaken(err)) throw err;
      throw new SetupFailure(errorOf('pipeline_name_taken'));
    }
  };

  return {
    name,
    key: azureProjectKey(name, repositoryId),
    mappingRef: repositoryId,
    defaultBranch,
    mayChange: true,
    ci: {
      csharp,
      async read() {
        const head = await baseHead();
        const existing = {
          gitlabCi: null,
          workflowFiles: [],
          workflowTexts: [],
          tokenSecretSet: false,
          inheritedTokenSet: false,
        };
        if (head === null) {
          return {
            csharp: false,
            empty: true,
            customCiPath: false,
            existing,
            azure: {
              pool,
              existing: { pipelineFile: false, azurePipelinesYml: null, definition: null },
            },
          };
        }
        const file = await client.fileText(repositoryId, AZURE_FILE, head);
        const yml = await client.fileText(repositoryId, AZURE_PIPELINES_YML, head);
        listed =
          (await client.definitions(projectId, repositoryId)).find(
            (d) => yamlPathOf(d) === AZURE_FILE,
          ) ?? null;
        return {
          csharp: await csharp(),
          empty: false,
          // Qualor writes a file of its own and never edits another: no custom path to refuse.
          customCiPath: false,
          existing: { ...existing, tokenSecretSet: listed?.secretSet ?? false },
          azure: {
            pool,
            existing: {
              pipelineFile: !('skipped' in file && file.skipped === 'missing'),
              azurePipelinesYml: 'text' in yml ? yml.text : null,
              definition:
                listed === null
                  ? null
                  : { yamlPath: yamlPathOf(listed), secretSet: listed.secretSet },
            },
          },
        };
      },
      async prepare() {
        await queueOfPool();
      },
      branchExists: async () => (await client.branchHead(repositoryId, SETUP_BRANCH)) !== null,
      // The branch is made by the first push, on the default branch's head (probe item 26).
      async createBranch() {
        if ((await baseHead()) === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
      },
      async writeFiles(files, reused) {
        const head = reused ? await client.branchHead(repositoryId, SETUP_BRANCH) : null;
        const parent = head ?? (await baseHead());
        if (parent === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        const changes: { path: string; content: string; change: 'add' | 'edit' }[] = [];
        for (const file of files) {
          const current = await client.fileText(repositoryId, file.path, parent);
          if ('text' in current && current.text === file.content) continue;
          const absent = 'skipped' in current && current.skipped === 'missing';
          changes.push({ path: file.path, content: file.content, change: absent ? 'add' : 'edit' });
        }
        if (changes.length === 0) return;
        await client.push(repositoryId, {
          ref: `refs/heads/${SETUP_BRANCH}`,
          // A new branch: the zero id, on the default branch's head.
          oldObjectId: head,
          parent,
          message: SETUP_TITLE,
          files: changes,
        });
      },
      // The pipeline with the secret and QUALOR_URL in one write: created, or the repository's
      // pipeline for the file (GET+PUT, which keeps what it has: rule 15).
      async storeToken(token) {
        const variables: Record<string, AzureDefinitionVariable> = {
          [AZURE_SECRET_VARIABLE]: { value: token, isSecret: true },
          QUALOR_URL: { value: serverUrl },
        };
        const target = await queueOfPool();
        written =
          listed === null
            ? await createPipeline(target, variables)
            : await client.replaceDefinition(projectId, listed, variables);
        await updateItem(db, item, { azurePipelineId: written.id });
      },
      async setVariables(variables) {
        if (written !== null) {
          // QUALOR_URL went with the secret; the pool the file names is the run's.
          return authorise(written.id, queue?.id ?? written.queueId);
        }
        // A resumed setup: the pipeline an earlier job made, its address set again.
        if (listed === null) return;
        const again = await client.replaceDefinition(
          projectId,
          listed,
          Object.fromEntries(variables.map((v) => [v.key, { value: v.value }])),
        );
        await updateItem(db, item, { azurePipelineId: again.id });
        await authorise(again.id, again.queueId);
      },
      async findMergeRequest() {
        if (defaultBranch === null) return null;
        const open = await client.pullRequestsFrom(repositoryId, SETUP_BRANCH, defaultBranch);
        return open[0]?.webUrl ?? null;
      },
      async openMergeRequest(description) {
        if (defaultBranch === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
        const pipeline = written ?? listed;
        const opened = await client.createPullRequest(repositoryId, {
          sourceBranch: SETUP_BRANCH,
          targetBranch: defaultBranch,
          title: SETUP_TITLE,
          description:
            pipeline === null ? description : azurePipelineNamed(description, pipeline.name),
        });
        // The Build validation policy follows the first main-branch analysis (azure-policy.ts).
        await updateItem(db, item, { azurePolicy: 'pending', azurePolicyError: null });
        return opened.webUrl;
      },
    },
  };
}

/**
 * One client for the repository (the request budget is per client), and what the provider calls
 * it. GitHub's token asks for Workflows and Secrets (write) only when the run changes CI (Contents
 * (write) whenever the installation grants it).
 */
async function openRepository(ctx: ItemContext, changesCi: boolean): Promise<OpenedRepository> {
  const { deps, connection, run, item } = ctx;
  const ref = item.repositoryRef;
  switch (connection.provider) {
    case 'github': {
      const repo = parseRepoRef(ref);
      if (repo === null) throw new ScmError('not_found', ERROR_TEXT.not_found);
      const made = githubClientFor(connection, deps.scm, deps.runtime);
      if ('problem' in made) throw new UnusableConnection();
      const found = await made.client.useRepository(repo, changesCi ? { ciSetup: true } : {});
      return githubRepository(made.client, found);
    }
    case 'gitlab': {
      const made = gitlabClientFor(connection, deps.scm);
      if ('problem' in made) throw new UnusableConnection();
      return gitlabRepository(made.client, await made.client.project(ref));
    }
    case 'azure': {
      const made = azureClientFor(connection, deps.scm, deps.runtime);
      if ('problem' in made) throw new UnusableConnection();
      return azureRepository(made.client, await made.client.repository(ref), {
        db: deps.db,
        item,
        serverUrl: deps.publicUrl ?? URL_PLACEHOLDER,
        pool: azurePoolOf(run, connection),
      });
    }
    default:
      return assertNever(connection.provider, 'provider');
  }
}

// ─── The project ───────────────────────────────────────────────────────────────────────────

/**
 * Maps the project to the repository as `PATCH /projects/:id` does, with its `project.updated`
 * event. An adopted project may still hold review copies of an earlier mapping (an unmap whose
 * purge has not run yet): they go, as `PATCH` has them go (R41).
 */
async function mapProject(
  tx: Executor,
  project: ProjectRow,
  connectionId: string,
  ref: string,
  by: AuditedActor,
): Promise<ProjectRow> {
  const saved = first(
    await tx
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: ref, updatedAt: new Date() })
      .where(eq(projects.id, project.id))
      .returning(),
  );
  // scm.md §8: merge request links are kept only on the mapped connection's address.
  if (project.scmConnectionId !== connectionId) {
    await forgetForeignMergeRequestUrls(tx, { projectId: saved.id });
  }
  await queueRemapPurgeIfCopies(tx, project, saved);
  const changes = PROJECT_CHANGE_FIELDS.filter(
    (field) => canonicalJson(project[field]) !== canonicalJson(saved[field]),
  ).map((field) => ({ field, from: project[field], to: saved[field] }));
  if (changes.length > 0 && by.audit.active()) {
    const refs = await projectRefs(tx, saved.id);
    await by.audit.record(tx, by.actor, [
      {
        action: 'project.updated',
        organization: refs.organization,
        project: refs.project,
        target: { type: 'project', id: saved.id, label: saved.name },
        details: { changes },
      },
    ]);
  }
  return saved;
}

/**
 * The item's project, in one transaction with its outcome: the project of the organisation that
 * already maps this repository through this connection (a second run, a retry), else the unmapped
 * project whose key is the repository's key (adopted), else a new one with the first free key of
 * `key`, `key-2` … `key-20`, named as the repository. Null when the item failed (saved too).
 */
async function settleProject(
  deps: SetupRunDeps,
  run: RunRow,
  item: ItemRow,
  connectionId: string,
  repo: OpenedRepository,
  by: AuditedActor,
): Promise<ProjectRow | null> {
  return deps.db.transaction(async (tx) => {
    // Locked as PATCH /projects locks it, before any project: a concurrent DELETE waits.
    const [connection] = await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(
        and(
          eq(scmConnections.id, connectionId),
          eq(scmConnections.organizationId, run.organizationId),
        ),
      )
      .for('key share');
    if (!connection) {
      await failItem(tx, item, errorOf('connection_gone'));
      return null;
    }
    const settled = async (outcome: SetupProjectOutcome, project: ProjectRow) => {
      await updateItem(tx, item, {
        projectOutcome: outcome,
        projectId: project.id,
        repositoryName: repo.name,
      });
      return project;
    };
    // GitHub names and GitLab paths compare without case; a GitLab id as written.
    const refs = [...new Set([repo.mappingRef, repo.name].map((r) => r.toLowerCase()))];
    const [mapped] = await tx
      .select()
      .from(projects)
      .where(
        and(
          eq(projects.organizationId, run.organizationId),
          eq(projects.scmConnectionId, connection.id),
          inArray(sql`lower(${projects.scmProjectRef})`, refs),
        ),
      )
      .orderBy(asc(projects.createdAt))
      .limit(1);
    if (mapped) return settled('adopted', mapped);
    const [free] = await tx
      .select()
      .from(projects)
      .where(
        and(
          eq(projects.organizationId, run.organizationId),
          eq(projects.key, repo.key),
          isNull(projects.scmConnectionId),
        ),
      )
      .for('no key update');
    if (free) {
      return settled('adopted', await mapProject(tx, free, connection.id, repo.mappingRef, by));
    }
    const candidates = [
      repo.key,
      ...Array.from({ length: MAX_KEY_SUFFIX - 1 }, (_, i) => `${repo.key}-${i + 2}`),
    ].filter((key) => PROJECT_KEY_PATTERN.test(key));
    const taken = new Set(
      candidates.length === 0
        ? []
        : (
            await tx
              .select({ key: projects.key })
              .from(projects)
              .where(inArray(projects.key, candidates))
          ).map((p) => p.key),
    );
    for (const key of candidates) {
      if (taken.has(key)) continue;
      let created: ProjectRow;
      try {
        // A savepoint: a key taken meanwhile fails it alone, and the next key is tried.
        created = await tx.transaction((sp) =>
          createProject(sp, {
            organizationId: run.organizationId,
            key,
            name: repo.name.slice(0, PROJECT_NAME_MAX),
            mainBranchName: repo.defaultBranch ?? 'main',
            createdBy: by,
          }),
        );
      } catch (err) {
        if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) continue;
        throw err;
      }
      return settled('created', await mapProject(tx, created, connection.id, repo.mappingRef, by));
    }
    await failItem(tx, item, errorOf('key_taken'));
    return null;
  });
}

// ─── CI ────────────────────────────────────────────────────────────────────────────────────

/** The item's project, as CI setup needs it: its key goes into every CI file and snippet. */
type SetupProject = Pick<ProjectRow, 'id' | 'key'>;

async function setupProjectOf(db: Executor, projectId: string): Promise<SetupProject | null> {
  const [row] = await db
    .select({ id: projects.id, key: projects.key })
    .from(projects)
    .where(eq(projects.id, projectId));
  return row ?? null;
}

/** Whether the project has a live CI setup token already: a snippet then gets no second one. */
async function hasSetupToken(db: Executor, projectId: string): Promise<boolean> {
  const [row] = await db
    .select({ id: apiTokens.id })
    .from(apiTokens)
    .where(
      and(
        eq(apiTokens.projectId, projectId),
        eq(apiTokens.name, SETUP_TOKEN_NAME),
        isNull(apiTokens.revokedAt),
      ),
    )
    .limit(1);
  return row !== undefined;
}

function createSetupToken(
  tx: Executor,
  projectId: string,
  by: AuditedActor,
  userId: string | null,
) {
  return createProjectToken(tx, {
    projectId,
    name: SETUP_TOKEN_NAME,
    scopes: ['analysis:write'],
    expiresAt: null,
    createdBy: { ...by, userId },
  });
}

/**
 * The snippet a repository without CI would get: the planner's change for a fresh repository. On
 * Azure DevOps (the run's pool) the file comes with the steps outside it: the pipeline, its
 * `QUALOR_URL` and its secret.
 */
function freshSnippet(input: Omit<CiSetupInput, 'existing' | 'azure'>, pool: AzurePool): string {
  const azure = input.provider === 'azure';
  const plan = planCiSetup({
    ...input,
    existing: {
      gitlabCi: null,
      workflowFiles: [],
      workflowTexts: [],
      tokenSecretSet: false,
      inheritedTokenSet: false,
    },
    ...(azure
      ? {
          azure: {
            pool,
            existing: { pipelineFile: false, azurePipelinesYml: null, definition: null },
          },
        }
      : {}),
  });
  if (plan.kind === 'snippet') return plan.snippet;
  const content = plan.files[0]?.content ?? '';
  return azure ? azureSnippet(content, input.serverUrl) : content;
}

interface ItemContext {
  deps: SetupRunDeps;
  run: RunRow;
  item: ItemRow;
  connection: ScmConnectionRow;
  status: CiSetupStatus | null;
  by: AuditedActor;
  /** The CI-setup status could not be read, and the run paused as often as it may. */
  statusFailure: ScmError | null;
  /** A rate limit pauses the run (rather than failing the repository). */
  mayPause: boolean;
  /** Where the item's CI setup is: a failure's log line names it, and a read's error says so. */
  ciStep: CiStep;
}

/**
 * The item's CI outcome with a snippet to copy, and the token revealed once with it: a new CI
 * setup token, unless the project already has a live one (a second run of the same repository).
 */
async function finishWithSnippet(
  ctx: ItemContext,
  projectId: string,
  outcome: Extract<SetupCiOutcome, 'snippet' | 'skipped'>,
  reason: SetupCiReason | null,
  snippet: string,
): Promise<void> {
  const key = encryptionKey(ctx.deps.scm.secretKey);
  await ctx.deps.db.transaction(async (tx) => {
    let tokenEnc: EncryptedValue | null = null;
    if (!(await hasSetupToken(tx, projectId))) {
      const { token } = await createSetupToken(tx, projectId, ctx.by, ctx.run.createdBy);
      tokenEnc = encryptSecret(key, token, SETUP_TOKEN_AAD);
    }
    await updateItem(tx, ctx.item, { ciOutcome: outcome, ciReason: reason, snippet, tokenEnc });
  });
}

/** Whether the repository is C#; a failed read gives false, a snippet is still worth giving. */
async function detectCsharp(repo: OpenedRepository): Promise<boolean> {
  try {
    return await repo.ci.csharp();
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    return false;
  }
}

/** The repository already runs Qualor: points at its open merge request, or finishes an earlier run. */
async function settleAlreadySetUp(
  ctx: ItemContext,
  repo: OpenedRepository,
  input: CiSetupInput,
  snippet: string,
): Promise<void> {
  const { deps, item } = ctx;
  ctx.ciStep = 'merge_request';
  const open = await repo.ci.findMergeRequest();
  if (open !== null) {
    return updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: open });
  }
  // A run that stored the token and then could not open the merge request: open it now.
  if (input.existing.tokenSecretSet) {
    const resumed = planCiSetup({
      ...input,
      existing: { ...input.existing, tokenSecretSet: false },
      // Azure DevOps: the pipeline holding the secret is what counted as set up.
      ...(input.azure
        ? { azure: { ...input.azure, existing: { ...input.azure.existing, definition: null } } }
        : {}),
    });
    ctx.ciStep = 'branch';
    if (resumed.kind === 'change' && (await repo.ci.branchExists())) {
      // What failed after the token may be a variable (on Azure DevOps the pipeline's agent pool
      // authorisation): set them again (an upsert) first.
      ctx.ciStep = 'variables';
      await repo.ci.setVariables(resumed.variables);
      ctx.ciStep = 'merge_request';
      const url = await repo.ci.openMergeRequest(resumed.description);
      return updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: url });
    }
  }
  return updateItem(deps.db, item, {
    ciOutcome: 'already',
    ciReason: 'already_set_up' satisfies CiSnippetReason,
    snippet,
  });
}

/** Writes the plan: the branch, the files, the token and variables, the merge request. */
async function applyCiChange(
  ctx: ItemContext,
  repo: OpenedRepository,
  projectId: string,
  plan: Extract<CiPlan, { kind: 'change' }>,
): Promise<void> {
  const { deps, run, item } = ctx;
  // Still a read: what the change needs besides the repository, before anything is written.
  await repo.ci.prepare?.();
  ctx.ciStep = 'branch';
  const reused = await repo.ci.branchExists();
  if (!reused) await repo.ci.createBranch();
  ctx.ciStep = 'files';
  await repo.ci.writeFiles(plan.files, reused);
  // Made only now, committed before it is written: the token is never stored in Qualor.
  const { row, token } = await deps.db.transaction((tx) =>
    createSetupToken(tx, projectId, ctx.by, run.createdBy),
  );
  let stored = false;
  try {
    ctx.ciStep = 'secret';
    try {
      await repo.ci.storeToken(token);
    } catch (err) {
      // A refusal, or a stop in Qualor's words, stored nothing; a lost answer may have stored it.
      stored = !(definitelyRefused(err) || err instanceof SetupFailure);
      throw err;
    }
    stored = true;
    ctx.ciStep = 'variables';
    await repo.ci.setVariables(plan.variables);
    ctx.ciStep = 'merge_request';
    const url =
      (await repo.ci.findMergeRequest()) ?? (await repo.ci.openMergeRequest(plan.description));
    await updateItem(deps.db, item, { ciOutcome: 'merge_request', ciUrl: url });
  } catch (err) {
    if (!stored) {
      await deps.db.transaction((tx) =>
        revokeProjectToken(tx, { projectId, tokenId: row.id, revokedBy: ctx.by }),
      );
    }
    throw err;
  }
}

/**
 * CI setup for one repository: the plan, then for a change the branch, the files, the token in
 * the CI secrets and the merge request, in that order (the pipeline the merge request starts
 * finds the token). A token whose write failed is revoked; one that may be stored stays.
 */
async function setUpCi(
  ctx: ItemContext,
  repo: OpenedRepository,
  project: SetupProject,
): Promise<void> {
  const { deps, run, connection, status } = ctx;
  const projectId = project.id;
  const base = {
    provider: connection.provider,
    host: (deps.host ?? ciHostOf)(connection),
    serverUrl: deps.publicUrl ?? URL_PLACEHOLDER,
    // Always written: the key may differ from the repository's path, which the scanner would use.
    projectKey: project.key,
    version: VERSION,
    defaultBranch: repo.defaultBranch ?? 'main',
  };
  const snippet = async (
    outcome: 'snippet' | 'skipped',
    reason: SetupCiReason | null,
    csharp?: boolean,
  ) => {
    const isCsharp = csharp ?? (await detectCsharp(repo));
    await finishWithSnippet(
      ctx,
      projectId,
      outcome,
      reason,
      freshSnippet({ ...base, csharp: isCsharp }, azurePoolOf(run, connection)),
    );
  };
  if (!run.ciSetup) return snippet('skipped', null);
  if (status === null || !status.available) {
    return snippet('snippet', status?.reason ?? 'not_allowed');
  }
  if (!repo.mayChange) return snippet('snippet', 'missing_permissions');
  if (repo.defaultBranch === null) return snippet('snippet', 'empty_repository');

  ctx.ciStep = 'read';
  const read = await repo.ci.read();
  if (read.empty) return snippet('snippet', 'empty_repository', read.csharp);
  if (read.customCiPath) return snippet('snippet', 'custom_ci_path', read.csharp);
  const input: CiSetupInput = {
    ...base,
    csharp: read.csharp,
    existing: read.existing,
    ...(read.azure ? { azure: read.azure } : {}),
  };
  const plan: CiPlan = planCiSetup(input);
  if (plan.kind === 'snippet') {
    if (plan.reason !== 'already_set_up') {
      return finishWithSnippet(ctx, projectId, 'snippet', plan.reason, plan.snippet);
    }
    return settleAlreadySetUp(ctx, repo, input, plan.snippet);
  }
  return applyCiChange(ctx, repo, projectId, plan);
}

// ─── The run ───────────────────────────────────────────────────────────────────────────────

function pauseFor(err: ScmError): RateLimitPause {
  return new RateLimitPause(err.retryAfterSeconds ?? DEFAULT_PAUSE_SECONDS);
}

type ItemLog = { runId: string; position: number };

/** A repository that could not be opened: the item fails, or only its CI setup does. */
async function recordOpenFailure(ctx: ItemContext, err: unknown, log: ItemLog): Promise<void> {
  const { deps, connection, item } = ctx;
  let error: ItemError;
  if (err instanceof UnusableConnection) {
    error = errorOf('connection_unusable');
  } else if (err instanceof ScmError) {
    if (err.kind === 'rate_limited' && ctx.mayPause) throw pauseFor(err);
    deps.logger?.warn(
      { ...log, request: err.request, kind: err.kind, reason: err.reason, status: err.status },
      'repository setup could not read the repository',
    );
    error = scmErrorOf(err, connection.provider, 'open');
  } else {
    throw err;
  }
  if (item.projectOutcome === 'pending') return failItem(deps.db, item, error);
  return updateItem(deps.db, item, {
    ciOutcome: 'failed',
    errorCode: error.code,
    errorMessage: error.message,
  });
}

/**
 * The item's project: settled now, or as it is now for a resumed item. Null: nothing more to do,
 * the item is already recorded (settled as finished, or failed with project_gone).
 */
async function projectOfItem(
  ctx: ItemContext,
  repo: OpenedRepository,
): Promise<SetupProject | null> {
  const { deps, run, connection, item } = ctx;
  if (item.projectOutcome === 'pending') {
    return settleProject(deps, run, item, connection.id, repo, ctx.by);
  }
  // A resumed item: its project as it is now (deleted since: none).
  const project = item.projectId === null ? null : await setupProjectOf(deps.db, item.projectId);
  if (project === null) {
    await updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: 'project_gone',
      errorMessage: ERROR_TEXT.project_gone,
    });
  }
  return project;
}

/** The CI setup of a repository failed with a provider error: the item stays pending or fails. */
async function recordCiFailure(ctx: ItemContext, err: unknown, log: ItemLog): Promise<void> {
  const { deps, connection, item } = ctx;
  if (err instanceof SetupFailure) {
    // Its code only: the message may hold the pool's name, which a person typed.
    deps.logger?.warn(
      { ...log, step: ctx.ciStep, code: err.error.code },
      'repository setup could not set up CI',
    );
    return updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: err.error.code,
      errorMessage: err.error.message,
    });
  }
  if (!(err instanceof ScmError)) throw err;
  // The item stays pending: the next job resumes it (the branch is reused, the files kept).
  if (err.kind === 'rate_limited' && ctx.mayPause) throw pauseFor(err);
  deps.logger?.warn(
    {
      ...log,
      step: ctx.ciStep,
      request: err.request,
      kind: err.kind,
      reason: err.reason,
      status: err.status,
    },
    'repository setup could not set up CI',
  );
  const error = scmErrorOf(
    err,
    connection.provider,
    ctx.ciStep === 'read' ? 'ci_read' : 'change',
    ctx.ciStep,
  );
  await updateItem(deps.db, item, {
    ciOutcome: 'failed',
    errorCode: error.code,
    errorMessage: error.message,
  });
}

async function setUpRepository(ctx: ItemContext): Promise<void> {
  const { deps, run, connection, status, item } = ctx;
  const changesCi = run.ciSetup && status?.available === true;
  const log = { runId: run.id, position: item.position };
  let repo: OpenedRepository;
  try {
    repo = await openRepository(ctx, changesCi);
  } catch (err) {
    return recordOpenFailure(ctx, err, log);
  }

  const project = await projectOfItem(ctx, repo);
  if (project === null) return;
  if (run.ciSetup && ctx.statusFailure !== null) {
    // Never a snippet for want of an answer: the CI setup fails, with why.
    const error = scmErrorOf(ctx.statusFailure, connection.provider, 'open');
    return updateItem(deps.db, item, {
      ciOutcome: 'failed',
      errorCode: error.code,
      errorMessage: error.message,
    });
  }

  try {
    await setUpCi(ctx, repo, project);
  } catch (err) {
    await recordCiFailure(ctx, err, log);
  }
}

/** The same run, later: the job is queued again, under the same key (one job per connection). */
async function pauseRun(
  deps: SetupRunDeps,
  run: RunRow,
  connectionId: string,
  pauses: number,
  seconds: number,
): Promise<void> {
  await enqueue(deps.db, {
    queue: REPOSITORY_SETUP_QUEUE,
    payload: { runId: run.id, pauses: pauses + 1 },
    concurrencyKey: connectionId,
    runAt: sql`now() + make_interval(secs => ${seconds})`,
  });
}

async function connectionOfRun(deps: SetupRunDeps, run: RunRow) {
  if (run.connectionId === null) return undefined;
  const [connection] = await deps.db
    .select()
    .from(scmConnections)
    .where(
      and(
        eq(scmConnections.id, run.connectionId),
        eq(scmConnections.organizationId, run.organizationId),
      ),
    );
  return connection;
}

type RunStatus =
  | { paused: true }
  | { paused: false; status: CiSetupStatus | null; statusFailure: ScmError | null };

/**
 * Read once per run, uncached: the GitHub installations' permissions, the GitLab setting, the
 * URL. Only a definite "not available" turns the repositories' CI into snippets; a failed read
 * pauses the run and reads again later.
 */
async function readRunStatus(
  deps: SetupRunDeps,
  run: RunRow,
  connection: ScmConnectionRow,
  pauses: number,
): Promise<RunStatus> {
  try {
    const status = await readCiSetupStatus(connection, deps.scm, deps.publicUrl);
    return { paused: false, status, statusFailure: null };
  } catch (err) {
    if (!(err instanceof ScmError)) throw err;
    deps.logger?.warn(
      {
        runId: run.id,
        request: err.request,
        kind: err.kind,
        reason: err.reason,
        status: err.status,
      },
      'repository setup could not read the CI-setup status',
    );
    // An unusable connection (its key, its address) does not get better: each repository
    // fails on it at once.
    if (err.reason === 'invalid_input' || pauses >= MAX_PAUSES) {
      return { paused: false, status: null, statusFailure: err };
    }
    const seconds = err.retryAfterSeconds ?? DEFAULT_PAUSE_SECONDS;
    await pauseRun(deps, run, connection.id, pauses, seconds);
    deps.logger?.info(
      { runId: run.id, retryInSeconds: seconds },
      'repository setup paused: the CI-setup status could not be read',
    );
    return { paused: true };
  }
}

/** One item of the run; true when the provider's rate limit paused the whole run. */
async function runItem(
  ctx: ItemContext,
  pauses: number,
  connection: ScmConnectionRow,
): Promise<boolean> {
  const { deps, run, item } = ctx;
  try {
    await setUpRepository(ctx);
    return false;
  } catch (err) {
    if (err instanceof RateLimitPause) {
      await pauseRun(deps, run, connection.id, pauses, err.seconds);
      deps.logger?.info(
        { runId: run.id, position: item.position, retryInSeconds: err.seconds },
        'repository setup paused: the provider is rate limiting',
      );
      return true;
    }
    // One repository's failure never loses the others (no token is in this error: the clients'
    // errors are ScmErrors, handled above, and the token never reaches a query).
    deps.logger?.error({ err, runId: run.id, position: item.position }, 'repository setup failed');
    const [now] = await deps.db
      .select()
      .from(repositorySetupItems)
      .where(
        and(
          eq(repositorySetupItems.runId, item.runId),
          eq(repositorySetupItems.position, item.position),
        ),
      );
    await failItem(deps.db, now ?? item, errorOf('internal'));
    return false;
  }
}

async function runSetup(deps: SetupRunDeps, payload: z.infer<typeof payloadSchema>): Promise<void> {
  const { runId, pauses } = payload;
  const [run] = await deps.db
    .select()
    .from(repositorySetupRuns)
    .where(eq(repositorySetupRuns.id, runId));
  if (!run || run.status === 'done') return;
  if (run.status === 'queued') {
    await deps.db
      .update(repositorySetupRuns)
      .set({ status: 'running' })
      .where(eq(repositorySetupRuns.id, run.id));
  }
  const connection = await connectionOfRun(deps, run);
  const by: AuditedActor = { audit: deps.audit, actor: await actorOf(deps.db, run.createdBy) };
  let status: CiSetupStatus | null = null;
  let statusFailure: ScmError | null = null;
  if (connection && run.ciSetup) {
    const read = await readRunStatus(deps, run, connection, pauses);
    if (read.paused) return;
    ({ status, statusFailure } = read);
  }
  const items = await deps.db
    .select()
    .from(repositorySetupItems)
    .where(eq(repositorySetupItems.runId, run.id))
    .orderBy(asc(repositorySetupItems.position));
  for (const item of items) {
    if (item.projectOutcome !== 'pending' && item.ciOutcome !== 'pending') continue;
    if (!connection) {
      await failItem(deps.db, item, errorOf('connection_gone'));
      continue;
    }
    const ctx: ItemContext = {
      deps,
      run,
      item,
      connection,
      status,
      statusFailure,
      by,
      mayPause: pauses < MAX_PAUSES,
      ciStep: 'read',
    };
    if (await runItem(ctx, pauses, connection)) return;
  }
  await deps.db
    .update(repositorySetupRuns)
    .set({ status: 'done', finishedAt: new Date() })
    .where(eq(repositorySetupRuns.id, run.id));
}

/** The `repository-setup` queue's handler; the `scm` worker runs it (main.ts). */
export function repositorySetupHandlers(deps: SetupRunDeps): JobHandlers {
  return {
    [REPOSITORY_SETUP_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed repository-setup job payload; completing');
        return;
      }
      await runSetup(deps, parsed.data);
    },
  };
}

/**
 * Finishes the runs whose job is gone (dead after its attempts, or lost): their unfinished
 * repositories fail as `abandoned`, so the page polling them stops. The `scm` worker runs it after
 * every reap. Returns the number of runs finished.
 */
export async function reconcileStuckSetupRuns(db: Executor): Promise<number> {
  const result = await db.execute(sql`
    WITH stuck AS (
      SELECT r.id FROM repository_setup_runs r
       WHERE r.status <> 'done'
         AND NOT EXISTS (
               SELECT 1 FROM jobs j
                WHERE j.queue = ${REPOSITORY_SETUP_QUEUE} AND j.status IN ('queued', 'running')
                  -- Compared as text: a malformed payload must not make the sweep fail.
                  AND j.payload ->> 'runId' = r.id::text)
    ), items AS (
      UPDATE repository_setup_items i
         SET project_outcome = CASE WHEN i.project_outcome = 'pending' THEN 'failed'
                                    ELSE i.project_outcome END,
             ci_outcome = 'failed',
             error_code = 'abandoned',
             error_message = ${ERROR_TEXT.abandoned}
        FROM stuck
       WHERE i.run_id = stuck.id AND (i.project_outcome = 'pending' OR i.ci_outcome = 'pending')
    )
    UPDATE repository_setup_runs r
       SET status = 'done', finished_at = now()
      FROM stuck
     WHERE r.id = stuck.id`);
  return result.rowCount ?? 0;
}
