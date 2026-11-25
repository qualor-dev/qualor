import type { IncomingHttpHeaders } from 'node:http';
import { z } from 'zod';
import { outboundRequest, type OutboundFailed, type Resolver } from '../../http/outbound';
import { VERSION } from '../../index';
import { namedRequest, ScmError, type ScmErrorKind, type ScmErrorOptions } from '../provider';
import { retryAfterSeconds } from '../retry-after';
import { scmRefusedAddress } from '../url';
import {
  AZURE_REPOSITORY_ID,
  azureDeployment,
  azureIdentitiesBase,
  azurePullRequestWebUrl,
} from './url';

/** The id of an Azure DevOps pull request, as an Azure analysis names its branch (digits only). */
export const AZURE_PR_ID = /^[0-9]{1,10}$/;

/** Azure DevOps design §7.4, as for GitLab: every request has 10 s in all ... */
export const AZURE_TIMEOUT_MS = 10_000;
/** ... answers over 8 MiB are refused ... */
export const MAX_AZURE_RESPONSE_BYTES = 8 * 1024 * 1024;
/** ... and one job makes at most this many requests. */
export const MAX_AZURE_REQUESTS = 400;
/** Design §7.9 and the probe (item 19): `7.0` everywhere, named preview versions where needed. */
export const AZURE_API_VERSION = '7.0';
/** The agent queues and their pipeline permissions are preview routes (probe item 26). */
export const AZURE_PREVIEW_API_VERSION = '7.0-preview.1';
/** connectionData is a preview route (Server answers 7.0 with VssInvalidPreviewVersionException). */
export const CONNECTION_DATA_API_VERSION = '7.0-preview';
/** A success that asks the next request to wait (`Retry-After`, `X-RateLimit-Delay`): at most 30 s. */
export const MAX_AZURE_PACE_MS = 30_000;

/** The fixed texts; Azure DevOps' own words are never shown or logged. */
export const AZURE_TEXT = {
  signInPage: 'Azure DevOps answered with a sign-in page; check the credential',
  refused: 'Azure DevOps refused the credential (HTTP 401)',
  signInRequired: 'The identity is not a member of this organization or has no access level',
  forbidden: 'The Azure DevOps identity lacks the permission for this request (HTTP 403)',
  rightMissing: 'The Azure DevOps identity lacks a right on the repository',
  notFound: 'Azure DevOps found nothing there, or the identity cannot see it (HTTP 404)',
  rateLimited: 'Azure DevOps is limiting requests (HTTP 429)',
  badAnswer: "Azure DevOps's answer was not understood",
  repositoryId: 'The repository id is not an Azure DevOps repository id (a GUID)',
  guid: 'The id is not an Azure DevOps id (a GUID)',
  commitId: 'The commit id is not a commit id',
  notPublic:
    'The Azure DevOps host resolves to a private, loopback or otherwise non-public address; list it in QUALOR_SCM_INTERNAL_HOSTS',
  refusedAddress:
    'The Azure DevOps host resolves to a link-local, cloud metadata or loopback address',
  unresolved: 'The Azure DevOps host could not be resolved',
  timeout: 'Azure DevOps did not answer in time',
  refStale: 'The branch moved while Qualor was changing it',
  refRefused: 'Azure DevOps refused to change the branch',
  workItemId: 'The id is not an Azure DevOps work item id',
  workItemType: 'The work item type name is empty or longer than 128 characters',
  workItemBatch: 'At most 200 work items are read in one request',
  classificationGroup: 'The classification group is areas or iterations',
} as const;

/** JSON Patch bodies of work item writes (probe item 30c: `application/json` is a 400). */
export const AZURE_JSON_PATCH = 'application/json-patch+json';
/** `workitemsbatch` reads at most this many ids per request. */
export const MAX_WORK_ITEM_BATCH = 200;
/** A WIQL query answers at most this many ids (`$top`). */
export const WORK_ITEM_QUERY_TOP = 200;
/** `projects()` reads at most this many projects, 100 per page. */
export const MAX_AZURE_PROJECTS = 1000;
/** `classificationPaths()` reads this many levels below the root, and at most 2000 paths. */
export const CLASSIFICATION_DEPTH = 10;
export const MAX_CLASSIFICATION_PATHS = 2000;
/** The fields a batch read asks for (never with `$expand`, probe item 30g). */
export const WORK_ITEM_BATCH_FIELDS = [
  'System.State',
  'System.TeamProject',
  'System.WorkItemType',
  'System.Tags',
  'System.Description',
] as const;
/** Server errors that are refusals, not outages: a long text field over 1,048,576 characters (30e). */
const REFUSED_SERVER_ERRORS: ReadonlySet<string> = new Set([
  'WorkItemFieldMaxLongTextSizeExceededException',
]);

/** A failed Azure DevOps request; see {@link ScmError}. */
export class AzureError extends ScmError {
  /**
   * The `typeKey` of Azure DevOps' error body (`DefinitionExistsException`), for decisions only:
   * not enumerable, like the message. Unlike the message it is not translated.
   */
  declare readonly azureTypeKey: string | null;

  constructor(
    kind: ScmErrorKind,
    message: string,
    options: Omit<ScmErrorOptions, 'providerMessage'> & {
      azureMessage?: string | null;
      azureTypeKey?: string | null;
    } = {},
  ) {
    const { azureMessage, azureTypeKey, ...rest } = options;
    super(kind, message, { ...rest, providerMessage: azureMessage ?? null });
    this.name = 'AzureError';
    Object.defineProperty(this, 'azureTypeKey', {
      value: azureTypeKey ?? null,
      enumerable: false,
      writable: false,
    });
  }

  /** The `message` of Azure DevOps' error body (decisions only, never logged or shown). */
  get azureMessage(): string | null {
    return this.providerMessage;
  }
}

/** Where the client says what it let pass: a re-save that failed after the create (warn only). */
export interface AzureClientLogger {
  warn(details: object, message: string): void;
}

/**
 * A PAT (sent as Basic with an empty user name), or a bearer token from Microsoft Entra that
 * `token()` gives for each request (the caller caches it); an Entra failure is the error
 * `entraToken` throws, passed on as it is.
 */
export type AzureCredential =
  { kind: 'pat'; pat: string } | { kind: 'bearer'; token: () => Promise<string> };

export interface AzureConnectionInput {
  /** The normalised base URL: `https://dev.azure.com/<organization>`, or a Server collection. */
  baseUrl: string;
  credential: AzureCredential;
  allowInternalHosts: boolean;
  /**
   * Where identities are looked up (the `vssps` host of a Services organisation) and whether that
   * host may be an internal one. Default: {@link azureIdentitiesBase} of `baseUrl`, internal hosts
   * allowed only where it is the base itself (a Server collection). The rules of the base apply to
   * this host as they are, never the base's permission.
   */
  identities?: { baseUrl: string; allowInternalHosts: boolean };
}

export interface AzureClientOptions {
  timeoutMs?: number;
  resolve?: Resolver;
  /** Default {@link MAX_AZURE_REQUESTS}. */
  maxRequests?: number;
  /** How the client waits before a request a success asked to delay; default a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** Milliseconds since the epoch. */
  now?: () => number;
  /** Gives up every request of this client once it aborts. */
  signal?: AbortSignal;
}

/** Who the credential is: `authenticatedUser` of connectionData. */
export interface AzureIdentity {
  id: string;
  /** `providerDisplayName`: the app's name for a service principal, else the account's. */
  displayName: string;
}

export interface AzureRepository {
  /** Lower-case GUIDs. */
  id: string;
  name: string;
  projectId: string;
  projectName: string;
  webUrl: string;
  /** Without `refs/heads/`; null for an empty repository. */
  defaultBranch: string | null;
  isDisabled: boolean;
}

export interface AzurePullRequest {
  id: number;
  status: 'active' | 'completed' | 'abandoned';
  isDraft: boolean;
  title: string;
  sourceRefName: string;
  targetRefName: string;
  /** `lastMergeSourceCommit`: the source branch's head; null before Azure DevOps has merged. */
  headSha: string | null;
  webUrl: string;
  /** `succeeded`, `conflicts`, `queued` ...; null before Azure DevOps has tried a merge. */
  mergeStatus: string | null;
  /** Lower-case GUID of the repository the pull request is in. */
  repositoryId: string;
  /** The source branch is in a fork (`forkSource` is present). */
  fork: boolean;
}

export interface AzureIteration {
  id: number;
  /** Lower-case commit ids. */
  sourceRefCommit: string;
  commonRefCommit: string;
  targetRefCommit: string;
}

export interface AzureChange {
  /** Without the leading `/`. */
  path: string;
  originalPath: string | null;
  changeType: string;
  changeTrackingId: number;
}

export interface AzureThreadComment {
  id: number;
  /** '' for a deleted comment, which Azure DevOps may send without an author. */
  authorId: string;
  /** The author's `displayName`; '' when there is none. */
  authorName: string;
  content: string;
  /** `text`, `system`, `codeChange`. */
  commentType: string;
  /** The comment this one answers; 0 for a thread's first. */
  parentCommentId: number;
  /** As Azure DevOps wrote it (ISO 8601, 3 or 7 fraction digits); '' when absent. */
  publishedDate: string;
  isDeleted: boolean;
}

export interface AzureThread {
  id: number;
  /** `active`, `fixed`, `closed` ...; null for a system thread, which has none. */
  status: string | null;
  /** Without the leading `/`, as {@link AzureChange.path}. */
  filePath: string | null;
  rightLine: number | null;
  /** When the thread was created, as Azure DevOps wrote it; '' when absent. */
  publishedDate: string;
  comments: AzureThreadComment[];
}

/** Whether two identity ids name one identity: Azure DevOps writes a GUID in either case. */
export const sameAzureIdentity = (a: string, b: string): boolean =>
  a.toLowerCase() === b.toLowerCase();

/**
 * Whether a thread's status is an open one: `active`, or `pending` (Microsoft: "the issue in this
 * comment is under review and awaits something else"). Any other status (`fixed`, `wontFix`,
 * `closed`, `byDesign`) is resolved; a system thread has none and is neither.
 */
export const azureThreadOpen = (status: string | null): boolean =>
  status === 'active' || status === 'pending';

/** Comments Azure DevOps writes itself (a push, a changed file) are nobody's reply. */
export const machineMadeComment = (commentType: string): boolean =>
  commentType === 'system' || commentType === 'codeChange';

/** A service hook subscription, as far as Qualor reads it. */
export interface AzureSubscription {
  id: string;
  /** `enabled`, `onProbation`, `disabledByUser`, `disabledBySystem`, `disabledByInactiveIdentity`. */
  status: string;
  eventType: string;
  resourceVersion: string;
  projectId: string;
  /** The webhook address the subscription delivers to (`consumerInputs.url`). */
  url: string;
}

export interface NewAzureSubscription {
  eventType: string;
  /** The event's newest released version, from {@link AzureDevOpsClient.hookEventTypes}. */
  resourceVersion: string;
  projectId: string;
  /** Narrows the deliveries to this repository (`publisherInputs.repository`); none: the whole project. */
  repositoryId?: string;
  /** A ref name filter (`publisherInputs.branch`); none: every branch. */
  branch?: string;
  url: string;
  /** The Basic password Azure DevOps sends with every delivery (https only). */
  password: string;
}

/** Whole lines of the right side: from the start of `startLine` to the end of `endLine` (item 23). */
export interface AzureThreadAnchor {
  /** Without the leading `/`. */
  filePath: string;
  startLine: number;
  endLine: number;
  /** The length of line `endLine`: the selection ends just after it. */
  endLineLength: number;
}

export interface NewAzureThread {
  content: string;
  status: 'active' | 'closed';
  /** None: a thread on the pull request as a whole. */
  anchor?: AzureThreadAnchor;
}

export interface NewAzurePullRequest {
  /** Branch names, without `refs/heads/`. */
  sourceBranch: string;
  targetBranch: string;
  title: string;
  description: string;
}

export interface AzurePushInput {
  /** A full ref name: `refs/heads/<branch>` or a temporary `refs/qualor/fix-tmp/<id>`. */
  ref: string;
  /** The ref's head the push expects; null for a ref that does not exist yet. */
  oldObjectId: string | null;
  parent: string;
  message: string;
  /** Files to add or edit; `path` without the leading `/`. `change` is `edit` unless said. */
  files: readonly { path: string; content: string; change?: 'add' | 'edit' }[];
}

/** A queue of a project: an agent pool as the project uses it. */
export interface AzureQueue {
  id: number;
  name: string;
  poolName: string;
}

/** What may run on a queue: every pipeline (`open`) or the ones named. */
export interface AzureQueuePermissions {
  open: boolean;
  pipelineIds: number[];
}

/** The variable the pipeline's secret lives in. */
export const AZURE_SECRET_VARIABLE = 'QUALOR_TOKEN';
/** The Build policy type (the same id on Services and Server; probe items 7 and 26). */
export const AZURE_BUILD_POLICY_TYPE = '0609b952-1397-4640-95ec-e00a01b2c241';

export interface AzureDefinitionVariable {
  value: string;
  /** A secret's value is cut from every error text and never read back. */
  isSecret?: boolean;
}

export interface NewAzureDefinition {
  name: string;
  /** The YAML file in the repository, without the leading `/`. */
  yamlPath: string;
  repositoryId: string;
  repositoryName: string;
  /** The branch the definition reads the file from (`refs/heads/<name>`). */
  defaultBranch: string;
  queueId: number;
  variables: Readonly<Record<string, AzureDefinitionVariable>>;
}

/** A Build definition (a pipeline) as Qualor reads it; `secretSet`: the secret variable exists. */
export interface AzureDefinition {
  id: number;
  name: string;
  yamlPath: string | null;
  repositoryId: string;
  queueId: number | null;
  webUrl: string | null;
  secretSet: boolean;
  /** `authoredBy.id`: the identity that wrote the definition; null when Azure DevOps names none. */
  authoredBy: string | null;
}

export interface AzureBuildPolicy {
  id: number;
  definitionId: number;
  isBlocking: boolean;
  isEnabled: boolean;
}

export interface NewAzureBuildPolicy {
  definitionId: number;
  repositoryId: string;
  /** A full ref name: `refs/heads/<branch>`. */
  refName: string;
}

export type AzureStatus = {
  iterationId: number;
  /** `notSet` only when read: Azure DevOps omits `state` of a status that has none (probe item 19). */
  state: 'succeeded' | 'failed' | 'error' | 'pending' | 'notSet';
  description: string;
  targetUrl: string | null;
  genre: 'qualor';
  name: string;
};

/** A file {@link AzureDevOpsClient.fileText} did not read, and why. */
export type AzureFileSkipped = 'too_large' | 'binary' | 'missing';

/** A project of the organisation or collection; `id` is its GUID, lower case. */
export interface AzureProject {
  id: string;
  name: string;
}

/**
 * A work item type as `workitemtypes` lists it: the name a create takes, the reference name that
 * survives a rename, the states with Azure DevOps' category (`Proposed`, `InProgress`, `Resolved`,
 * `Completed`, `Removed`; empty when it names none) and every field with whether it is always
 * required and has a default.
 */
export interface AzureWorkItemType {
  name: string;
  referenceName: string;
  states: { name: string; category: string }[];
  fields: { referenceName: string; alwaysRequired: boolean; hasDefault: boolean }[];
}

/**
 * A work item as Qualor reads it: a field Azure DevOps did not send is null. `tags` are split on
 * `;` in the order Azure DevOps keeps them (it reorders them). `url` is the REST URL it answered.
 */
export interface AzureWorkItem {
  id: number;
  rev: number;
  state: string | null;
  typeName: string | null;
  projectName: string | null;
  tags: string[];
  description: string | null;
  url: string;
}

/** One JSON Patch operation of a work item write (`/fields/<reference name>`, `/relations/-`, `/rev`). */
export interface AzureJsonPatch {
  op: 'add' | 'replace' | 'test';
  path: string;
  value: unknown;
}

type AzureMethod = 'GET' | 'POST' | 'PUT' | 'PATCH';
/** What one call may ask differently from the rest. */
interface AzureCallOptions {
  /** This call's answer limit; default {@link MAX_AZURE_RESPONSE_BYTES}. */
  maxBytes?: number;
  /** The answer is the file's bytes, not JSON: the schema reads a Buffer. */
  raw?: true;
  /** The body's content type; default `application/json`. */
  contentType?: typeof AZURE_JSON_PATCH;
  /** Reads a success's headers (a paging token) before the body is parsed. */
  onHeaders?: (headers: IncomingHttpHeaders) => void;
}
const ZERO_OBJECT_ID = '0'.repeat(40);
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
/** A pull request's changes come in pages of this many. */
const CHANGES_PAGE = 100;
/** The file size `fileText` reads by default. */
export const AZURE_FILE_MAX_BYTES = 1024 * 1024;
/** Thread status as the REST body takes it. */
const THREAD_STATUS = { active: 1, fixed: 2, closed: 4 } as const;
const STATUS_STATES: readonly string[] = ['succeeded', 'failed', 'error', 'pending', 'notSet'];
const COMMIT_ID = /^[0-9a-f]{40,64}$/i;
/** The Git Repositories security namespace (A §10); contribute is bit 4 of its `effectiveAllow`. */
const GIT_NAMESPACE = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87';
const CONTRIBUTE = 4;
/** The user name of a subscription's Basic credential; the password is the connection's secret. */
const HOOK_USER = 'qualor';

// ─── Response shapes (the fields Qualor reads; server/test/azure-shapes/ holds recorded ones) ──

const connectionData = z.looseObject({
  authenticatedUser: z.looseObject({
    id: z.string().min(1),
    providerDisplayName: z.string().min(1),
  }),
});
const repository = z.looseObject({
  id: z.string().regex(AZURE_REPOSITORY_ID),
  name: z.string().min(1),
  project: z.looseObject({ id: z.string().regex(AZURE_REPOSITORY_ID), name: z.string().min(1) }),
  webUrl: z.string().min(1),
  defaultBranch: z.string().nullish(),
  isDisabled: z.boolean().nullish(),
});
const repositoryList = z.looseObject({ value: z.array(repository) });
/** WrappedException, the error body (probe item 10). */
const errorBody = z.looseObject({ message: z.string() });
/** An exception's type name, as Azure DevOps' error body keys it (`DefinitionExistsException`). */
const errorTypeKey = z.looseObject({ typeKey: z.string().regex(/^[A-Za-z][A-Za-z0-9_.]{0,199}$/) });

const commitRef = z.looseObject({ commitId: z.string().min(1) });
const pullRequestAnswer = z.looseObject({
  status: z.enum(['active', 'completed', 'abandoned']),
  isDraft: z.boolean().nullish(),
  title: z.string(),
  sourceRefName: z.string(),
  targetRefName: z.string(),
  mergeStatus: z.string().nullish(),
  forkSource: z.unknown().optional(),
  lastMergeSourceCommit: commitRef.nullish(),
  repository: z.looseObject({
    id: z.string().regex(AZURE_REPOSITORY_ID),
    webUrl: z.string().min(1),
  }),
});
const pullRequestWithId = pullRequestAnswer.extend({ pullRequestId: z.number().int() });
/** A listed pull request's repository is minimal: no `webUrl` (item 22g). */
const pullRequestListed = pullRequestAnswer.extend({
  pullRequestId: z.number().int(),
  repository: z.looseObject({
    id: z.string().regex(AZURE_REPOSITORY_ID),
    webUrl: z.string().min(1).optional(),
  }),
});
const pullRequestList = z.looseObject({ value: z.array(pullRequestListed) });
/** `refs?filter=`: a prefix match, so the caller picks the exact name. */
const refList = z.looseObject({
  value: z.array(z.looseObject({ name: z.string(), objectId: z.string().regex(COMMIT_ID) })),
});
const commitsDiff = z.looseObject({ commonCommit: z.string().regex(COMMIT_ID).nullish() });
const pushAnswer = z.looseObject({ commits: z.array(commitRef).min(1) });
const refUpdates = z.looseObject({
  value: z.array(z.looseObject({ success: z.boolean(), updateStatus: z.string() })).min(1),
});
const queueList = z.looseObject({
  value: z.array(
    z.looseObject({
      id: z.number().int(),
      name: z.string().min(1),
      pool: z.looseObject({ name: z.string().min(1) }),
    }),
  ),
});
const queuePermissions = z.looseObject({
  allPipelines: z.looseObject({ authorized: z.boolean().nullish() }).nullish(),
  pipelines: z
    .array(z.looseObject({ id: z.number().int(), authorized: z.boolean().nullish() }))
    .nullish(),
});
const definitionAnswer = z.looseObject({
  id: z.number().int(),
  name: z.string().min(1),
  process: z.looseObject({ yamlFilename: z.string().nullish() }).nullish(),
  repository: z.looseObject({ id: z.string().regex(AZURE_REPOSITORY_ID) }),
  queue: z.looseObject({ id: z.number().int() }).nullish(),
  variables: z
    .record(z.string(), z.looseObject({ isSecret: z.boolean().nullish() }).nullable())
    .nullish(),
  _links: z.looseObject({ web: z.looseObject({ href: z.string().min(1) }).nullish() }).nullish(),
  authoredBy: z.looseObject({ id: z.string().min(1).nullish() }).nullish(),
});
const definitionList = z.looseObject({ value: z.array(definitionAnswer) });
const policyAnswer = z.looseObject({
  id: z.number().int(),
  isBlocking: z.boolean(),
  isEnabled: z.boolean(),
  settings: z.looseObject({ buildDefinitionId: z.number().int().nullish() }),
});
const policyList = z.looseObject({ value: z.array(policyAnswer) });
const itemList = z.looseObject({
  value: z.array(z.looseObject({ path: z.string().min(1), isFolder: z.boolean().nullish() })),
});
const rawBytes = z.instanceof(Buffer);
const iterationList = z.looseObject({
  value: z.array(
    z.looseObject({
      id: z.number().int(),
      sourceRefCommit: commitRef,
      commonRefCommit: commitRef,
      targetRefCommit: commitRef,
    }),
  ),
});
const changesAnswer = z.looseObject({
  changeEntries: z.array(
    z.looseObject({
      changeTrackingId: z.number().int(),
      changeType: z.string(),
      item: z.looseObject({ path: z.string().min(1) }),
      originalPath: z.string().nullish(),
    }),
  ),
  nextSkip: z.number().int().nullish(),
});
const itemAnswer = z.looseObject({
  content: z.string().nullish(),
  contentMetadata: z.looseObject({ isBinary: z.boolean().nullish() }).nullish(),
});
const threadAnswer = z.looseObject({
  id: z.number().int(),
  status: z.string().nullish(),
  publishedDate: z.string().nullish(),
  threadContext: z
    .looseObject({
      filePath: z.string().nullish(),
      rightFileStart: z.looseObject({ line: z.number().int() }).nullish(),
    })
    .nullish(),
  comments: z
    .array(
      z.looseObject({
        id: z.number().int(),
        // A deleted comment may come without its author.
        author: z
          .looseObject({ id: z.string().nullish(), displayName: z.string().nullish() })
          .nullish(),
        content: z.string().nullish(),
        commentType: z.string().nullish(),
        parentCommentId: z.number().int().nullish(),
        publishedDate: z.string().nullish(),
        isDeleted: z.boolean().nullish(),
      }),
    )
    .nullish(),
});
const threadList = z.looseObject({ value: z.array(threadAnswer) });
const createdComment = z.looseObject({ id: z.number().int() });
const identityList = z.looseObject({
  // The identity service may answer an id it does not know with a positional null.
  value: z.array(z.looseObject({ descriptor: z.string().nullish() }).nullable()),
});
const aclList = z.looseObject({
  value: z.array(
    z.looseObject({
      acesDictionary: z
        .record(
          z.string(),
          z.looseObject({
            descriptor: z.string().nullish(),
            extendedInfo: z.looseObject({ effectiveAllow: z.number().int().nullish() }).nullish(),
          }),
        )
        .nullish(),
    }),
  ),
});
const eventTypeList = z.looseObject({
  value: z.array(
    z.looseObject({
      id: z.string().min(1),
      supportedResourceVersions: z.array(z.string()).nullish(),
    }),
  ),
});
const subscriptionAnswer = z.looseObject({
  id: z.string().min(1),
  status: z.string().min(1),
  eventType: z.string().min(1),
  resourceVersion: z.string().min(1),
  publisherInputs: z.looseObject({ projectId: z.string().nullish() }).nullish(),
  consumerInputs: z.looseObject({ url: z.string().nullish() }).nullish(),
});
const subscriptionList = z.looseObject({ value: z.array(subscriptionAnswer) });
const createdThread = z.looseObject({
  id: z.number().int(),
  comments: z.array(z.looseObject({ id: z.number().int() })).min(1),
});
/** A status of Qualor's genre: what the decoration reads of it. Others are not validated. */
const qualorStatus = z.looseObject({
  id: z.number().int(),
  iterationId: z.number().int().nullish(),
  // Absent while the state is the default, notSet: statuses of other tools come so (probe item 19).
  state: z.string().nullish(),
  description: z.string().nullish(),
  targetUrl: z.string().nullish(),
  context: z.looseObject({ genre: z.string().nullish(), name: z.string() }),
  createdBy: z.looseObject({ id: z.string() }).nullish(),
});
/** The list is read leniently: a status of another tool may lack an id or a context name. */
const statusList = z.looseObject({
  value: z.array(z.looseObject({ context: z.looseObject({ genre: z.unknown() }).nullish() })),
});

// Azure Boards (sub-plan 8; probe items 13 and 30).
const projectList = z.looseObject({
  value: z.array(
    z.looseObject({ id: z.string().regex(AZURE_REPOSITORY_ID), name: z.string().min(1) }),
  ),
});
const workItemTypeList = z.looseObject({
  value: z.array(
    z.looseObject({
      name: z.string().min(1),
      referenceName: z.string().min(1),
      states: z
        .array(z.looseObject({ name: z.string().min(1), category: z.string().nullish() }))
        .nullish(),
      fields: z
        .array(
          z.looseObject({
            referenceName: z.string().min(1),
            alwaysRequired: z.boolean().nullish(),
            defaultValue: z.unknown(),
          }),
        )
        .nullish(),
    }),
  ),
});
/** The categories list type names only, no reference names (probe item 30b). */
const workItemTypeCategoryList = z.looseObject({
  value: z.array(
    z.looseObject({
      referenceName: z.string().min(1),
      workItemTypes: z.array(z.looseObject({ name: z.string().min(1) })).nullish(),
    }),
  ),
});
interface ClassificationNodeAnswer {
  path: string;
  children?: ClassificationNodeAnswer[] | null | undefined;
}
/** `children` only when the node has some (probe item 30a). */
const classificationNode: z.ZodType<ClassificationNodeAnswer> = z.lazy(() =>
  z.looseObject({ path: z.string().min(1), children: z.array(classificationNode).nullish() }),
);
const workItemAnswer = z.looseObject({
  id: z.number().int().positive(),
  rev: z.number().int(),
  fields: z
    .looseObject({
      'System.State': z.string().nullish(),
      'System.WorkItemType': z.string().nullish(),
      'System.TeamProject': z.string().nullish(),
      'System.Tags': z.string().nullish(),
      'System.Description': z.string().nullish(),
    })
    .nullish(),
  url: z.string().min(1),
});
/** A `validateOnly` create answers the fields it would store: no id, rev or relations (30d). */
const validatedWorkItem = z.looseObject({ fields: z.record(z.string(), z.unknown()) });
const wiqlAnswer = z.looseObject({
  workItems: z.array(z.looseObject({ id: z.number().int().positive() })),
});
/** With `errorPolicy: 'omit'` a missing id is left out (30g); Microsoft documents a null entry. */
const workItemBatch = z.looseObject({ value: z.array(workItemAnswer.nullable()) });

/** For tests against the recorded shapes. */
export const AZURE_SHAPES = {
  connectionData,
  repository,
  repositoryList,
  pullRequestWithId,
  pullRequestList,
  refList,
  commitsDiff,
  pushAnswer,
  refUpdates,
  queueList,
  queuePermissions,
  definitionAnswer,
  definitionList,
  policyAnswer,
  policyList,
  itemList,
  projectList,
  workItemTypeList,
  workItemTypeCategoryList,
  classificationNode,
  workItemAnswer,
  validatedWorkItem,
  wiqlAnswer,
  workItemBatch,
} as const;

/** The name of the category whose types the picker leaves out (probe item 30b). */
const HIDDEN_CATEGORY = 'Microsoft.HiddenCategory';

/**
 * A classification node's `path` (`\<project>\Area\<child>`) in the form a create takes and stores
 * (`<project>\<child>`): the leading `\` and the `Area` or `Iteration` segment dropped (30a).
 */
export function azureFieldPath(nodePath: string): string {
  const [project = '', , ...rest] = nodePath.replace(/^\\/, '').split('\\');
  return [project, ...rest].join('\\');
}

function workItemOf(answer: z.infer<typeof workItemAnswer>): AzureWorkItem {
  const fields = answer.fields ?? {};
  return {
    id: answer.id,
    rev: answer.rev,
    state: fields['System.State'] ?? null,
    typeName: fields['System.WorkItemType'] ?? null,
    projectName: fields['System.TeamProject'] ?? null,
    tags: (fields['System.Tags'] ?? '')
      .split(';')
      .map((t) => t.trim())
      .filter((t) => t.length > 0),
    description: fields['System.Description'] ?? null,
    url: answer.url,
  };
}

/** A work item id as the REST paths and the `work_item_id` column take it. */
function checkWorkItemId(id: number): void {
  if (!Number.isInteger(id) || id <= 0 || id > 2_147_483_647) {
    throw new AzureError('refused', AZURE_TEXT.workItemId, { reason: 'invalid_input' });
  }
}

function definitionOf(d: z.infer<typeof definitionAnswer>): AzureDefinition {
  return {
    id: d.id,
    name: d.name,
    yamlPath: d.process?.yamlFilename ?? null,
    repositoryId: d.repository.id.toLowerCase(),
    queueId: d.queue?.id ?? null,
    webUrl: d._links?.web?.href ?? null,
    secretSet: d.variables?.[AZURE_SECRET_VARIABLE]?.isSecret === true,
    authoredBy: d.authoredBy?.id ?? null,
  };
}

/**
 * The pipeline's CI trigger: `settingsSourceType` 2 makes the YAML file's own `trigger:` block
 * decide which pushes run it. A definition created without a trigger does not run on a push (the
 * probe items queued every build by hand), so a merged setup would never analyse main.
 */
export const AZURE_YAML_CI_TRIGGER = {
  triggerType: 'continuousIntegration',
  settingsSourceType: 2,
  branchFilters: [],
  pathFilters: [],
  batchChanges: false,
  maxConcurrentBuildsPerBranch: 1,
} as const;

/** Variables as a definition body takes them: a secret is flagged, none may be overridden by a run. */
function variablesBody(
  variables: Readonly<Record<string, AzureDefinitionVariable>>,
): Record<string, Record<string, unknown>> {
  return Object.fromEntries(
    Object.entries(variables).map(([name, v]) => [
      name,
      { value: v.value, ...(v.isSecret ? { isSecret: true } : {}), allowOverride: false },
    ]),
  );
}

/** The secret values of `variables`: cut from an error text that echoes them. */
function secretValues(variables: Readonly<Record<string, AzureDefinitionVariable>>): string[] {
  return Object.values(variables)
    .filter((v) => v.isSecret)
    .map((v) => v.value);
}

function threadOf(t: z.infer<typeof threadAnswer>): AzureThread {
  return {
    id: t.id,
    status: t.status ?? null,
    filePath: t.threadContext?.filePath ? t.threadContext.filePath.replace(/^\//, '') : null,
    rightLine: t.threadContext?.rightFileStart?.line ?? null,
    publishedDate: t.publishedDate ?? '',
    comments: (t.comments ?? []).map((c) => ({
      id: c.id,
      authorId: c.author?.id ?? '',
      authorName: c.author?.displayName ?? '',
      content: c.content ?? '',
      commentType: c.commentType ?? 'text',
      parentCommentId: c.parentCommentId ?? 0,
      publishedDate: c.publishedDate ?? '',
      isDeleted: c.isDeleted ?? false,
    })),
  };
}

function subscriptionOf(s: z.infer<typeof subscriptionAnswer>): AzureSubscription {
  return {
    id: s.id,
    status: s.status,
    eventType: s.eventType,
    resourceVersion: s.resourceVersion,
    projectId: s.publisherInputs?.projectId ?? '',
    url: s.consumerInputs?.url ?? '',
  };
}

function repositoryOf(answer: z.infer<typeof repository>): AzureRepository {
  return {
    id: answer.id.toLowerCase(),
    name: answer.name,
    projectId: answer.project.id.toLowerCase(),
    projectName: answer.project.name,
    webUrl: answer.webUrl,
    defaultBranch: answer.defaultBranch ? answer.defaultBranch.replace(/^refs\/heads\//, '') : null,
    isDisabled: answer.isDisabled ?? false,
  };
}

function pullRequestOf(
  answer: Pick<
    z.infer<typeof pullRequestAnswer>,
    | 'status'
    | 'isDraft'
    | 'title'
    | 'sourceRefName'
    | 'targetRefName'
    | 'mergeStatus'
    | 'forkSource'
    | 'lastMergeSourceCommit'
  >,
  id: number,
  repository: { id: string; webUrl: string },
): AzurePullRequest {
  return {
    id,
    status: answer.status,
    isDraft: answer.isDraft ?? false,
    title: answer.title,
    sourceRefName: answer.sourceRefName,
    targetRefName: answer.targetRefName,
    headSha: answer.lastMergeSourceCommit?.commitId ?? null,
    webUrl: azurePullRequestWebUrl(repository.webUrl, id),
    mergeStatus: answer.mergeStatus ?? null,
    repositoryId: repository.id.toLowerCase(),
    fork: answer.forkSource !== undefined && answer.forkSource !== null,
  };
}

/** The update statuses that say the identity lacks a right of the repository. */
const REF_RIGHT_MISSING = new Set([
  'createBranchPermissionRequired',
  'createTagPermissionRequired',
  'forcePushRequired',
  'writePermissionRequired',
  'manageNotePermissionRequired',
]);

/**
 * A ref update that did not succeed: a stale old id, a missing right (an auth failure, as a 403
 * is), or a refusal by policy.
 */
function throwRefRefused(updateStatus: string | undefined): never {
  if (updateStatus === 'staleOldObjectId') {
    throw new AzureError('refused', AZURE_TEXT.refStale, { status: 409, reason: 'stale' });
  }
  if (updateStatus !== undefined && REF_RIGHT_MISSING.has(updateStatus)) {
    throw new AzureError('auth', AZURE_TEXT.rightMissing, {
      status: 403,
      reason: 'permission_missing',
      azureMessage: updateStatus,
    });
  }
  // The update status is Azure DevOps' own word: kept for decisions only, never shown.
  throw new AzureError('refused', AZURE_TEXT.refRefused, {
    status: 403,
    azureMessage: updateStatus ?? null,
  });
}

/** A request as a fixed text for the logs: each GUID Qualor put in the path is `{id}`. */
export function azureRoute(method: string, path: string): string {
  return `${method} ${path.replace(/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/g, '{id}')}`;
}

function transportError(failed: OutboundFailed): AzureError {
  switch (failed.cause) {
    case 'not_public':
      return new AzureError('refused', AZURE_TEXT.notPublic, { reason: 'not_public' });
    case 'refused_address':
      return new AzureError('refused', AZURE_TEXT.refusedAddress, { reason: 'not_public' });
    case 'unresolved':
      return new AzureError('transient', AZURE_TEXT.unresolved, { reason: 'unresolved' });
    case 'too_large':
      return new AzureError('bad_answer', AZURE_TEXT.badAnswer);
    case 'timeout':
    case 'connect_timeout':
      return new AzureError('transient', AZURE_TEXT.timeout, { reason: 'timeout' });
    default:
      return new AzureError(
        'transient',
        failed.code
          ? `Azure DevOps could not be reached (${failed.code})`
          : 'Azure DevOps could not be reached',
        { reason: 'unreachable' },
      );
  }
}

/** The body's text without a leading byte order mark (Server writes one before JSON). */
function textOf(body: Buffer): string {
  const text = body.toString('utf8');
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Azure DevOps' error `message` (the credential cut out) and `typeKey` (a type name only), for
 * decisions only.
 */
function azureErrorOf(
  body: Buffer,
  secrets: string[],
): { azureMessage: string | null; azureTypeKey: string | null } {
  let json: unknown;
  try {
    json = JSON.parse(textOf(body));
  } catch {
    return { azureMessage: null, azureTypeKey: null };
  }
  const parsed = errorBody.safeParse(json);
  let azureMessage: string | null = null;
  if (parsed.success) {
    let text = parsed.data.message;
    for (const secret of secrets) if (secret) text = text.split(secret).join('[credential]');
    azureMessage = text.slice(0, 1_000);
  }
  const typed = errorTypeKey.safeParse(json);
  return { azureMessage, azureTypeKey: typed.success ? typed.data.typeKey : null };
}

/** Milliseconds a success asks the next request to wait: `Retry-After`, else `X-RateLimit-Delay`. */
function paceOf(headers: IncomingHttpHeaders, nowMs: number): number {
  const retryAfter = headers['retry-after']?.trim() ?? '';
  const delay = headers['x-ratelimit-delay'];
  let ms = 0;
  if (/^\d{1,9}(\.\d+)?$/.test(retryAfter)) ms = Number(retryAfter) * 1000;
  else if (retryAfter !== '' && !Number.isNaN(Date.parse(retryAfter))) {
    ms = Date.parse(retryAfter) - nowMs;
  } else if (typeof delay === 'string' && /^\d{1,9}(\.\d+)?$/.test(delay.trim())) {
    ms = Number(delay.trim()) * 1000;
  }
  return Math.min(MAX_AZURE_PACE_MS, Math.max(0, Math.ceil(ms)));
}

/** Waits `ms`, or less when `signal` aborts (the next request then fails at once). */
function timer(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      clearTimeout(handle);
      signal?.removeEventListener('abort', done);
      resolve();
    };
    const handle = setTimeout(done, ms);
    signal?.addEventListener('abort', done, { once: true });
  });
}

/**
 * Azure DevOps REST (design §7.1, §7.9), through {@link outboundRequest}: the connection's base URL
 * only, the SSRF rules unless the host is listed in `QUALOR_SCM_INTERNAL_HOSTS`, 10 s per request,
 * answers up to 8 MiB, at most {@link MAX_AZURE_REQUESTS} requests per client (one client per job),
 * `api-version=7.0` unless a route names its own. No redirect is followed: any 3xx, and any 2xx
 * HTML page, is a sign-in page, so a refused credential. Nothing is retried; a success with
 * `Retry-After` or `X-RateLimit-Delay` makes the next request wait (at most 30 s). The credential
 * goes only into `Authorization`; no error, return value or log line carries it.
 */
export class AzureDevOpsClient {
  #requestCount = 0;
  /** Until when (ms since the epoch) the next request waits; 0: it does not. */
  #notBefore = 0;
  /** True private fields: the credential is no property a logger could print. */
  readonly #connection: AzureConnectionInput;
  readonly #options: AzureClientOptions;

  constructor(connection: AzureConnectionInput, options: AzureClientOptions = {}) {
    this.#connection = connection;
    this.#options = options;
  }

  /**
   * Requests counted against the budget so far; one the outbound rules refused, or whose token
   * Entra refused, counts too.
   */
  get requestCount(): number {
    return this.#requestCount;
  }

  /** Requests the budget still allows. */
  get remaining(): number {
    return Math.max(0, (this.#options.maxRequests ?? MAX_AZURE_REQUESTS) - this.#requestCount);
  }

  async connectionData(): Promise<AzureIdentity> {
    const answer = await this.#get(
      '/_apis/connectionData',
      connectionData,
      CONNECTION_DATA_API_VERSION,
    );
    const { id, providerDisplayName } = answer.authenticatedUser;
    return { id, displayName: providerDisplayName };
  }

  /** Every repository of the organisation or collection, with its project (design §7.2). */
  async repositories(): Promise<AzureRepository[]> {
    const answer = await this.#get('/_apis/git/repositories', repositoryList);
    return answer.value.map(repositoryOf);
  }

  async repository(id: string): Promise<AzureRepository> {
    if (!AZURE_REPOSITORY_ID.test(id)) {
      throw new AzureError('refused', AZURE_TEXT.repositoryId, { reason: 'invalid_input' });
    }
    return repositoryOf(await this.#get(`/_apis/git/repositories/${id.toLowerCase()}`, repository));
  }

  /** `/_apis/git/repositories/<id>`: the id checked and lower-cased, so no path can be injected. */
  #repositoryPath(id: string): string {
    if (!AZURE_REPOSITORY_ID.test(id)) {
      throw new AzureError('refused', AZURE_TEXT.repositoryId, { reason: 'invalid_input' });
    }
    return `/_apis/git/repositories/${id.toLowerCase()}`;
  }

  #pullRequestPath(repositoryId: string, prId: number): string {
    return `${this.#repositoryPath(repositoryId)}/pullrequests/${prId}`;
  }

  async pullRequest(repositoryId: string, id: number): Promise<AzurePullRequest> {
    const answer = await this.#get(this.#pullRequestPath(repositoryId, id), pullRequestAnswer);
    return pullRequestOf(answer, id, answer.repository);
  }

  /** The active pull requests from `sourceBranch` into `targetBranch` (names without `refs/heads/`). */
  async pullRequestsFrom(
    repositoryId: string,
    sourceBranch: string,
    targetBranch: string,
  ): Promise<AzurePullRequest[]> {
    const query = new URLSearchParams({
      'searchCriteria.sourceRefName': `refs/heads/${sourceBranch}`,
      'searchCriteria.targetRefName': `refs/heads/${targetBranch}`,
      'searchCriteria.status': 'active',
    });
    const answer = await this.#get(
      `${this.#repositoryPath(repositoryId)}/pullrequests?${query}`,
      pullRequestList,
    );
    if (answer.value.length === 0) return [];
    // The listed repository has no web URL: one read of the repository gives it.
    const webUrl =
      answer.value.find((p) => p.repository.webUrl)?.repository.webUrl ??
      (await this.repository(repositoryId)).webUrl;
    return answer.value.map((p) =>
      pullRequestOf(p, p.pullRequestId, { id: p.repository.id, webUrl }),
    );
  }

  async createPullRequest(
    repositoryId: string,
    input: NewAzurePullRequest,
  ): Promise<AzurePullRequest> {
    const answer = await this.#call(
      'POST',
      `${this.#repositoryPath(repositoryId)}/pullrequests`,
      pullRequestWithId,
      {
        sourceRefName: `refs/heads/${input.sourceBranch}`,
        targetRefName: `refs/heads/${input.targetBranch}`,
        title: input.title,
        description: input.description,
      },
    );
    return pullRequestOf(answer, answer.pullRequestId, answer.repository);
  }

  async updatePullRequest(
    repositoryId: string,
    id: number,
    patch: { title?: string; description?: string; status?: 'abandoned' },
  ): Promise<void> {
    await this.#call('PATCH', this.#pullRequestPath(repositoryId, id), z.unknown(), patch);
  }

  /** The head of branch `name` (without `refs/heads/`), lower-case; null when there is none. */
  async branchHead(repositoryId: string, name: string): Promise<string | null> {
    const filter = encodeURIComponent(`heads/${name}`);
    const answer = await this.#get(
      `${this.#repositoryPath(repositoryId)}/refs?filter=${filter}`,
      refList,
    );
    // The filter is a prefix match: `a` also finds `a-2`.
    const exact = answer.value.find((r) => r.name === `refs/heads/${name}`);
    return exact ? exact.objectId.toLowerCase() : null;
  }

  /** The commit `base` and `target` (commit ids) have in common; null when Azure DevOps names none. */
  async commonCommit(repositoryId: string, base: string, target: string): Promise<string | null> {
    const query = new URLSearchParams({
      baseVersion: base,
      baseVersionType: 'commit',
      targetVersion: target,
      targetVersionType: 'commit',
      $top: '1',
    });
    const answer = await this.#get(
      `${this.#repositoryPath(repositoryId)}/diffs/commits?${query}`,
      commitsDiff,
    );
    return answer.commonCommit?.toLowerCase() ?? null;
  }

  /**
   * One commit on `ref` that adds or edits `files` (sent as base64) on top of `parent`; its id. A 400 is the
   * usual `refused` error: a stale head and a parent that is not the head look alike (item 22e).
   */
  async push(repositoryId: string, input: AzurePushInput): Promise<string> {
    const answer = await this.#call(
      'POST',
      `${this.#repositoryPath(repositoryId)}/pushes`,
      pushAnswer,
      {
        refUpdates: [{ name: input.ref, oldObjectId: input.oldObjectId ?? ZERO_OBJECT_ID }],
        commits: [
          {
            comment: input.message,
            parents: [input.parent],
            changes: input.files.map((f) => ({
              changeType: f.change ?? 'edit',
              item: { path: `/${f.path}` },
              newContent: {
                content: Buffer.from(f.content, 'utf8').toString('base64'),
                contentType: 'base64encoded',
              },
            })),
          },
        ],
      },
    );
    const commit = answer.commits.at(-1);
    if (!commit) throw new AzureError('bad_answer', AZURE_TEXT.badAnswer);
    return commit.commitId.toLowerCase();
  }

  /**
   * The entries of the repository root at a commit (one level): names without the leading `/`,
   * the root itself left out (Azure DevOps lists it as `/`; probe item 26).
   */
  async rootItems(
    repositoryId: string,
    commit: string,
  ): Promise<{ path: string; isFolder: boolean }[]> {
    if (!COMMIT_ID.test(commit)) {
      throw new AzureError('refused', AZURE_TEXT.commitId, { reason: 'invalid_input' });
    }
    const query = new URLSearchParams({
      scopePath: '/',
      recursionLevel: 'OneLevel',
      'versionDescriptor.version': commit.toLowerCase(),
      'versionDescriptor.versionType': 'commit',
    });
    const answer = await this.#get(
      `${this.#repositoryPath(repositoryId)}/items?${query}`,
      itemList,
    );
    return answer.value
      .filter((e) => e.path !== '/')
      .map((e) => ({ path: e.path.replace(/^\//, ''), isFolder: e.isFolder === true }));
  }

  /** `/{projectId}/_apis`: the id checked and lower-cased, so no path can be injected. */
  #projectPath(projectId: string): string {
    if (!AZURE_REPOSITORY_ID.test(projectId)) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    return `/${projectId.toLowerCase()}/_apis`;
  }

  /** The agent queues of a project, all or the one named `name` (a preview route). */
  async queues(projectId: string, name?: string): Promise<AzureQueue[]> {
    const query = name === undefined ? '' : `?${new URLSearchParams({ queueName: name })}`;
    const answer = await this.#get(
      `${this.#projectPath(projectId)}/distributedtask/queues${query}`,
      queueList,
      AZURE_PREVIEW_API_VERSION,
    );
    return answer.value.map((q) => ({ id: q.id, name: q.name, poolName: q.pool.name }));
  }

  /** Whether every pipeline may use the queue, and which pipelines are authorised one by one. */
  async queuePermissions(projectId: string, queueId: number): Promise<AzureQueuePermissions> {
    const answer = await this.#get(
      this.#queuePermissionsPath(projectId, queueId),
      queuePermissions,
      AZURE_PREVIEW_API_VERSION,
    );
    return {
      open: answer.allPipelines?.authorized === true,
      pipelineIds: (answer.pipelines ?? []).filter((p) => p.authorized !== false).map((p) => p.id),
    };
  }

  /** Authorises one pipeline on a queue; the other permissions are left as they are. */
  async authorizeOnQueue(projectId: string, queueId: number, definitionId: number): Promise<void> {
    await this.#call(
      'PATCH',
      this.#queuePermissionsPath(projectId, queueId),
      z.unknown(),
      { pipelines: [{ id: definitionId, authorized: true }] },
      AZURE_PREVIEW_API_VERSION,
    );
  }

  #queuePermissionsPath(projectId: string, queueId: number): string {
    if (!Number.isInteger(queueId) || queueId < 0) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    return `${this.#projectPath(projectId)}/pipelines/pipelinePermissions/queue/${queueId}`;
  }

  /** The Build definitions of a repository (YAML path, queue, variables read; secrets read as null). */
  async definitions(projectId: string, repositoryId: string): Promise<AzureDefinition[]> {
    this.#repositoryPath(repositoryId); // validates the id
    const query = new URLSearchParams({
      repositoryId: repositoryId.toLowerCase(),
      repositoryType: 'TfsGit',
      includeAllProperties: 'true',
    });
    const answer = await this.#get(
      `${this.#projectPath(projectId)}/build/definitions?${query}`,
      definitionList,
    );
    return answer.value.map(definitionOf);
  }

  /**
   * Creates the definition, then re-saves it unchanged (GET, PUT). A YAML pipeline made by the POST
   * does not run its CI trigger on pushes for the first 5 to 12 minutes; a PUT right after the
   * create switches it on at once (probe item 28, Azure DevOps Services), and a quick merge of the
   * setup PR must still be analysed. A manual run does not do it.
   *
   * The re-save is best effort: once the POST answered 2xx the pipeline exists and holds the
   * secret, so an error of the GET or PUT is never thrown (a caller would read a 4xx as "nothing
   * stored"). It is logged with its kind, status and route only, and the created definition is
   * returned; its trigger switches itself on within minutes (item 28 S2).
   */
  async createDefinition(
    projectId: string,
    input: NewAzureDefinition,
    logger?: AzureClientLogger,
  ): Promise<AzureDefinition> {
    this.#repositoryPath(input.repositoryId); // validates the id
    const created = await this.#call(
      'POST',
      `${this.#projectPath(projectId)}/build/definitions`,
      definitionAnswer,
      {
        name: input.name,
        path: '\\',
        type: 'build',
        queue: { id: input.queueId },
        process: { type: 2, yamlFilename: input.yamlPath },
        repository: {
          id: input.repositoryId.toLowerCase(),
          name: input.repositoryName,
          type: 'TfsGit',
          defaultBranch: input.defaultBranch,
        },
        variables: variablesBody(input.variables),
        triggers: [AZURE_YAML_CI_TRIGGER],
      },
      AZURE_API_VERSION,
      'base',
      secretValues(input.variables),
    );
    try {
      return await this.#resave(projectId, created.id);
    } catch (err) {
      const scm = err instanceof ScmError ? err : null;
      logger?.warn(
        { kind: scm?.kind ?? 'unknown', status: scm?.status ?? null, route: scm?.request ?? null },
        'could not re-save the new Azure DevOps pipeline; its CI trigger starts later',
      );
      return definitionOf(created);
    }
  }

  async definition(projectId: string, id: number): Promise<AzureDefinition> {
    return definitionOf(await this.#definitionBody(projectId, id));
  }

  async #definitionBody(projectId: string, id: number) {
    return this.#get(this.#definitionPath(projectId, id), definitionAnswer);
  }

  #definitionPath(projectId: string, id: number): string {
    if (!Number.isInteger(id) || id < 0) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    return `${this.#projectPath(projectId)}/build/definitions/${id}`;
  }

  /**
   * GET then PUT: the definition as Azure DevOps has it (unknown fields kept, its `triggers` too: a
   * PUT replaces the whole definition; a secret reads back `null` and survives the PUT) with
   * `variables` laid over its own.
   */
  async replaceDefinition(
    projectId: string,
    definition: Pick<AzureDefinition, 'id'>,
    variables: Readonly<Record<string, AzureDefinitionVariable>>,
  ): Promise<AzureDefinition> {
    const path = this.#definitionPath(projectId, definition.id);
    const current = await this.#get(path, definitionAnswer);
    const answer = await this.#call(
      'PUT',
      path,
      definitionAnswer,
      { ...current, variables: { ...current.variables, ...variablesBody(variables) } },
      AZURE_API_VERSION,
      'base',
      secretValues(variables),
    );
    return definitionOf(answer);
  }

  /** GET then PUT of the same body: the secret reads back `null` and survives. */
  async #resave(projectId: string, id: number): Promise<AzureDefinition> {
    const path = this.#definitionPath(projectId, id);
    const answer = await this.#call(
      'PUT',
      path,
      definitionAnswer,
      await this.#get(path, definitionAnswer),
      AZURE_API_VERSION,
    );
    return definitionOf(answer);
  }

  /** The Build policies on a branch of a repository (every policy of the Build type there). */
  async buildPolicies(
    projectId: string,
    repositoryId: string,
    refName: string,
  ): Promise<AzureBuildPolicy[]> {
    this.#repositoryPath(repositoryId); // validates the id
    const query = new URLSearchParams({
      repositoryId: repositoryId.toLowerCase(),
      refName,
      policyType: AZURE_BUILD_POLICY_TYPE,
    });
    const answer = await this.#get(
      `${this.#projectPath(projectId)}/policy/configurations?${query}`,
      policyList,
    );
    return answer.value.map((p) => ({
      id: p.id,
      definitionId: p.settings.buildDefinitionId ?? 0,
      isBlocking: p.isBlocking,
      isEnabled: p.isEnabled,
    }));
  }

  /** A Build validation policy that does not block, on the branch exactly. */
  async createBuildPolicy(projectId: string, input: NewAzureBuildPolicy): Promise<{ id: number }> {
    this.#repositoryPath(input.repositoryId); // validates the id
    const answer = await this.#call(
      'POST',
      `${this.#projectPath(projectId)}/policy/configurations`,
      policyAnswer,
      {
        isEnabled: true,
        isBlocking: false,
        type: { id: AZURE_BUILD_POLICY_TYPE },
        settings: {
          buildDefinitionId: input.definitionId,
          queueOnSourceUpdateOnly: false,
          manualQueueOnly: false,
          displayName: 'Qualor',
          validDuration: 0,
          scope: [
            {
              repositoryId: input.repositoryId.toLowerCase(),
              refName: input.refName,
              matchKind: 'exact',
            },
          ],
        },
      },
    );
    return { id: answer.id };
  }

  /** Moves `name` (a full ref name) to `newObjectId`; a non-fast-forward move is allowed (item 22d). */
  async updateRef(
    repositoryId: string,
    name: string,
    oldObjectId: string,
    newObjectId: string,
  ): Promise<void> {
    const answer = await this.#call(
      'POST',
      `${this.#repositoryPath(repositoryId)}/refs`,
      refUpdates,
      [{ name, oldObjectId, newObjectId }],
    );
    const [first] = answer.value;
    if (first?.success !== true) throwRefRefused(first?.updateStatus);
  }

  /** Deletes `name`; `succeededCorruptRef` is a delete too: the old id is not enforced (item 22j). */
  async deleteRef(repositoryId: string, name: string, oldObjectId: string): Promise<void> {
    await this.updateRef(repositoryId, name, oldObjectId, ZERO_OBJECT_ID);
  }

  /**
   * A file's bytes at a commit as UTF-8 text (`$format=octetStream`, byte-exact). One over `maxBytes`,
   * a binary one (a NUL byte, or not valid UTF-8) and a missing one are `skipped`. Only this call's
   * answer limit is `maxBytes`; every other call keeps 8 MiB.
   */
  async fileBytes(
    repositoryId: string,
    path: string,
    commit: string,
    maxBytes: number,
  ): Promise<{ text: string } | { skipped: AzureFileSkipped }> {
    const query = new URLSearchParams({
      path: `/${path}`,
      'versionDescriptor.version': commit,
      'versionDescriptor.versionType': 'commit',
      $format: 'octetStream',
    });
    let bytes: Buffer;
    try {
      bytes = await this.#call(
        'GET',
        `${this.#repositoryPath(repositoryId)}/items?${query}`,
        rawBytes,
        undefined,
        AZURE_API_VERSION,
        'base',
        [],
        { raw: true, maxBytes },
      );
    } catch (err) {
      if (err instanceof AzureError && err.kind === 'not_found') return { skipped: 'missing' };
      // Over the answer limit: the client's own bad_answer, without a status.
      if (err instanceof AzureError && err.kind === 'bad_answer' && err.status === null) {
        return { skipped: 'too_large' };
      }
      throw err;
    }
    if (bytes.length > maxBytes) return { skipped: 'too_large' };
    if (bytes.includes(0)) return { skipped: 'binary' };
    try {
      return { text: UTF8_STRICT.decode(bytes) };
    } catch {
      return { skipped: 'binary' };
    }
  }

  async iterations(repositoryId: string, prId: number): Promise<AzureIteration[]> {
    const answer = await this.#get(
      `${this.#pullRequestPath(repositoryId, prId)}/iterations`,
      iterationList,
    );
    return answer.value.map((i) => ({
      id: i.id,
      sourceRefCommit: i.sourceRefCommit.commitId.toLowerCase(),
      commonRefCommit: i.commonRefCommit.commitId.toLowerCase(),
      targetRefCommit: i.targetRefCommit.commitId.toLowerCase(),
    }));
  }

  /**
   * The files an iteration changed, in pages of 100 (`$top`, `$skip`); `complete` is false when
   * more than `maxPages` pages were needed and the rest was not read.
   */
  async iterationChanges(
    repositoryId: string,
    prId: number,
    iterationId: number,
    maxPages = 10,
  ): Promise<{ changes: AzureChange[]; complete: boolean }> {
    const base = `${this.#pullRequestPath(repositoryId, prId)}/iterations/${iterationId}/changes`;
    const changes: AzureChange[] = [];
    let skip = 0;
    for (let page = 0; page < maxPages; page++) {
      const answer = await this.#get(`${base}?$top=${CHANGES_PAGE}&$skip=${skip}`, changesAnswer);
      const entries = answer.changeEntries;
      for (const entry of entries) {
        changes.push({
          path: entry.item.path.replace(/^\//, ''),
          originalPath: entry.originalPath ? entry.originalPath.replace(/^\//, '') : null,
          changeType: entry.changeType,
          changeTrackingId: entry.changeTrackingId,
        });
      }
      const next = answer.nextSkip ?? (entries.length >= CHANGES_PAGE ? skip + entries.length : 0);
      if (next <= skip) return { changes, complete: true };
      skip = next;
    }
    return { changes, complete: false };
  }

  /**
   * A file's text at a commit. A binary file, one over `maxBytes` (or over the 8 MiB an answer may
   * have) and one that is not there are `skipped`, never thrown: they are no failure of the job.
   */
  async fileText(
    repositoryId: string,
    path: string,
    commit: string,
    maxBytes = AZURE_FILE_MAX_BYTES,
  ): Promise<{ text: string } | { skipped: AzureFileSkipped }> {
    const query = new URLSearchParams({
      path: `/${path}`,
      'versionDescriptor.version': commit,
      'versionDescriptor.versionType': 'commit',
      includeContent: 'true',
      $format: 'json',
    });
    let item: z.infer<typeof itemAnswer>;
    try {
      item = await this.#get(`${this.#repositoryPath(repositoryId)}/items?${query}`, itemAnswer);
    } catch (err) {
      if (err instanceof AzureError && err.kind === 'not_found') return { skipped: 'missing' };
      // Over the answer limit: the client's own bad_answer, without a status.
      if (err instanceof AzureError && err.kind === 'bad_answer' && err.status === null) {
        return { skipped: 'too_large' };
      }
      throw err;
    }
    const text = item.content;
    if (item.contentMetadata?.isBinary === true || text?.includes('\u0000')) {
      return { skipped: 'binary' };
    }
    if (text === undefined || text === null) return { skipped: 'missing' };
    return Buffer.byteLength(text) > maxBytes ? { skipped: 'too_large' } : { text };
  }

  /** Every thread, system threads (no status) included. */
  async threads(repositoryId: string, prId: number): Promise<AzureThread[]> {
    const answer = await this.#get(
      `${this.#pullRequestPath(repositoryId, prId)}/threads`,
      threadList,
    );
    return answer.value.map(threadOf);
  }

  /** One thread with its comments (dates, parents, authors' names). */
  async thread(repositoryId: string, prId: number, threadId: number): Promise<AzureThread> {
    return threadOf(
      await this.#get(
        `${this.#pullRequestPath(repositoryId, prId)}/threads/${threadId}`,
        threadAnswer,
      ),
    );
  }

  /**
   * A thread with one comment. With an `anchor` it sits on the right side of those whole lines and
   * carries no `pullRequestThreadContext` (probe items 5, 6 and 23).
   */
  async createThread(
    repositoryId: string,
    prId: number,
    thread: NewAzureThread,
  ): Promise<{ id: number; commentId: number }> {
    const { anchor } = thread;
    const threadContext = anchor
      ? {
          filePath: `/${anchor.filePath}`,
          rightFileStart: { line: anchor.startLine, offset: 1 },
          rightFileEnd: { line: anchor.endLine, offset: anchor.endLineLength + 1 },
        }
      : undefined;
    const answer = await this.#call(
      'POST',
      `${this.#pullRequestPath(repositoryId, prId)}/threads`,
      createdThread,
      {
        comments: [{ parentCommentId: 0, content: thread.content, commentType: 1 }],
        status: THREAD_STATUS[thread.status],
        ...(threadContext ? { threadContext } : {}),
      },
    );
    const [first] = answer.comments;
    if (!first) throw new AzureError('bad_answer', AZURE_TEXT.badAnswer);
    return { id: answer.id, commentId: first.id };
  }

  /** Only `status` is sent: Azure DevOps refuses a PATCH with `properties` (probe item 3). */
  async setThreadStatus(
    repositoryId: string,
    prId: number,
    threadId: number,
    status: 'active' | 'fixed',
  ): Promise<void> {
    await this.#call(
      'PATCH',
      `${this.#pullRequestPath(repositoryId, prId)}/threads/${threadId}`,
      z.unknown(),
      { status: THREAD_STATUS[status] },
    );
  }

  async addComment(
    repositoryId: string,
    prId: number,
    threadId: number,
    content: string,
  ): Promise<void> {
    await this.#call(
      'POST',
      `${this.#pullRequestPath(repositoryId, prId)}/threads/${threadId}/comments`,
      z.unknown(),
      { content, parentCommentId: 0, commentType: 1 },
    );
  }

  /** A comment that answers comment `parentCommentId` of the thread; the new comment's id. */
  async reply(
    repositoryId: string,
    prId: number,
    threadId: number,
    parentCommentId: number,
    content: string,
  ): Promise<number> {
    const answer = await this.#call(
      'POST',
      `${this.#pullRequestPath(repositoryId, prId)}/threads/${threadId}/comments`,
      createdComment,
      { content, parentCommentId, commentType: 1 },
    );
    return answer.id;
  }

  async editComment(
    repositoryId: string,
    prId: number,
    threadId: number,
    commentId: number,
    content: string,
  ): Promise<void> {
    await this.#call(
      'PATCH',
      `${this.#pullRequestPath(repositoryId, prId)}/threads/${threadId}/comments/${commentId}`,
      z.unknown(),
      { content },
    );
  }

  /** On an iteration: a status policy refuses one without (probe item 7). */
  async postPullRequestStatus(
    repositoryId: string,
    prId: number,
    status: AzureStatus,
  ): Promise<void> {
    await this.#call('POST', `${this.#pullRequestPath(repositoryId, prId)}/statuses`, z.unknown(), {
      iterationId: status.iterationId,
      state: status.state,
      description: status.description,
      ...(status.targetUrl === null ? {} : { targetUrl: status.targetUrl }),
      context: { genre: status.genre, name: status.name },
    });
  }

  /**
   * The statuses of Qualor's genre on an iteration, in the order Azure DevOps lists them (not to be
   * relied on): each carries its `id`, and the highest id of a context is the newest status, and
   * who posted it (`createdBy.id`, null when the answer names nobody).
   */
  async iterationStatuses(
    repositoryId: string,
    prId: number,
    iterationId: number,
  ): Promise<(AzureStatus & { id: number; authorId: string | null })[]> {
    const answer = await this.#get(
      `${this.#pullRequestPath(repositoryId, prId)}/iterations/${iterationId}/statuses`,
      statusList,
    );
    const ours: (AzureStatus & { id: number; authorId: string | null })[] = [];
    for (const entry of answer.value) {
      if (entry.context?.genre !== 'qualor') continue;
      const checked = qualorStatus.safeParse(entry);
      if (!checked.success) throw new AzureError('bad_answer', AZURE_TEXT.badAnswer);
      const s = checked.data;
      const state = s.state ?? 'notSet';
      if (!STATUS_STATES.includes(state)) continue;
      ours.push({
        id: s.id,
        iterationId: s.iterationId ?? iterationId,
        state: state as AzureStatus['state'],
        description: s.description ?? '',
        targetUrl: s.targetUrl ?? null,
        genre: 'qualor',
        name: s.context.name,
        authorId: s.createdBy?.id ?? null,
      });
    }
    return ours;
  }

  /** A status on a commit; it does not satisfy a status policy of the pull request. */
  async postCommitStatus(
    repositoryId: string,
    sha: string,
    status: Omit<AzureStatus, 'iterationId'>,
  ): Promise<void> {
    if (!COMMIT_ID.test(sha)) {
      throw new AzureError('refused', 'The commit id is not a commit id', {
        reason: 'invalid_input',
      });
    }
    await this.#call(
      'POST',
      `${this.#repositoryPath(repositoryId)}/commits/${sha.toLowerCase()}/statuses`,
      z.unknown(),
      {
        state: status.state,
        description: status.description,
        ...(status.targetUrl === null ? {} : { targetUrl: status.targetUrl }),
        context: { genre: status.genre, name: status.name },
      },
    );
  }

  /**
   * The identity descriptor (`Microsoft.IdentityModel.Claims.ClaimsIdentity;<tenant>\\<name>` and its
   * kin, the form the access control lists take) of an identity id, asked of the identities host
   * with this connection's credential; null when the answer holds no identity or no descriptor.
   */
  async identityDescriptor(identityId: string): Promise<string | null> {
    if (!AZURE_REPOSITORY_ID.test(identityId)) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    const answer = await this.#call(
      'GET',
      `/_apis/identities?identityIds=${identityId.toLowerCase()}`,
      identityList,
      undefined,
      AZURE_API_VERSION,
      'identities',
    );
    return answer.value[0]?.descriptor || null;
  }

  /**
   * Whether the identity may contribute to the repository (Git Repositories permission bit 4 of
   * `extendedInfo.effectiveAllow`, so group membership and inheritance are counted). False when
   * the list has no entry for the descriptor.
   */
  async contributeAllowed(
    projectId: string,
    repositoryId: string,
    descriptor: string,
  ): Promise<boolean> {
    if (!AZURE_REPOSITORY_ID.test(projectId)) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    this.#repositoryPath(repositoryId); // validates the id
    const query = new URLSearchParams({
      token: `repoV2/${projectId.toLowerCase()}/${repositoryId.toLowerCase()}`,
      descriptors: descriptor,
      includeExtendedInfo: 'true',
    });
    const answer = await this.#get(`/_apis/accesscontrollists/${GIT_NAMESPACE}?${query}`, aclList);
    const wanted = descriptor.toLowerCase();
    for (const acl of answer.value) {
      for (const [key, ace] of Object.entries(acl.acesDictionary ?? {})) {
        if (key.toLowerCase() !== wanted && (ace.descriptor ?? '').toLowerCase() !== wanted)
          continue;
        return ((ace.extendedInfo?.effectiveAllow ?? 0) & CONTRIBUTE) !== 0;
      }
    }
    return false;
  }

  /** The service hook event types of the `tfs` publisher with the resource versions each offers. */
  async hookEventTypes(): Promise<{ id: string; versions: string[] }[]> {
    const answer = await this.#get('/_apis/hooks/publishers/tfs/eventTypes', eventTypeList);
    return answer.value.map((e) => ({ id: e.id, versions: e.supportedResourceVersions ?? [] }));
  }

  /** The web hook subscriptions of the organisation or collection (any publisher filter is ours). */
  async subscriptions(): Promise<AzureSubscription[]> {
    const answer = await this.#get(
      '/_apis/hooks/subscriptions?publisherId=tfs&consumerId=webHooks&consumerActionId=httpRequest',
      subscriptionList,
    );
    return answer.value.map(subscriptionOf);
  }

  async createSubscription(input: NewAzureSubscription): Promise<AzureSubscription> {
    return subscriptionOf(
      await this.#call(
        'POST',
        '/_apis/hooks/subscriptions',
        subscriptionAnswer,
        this.#subscriptionBody(input),
        AZURE_API_VERSION,
        'base',
        [input.password],
      ),
    );
  }

  /** PUT: the subscription is rewritten (a changed address or version, or enabled again). */
  async replaceSubscription(id: string, input: NewAzureSubscription): Promise<AzureSubscription> {
    if (!AZURE_REPOSITORY_ID.test(id)) {
      throw new AzureError('refused', AZURE_TEXT.guid, { reason: 'invalid_input' });
    }
    return subscriptionOf(
      await this.#call(
        'PUT',
        `/_apis/hooks/subscriptions/${id.toLowerCase()}`,
        subscriptionAnswer,
        // `status` is sent: a PUT without it is not recorded to enable the subscription again.
        { ...this.#subscriptionBody(input), id: id.toLowerCase(), status: 'enabled' },
        AZURE_API_VERSION,
        'base',
        [input.password],
      ),
    );
  }

  #subscriptionBody(input: NewAzureSubscription): Record<string, unknown> {
    return {
      publisherId: 'tfs',
      eventType: input.eventType,
      resourceVersion: input.resourceVersion,
      consumerId: 'webHooks',
      consumerActionId: 'httpRequest',
      publisherInputs: {
        projectId: input.projectId,
        ...(input.repositoryId === undefined ? {} : { repository: input.repositoryId }),
        ...(input.branch === undefined ? {} : { branch: input.branch }),
      },
      consumerInputs: {
        url: input.url,
        basicAuthUsername: HOOK_USER,
        basicAuthPassword: input.password,
        resourceDetailsToSend: 'all',
        // Qualor reads the resource only; the texts Azure DevOps would compose are never sent.
        messagesToSend: 'none',
        detailedMessagesToSend: 'none',
      },
    };
  }

  // ─── Azure Boards (design §7.8; probe items 13 and 30): every work item path names the project GUID ──

  /**
   * The projects of the organisation or collection: pages of 100 that follow
   * `x-ms-continuationtoken` (a running offset) until it is absent or a page is empty, at most
   * {@link MAX_AZURE_PROJECTS} (probe item 30a).
   */
  async projects(): Promise<AzureProject[]> {
    const found: AzureProject[] = [];
    const page: { token: string | null } = { token: null };
    do {
      const after =
        page.token === null ? '' : `&continuationToken=${encodeURIComponent(page.token)}`;
      page.token = null;
      const answer = await this.#call(
        'GET',
        `/_apis/projects?$top=100${after}`,
        projectList,
        undefined,
        AZURE_API_VERSION,
        'base',
        [],
        {
          onHeaders: (headers) => {
            const token = [headers['x-ms-continuationtoken'] ?? []].flat()[0]?.trim();
            page.token = token ? token : null;
          },
        },
      );
      for (const p of answer.value) found.push({ id: p.id.toLowerCase(), name: p.name });
      if (answer.value.length === 0) break;
    } while (page.token !== null && found.length < MAX_AZURE_PROJECTS);
    return found.slice(0, MAX_AZURE_PROJECTS);
  }

  /** The work item types of a project, hidden ones included (see {@link hiddenWorkItemTypes}). */
  async workItemTypes(projectId: string): Promise<AzureWorkItemType[]> {
    const answer = await this.#get(
      `${this.#projectPath(projectId)}/wit/workitemtypes`,
      workItemTypeList,
    );
    return answer.value.map((t) => ({
      name: t.name,
      referenceName: t.referenceName,
      states: (t.states ?? []).map((s) => ({ name: s.name, category: s.category ?? '' })),
      fields: (t.fields ?? []).map((f) => ({
        referenceName: f.referenceName,
        alwaysRequired: f.alwaysRequired === true,
        hasDefault:
          f.defaultValue !== null && f.defaultValue !== undefined && f.defaultValue !== '',
      })),
    }));
  }

  /**
   * The NAMES of the types in `Microsoft.HiddenCategory` (Test Plan, Code Review Request ...): the
   * category lists names only, so a caller matches them against {@link workItemTypes} by name.
   */
  async hiddenWorkItemTypes(projectId: string): Promise<Set<string>> {
    const answer = await this.#get(
      `${this.#projectPath(projectId)}/wit/workitemtypecategories`,
      workItemTypeCategoryList,
    );
    const hidden = answer.value.find((c) => c.referenceName === HIDDEN_CATEGORY);
    return new Set((hidden?.workItemTypes ?? []).map((t) => t.name));
  }

  /**
   * The area or iteration paths of a project in the create's `System.AreaPath` form
   * ({@link azureFieldPath}): the root (the project name) first, then depth first, at most
   * {@link CLASSIFICATION_DEPTH} levels below the root and {@link MAX_CLASSIFICATION_PATHS} paths.
   */
  async classificationPaths(projectId: string, group: 'areas' | 'iterations'): Promise<string[]> {
    const base = this.#projectPath(projectId);
    if (group !== 'areas' && group !== 'iterations') {
      throw new AzureError('refused', AZURE_TEXT.classificationGroup, { reason: 'invalid_input' });
    }
    const root = await this.#get(
      `${base}/wit/classificationnodes/${group}?$depth=${CLASSIFICATION_DEPTH}`,
      classificationNode,
    );
    const paths: string[] = [];
    const todo: { node: ClassificationNodeAnswer; depth: number }[] = [{ node: root, depth: 0 }];
    for (let next = todo.pop(); next !== undefined; next = todo.pop()) {
      if (paths.length >= MAX_CLASSIFICATION_PATHS) break;
      paths.push(azureFieldPath(next.node.path));
      if (next.depth >= CLASSIFICATION_DEPTH) continue;
      const depth = next.depth + 1;
      todo.push(...[...(next.node.children ?? [])].reverse().map((node) => ({ node, depth })));
    }
    return paths;
  }

  /** `/{projectId}/_apis/wit/workitems/$<type>`: the type by its name, URL-encoded. */
  #workItemTypePath(projectId: string, typeName: string): string {
    const base = this.#projectPath(projectId);
    if (typeName.length === 0 || typeName.length > 128) {
      throw new AzureError('refused', AZURE_TEXT.workItemType, { reason: 'invalid_input' });
    }
    return `${base}/wit/workitems/$${encodeURIComponent(typeName)}`;
  }

  /**
   * Creates a work item of the type named `typeName`. A refusal is `refused` with Azure DevOps'
   * words in `azureMessage` (decisions and `field_refused` only); an unknown type is `not_found`
   * with typeKey `WorkItemTypeNotFoundException`.
   */
  async createWorkItem(
    projectId: string,
    typeName: string,
    ops: readonly AzureJsonPatch[],
  ): Promise<AzureWorkItem> {
    const answer = await this.#call(
      'POST',
      this.#workItemTypePath(projectId, typeName),
      workItemAnswer,
      ops,
      AZURE_API_VERSION,
      'base',
      [],
      { contentType: AZURE_JSON_PATCH },
    );
    return workItemOf(answer);
  }

  /**
   * The same POST with `validateOnly=true`: a dry run that makes nothing and refuses exactly as
   * {@link createWorkItem} does (probe item 30d). Its answer has no id, so it returns nothing.
   */
  async validateWorkItem(
    projectId: string,
    typeName: string,
    ops: readonly AzureJsonPatch[],
  ): Promise<void> {
    await this.#call(
      'POST',
      `${this.#workItemTypePath(projectId, typeName)}?validateOnly=true`,
      validatedWorkItem,
      ops,
      AZURE_API_VERSION,
      'base',
      [],
      { contentType: AZURE_JSON_PATCH },
    );
  }

  /** A PATCH of a work item (a `System.History` note); either project's path reads a moved item. */
  async updateWorkItem(
    projectId: string,
    id: number,
    ops: readonly AzureJsonPatch[],
  ): Promise<AzureWorkItem> {
    const base = this.#projectPath(projectId);
    checkWorkItemId(id);
    const answer = await this.#call(
      'PATCH',
      `${base}/wit/workitems/${id}`,
      workItemAnswer,
      ops,
      AZURE_API_VERSION,
      'base',
      [],
      { contentType: AZURE_JSON_PATCH },
    );
    return workItemOf(answer);
  }

  /**
   * The ids a WIQL query of the project finds, always with `timePrecision=true` (a time in a date
   * is refused without it, probe item 30f) and at most {@link WORK_ITEM_QUERY_TOP}.
   */
  async queryWorkItemIds(projectId: string, wiql: string): Promise<number[]> {
    const answer = await this.#call(
      'POST',
      `${this.#projectPath(projectId)}/wit/wiql?timePrecision=true&$top=${WORK_ITEM_QUERY_TOP}`,
      wiqlAnswer,
      { query: wiql },
    );
    return answer.workItems.slice(0, WORK_ITEM_QUERY_TOP).map((w) => w.id);
  }

  /**
   * Reads up to {@link MAX_WORK_ITEM_BATCH} work items on the organisation route (it reads items
   * moved to another project), with `errorPolicy: 'omit'` and {@link WORK_ITEM_BATCH_FIELDS}: a
   * deleted or unknown id is simply absent (probe item 30g). With `description: false` the
   * description is not asked for (it is null): a state read of 200 items stays far below 8 MiB.
   */
  async workItemsBatch(
    ids: readonly number[],
    options: { description?: boolean } = {},
  ): Promise<AzureWorkItem[]> {
    if (ids.length > MAX_WORK_ITEM_BATCH) {
      throw new AzureError('refused', AZURE_TEXT.workItemBatch, { reason: 'invalid_input' });
    }
    for (const id of ids) checkWorkItemId(id);
    if (ids.length === 0) return [];
    const fields =
      options.description === false
        ? WORK_ITEM_BATCH_FIELDS.filter((f) => f !== 'System.Description')
        : WORK_ITEM_BATCH_FIELDS;
    const answer = await this.#call('POST', '/_apis/wit/workitemsbatch', workItemBatch, {
      ids: [...ids],
      fields,
      errorPolicy: 'omit',
    });
    return answer.value.filter((w) => w !== null).map(workItemOf);
  }

  /** The answer of a GET as `schema` reads it; its error names the route ({@link azureRoute}). */
  #get<T>(path: string, schema: z.ZodType<T>, apiVersion: string = AZURE_API_VERSION): Promise<T> {
    return this.#call('GET', path, schema, undefined, apiVersion);
  }

  /**
   * One request, GET or a write with a JSON body; a write counts against the same budget as a read.
   * An empty 2xx body is `undefined` to `schema` (so `z.unknown()` takes a write's empty answer).
   */
  async #call<T>(
    method: AzureMethod,
    path: string,
    schema: z.ZodType<T>,
    body?: unknown,
    apiVersion: string = AZURE_API_VERSION,
    host: 'base' | 'identities' = 'base',
    /** Secrets of this request's body (a hook's password): cut from Azure DevOps' error text too. */
    bodySecrets: readonly string[] = [],
    options: AzureCallOptions = {},
  ): Promise<T> {
    const max = this.#options.maxRequests ?? MAX_AZURE_REQUESTS;
    if (this.#requestCount >= max) {
      throw new AzureError('budget', `More than ${max} Azure DevOps requests in one job`);
    }
    this.#requestCount += 1;
    const now = this.#options.now ?? Date.now;
    const wait = this.#notBefore - now();
    this.#notBefore = 0;
    if (wait > 0) {
      await (this.#options.sleep ?? ((ms) => timer(ms, this.#options.signal)))(wait);
    }
    // Outside the naming below: an Entra failure keeps the request it names.
    const { authorization, secrets } = await this.#authorization();
    try {
      const { status, json } = await this.#send(
        method,
        path,
        body,
        apiVersion,
        authorization,
        [...secrets, ...bodySecrets],
        now,
        host,
        options,
      );
      const parsed = schema.safeParse(json);
      if (!parsed.success) throw new AzureError('bad_answer', AZURE_TEXT.badAnswer, { status });
      return parsed.data;
    } catch (err) {
      throw namedRequest(err, azureRoute(method, path.split('?', 1)[0] ?? path));
    }
  }

  /**
   * The identities host and its own permission to be internal: the address rules (the SSRF check
   * of every resolved address, the refused ranges) are applied to it as to the base, per request.
   */
  #identities(): { baseUrl: string; allowInternalHosts: boolean } {
    const { identities, baseUrl, allowInternalHosts } = this.#connection;
    if (identities) return identities;
    const deployment = azureDeployment(baseUrl);
    return {
      baseUrl: azureIdentitiesBase(baseUrl, deployment),
      allowInternalHosts: deployment === 'server' ? allowInternalHosts : false,
    };
  }

  /** The `Authorization` header, and the secrets no message may carry. */
  async #authorization(): Promise<{ authorization: string; secrets: string[] }> {
    const { credential } = this.#connection;
    if (credential.kind === 'pat') {
      const basic = Buffer.from(`:${credential.pat}`).toString('base64');
      return { authorization: `Basic ${basic}`, secrets: [credential.pat, basic] };
    }
    const token = await credential.token();
    return { authorization: `Bearer ${token}`, secrets: [token] };
  }

  async #send(
    method: AzureMethod,
    path: string,
    body: unknown,
    apiVersion: string,
    authorization: string,
    secrets: string[],
    now: () => number,
    host: 'base' | 'identities',
    options: AzureCallOptions = {},
  ): Promise<{ status: number; json: unknown }> {
    const { baseUrl, allowInternalHosts } = host === 'base' ? this.#connection : this.#identities();
    const separator = path.includes('?') ? '&' : '?';
    const result = await outboundRequest(
      {
        url: `${baseUrl}${path}${separator}api-version=${apiVersion}`,
        method,
        headers: {
          authorization,
          accept: 'application/json',
          'user-agent': `Qualor/${VERSION}`,
          ...(body === undefined
            ? {}
            : { 'content-type': options.contentType ?? 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      {
        allowInternalHosts,
        refuseAddress: scmRefusedAddress(new URL(baseUrl)),
        timeoutMs: this.#options.timeoutMs ?? AZURE_TIMEOUT_MS,
        ...(this.#options.resolve ? { resolve: this.#options.resolve } : {}),
        maxResponseBytes: options.maxBytes ?? MAX_AZURE_RESPONSE_BYTES,
        overflow: 'fail',
        names: { noun: 'Azure DevOps', target: 'Azure DevOps' },
        ...(this.#options.signal ? { signal: this.#options.signal } : {}),
      },
    );
    if (result.kind === 'failed') throw transportError(result);
    const { status, headers, body: answer } = result;
    const html = /text\/html/i.test(headers['content-type'] ?? '');
    if ((status >= 300 && status < 400) || (status >= 200 && status < 300 && html)) {
      throw new AzureError('auth', AZURE_TEXT.signInPage, { status, reason: 'html_answer' });
    }
    if (status >= 200 && status < 300) {
      this.#notBefore = now() + paceOf(headers, now());
      options.onHeaders?.(headers);
      if (options.raw) return { status, json: answer };
      try {
        return {
          status,
          json: answer.length === 0 ? undefined : (JSON.parse(textOf(answer)) as unknown),
        };
      } catch {
        throw new AzureError('bad_answer', AZURE_TEXT.badAnswer, { status });
      }
    }
    if (status === 401) {
      const serviceError = [headers['x-tfs-serviceerror'] ?? []].flat().join(' ');
      if (serviceError.includes('TF401444') || answer.includes('TF401444')) {
        throw new AzureError('auth', AZURE_TEXT.signInRequired, {
          status,
          reason: 'sign_in_required',
        });
      }
      throw new AzureError('auth', AZURE_TEXT.refused, { status, reason: 'http' });
    }
    const found = azureErrorOf(answer, secrets);
    if (status === 403) {
      throw new AzureError('auth', AZURE_TEXT.forbidden, {
        status,
        reason: 'permission_missing',
        ...found,
      });
    }
    if (status === 404) {
      throw new AzureError('not_found', AZURE_TEXT.notFound, {
        status,
        reason: 'http',
        ...found,
      });
    }
    if (status === 429) {
      throw new AzureError('rate_limited', AZURE_TEXT.rateLimited, {
        status,
        reason: 'http',
        retryAfterSeconds: retryAfterSeconds(headers, now()),
        ...found,
      });
    }
    // A long text over Azure DevOps' limit is a 500 (probe item 30e), yet asking again cannot help.
    const outage = status >= 500 && !REFUSED_SERVER_ERRORS.has(found.azureTypeKey ?? '');
    throw new AzureError(outage ? 'transient' : 'refused', `Azure DevOps answered HTTP ${status}`, {
      status,
      reason: 'http',
      ...found,
    });
  }
}
