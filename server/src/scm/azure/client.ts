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
  notFound: 'Azure DevOps found nothing there, or the identity cannot see it (HTTP 404)',
  rateLimited: 'Azure DevOps is limiting requests (HTTP 429)',
  badAnswer: "Azure DevOps's answer was not understood",
  repositoryId: 'The repository id is not an Azure DevOps repository id (a GUID)',
  guid: 'The id is not an Azure DevOps id (a GUID)',
  notPublic:
    'The Azure DevOps host resolves to a private, loopback or otherwise non-public address; list it in QUALOR_SCM_INTERNAL_HOSTS',
  refusedAddress:
    'The Azure DevOps host resolves to a link-local, cloud metadata or loopback address',
  unresolved: 'The Azure DevOps host could not be resolved',
  timeout: 'Azure DevOps did not answer in time',
} as const;

/** A failed Azure DevOps request; see {@link ScmError}. */
export class AzureError extends ScmError {
  constructor(
    kind: ScmErrorKind,
    message: string,
    options: Omit<ScmErrorOptions, 'providerMessage'> & { azureMessage?: string | null } = {},
  ) {
    const { azureMessage, ...rest } = options;
    super(kind, message, { ...rest, providerMessage: azureMessage ?? null });
    this.name = 'AzureError';
  }

  /** The `message` of Azure DevOps' error body (decisions only, never logged or shown). */
  get azureMessage(): string | null {
    return this.providerMessage;
  }
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

export interface NewAzureThread {
  content: string;
  status: 'active' | 'closed';
  /** Without the leading `/`; none: a thread on the pull request as a whole. */
  filePath?: string;
  line?: number;
  /** The line's length: the thread selects the whole line (probe item 5). */
  lineLength?: number;
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

type AzureMethod = 'GET' | 'POST' | 'PUT' | 'PATCH';
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

const commitRef = z.looseObject({ commitId: z.string().min(1) });
const pullRequestAnswer = z.looseObject({
  status: z.enum(['active', 'completed', 'abandoned']),
  isDraft: z.boolean().nullish(),
  title: z.string(),
  sourceRefName: z.string(),
  targetRefName: z.string(),
  lastMergeSourceCommit: commitRef.nullish(),
  repository: z.looseObject({ webUrl: z.string().min(1) }),
});
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
const statusList = z.looseObject({
  value: z.array(
    z.looseObject({
      id: z.number().int(),
      iterationId: z.number().int().nullish(),
      // Absent while the state is the default, notSet: statuses of other tools come so (probe item 19).
      state: z.string().nullish(),
      description: z.string().nullish(),
      targetUrl: z.string().nullish(),
      context: z.looseObject({ genre: z.string().nullish(), name: z.string() }),
      createdBy: z.looseObject({ id: z.string() }).nullish(),
    }),
  ),
});

/** For tests against the recorded shapes. */
export const AZURE_SHAPES = { connectionData, repository, repositoryList } as const;

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

/** Azure DevOps' error `message`, for decisions only, with the credential cut out. */
function azureMessageOf(body: Buffer, secrets: string[]): string | null {
  try {
    const parsed = errorBody.safeParse(JSON.parse(textOf(body)));
    if (!parsed.success) return null;
    let text = parsed.data.message;
    for (const secret of secrets) if (secret) text = text.split(secret).join('[credential]');
    return text.slice(0, 1_000);
  } catch {
    return null;
  }
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
    return {
      id,
      status: answer.status,
      isDraft: answer.isDraft ?? false,
      title: answer.title,
      sourceRefName: answer.sourceRefName,
      targetRefName: answer.targetRefName,
      headSha: answer.lastMergeSourceCommit?.commitId ?? null,
      webUrl: azurePullRequestWebUrl(answer.repository.webUrl, id),
    };
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
   * A thread with one comment. With `filePath` and `line` it sits on the right side of that line,
   * selecting all of it, and carries no `pullRequestThreadContext` (probe items 5 and 6).
   */
  async createThread(
    repositoryId: string,
    prId: number,
    thread: NewAzureThread,
  ): Promise<{ id: number; commentId: number }> {
    const { filePath, line, lineLength } = thread;
    const threadContext =
      filePath !== undefined && line !== undefined
        ? {
            filePath: `/${filePath}`,
            rightFileStart: { line, offset: 1 },
            rightFileEnd: { line, offset: (lineLength ?? 0) + 1 },
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
    for (const s of answer.value) {
      const state = s.state ?? 'notSet';
      if (s.context.genre !== 'qualor' || !STATUS_STATES.includes(state)) continue;
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
        { ...this.#subscriptionBody(input), id: id.toLowerCase() },
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
          ...(body === undefined ? {} : { 'content-type': 'application/json' }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      },
      {
        allowInternalHosts,
        refuseAddress: scmRefusedAddress(new URL(baseUrl)),
        timeoutMs: this.#options.timeoutMs ?? AZURE_TIMEOUT_MS,
        ...(this.#options.resolve ? { resolve: this.#options.resolve } : {}),
        maxResponseBytes: MAX_AZURE_RESPONSE_BYTES,
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
    const azureMessage = azureMessageOf(answer, secrets);
    if (status === 403) {
      throw new AzureError('auth', AZURE_TEXT.forbidden, {
        status,
        reason: 'permission_missing',
        azureMessage,
      });
    }
    if (status === 404) {
      throw new AzureError('not_found', AZURE_TEXT.notFound, {
        status,
        reason: 'http',
        azureMessage,
      });
    }
    if (status === 429) {
      throw new AzureError('rate_limited', AZURE_TEXT.rateLimited, {
        status,
        reason: 'http',
        retryAfterSeconds: retryAfterSeconds(headers, now()),
        azureMessage,
      });
    }
    throw new AzureError(
      status >= 500 ? 'transient' : 'refused',
      `Azure DevOps answered HTTP ${status}`,
      {
        status,
        reason: 'http',
        azureMessage,
      },
    );
  }
}
