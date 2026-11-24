import {
  createHash,
  randomBytes,
  randomInt,
  randomUUID,
  verify,
  X509Certificate,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from './tls';

/**
 * A local fake of the Azure DevOps REST routes Qualor uses (Azure DevOps design §7.1, §7.9), with
 * a fake Microsoft Entra token endpoint (https, the test CA: call `trustTestCa()`), for tests:
 * nothing in `pnpm test` contacts Azure DevOps or Entra. One fake is one Services organisation
 * (`<url>` = `http://127.0.0.1:<port>/probe-org`) or one Server collection
 * (`…/DefaultCollection`), as the probe bench was.
 *
 * Recorded answers. The probe (sub-plan 0, `tools/azure/`) recorded real answers of Azure DevOps
 * Server 20.0 and of a Services organisation in `azure-shapes/<deployment>/` (status, content type
 * and body, or for a refusal the status, the headers and the body's first 200 characters; ids made
 * synthetic, ending `fa6e0000…`). The fake serves them with its own values laid over them:
 * - `GET _apis/connectionData` (`api-version=7.0-preview`): `1-connectiondata-pat` for the PAT, and
 *   on Services `1-connectiondata-secret` / `-certificate` for a token the fake Entra issued; the
 *   fake's id and display name (`patUser`, `principalUser`) over both users of the answer.
 * - A repository: the repository object of `9-event-pr-updated` (`resource.repository`, the same
 *   GitRepository a `GET _apis/git/repositories/{id}` answers), with the fake's id, name, project
 *   and URLs; `defaultBranch` (`refs/heads/<name>`, the form of `8-definition-get`) is left out for
 *   an empty repository, as Azure DevOps does. Its other fields are as recorded.
 * - An unknown repository: `10-not-found` (404 WrappedException, TF401019), with the id asked for.
 * - A wrong PAT, an unknown or expired bearer token (any bearer token on Server, which takes PATs
 *   only), and any other scheme: `10-wrong-pat` (401, no content type, empty body).
 * - A request without a credential: `10-no-credential`, which is a 302 to the sign-in page on
 *   Services and a 401 JSON (TF400813) on Server; its body is the recorded excerpt (the probe kept
 *   the first 200 characters), which nobody parses.
 *
 * Constructions, where nothing was recorded:
 * - The repositories list (`GET _apis/git/repositories`): the `{ count, value }` envelope of the
 *   recorded lists (`7-policy-types`) around the repository objects above. The probe listed no
 *   projects or repositories.
 * - TF401444 (an identity the organisation has not added, `identityAdded: false`; the probe could
 *   not make one): a 401 with the recorded wrong-PAT `www-authenticate`, the message URL-encoded in
 *   `x-tfs-serviceerror` (as the recorded Server 401 carries TF400813) and the WrappedException
 *   body of `10-not-found` with Microsoft's TF401444 text. It answers the service principal only.
 * - A 400 for a route asked at another api-version than Qualor's (the probe saw Server refuse
 *   connectionData at 7.0 with VssInvalidPreviewVersionException), and a 404 for any other route:
 *   the WrappedException body of `10-not-found` with the fake's own message.
 * - Pull request decoration (sub-plan 4), under `[/<project>]/_apis/git/repositories/{id}/`, all at
 *   api-version 7.0, with state the tests seed (`addPullRequest`, `addIteration`, `addFile`,
 *   `addThread`, `addSystemThread`) and read back (`pullRequest()`, `commitStatuses`):
 *   - `pullrequests/{id}` (GET): the pull request object of `9-event-pr-updated` (`resource`), with
 *     the fake's id, status, title, refs, head commit and repository. The probe recorded no GET.
 *   - `pullrequests/{id}/iterations` (GET): `{ count, value }` of iterations with `id` and
 *     `sourceRefCommit` / `commonRefCommit` / `targetRefCommit` as `{ commitId }`; the probe read
 *     the list but recorded only the changes.
 *   - `.../iterations/{n}/changes` (GET, `$top`, `$skip`): the `changeEntries` of
 *     `6-iteration-changes`; `nextSkip` (the REST docs' paging field, not recorded) while more
 *     remain; `originalPath` on a rename.
 *   - `items?path&versionDescriptor.version&includeContent=true&$format=json` (GET): a JSON item
 *     `{ objectId, gitObjectType, commitId, path, content, contentMetadata }`; a binary file has
 *     `contentMetadata.isBinary` and no `content`; a file the commit does not hold answers 404
 *     TF401174. Not recorded: the probe never read file content.
 *   - `pullrequests/{id}/threads` (GET, POST) and `threads/{t}` (PATCH): the thread of
 *     `3-thread-list` / `3-thread-create` with the fake's values. Thread ids count per fake (probe
 *     item 15), comment ids per thread from 1. A PATCH carrying `properties` is the recorded 400
 *     (`3-thread-patch-add`); one with `status` answers as `4-patch-status-*`. A system thread
 *     (no recording holds one; the REST docs name `commentType: 'system'`) has no `status`.
 *   - `threads/{t}/comments` (POST) and `threads/{t}/comments/{c}` (PATCH): the comment object of
 *     the thread recordings. Constructed: the probe never added or edited a comment.
 *   - `pullrequests/{id}/statuses` (POST): `7-pr-status-iteration`, its `createdBy.id` the
 *     caller's identity; without `iterationId` and with `statusPolicy: true` on the seeded pull
 *     request, the recorded 403 (`7-pr-status-no-iteration`).
 *   - `.../iterations/{n}/statuses` (GET): `{ count, value }` of the statuses posted on the
 *     iteration, newest first, each with its `id`: a POST adds a status with a higher id, and the newest
 *     of a genre and name supersedes the older ones (the list keeps them). Constructed.
 *   - `commits/{sha}/statuses` (POST): `7-commit-status` (201).
 * - Replies, commenter rights and service hooks (sub-plan 5), all at api-version 7.0:
 *   - `pullrequests/{id}/threads/{t}` (GET): the thread object of `20-thread-get`. A comment keeps
 *     `parentCommentId`, `publishedDate` (`lastUpdatedDate` and `lastContentUpdatedDate` follow
 *     it) and the author's `displayName`; a deleted comment (`isDeleted`) has no `author` and no
 *     `content`. `threads/{t}/comments` (POST) keeps the body's `parentCommentId` (`20-reply-post`)
 *     and dates the comment by the fake's clock.
 *   - Users (`addUser`, `users`): an identity with a role (`owner`, `contributor`, `reader`), by id
 *     (a GUID) and identity descriptor. The PAT's user is an owner, the service principal a
 *     contributor; both carry the descriptors of `20-identities-pat-user` / `-service-principal`.
 *   - THE SECOND HOST. On Services the identities live on `vssps.dev.azure.com/<org>`, a host other
 *     than the organisation's. The fake serves them on its one server under the prefix
 *     `/vssps/<org>` (`identitiesUrl`), where the test origin seam
 *     (`QUALOR_AZURE_TEST_ORIGIN`, `Config.azureTestOrigin`) maps that host: a Services
 *     organisation's identities target is `<origin>/vssps<path of the organisation>`
 *     (`azureClientFor`), in the `requests` list as `/vssps/_apis/identities`. A Server fake
 *     answers them on the collection itself (`/_apis/identities`), as Server does.
 *   - `GET _apis/identities?identityIds=<ids>`: `{ count, value }` of the `20-identities-*`
 *     identity with the user's id, descriptor (`Microsoft.IdentityModel.Claims.ClaimsIdentity;…`,
 *     the form the ACL takes), subject descriptor and display name; an unknown id is not listed
 *     (`count: 0`; Microsoft documents no other answer, the probe never asked for one).
 *   - `GET _apis/accesscontrollists/{git namespace}?token=repoV2/{project}/{repository}&descriptors=
 *     &includeExtendedInfo=true`: the `20-acl-*` answer with the user's `allow` and
 *     `extendedInfo.effectiveAllow` by role, taken from the recordings (owner: `20-acl-pat-user`,
 *     contributor: `20-acl-service-principal`, reader: `server/16-acl-reader`; the services
 *     recordings hold no reader, and the reader's value is the same ACL form). An unknown
 *     descriptor has an entry-less `acesDictionary` (constructed). Bit 4 is set for owner and
 *     contributor, clear for reader.
 *   - `GET _apis/hooks/publishers/tfs/eventTypes`: `{ count, value }` of the four pull request event
 *     types with `supportedResourceVersions` from `9-event-types`. THAT FILE IS REDUCED (`{ status,
 *     pullRequestEvents[{ id, supportedResourceVersions }] }`: the probe kept only those two fields
 *     of the real answer), so the rest of each event type (`name`, `description`, `publisherId`,
 *     `inputDescriptors`, `url`) is built here after Microsoft's EventTypeDescription and is
 *     constructed, not recorded.
 *   - `_apis/hooks/subscriptions` (GET with the `publisherId`, `eventType`, `consumerId` and
 *     `consumerActionId` filters; POST; `/{id}` PUT): the subscription object of
 *     `9-subscription-comment` with the fake's values; `consumerInputs.basicAuthPassword` is
 *     `********` as recorded and the real password stays in `subscriptions`. A POST or PUT needs
 *     `publisherId: tfs`, `consumerId: webHooks`, `consumerActionId: httpRequest`, an event type of the
 *     list and one of its resource versions (else a 400 SubscriptionInputException, constructed);
 *     a password with an `http://` url is the recorded 400 (`9-subscription-http-basic-auth`).
 *     A POST is `enabled`; a PUT without `status` enables it again (constructed); a test sets a
 *     status with `setSubscriptionStatus` (`onProbation` ...). Nothing is delivered: the fake calls no
 *     webhook (`deliverAzureEvent` in `test/azure.ts` posts a recorded event to Qualor's route).
 * - Fix branches and pull requests (sub-plan 6), at api-version 7.0, from the 22-* recordings of a
 *   Services organisation (`azure-shapes/services/`) with the fake's own values laid over them. A
 *   repository holds commits (parents and files; `addCommit`, `addFile`) and refs (`setBranch`):
 *   - `refs?filter=` (GET): `{ count, value }` of `22-refs-prefix` entries, a PREFIX match
 *     (`heads/a` also lists `heads/a-2`). `refs` (POST, an array of updates): `22-ref-move`; a
 *     stale old id is `staleOldObjectId` (`success: false`, constructed), a move need not be a
 *     fast-forward, and a delete ignores a wrong old id: `succeededCorruptRef` (`22-ref-delete-stale`),
 *     `succeeded` with the right one (`22-ref-delete-tmp`), `succeededNonExistentRef` for no ref.
 *   - `pushes` (POST): one commit of edits (base64 or raw text) onto the parent's files, 201 as
 *     `22-push-new-branch`, to any ref (`refs/heads/…`, `refs/qualor/…`). A parent that is not the
 *     ref's head, or an old id that is not its head (zero for a new ref), is `22-push-force-move`: 400
 *     `baseCommitId` (item 22e: a stale push looks the same).
 *   - `diffs/commits` (GET, commit versions): `22-ancestry-diverged` with the `commonCommit` the
 *     graph gives (the merge base; absent for commits with no history in common).
 *   - `items?…&$format=octetStream` (GET): the file's bytes, `text/plain; api-version=7.0`, as stored.
 *   - `pullrequests` (GET with `searchCriteria.sourceRefName` / `targetRefName` / `status`, default
 *     active; POST), and `pullrequests/{id}` (PATCH title, description, status): the pull request of
 *     `22-pr-get`, with `mergeStatus` (`setMergeStatus`, default `succeeded`), `description` (over
 *     4000 characters is `22-pr-description-4001`) and `forkSource` for a fork. `completePullRequest`
 *     completes one (a merge the fake does not make).
 * - The CI setup (sub-plan 7), under `/<project id>/_apis/`, from the 8-*, 17-* and 26-* recordings
 *   of a Services organisation with the fake's own values laid over them. Each project has the queues
 *   `Default` (pool `Default`, own agents) and, on Services, the hosted `Azure Pipelines` (open to
 *   every pipeline); `addQueue` adds more. A path with an unknown project id is a 404.
 *   - `distributedtask/queues` (GET, `queueName`; api-version 7.0-preview.1): `{ count, value }` of
 *     `26-queues` entries.
 *   - `pipelines/pipelinePermissions/queue/{id}` (GET, PATCH; 7.0-preview.1): `26-hosted-queue-permissions`
 *     (`allPipelines` only for a queue open to all) and `8-queue-authorize-1`; a PATCH
 *     `{ pipelines: [{ id, authorized }] }` of a definition of the project authorises or withdraws it.
 *   - `build/definitions` (GET with `repositoryId` and `repositoryType`, POST), `build/definitions/{id}`
 *     (GET, PUT): `26-definition-create` with the definition's values. A secret variable reads back
 *     `{ value: null, isSecret: true }`, survives a PUT that leaves its value out and is replaced by
 *     one that sends it (`definitions[n].secrets`); a PUT keeps the body's unknown fields. A name
 *     the project already has is 409 (`DefinitionExistsException`, constructed).
 *   - `policy/configurations` (GET with `repositoryId`, `refName`, `policyType`; POST): `26-policy-create`
 *     / `26-policies-search`; only the Build policy type is known, the matchKind reads back `Exact`.
 *   - `items?scopePath=/&recursionLevel=OneLevel&versionDescriptor.…` (GET) of a repository: the root
 *     `/` and the commit's top-level files and folders (`26-root-items`).
 * - The token endpoint (`POST /{tenant}/oauth2/v2.0/token`): Microsoft's documented client
 *   credentials answer, and its documented error body (`error`, `error_description` with an
 *   AADSTS code) for a refusal: 400, or 401 `invalid_client` for a wrong secret or assertion. It
 *   checks the tenant, `client_id`, the scope, and either the secret or the client assertion: an
 *   RS256 JWT whose `x5t` is the registered certificate's SHA-1, signed by its key, with `aud` this
 *   endpoint, `iss` = `sub` = the client id, a `jti`, and `nbf`/`exp` around the fake's clock.
 */

export type FakeAzureDeployment = 'services' | 'server';

const SHAPES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'azure-shapes');
/** The organisation (Services) and the collection (Server) of the recordings. */
const BASE_PATH: Record<FakeAzureDeployment, string> = {
  services: '/probe-org',
  server: '/DefaultCollection',
};
/** What Entra requires; written out here, not imported, so the fake checks the client. */
const ENTRA_SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const TOKEN_SECONDS = 3599;
const CLOCK_SKEW_SECONDS = 300;
const JSON_7_0 = 'application/json; charset=utf-8; api-version=7.0';
const TF401444_TYPE =
  'Microsoft.TeamFoundation.Framework.Server.UnauthorizedRequestException, Microsoft.TeamFoundation.Framework.Server';

/** A recorded answer (`azure-shapes/<deployment>/<name>.json`). */
export function azureShape<T = Record<string, unknown>>(
  deployment: FakeAzureDeployment,
  name: string,
): T {
  return JSON.parse(readFileSync(path.join(SHAPES, deployment, `${name}.json`), 'utf8')) as T;
}

/** A recording: an answer with its JSON body, or a refusal with its headers and body excerpt. */
interface Recording {
  status: number;
  contentType: string | null;
  body?: unknown;
  wwwAuthenticate?: string | null;
  location?: string | null;
  tfsServiceError?: string | null;
  first200?: string;
}

/** A recording as an answer to inject: its status, headers and body as recorded. */
export function recordedAnswer(deployment: FakeAzureDeployment, name: string): InjectedAnswer {
  const shape = azureShape<Recording>(deployment, name);
  const headers: Record<string, string> = {};
  if (shape.contentType) headers['content-type'] = shape.contentType;
  if (shape.wwwAuthenticate) headers['www-authenticate'] = shape.wwwAuthenticate;
  if (shape.location) headers.location = shape.location;
  if (shape.tfsServiceError) headers['x-tfs-serviceerror'] = shape.tfsServiceError;
  const body = 'body' in shape ? JSON.stringify(shape.body) : (shape.first200 ?? '');
  return { status: shape.status, headers, body };
}

export interface FakeAzureIdentity {
  id: string;
  displayName: string;
}

/** The service principal the fake Entra knows: a client secret, a certificate (PEM), or both. */
export interface FakeAzurePrincipal {
  tenantId: string;
  clientId: string;
  secret?: string;
  certificatePem?: string;
}

export interface FakeAzureRepositoryInput {
  id?: string;
  name: string;
  /** Repositories with the same project name share one project (and its id). */
  projectName: string;
  /** Default `main`; null: an empty repository, which has none. */
  defaultBranch?: string | null;
  isDisabled?: boolean;
}

export interface FakeAzureRepository {
  id: string;
  name: string;
  projectId: string;
  projectName: string;
  defaultBranch: string | null;
  isDisabled: boolean;
}

export interface FakeAzureChange {
  /** Without the leading `/`. */
  path: string;
  /** A rename: where the file was. */
  originalPath?: string;
  /** Default `edit`. */
  changeType?: string;
  /** Default its position in the iteration, from 1. */
  changeTrackingId?: number;
}

export interface FakeAzureStatus {
  /** Assigned on a POST (rising); a test that seeds a status by hand may set it. */
  id?: number;
  iterationId: number | null;
  /** null: the answer omits `state`, as Azure DevOps does for notSet (probe item 19). */
  state: string | null;
  description: string;
  targetUrl: string | null;
  genre: string;
  name: string;
  /** Its `createdBy.id`: the caller's identity on a POST; a status seeded without one is the PAT user's. */
  authorId?: string;
}

export interface FakeAzureIteration {
  id: number;
  sourceRefCommit: string;
  commonRefCommit: string;
  targetRefCommit: string;
  changes: FakeAzureChange[];
  /** What was posted on this iteration, one per genre and name. */
  statuses: FakeAzureStatus[];
}

export interface FakeAzureComment {
  id: number;
  authorId: string;
  content: string;
  commentType: 'text' | 'system' | 'codeChange';
  /** The comment it answers; 0 for a thread's first. */
  parentCommentId: number;
  /** ISO 8601, as Azure DevOps writes it. */
  publishedDate: string;
  /** A deleted comment has no author and no content in the answer. */
  isDeleted: boolean;
}

/** What a person has in the organisation: the rights the ACL answers by. */
export type FakeAzureRole = 'owner' | 'contributor' | 'reader';

export interface FakeAzureUser {
  id: string;
  displayName: string;
  role: FakeAzureRole;
  /** The identity descriptor: what the identities lookup answers and the ACL is asked with. */
  descriptor: string;
  /** The Graph form (`aad.…`) a comment's `author.descriptor` carries. */
  subjectDescriptor: string;
}

export interface FakeAzureUserInput {
  role: FakeAzureRole;
  /** Default a new GUID. */
  id?: string;
  displayName?: string;
  descriptor?: string;
}

export interface FakeAzureSubscription {
  id: string;
  status: string;
  eventType: string;
  resourceVersion: string;
  projectId: string;
  repositoryId: string | null;
  branch: string | null;
  url: string;
  username: string;
  /** What the client sent; the answer shows `********`. */
  password: string;
}

export interface FakeAzureCommentInput {
  content: string;
  /** Default the PAT's user. */
  authorId?: string;
  commentType?: FakeAzureComment['commentType'];
  /** Default 0. */
  parentCommentId?: number;
  /** Default now, by the fake's clock. */
  publishedDate?: string;
  isDeleted?: boolean;
}

export type FakeAzureThreadStatus =
  'active' | 'fixed' | 'wontFix' | 'closed' | 'byDesign' | 'pending';

export interface FakeAzureThread {
  id: number;
  /** Null: a system thread. */
  status: FakeAzureThreadStatus | null;
  /** Without the leading `/`; null: a thread on the pull request as a whole. */
  filePath: string | null;
  /** The right side's first line, when there is a position. */
  line: number | null;
  /** The `threadContext` as it was created (null: none). */
  threadContext: Record<string, unknown> | null;
  /** The first comment's `publishedDate`. */
  publishedDate: string;
  comments: FakeAzureComment[];
}

export interface FakeAzurePullRequestInput {
  /** Default: the next free id of the repository, from 1. */
  id?: number;
  /** Default `active`. */
  status?: 'active' | 'completed' | 'abandoned';
  isDraft?: boolean;
  title?: string;
  sourceRefName?: string;
  targetRefName?: string;
  /** `lastMergeSourceCommit`; default a synthetic commit id, null: none. */
  headSha?: string | null;
  /** A status policy that wants every status on an iteration (probe item 7). Default false. */
  statusPolicy?: boolean;
  /** Default `succeeded`; null: none (Azure DevOps has not tried a merge). */
  mergeStatus?: string | null;
  description?: string;
  /** The source branch is in a fork (`forkSource` in the answer). Default false. */
  fork?: boolean;
}

export interface FakeAzurePullRequest {
  id: number;
  status: 'active' | 'completed' | 'abandoned';
  isDraft: boolean;
  title: string;
  sourceRefName: string;
  targetRefName: string;
  headSha: string | null;
  statusPolicy: boolean;
  mergeStatus: string | null;
  description: string;
  fork: boolean;
  iterations: FakeAzureIteration[];
  threads: FakeAzureThread[];
  /** Statuses posted without an iteration (accepted only without a status policy). */
  statuses: FakeAzureStatus[];
}

export interface FakeAzureThreadInput {
  /** Default `active`. */
  status?: FakeAzureThreadStatus;
  filePath?: string;
  line?: number;
  /** Default: one comment by the PAT's user. */
  comments?: FakeAzureCommentInput[];
}

export interface FakeAzureQueue {
  id: number;
  projectId: string;
  name: string;
  poolId: number;
  poolName: string;
  hosted: boolean;
  /** Open to every pipeline (`allPipelines.authorized`). */
  open: boolean;
  /** The definitions authorised one by one. */
  pipelineIds: number[];
}

export interface FakeAzureDefinition {
  id: number;
  projectId: string;
  /** The definition as GET answers it (the secrets read `null`). */
  body: Record<string, unknown>;
  /** The secret variables' values, which no answer shows. */
  secrets: Record<string, string>;
}

export interface FakeAzurePolicy {
  id: number;
  projectId: string;
  type: string;
  isEnabled: boolean;
  isBlocking: boolean;
  settings: Record<string, unknown>;
}

export interface RecordedRequest {
  method: string;
  /** The path under the organisation or collection (`/_apis/…`), still percent-encoded. */
  path: string;
  query: string;
  headers: IncomingMessage['headers'];
  body: string;
}

export interface InjectedAnswer {
  status: number;
  headers?: Record<string, string>;
  /** A string is sent as it is; anything else as JSON. None: an empty body. */
  body?: unknown;
  /** Never answer (the client's deadline must fire). */
  hang?: boolean;
  /** Runs before the answer (a test's change in the middle of a job). */
  before?: () => Promise<void>;
  /** After `before`, answer as the fake normally would, with `headers` added (`status` ignored). */
  passThrough?: boolean;
}

interface Injection {
  method: string;
  path: RegExp;
  answers: InjectedAnswer[];
}

export interface FakeAzureDevOps {
  /** The base URL (no trailing slash), as a connection stores it. */
  readonly url: string;
  readonly deployment: FakeAzureDeployment;
  readonly pat: string;
  /** Who the PAT is (connectionData). */
  readonly patUser: FakeAzureIdentity;
  /** Who the service principal is, on a fake with one. */
  readonly principalUser: FakeAzureIdentity | null;
  /** The fake Entra's token endpoint for a tenant (`EntraOptions.tokenUrl`). */
  tokenUrl(tenantId: string): string;
  /** False: the organisation has not added the service principal (TF401444). Default true. */
  identityAdded: boolean;
  readonly repositories: readonly FakeAzureRepository[];
  addRepository(input: FakeAzureRepositoryInput): FakeAzureRepository;
  /** A pull request of a repository (by its id), to be read and decorated. */
  addPullRequest(repositoryId: string, input?: FakeAzurePullRequestInput): FakeAzurePullRequest;
  /** The seeded pull request, whose threads and statuses a test reads back; throws when unknown. */
  pullRequest(repositoryId: string, id: number): FakeAzurePullRequest;
  /** An iteration (ids from 1); `targetRefCommit` defaults to `commonRefCommit`. */
  addIteration(
    repositoryId: string,
    prId: number,
    input: {
      sourceRefCommit: string;
      commonRefCommit: string;
      targetRefCommit?: string;
      changes?: FakeAzureChange[];
    },
  ): FakeAzureIteration;
  /** A file as a commit holds it (a Buffer with a NUL byte is binary); `path` has no leading `/`. */
  addFile(repositoryId: string, commit: string, path: string, content: string | Buffer): void;
  /**
   * A commit: the files of its first parent, with `files` laid over them. Default id: a new one.
   * Returns the (lower-case) id.
   */
  addCommit(
    repositoryId: string,
    input?: { id?: string; parents?: string[]; files?: Record<string, string | Buffer> },
  ): string;
  /** Points branch `name` (without `refs/heads/`) at a commit, creating it. */
  setBranch(repositoryId: string, name: string, commit: string): void;
  /** The branches (heads) by name, without `refs/heads/`. */
  branches(repositoryId: string): Record<string, string>;
  /** Every ref by its full name. */
  refs(repositoryId: string): Record<string, string>;
  /** The text of a file at a ref, a branch name or a commit; null when there is none. */
  fileAt(repositoryId: string, refOrSha: string, path: string): string | null;
  /** The repository's pull requests. */
  pullRequests(repositoryId: string): FakeAzurePullRequest[];
  /** What Azure DevOps will say of a pull request's merge (`conflicts`, `queued` ...). */
  setMergeStatus(repositoryId: string, prId: number, mergeStatus: string | null): void;
  /** Completes a pull request (the merge itself is not made). */
  completePullRequest(repositoryId: string, prId: number): void;
  /** A thread, as a person or another tool made it (the default author is the PAT's user). */
  addThread(repositoryId: string, prId: number, input?: FakeAzureThreadInput): FakeAzureThread;
  /** A system thread (`commentType: 'system'`, no status), as Azure DevOps writes for a push. */
  addSystemThread(repositoryId: string, prId: number, content?: string): FakeAzureThread;
  /** A comment added to a thread, as a person or another tool made it (id: the next free one). */
  addComment(
    repositoryId: string,
    prId: number,
    threadId: number,
    input: FakeAzureCommentInput,
  ): FakeAzureComment;
  /** The identities of the organisation: the PAT's user (owner), the principal (contributor), added ones. */
  readonly users: readonly FakeAzureUser[];
  /** A person with a role, to be looked up by id and asked about in the ACL. */
  addUser(input: FakeAzureUserInput): FakeAzureUser;
  /**
   * Where a client looks up identities: on Services the fake's second host, a prefix of its one
   * server (`<origin>/vssps/<org>`, which the test origin seam maps the `vssps` host to); on Server
   * the collection `url`.
   */
  readonly identitiesUrl: string;
  /** The service hook subscriptions, with the passwords the clients sent. */
  readonly subscriptions: readonly FakeAzureSubscription[];
  /** What Azure DevOps does to a subscription that fails (`onProbation`, `disabledBySystem`, ...). */
  setSubscriptionStatus(id: string, status: string): void;
  /** The queues of a project (agent pools as the project uses them), created on first use. */
  queues(projectId: string): FakeAzureQueue[];
  addQueue(
    projectId: string,
    input: { name: string; poolName?: string; hosted?: boolean; open?: boolean },
  ): FakeAzureQueue;
  /** The build definitions of every project, in creation order. */
  readonly definitions: readonly FakeAzureDefinition[];
  /** The policy configurations of every project (the Build policy type). */
  readonly policies: readonly FakeAzurePolicy[];
  /** The commit statuses posted, in order. */
  readonly commitStatuses: { repositoryId: string; sha: string; status: FakeAzureStatus }[];
  readonly requests: RecordedRequest[];
  /** The requests to the token endpoint (path from `/`). */
  readonly tokenRequests: RecordedRequest[];
  /** The next matching requests get these answers, in order, before the fake answers normally. */
  inject(method: string, path: RegExp, ...answers: InjectedAnswer[]): void;
  /** Forgets the recorded requests (not the state). */
  clearRequests(): void;
  close(): Promise<void>;
}

/**
 * Entra's refusals as Microsoft's error-code reference names them: status, `error`, AADSTS code
 * and text. Qualor reads none of it (any refusal is `token_endpoint`).
 */
const ENTRA_REFUSAL = {
  tenant: [400, 'invalid_request', 90002, 'Tenant not found.'],
  grant: [400, 'unsupported_grant_type', 70003, 'The app requested an unsupported grant type.'],
  client: [400, 'unauthorized_client', 700016, 'Application was not found in the directory.'],
  scope: [400, 'invalid_scope', 70011, "The value of the parameter 'scope' is not valid."],
  proof: [400, 'invalid_request', 7000218, "Neither 'client_assertion' nor 'client_secret' given."],
  wrongSecret: [401, 'invalid_client', 7000215, 'Invalid client secret provided.'],
  malformed: [401, 'invalid_client', 50027, 'JWT token is invalid or malformed.'],
  signature: [401, 'invalid_client', 700027, 'Client assertion failed signature validation.'],
  issuer: [401, 'invalid_client', 700021, "The assertion's issuer doesn't match 'client_id'."],
  lifetime: [401, 'invalid_client', 700024, 'Client assertion is not within its valid time range.'],
} as const;
type EntraRefusal = keyof typeof ENTRA_REFUSAL;

function send(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const json = body !== undefined && typeof body !== 'string';
  res.writeHead(status, {
    ...(json ? { 'content-type': 'application/json; charset=utf-8' } : {}),
    ...headers,
  });
  res.end(json ? JSON.stringify(body) : ((body as string | undefined) ?? ''));
}

/** The request as `requests` keeps it, once its body is read. */
function recorded(req: IncomingMessage, prefix: string): Promise<RecordedRequest> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    const [pathname = '/', query = ''] = (req.url ?? '/').split('?', 2) as [string, string?];
    const sub = pathname.startsWith(`${prefix}/`) ? pathname.slice(prefix.length) : pathname;
    const done = () =>
      resolve({
        method: req.method ?? '',
        path: sub,
        query,
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', done);
    req.on('error', done);
  });
}

function listen(server: Server | HttpsServer): Promise<number> {
  return new Promise((resolve) =>
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port)),
  );
}

function closeServer(server: Server | HttpsServer): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

/** A credential that has the form of a classic PAT (52 base32 characters). */
function newPat(): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  return Array.from({ length: 52 }, () => alphabet[randomInt(alphabet.length)]).join('');
}

const decoded = (part: string): Record<string, unknown> =>
  JSON.parse(Buffer.from(part, 'base64url').toString()) as Record<string, unknown>;

/** Why a client assertion is refused, or null. */
function assertionProblem(
  assertion: string,
  expected: {
    clientId: string;
    audience: string;
    certificate: X509Certificate | null;
    now: number;
  },
): EntraRefusal | null {
  const { certificate } = expected;
  const [header = '', claims = '', signature = '', ...rest] = assertion.split('.');
  let h: Record<string, unknown>;
  let c: Record<string, unknown>;
  try {
    h = decoded(header);
    c = decoded(claims);
  } catch {
    return 'malformed';
  }
  if (!certificate || rest.length > 0 || h.alg !== 'RS256') return 'signature';
  if (h.x5t !== createHash('sha1').update(certificate.raw).digest('base64url')) return 'signature';
  const signed = Buffer.from(`${header}.${claims}`);
  if (!verify('sha256', signed, certificate.publicKey, Buffer.from(signature, 'base64url'))) {
    return 'signature';
  }
  if (c.aud !== expected.audience || typeof c.jti !== 'string' || c.jti === '') return 'malformed';
  if (c.iss !== expected.clientId || c.sub !== expected.clientId) return 'issuer';
  const seconds = Math.floor(expected.now / 1000);
  if (typeof c.nbf !== 'number' || typeof c.exp !== 'number') return 'malformed';
  return c.nbf > seconds + CLOCK_SKEW_SECONDS || c.exp <= seconds ? 'lifetime' : null;
}

export async function createFakeAzureDevOps(options: {
  deployment: FakeAzureDeployment;
  pat?: string;
  principal?: FakeAzurePrincipal;
  identityAdded?: boolean;
  repositories?: FakeAzureRepositoryInput[];
  /** The fake Entra's clock (assertion lifetimes, token expiry). */
  now?: () => number;
}): Promise<FakeAzureDevOps> {
  const { deployment, principal } = options;
  if (principal && deployment === 'server') {
    throw new Error('fake Azure DevOps: Azure DevOps Server takes a personal access token only');
  }
  if (principal && !principal.secret && !principal.certificatePem) {
    throw new Error('fake Azure DevOps: the principal needs a secret or a certificate');
  }
  const certificatePem = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(
    principal?.certificatePem ?? '',
  )?.[0];
  const certificate = certificatePem ? new X509Certificate(certificatePem) : null;
  const now = options.now ?? Date.now;
  const pat = options.pat ?? newPat();
  const basePath = BASE_PATH[deployment];
  const patUser: FakeAzureIdentity =
    deployment === 'services'
      ? { id: 'c0ffee00-0000-4000-8000-000000000001', displayName: 'qualor-bot@example.com' }
      : { id: 'c0ffee00-0000-4000-8000-000000000002', displayName: 'Qualor Bot' };
  const principalUser: FakeAzureIdentity | null = principal
    ? { id: 'c0ffee00-0000-4000-8000-000000000003', displayName: 'Qualor Azure App' }
    : null;
  const requests: RecordedRequest[] = [];
  const tokenRequests: RecordedRequest[] = [];
  const PAT_DESCRIPTOR = azureShape<{ body: { value: { descriptor: string }[] } }>(
    'services',
    '20-identities-pat-user',
  ).body.value[0]!.descriptor;
  const PRINCIPAL_DESCRIPTOR = azureShape<{ body: { value: { descriptor: string }[] } }>(
    'services',
    '20-identities-service-principal',
  ).body.value[0]!.descriptor;
  const injections: Injection[] = [];
  const repositories: FakeAzureRepository[] = [];
  const projectIds = new Map<string, string>();
  /** Pull requests by `<repository id>#<id>`; files by `<repository id>@<commit>:<path>`. */
  const pullRequests = new Map<string, FakeAzurePullRequest>();
  /** Commits by `<repository id>@<sha>`; refs by repository id, then full ref name. */
  const commits = new Map<string, { parents: string[]; files: Map<string, Buffer> }>();
  const refsOf = new Map<string, Map<string, string>>();
  const repoRefs = (repoId: string) => {
    const known = refsOf.get(repoId);
    if (known) return known;
    const created = new Map<string, string>();
    refsOf.set(repoId, created);
    return created;
  };
  const commitOf = (repoId: string, sha: string) => commits.get(`${repoId}@${sha.toLowerCase()}`);
  const ensureCommit = (repoId: string, sha: string) => {
    const key = `${repoId}@${sha.toLowerCase()}`;
    let commit = commits.get(key);
    if (!commit) {
      commit = { parents: [], files: new Map() };
      commits.set(key, commit);
    }
    return commit;
  };
  /** A ref name, a branch name or a commit id as a commit id (null: nothing there). */
  const resolveCommit = (repoId: string, version: string, type = 'commit'): string | null => {
    const refs = repoRefs(repoId);
    const named =
      type === 'branch' || type === 'tag'
        ? refs.get(`refs/${type === 'tag' ? 'tags' : 'heads'}/${version}`)
        : undefined;
    return named ?? (commitOf(repoId, version) ? version.toLowerCase() : null);
  };
  /** Every commit reachable from `sha` (itself included). */
  const ancestorsOf = (repoId: string, sha: string): Set<string> => {
    const seen = new Set<string>();
    const todo = [sha.toLowerCase()];
    for (let next = todo.pop(); next !== undefined; next = todo.pop()) {
      if (seen.has(next)) continue;
      seen.add(next);
      todo.push(...(commitOf(repoId, next)?.parents ?? []));
    }
    return seen;
  };
  let commitCounter = 0;
  const newCommitId = (seed: string) =>
    createHash('sha1')
      .update(`${seed}#${(commitCounter += 1)}#${randomUUID()}`)
      .digest('hex');
  const commitStatuses: FakeAzureDevOps['commitStatuses'] = [];
  let threadCounter = 0;
  let statusCounter = 0;
  const users: FakeAzureUser[] = [];
  const subscriptions: FakeAzureSubscription[] = [];
  const clock = () => new Date(now()).toISOString();
  /** Issued bearer tokens: how the principal proved itself, and until when the token holds. */
  const tokens = new Map<string, { how: 'secret' | 'certificate'; expiresAt: number }>();
  let url = '';
  let tokenOrigin = '';

  const wrongPat = recordedAnswer(deployment, '10-wrong-pat');
  const noCredential = recordedAnswer(deployment, '10-no-credential');
  const notFound = azureShape<{ body: Record<string, unknown> }>(deployment, '10-not-found').body;
  type Event = { body: { resource: { repository: Record<string, unknown> } } };
  const { project: recordedProject, ...recordedRepository } = azureShape<Event>(
    deployment,
    '9-event-pr-updated',
  ).body.resource.repository;
  const listEnvelope = azureShape<{ body: Record<string, unknown> }>(deployment, '7-policy-types');

  const wrapped = (res: ServerResponse, status: number, message: string, typeKey: string) =>
    send(
      res,
      status,
      { ...notFound, message, typeName: typeKey, typeKey },
      { 'content-type': JSON_7_0 },
    );

  const identityAnswer = (res: ServerResponse, kind: 'pat' | 'secret' | 'certificate') => {
    type Users = {
      authenticatedUser: Record<string, unknown>;
      authorizedUser: Record<string, unknown>;
    };
    const shape = azureShape<{ contentType: string; body: Users }>(
      deployment,
      `1-connectiondata-${kind}`,
    );
    const who = kind === 'pat' ? patUser : principalUser!;
    const account = kind === 'pat' ? who.displayName : principal!.clientId;
    const overlay = (user: Record<string, unknown>) => ({
      ...user,
      id: who.id,
      providerDisplayName: who.displayName,
      ...('customDisplayName' in user ? { customDisplayName: who.displayName } : {}),
      properties: { Account: { $type: 'System.String', $value: account } },
    });
    const { authenticatedUser, authorizedUser } = shape.body;
    const body = {
      ...shape.body,
      authenticatedUser: overlay(authenticatedUser),
      authorizedUser: overlay(authorizedUser),
    };
    send(res, 200, body, { 'content-type': shape.contentType });
  };

  // Identities, the ACL and the hooks are recorded on Services (items 20 and 9); Server answers the same forms.
  type Answer<T> = { body: T };
  type RecordedIdentity = Record<string, unknown>;
  const recordedIdentity = azureShape<Answer<{ value: RecordedIdentity[] }>>(
    'services',
    '20-identities-pat-user',
  ).body.value[0]!;
  const recordedPrincipalIdentity = azureShape<Answer<{ value: RecordedIdentity[] }>>(
    'services',
    '20-identities-service-principal',
  ).body.value[0]!;
  type RecordedAce = Record<string, unknown> & { extendedInfo: Record<string, unknown> };
  type RecordedAcl = Record<string, unknown> & { acesDictionary: Record<string, RecordedAce> };
  const aceOf = (shape: Answer<{ value: RecordedAcl[] }>): RecordedAce =>
    Object.values(shape.body.value[0]!.acesDictionary)[0]!;
  const recordedAcl = azureShape<Answer<{ value: RecordedAcl[] }>>('services', '20-acl-pat-user')
    .body.value[0]!;
  const ACE_BY_ROLE: Record<FakeAzureRole, RecordedAce> = {
    owner: aceOf(azureShape('services', '20-acl-pat-user')),
    contributor: aceOf(azureShape('services', '20-acl-service-principal')),
    reader: aceOf(azureShape('server', '16-acl-reader')),
  };
  const recordedSubscription = azureShape<Answer<Record<string, unknown>>>(
    deployment,
    '9-subscription-comment',
  ).body;
  const recordedHttpRefusal = recordedAnswer(deployment, '9-subscription-http-basic-auth');
  const eventTypes = azureShape<{
    pullRequestEvents: { id: string; supportedResourceVersions: string[] }[];
  }>(deployment, '9-event-types').pullRequestEvents;

  const subjectOf = (id: string) => `aad.${Buffer.from(id).toString('base64url')}`;
  const addUserTo = (input: FakeAzureUserInput): FakeAzureUser => {
    const id = (input.id ?? randomUUID()).toLowerCase();
    const displayName = input.displayName ?? `User ${id.slice(0, 8)}`;
    const user: FakeAzureUser = {
      id,
      displayName,
      role: input.role,
      descriptor:
        input.descriptor ??
        `Microsoft.IdentityModel.Claims.ClaimsIdentity;ado.example.invalid\\${id.slice(0, 8)}@example.invalid`,
      subjectDescriptor: subjectOf(id),
    };
    users.push(user);
    return user;
  };
  const userById = (id: string) => users.find((u) => u.id === id.toLowerCase());
  const userByDescriptor = (descriptor: string) =>
    users.find((u) => u.descriptor.toLowerCase() === descriptor.toLowerCase());

  const repositoryJson = (r: FakeAzureRepository) => {
    const web = `${url}/${encodeURIComponent(r.projectName)}/_git/${encodeURIComponent(r.name)}`;
    return {
      ...recordedRepository,
      id: r.id,
      name: r.name,
      url: `${url}/${r.projectId}/_apis/git/repositories/${r.id}`,
      project: {
        ...(recordedProject as Record<string, unknown>),
        id: r.projectId,
        name: r.projectName,
        url: `${url}/_apis/projects/${r.projectId}`,
      },
      ...(r.defaultBranch === null ? {} : { defaultBranch: `refs/heads/${r.defaultBranch}` }),
      remoteUrl: web,
      webUrl: web,
      isDisabled: r.isDisabled,
    };
  };

  const tf401444 = (res: ServerResponse) => {
    const message = `TF401444: Please sign-in at least once as ${principal!.tenantId}\\${principal!.clientId} in a web browser to enable access to the service.`;
    const body = {
      ...notFound,
      message,
      typeName: TF401444_TYPE,
      typeKey: 'UnauthorizedRequestException',
    };
    send(res, 401, body, {
      ...wrongPat.headers,
      'content-type': 'application/json; charset=utf-8',
      'x-tfs-serviceerror': encodeURIComponent(message),
    });
  };

  /** Who the request is: the PAT's user, the service principal, nobody, or a refused credential. */
  const authenticate = (
    header: string | undefined,
  ): 'pat' | 'secret' | 'certificate' | 'none' | 'wrong' => {
    if (!header) return 'none';
    const [scheme = '', value = ''] = header.split(' ', 2);
    if (/^basic$/i.test(scheme)) {
      const text = Buffer.from(value, 'base64').toString('utf8');
      const colon = text.indexOf(':');
      return colon >= 0 && text.slice(colon + 1) === pat ? 'pat' : 'wrong';
    }
    const token =
      /^bearer$/i.test(scheme) && deployment === 'services' ? tokens.get(value) : undefined;
    return token && token.expiresAt > now() ? token.how : 'wrong';
  };

  const unknownRepository = (res: ServerResponse, id: string) => {
    const message = String(notFound.message).replace(
      /[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/i,
      id,
    );
    send(res, 404, { ...notFound, message }, { 'content-type': 'application/json; charset=utf-8' });
  };

  // The recorded objects the decoration routes lay their values over.
  const recordedPullRequest = azureShape<Event>(deployment, '9-event-pr-updated').body
    .resource as unknown as Record<string, unknown>;
  const recordedThread = azureShape<{ body: { value: Record<string, unknown>[] } }>(
    deployment,
    '3-thread-list',
  ).body.value[0]!;
  const recordedComment = (recordedThread.comments as Record<string, unknown>[])[0]!;
  const recordedPrStatus = azureShape<{ body: Record<string, unknown> }>(
    deployment,
    '7-pr-status-iteration',
  ).body;
  const recordedCommitStatus = azureShape<{ body: Record<string, unknown> }>(
    deployment,
    '7-commit-status',
  ).body;
  const recordedChange = azureShape<{ body: { changeEntries: Record<string, unknown>[] } }>(
    deployment,
    '6-iteration-changes',
  ).body.changeEntries[0] as Record<string, unknown>;
  const recordedStatusPolicyRefusal = recordedAnswer(deployment, '7-pr-status-no-iteration');
  const recordedPropertiesRefusal = recordedAnswer(deployment, '3-thread-patch-add');
  const THREAD_STATUS_BY_NUMBER: Record<number, FakeAzureThreadStatus> = {
    1: 'active',
    2: 'fixed',
    3: 'wontFix',
    4: 'closed',
    5: 'byDesign',
    6: 'pending',
  };

  const commentJson = (
    r: FakeAzureRepository,
    p: FakeAzurePullRequest,
    t: FakeAzureThread,
    c: FakeAzureComment,
  ) => {
    const author = recordedComment.author as Record<string, unknown>;
    const who = userById(c.authorId);
    const rest = { ...recordedComment };
    delete rest.author;
    delete rest.content;
    return {
      ...rest,
      id: c.id,
      parentCommentId: c.parentCommentId,
      ...(c.isDeleted
        ? { isDeleted: true }
        : {
            author: {
              ...author,
              id: c.authorId,
              displayName: who?.displayName ?? c.authorId,
              ...(who ? { descriptor: who.subjectDescriptor } : {}),
            },
            content: c.content,
          }),
      publishedDate: c.publishedDate,
      lastUpdatedDate: c.publishedDate,
      lastContentUpdatedDate: c.publishedDate,
      commentType: c.commentType,
      _links: {
        self: {
          href: `${url}/_apis/git/repositories/${r.id}/pullRequests/${p.id}/threads/${t.id}/comments/${c.id}`,
        },
      },
    };
  };

  const threadJson = (r: FakeAzureRepository, p: FakeAzurePullRequest, t: FakeAzureThread) => {
    const rest = { ...recordedThread };
    delete rest.status;
    return {
      ...rest,
      pullRequestThreadContext: null,
      id: t.id,
      publishedDate: t.publishedDate,
      lastUpdatedDate: t.comments.at(-1)?.publishedDate ?? t.publishedDate,
      comments: t.comments.map((c) => commentJson(r, p, t, c)),
      ...(t.status === null ? {} : { status: t.status }),
      threadContext: t.threadContext,
      properties: {},
      _links: {
        self: {
          href: `${url}/_apis/git/repositories/${r.id}/pullRequests/${p.id}/threads/${t.id}`,
        },
      },
    };
  };

  const pullRequestJson = (r: FakeAzureRepository, p: FakeAzurePullRequest) => ({
    ...recordedPullRequest,
    repository: repositoryJson(r),
    pullRequestId: p.id,
    codeReviewId: p.id,
    status: p.status,
    isDraft: p.isDraft,
    title: p.title,
    description: p.description,
    sourceRefName: p.sourceRefName,
    targetRefName: p.targetRefName,
    mergeStatus: p.mergeStatus ?? undefined,
    ...(p.fork ? { forkSource: { repository: repositoryJson(r), name: p.sourceRefName } } : {}),
    lastMergeSourceCommit:
      p.headSha === null
        ? undefined
        : {
            commitId: p.headSha,
            url: `${url}/_apis/git/repositories/${r.id}/commits/${p.headSha}`,
          },
    url: `${url}/_apis/git/repositories/${r.id}/pullRequests/${p.id}`,
  });

  const statusJson = (s: FakeAzureStatus, id: number) => ({
    ...recordedPrStatus,
    ...(s.iterationId === null ? { iterationId: undefined } : { iterationId: s.iterationId }),
    id,
    // undefined drops out of the JSON: the answer has no `state` (it overlays the recording's).
    state: s.state ?? undefined,
    description: s.description,
    ...(s.targetUrl === null ? {} : { targetUrl: s.targetUrl }),
    context: { name: s.name, genre: s.genre },
    createdBy: {
      ...(recordedPrStatus.createdBy as Record<string, unknown>),
      id: s.authorId ?? patUser.id,
    },
  });

  const statusOf = (body: Record<string, unknown>): FakeAzureStatus | null => {
    const context = body.context as { genre?: unknown; name?: unknown } | undefined;
    if (
      typeof body.state !== 'string' ||
      typeof context?.genre !== 'string' ||
      typeof context.name !== 'string'
    ) {
      return null;
    }
    return {
      iterationId: typeof body.iterationId === 'number' ? body.iterationId : null,
      state: body.state,
      description: typeof body.description === 'string' ? body.description : '',
      targetUrl: typeof body.targetUrl === 'string' ? body.targetUrl : null,
      genre: context.genre,
      name: context.name,
    };
  };

  const putStatus = (list: FakeAzureStatus[], status: FakeAzureStatus, id: number) => {
    list.push({ ...status, id });
  };

  const jsonBodyOf = (req: RecordedRequest): Record<string, unknown> | null => {
    try {
      const parsed: unknown = JSON.parse(req.body);
      return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  };

  const recordedPush = azureShape<{ body: Record<string, unknown> }>(
    'services',
    '22-push-new-branch',
  ).body;
  const recordedRefUpdate = azureShape<{ body: { value: Record<string, unknown>[] } }>(
    'services',
    '22-ref-move',
  ).body.value[0] as Record<string, unknown>;
  const recordedRef = azureShape<{ body: { value: Record<string, unknown>[] } }>(
    'services',
    '22-refs-prefix',
  ).body.value[0] as Record<string, unknown>;
  const recordedDiff = azureShape<{ body: Record<string, unknown> }>(
    'services',
    '22-ancestry-diverged',
  ).body;
  const recordedPushRefusal = recordedAnswer('services', '22-push-force-move');
  const recordedDescriptionRefusal = recordedAnswer('services', '22-pr-description-4001');
  const MAX_DESCRIPTION = 4000;
  interface FakePushChange {
    changeType?: string;
    item?: { path?: string };
    newContent?: { content?: string; contentType?: string };
  }
  const ZERO_ID = '0'.repeat(40);

  /** The routes of fix branches and pull requests (sub-plan 6); true when the request is one of them. */
  const fixRoute = (
    req: RecordedRequest,
    res: ServerResponse,
    repository: FakeAzureRepository,
    rest: string,
    query: URLSearchParams,
  ): boolean => {
    const answerJson = (status: number, body: unknown) =>
      send(res, status, body, { 'content-type': JSON_7_0 });
    const badRequest = (text: string) =>
      wrapped(res, 400, `fake Azure DevOps: ${text}`, 'ArgumentException');
    const refs = repoRefs(repository.id);
    const refJson = (name: string, objectId: string) => ({
      ...recordedRef,
      name,
      objectId,
      url: `${url}/_apis/git/repositories/${repository.id}/refs?filter=${encodeURIComponent(name.replace(/^refs\//, ''))}`,
    });

    if (rest === 'refs' && req.method === 'GET') {
      const filter = query.get('filter') ?? '';
      const value = [...refs]
        .filter(([name]) => name.startsWith(`refs/${filter}`))
        .map(([name, objectId]) => refJson(name, objectId));
      answerJson(200, { value, count: value.length });
      return true;
    }

    if (rest === 'refs' && req.method === 'POST') {
      let updates: unknown;
      try {
        updates = JSON.parse(req.body);
      } catch {
        updates = null;
      }
      if (!Array.isArray(updates)) {
        badRequest('ref updates are an array');
        return true;
      }
      const value = (updates as Record<string, unknown>[]).map((u) => {
        const name = String(u.name);
        const old = String(u.oldObjectId ?? ZERO_ID).toLowerCase();
        const next = String(u.newObjectId ?? ZERO_ID).toLowerCase();
        const current = refs.get(name);
        const done = (updateStatus: string, success = true) => ({
          ...recordedRefUpdate,
          repositoryId: repository.id,
          name,
          oldObjectId: old,
          newObjectId: next,
          updateStatus,
          success,
        });
        if (next === ZERO_ID) {
          if (current === undefined) return done('succeededNonExistentRef');
          refs.delete(name);
          return done(current === old ? 'succeeded' : 'succeededCorruptRef');
        }
        if ((current ?? ZERO_ID) !== old) return done('staleOldObjectId', false);
        if (!commitOf(repository.id, next)) return done('invalidObjectId', false);
        refs.set(name, next);
        return done('succeeded');
      });
      answerJson(200, { value, count: value.length });
      return true;
    }

    if (rest === 'pushes' && req.method === 'POST') {
      const body = jsonBodyOf(req);
      const update = (body?.refUpdates as Record<string, unknown>[] | undefined)?.[0];
      const made = (body?.commits as Record<string, unknown>[] | undefined)?.[0];
      const parent = (made?.parents as unknown[] | undefined)?.[0];
      if (!update || !made || typeof update.name !== 'string' || typeof parent !== 'string') {
        badRequest('a push is one ref update and one commit with a parent');
        return true;
      }
      const name = update.name;
      const old = String(update.oldObjectId ?? ZERO_ID).toLowerCase();
      const current = refs.get(name);
      const parentCommit = commitOf(repository.id, parent);
      // Item 22d and 22e: a parent that is not the head and a stale old id are the same 400.
      if (
        !parentCommit ||
        (current ?? ZERO_ID) !== old ||
        (current !== undefined && current !== parent.toLowerCase())
      ) {
        send(
          res,
          recordedPushRefusal.status,
          recordedPushRefusal.body,
          recordedPushRefusal.headers,
        );
        return true;
      }
      const edited = new Map(parentCommit.files);
      for (const change of (made.changes as FakePushChange[] | undefined) ?? []) {
        const filePath = String(change.item?.path ?? '').replace(/^\//, '');
        const content = change.newContent as { content?: string; contentType?: string } | undefined;
        if (!filePath || typeof content?.content !== 'string') {
          badRequest('a change needs a path and content');
          return true;
        }
        if (change.changeType === 'edit' && !edited.has(filePath)) {
          badRequest(`the file ${filePath} cannot be edited, it is not in the parent`);
          return true;
        }
        edited.set(
          filePath,
          content.contentType === 'base64encoded'
            ? Buffer.from(content.content, 'base64')
            : Buffer.from(content.content),
        );
      }
      const id = newCommitId(`${parent}${String(made.comment)}`);
      commits.set(`${repository.id}@${id}`, { parents: [parent.toLowerCase()], files: edited });
      refs.set(name, id);
      const [recordedCommit] = recordedPush.commits as Record<string, unknown>[];
      answerJson(201, {
        ...recordedPush,
        commits: [
          {
            ...recordedCommit,
            commitId: id,
            comment: made.comment,
            parents: [parent.toLowerCase()],
          },
        ],
        refUpdates: [{ repositoryId: repository.id, name, oldObjectId: old, newObjectId: id }],
        repository: repositoryJson(repository),
      });
      return true;
    }

    if (rest === 'diffs/commits' && req.method === 'GET') {
      const base = resolveCommit(repository.id, query.get('baseVersion') ?? '');
      const target = resolveCommit(repository.id, query.get('targetVersion') ?? '');
      if (!base || !target) {
        wrapped(res, 404, 'TF401175: The commit does not exist.', 'GitCommitDoesNotExistException');
        return true;
      }
      const fromBase = ancestorsOf(repository.id, base);
      const fromTarget = ancestorsOf(repository.id, target);
      const shared = [...fromBase].filter((c) => fromTarget.has(c));
      // The merge base: a shared commit no other shared commit descends from.
      const best = shared.find(
        (c) => !shared.some((o) => o !== c && ancestorsOf(repository.id, o).has(c)),
      );
      answerJson(200, {
        ...recordedDiff,
        changes: [],
        changeCounts: {},
        ...(best === undefined ? { commonCommit: undefined } : { commonCommit: best }),
        baseCommit: base,
        targetCommit: target,
        aheadCount: [...fromTarget].filter((c) => !fromBase.has(c)).length,
        behindCount: [...fromBase].filter((c) => !fromTarget.has(c)).length,
      });
      return true;
    }

    if (rest === 'pullrequests' && req.method === 'GET') {
      const status = query.get('searchCriteria.status') ?? 'active';
      const source = query.get('searchCriteria.sourceRefName');
      const target = query.get('searchCriteria.targetRefName');
      const value = [...pullRequests]
        .filter(([key]) => key.startsWith(`${repository.id}#`))
        .map(([, p]) => p)
        .filter(
          (p) =>
            (status === 'all' || p.status === status) &&
            (source === null || p.sourceRefName === source) &&
            (target === null || p.targetRefName === target),
        )
        .map((p) => {
          // A listed pull request has a minimal repository (item 22g): no web URL.
          const { id, name, url: repositoryUrl, project } = repositoryJson(repository);
          return {
            ...pullRequestJson(repository, p),
            repository: { id, name, url: repositoryUrl, project },
          };
        });
      answerJson(200, { value, count: value.length });
      return true;
    }

    if (rest === 'pullrequests' && req.method === 'POST') {
      const body = jsonBodyOf(req);
      if (
        !body ||
        typeof body.sourceRefName !== 'string' ||
        typeof body.targetRefName !== 'string' ||
        typeof body.title !== 'string'
      ) {
        badRequest('a pull request needs source, target and a title');
        return true;
      }
      const description = typeof body.description === 'string' ? body.description : '';
      if (description.length > MAX_DESCRIPTION) {
        send(
          res,
          recordedDescriptionRefusal.status,
          recordedDescriptionRefusal.body,
          recordedDescriptionRefusal.headers,
        );
        return true;
      }
      const sourceHead = refs.get(body.sourceRefName);
      if (sourceHead === undefined || !refs.has(body.targetRefName)) {
        badRequest('the source and the target branch must exist');
        return true;
      }
      const pr = fake.addPullRequest(repository.id, {
        title: body.title,
        description,
        sourceRefName: body.sourceRefName,
        targetRefName: body.targetRefName,
        headSha: sourceHead,
      });
      answerJson(201, pullRequestJson(repository, pr));
      return true;
    }

    return false;
  };

  const gitRoute = (
    req: RecordedRequest,
    res: ServerResponse,
    who: 'pat' | 'secret' | 'certificate',
    repositoryId: string,
    rest: string,
    version: string,
  ): void => {
    const answerJson = (status: number, body: unknown) =>
      send(res, status, body, { 'content-type': JSON_7_0 });
    const missing = (text: string, typeKey: string) => wrapped(res, 404, text, typeKey);
    const bad = (text: string) =>
      wrapped(res, 400, `fake Azure DevOps: ${text}`, 'ArgumentException');
    const refuse = (answerOf: InjectedAnswer) =>
      send(res, answerOf.status, answerOf.body, answerOf.headers);
    if (version !== '7.0') {
      const text = `fake Azure DevOps: this route is not asked at api-version ${version}`;
      return wrapped(res, 400, text, 'VssInvalidPreviewVersionException');
    }
    const repository = repositories.find((r) => r.id === repositoryId.toLowerCase());
    if (!repository) return unknownRepository(res, repositoryId);
    const authorId = who === 'pat' ? patUser.id : principalUser!.id;
    const query = new URLSearchParams(req.query);

    const commitRoute = /^commits\/([0-9a-fA-F]+)\/statuses$/.exec(rest);
    if (commitRoute && req.method === 'POST') {
      const body = jsonBodyOf(req);
      const status = body && statusOf(body);
      if (!status) return bad('a commit status needs a state and a context');
      statusCounter += 1;
      commitStatuses.push({
        repositoryId: repository.id,
        sha: commitRoute[1]!.toLowerCase(),
        status,
      });
      return answerJson(201, {
        ...recordedCommitStatus,
        ...statusJson(status, statusCounter),
        iterationId: undefined,
      });
    }

    if (rest === 'items' && req.method === 'GET' && query.get('scopePath') !== null) {
      if (query.get('scopePath') !== '/' || query.get('recursionLevel') !== 'OneLevel') {
        return bad('only the root with recursionLevel=OneLevel is listed');
      }
      const listed = rootItemsAnswer(
        repository,
        query.get('versionDescriptor.version') ?? '',
        query.get('versionDescriptor.versionType') ?? 'commit',
      );
      return answerJson(listed.status, listed.body);
    }

    if (rest === 'items' && req.method === 'GET') {
      const path = query.get('path') ?? '';
      const version = (query.get('versionDescriptor.version') ?? '').toLowerCase();
      const commit =
        resolveCommit(
          repository.id,
          version,
          query.get('versionDescriptor.versionType') ?? 'commit',
        ) ?? version;
      const content = commitOf(repository.id, commit)?.files.get(path.replace(/^\//, ''));
      if (content && query.get('$format') === 'octetStream') {
        res.writeHead(200, { 'content-type': 'text/plain; api-version=7.0' });
        res.end(content);
        return;
      }
      if (!content) {
        return missing(
          `TF401174: The item could not be found at commit ${commit}.`,
          'GitItemNotFoundException',
        );
      }
      const binary = content.includes(0);
      return answerJson(200, {
        objectId: createHash('sha1').update(content).digest('hex'),
        gitObjectType: 'blob',
        commitId: commit,
        path: path.startsWith('/') ? path : `/${path}`,
        ...(binary ? {} : { content: content.toString('utf8') }),
        contentMetadata: { fileName: path.split('/').pop(), isBinary: binary },
      });
    }

    if (fixRoute(req, res, repository, rest, query)) return;

    const prRoute = /^pullrequests\/(\d+)(?:\/(.*))?$/.exec(rest);
    if (!prRoute) return missing('fake Azure DevOps: no such route', 'NotFound');
    const pr = pullRequests.get(`${repository.id}#${prRoute[1]}`);
    if (!pr) {
      return missing(
        `TF401180: The requested pull request, ${prRoute[1]}, was not found.`,
        'GitPullRequestNotFoundException',
      );
    }
    const sub = prRoute[2] ?? '';
    const { method } = req;

    if (sub === '' && method === 'GET') return answerJson(200, pullRequestJson(repository, pr));

    if (sub === '' && method === 'PATCH') {
      const body = jsonBodyOf(req);
      if (!body) return bad('a pull request update is a JSON object');
      if (typeof body.description === 'string' && body.description.length > MAX_DESCRIPTION) {
        return refuse(recordedDescriptionRefusal);
      }
      if (typeof body.title === 'string') pr.title = body.title;
      if (typeof body.description === 'string') pr.description = body.description;
      if (body.status === 'abandoned' || body.status === 'active') pr.status = body.status;
      return answerJson(200, pullRequestJson(repository, pr));
    }

    if (sub === 'iterations' && method === 'GET') {
      const value = pr.iterations.map((i) => ({
        id: i.id,
        sourceRefCommit: { commitId: i.sourceRefCommit },
        commonRefCommit: { commitId: i.commonRefCommit },
        targetRefCommit: { commitId: i.targetRefCommit },
      }));
      return answerJson(200, { count: value.length, value });
    }

    const iterationRoute = /^iterations\/(\d+)\/(changes|statuses)$/.exec(sub);
    if (iterationRoute) {
      const iteration = pr.iterations.find((i) => i.id === Number(iterationRoute[1]));
      if (!iteration)
        return missing('TF401190: The iteration does not exist.', 'GitIterationNotFoundException');
      if (iterationRoute[2] === 'changes' && method === 'GET') {
        const top = Number(query.get('$top') ?? 100);
        const skip = Number(query.get('$skip') ?? 0);
        const page = iteration.changes.slice(skip, skip + top);
        const changeEntries = page.map((c, i) => ({
          ...recordedChange,
          changeTrackingId: c.changeTrackingId ?? skip + i + 1,
          changeId: skip + i + 1,
          item: { objectId: createHash('sha1').update(c.path).digest('hex'), path: `/${c.path}` },
          changeType: c.changeType ?? 'edit',
          ...(c.originalPath === undefined ? {} : { originalPath: `/${c.originalPath}` }),
        }));
        const more = skip + top < iteration.changes.length;
        return answerJson(200, {
          changeEntries,
          ...(more ? { nextTop: top, nextSkip: skip + top } : {}),
        });
      }
      if (iterationRoute[2] === 'statuses' && method === 'GET') {
        const value = iteration.statuses
          .map((s, i) => statusJson(s, s.id ?? i + 1))
          .sort((a, b) => b.id - a.id);
        return answerJson(200, { count: value.length, value });
      }
    }

    if (sub === 'statuses' && method === 'POST') {
      const body = jsonBodyOf(req);
      const parsed = body && statusOf(body);
      if (!parsed) return bad('a status needs a state and a context');
      const status = { ...parsed, authorId };
      const listed = [pr.statuses, ...pr.iterations.map((i) => i.statuses)].flat();
      statusCounter = Math.max(statusCounter, ...listed.map((x) => x.id ?? 0)) + 1;
      if (status.iterationId === null) {
        if (pr.statusPolicy) return refuse(recordedStatusPolicyRefusal);
        putStatus(pr.statuses, status, statusCounter);
      } else {
        const iteration = pr.iterations.find((i) => i.id === status.iterationId);
        if (!iteration) return bad(`the pull request has no iteration ${status.iterationId}`);
        putStatus(iteration.statuses, status, statusCounter);
      }
      return answerJson(200, statusJson(status, statusCounter));
    }

    if (sub === 'threads' && method === 'GET') {
      const value = pr.threads.map((t) => threadJson(repository, pr, t));
      return answerJson(200, { value, count: value.length });
    }

    if (sub === 'threads' && method === 'POST') {
      const body = jsonBodyOf(req);
      const comment = (body?.comments as { content?: unknown }[] | undefined)?.[0];
      if (!body || typeof comment?.content !== 'string') return bad('a thread needs a comment');
      const status = THREAD_STATUS_BY_NUMBER[Number(body.status)];
      if (!status) return bad('unknown thread status');
      const threadContext = (body.threadContext ?? null) as Record<string, unknown> | null;
      const thread = addThreadTo(pr, {
        status,
        threadContext,
        comments: [{ content: comment.content, authorId }],
      });
      return answerJson(200, threadJson(repository, pr, thread));
    }

    const threadRoute = /^threads\/(\d+)(?:\/comments(?:\/(\d+))?)?$/.exec(sub);
    const thread = threadRoute && pr.threads.find((t) => t.id === Number(threadRoute[1]));
    if (threadRoute && !thread)
      return missing('TF401152: The thread does not exist.', 'GitThreadNotFoundException');
    if (threadRoute && thread) {
      const isComments = sub.includes('/comments');
      if (!isComments && method === 'GET')
        return answerJson(200, threadJson(repository, pr, thread));
      if (!isComments && method === 'PATCH') {
        const body = jsonBodyOf(req);
        if (!body) return bad('a thread update is a JSON object');
        if ('properties' in body) return refuse(recordedPropertiesRefusal);
        if ('status' in body) {
          const status = THREAD_STATUS_BY_NUMBER[Number(body.status)];
          if (!status) return bad('unknown thread status');
          thread.status = status;
        }
        return answerJson(200, threadJson(repository, pr, thread));
      }
      if (isComments && threadRoute[2] === undefined && method === 'POST') {
        const body = jsonBodyOf(req);
        if (!body || typeof body.content !== 'string') return bad('a comment has content');
        const comment: FakeAzureComment = {
          id: Math.max(0, ...thread.comments.map((c) => c.id)) + 1,
          authorId,
          content: body.content,
          commentType: 'text',
          parentCommentId: typeof body.parentCommentId === 'number' ? body.parentCommentId : 0,
          publishedDate: clock(),
          isDeleted: false,
        };
        thread.comments.push(comment);
        return answerJson(200, commentJson(repository, pr, thread, comment));
      }
      if (isComments && threadRoute[2] !== undefined && method === 'PATCH') {
        const comment = thread.comments.find((c) => c.id === Number(threadRoute[2]));
        if (!comment)
          return missing('TF401153: The comment does not exist.', 'GitCommentNotFoundException');
        const body = jsonBodyOf(req);
        if (!body || typeof body.content !== 'string') return bad('a comment has content');
        comment.content = body.content;
        return answerJson(200, commentJson(repository, pr, thread, comment));
      }
    }
    return missing('fake Azure DevOps: no such route', 'NotFound');
  };

  const addThreadTo = (
    pr: FakeAzurePullRequest,
    input: {
      status: FakeAzureThreadStatus | null;
      threadContext: Record<string, unknown> | null;
      comments: FakeAzureCommentInput[];
    },
  ): FakeAzureThread => {
    const context = input.threadContext as {
      filePath?: string;
      rightFileStart?: { line?: number };
    } | null;
    threadCounter += 1;
    const thread: FakeAzureThread = {
      id: threadCounter,
      status: input.status,
      filePath: context?.filePath?.replace(/^\//, '') ?? null,
      line: context?.rightFileStart?.line ?? null,
      threadContext: input.threadContext,
      publishedDate: '',
      comments: input.comments.map((c, i) => ({
        id: i + 1,
        authorId: c.authorId ?? patUser.id,
        content: c.content,
        commentType: c.commentType ?? 'text',
        parentCommentId: c.parentCommentId ?? 0,
        publishedDate: c.publishedDate ?? clock(),
        isDeleted: c.isDeleted ?? false,
      })),
    };
    thread.publishedDate = thread.comments[0]?.publishedDate ?? clock();
    pr.threads.push(thread);
    return thread;
  };

  const hookBody = (
    res: ServerResponse,
    status: number,
    message: string,
    typeKey = 'SubscriptionInputException',
  ) => wrapped(res, status, message, typeKey);

  const subscriptionJson = (
    s: FakeAzureSubscription,
    callerId: string,
    createdAt: string,
    modifiedAt: string,
  ) => {
    const caller = userById(callerId)!;
    const person = {
      displayName: caller.displayName,
      id: caller.id,
      uniqueName: '',
      descriptor: caller.subjectDescriptor,
    };
    const self = `${url}/_apis/hooks/subscriptions/${s.id}`;
    return {
      ...recordedSubscription,
      id: s.id,
      url: self,
      status: s.status,
      eventType: s.eventType,
      resourceVersion: s.resourceVersion,
      createdBy: person,
      createdDate: createdAt,
      modifiedBy: person,
      modifiedDate: modifiedAt,
      publisherInputs: {
        projectId: s.projectId,
        ...(s.repositoryId === null ? {} : { repository: s.repositoryId }),
        ...(s.branch === null ? {} : { branch: s.branch }),
        tfsSubscriptionId: randomUUID(),
      },
      consumerInputs: {
        basicAuthUsername: s.username,
        detailedMessagesToSend: 'all',
        messagesToSend: 'all',
        resourceDetailsToSend: 'all',
        url: s.url,
        basicAuthPassword: '********',
      },
      _links: {
        ...(recordedSubscription._links as Record<string, unknown>),
        self: { href: self },
        notifications: { href: `${self}/notifications` },
      },
    };
  };

  /** What a POST or a PUT of a subscription says, or the reason it is refused (400). */
  const subscriptionFrom = (
    res: ServerResponse,
    req: RecordedRequest,
    id: string,
  ): Omit<FakeAzureSubscription, 'status'> | null => {
    const body = jsonBodyOf(req);
    const publisher = (body?.publisherInputs ?? {}) as Record<string, unknown>;
    const consumer = (body?.consumerInputs ?? {}) as Record<string, unknown>;
    const event = eventTypes.find((e) => e.id === body?.eventType);
    const text = (v: unknown) => (typeof v === 'string' && v !== '' ? v : null);
    if (
      !body ||
      body.publisherId !== 'tfs' ||
      body.consumerId !== 'webHooks' ||
      body.consumerActionId !== 'httpRequest'
    ) {
      hookBody(res, 400, 'fake Azure DevOps: a subscription is tfs to webHooks httpRequest');
      return null;
    }
    if (!event) {
      hookBody(res, 400, `fake Azure DevOps: unknown event type ${String(body.eventType)}`);
      return null;
    }
    if (!event.supportedResourceVersions.includes(String(body.resourceVersion))) {
      hookBody(
        res,
        400,
        `fake Azure DevOps: ${event.id} has no resource version ${String(body.resourceVersion)}`,
      );
      return null;
    }
    const target = text(consumer.url);
    if (!target || !/^https?:\/\//.test(target)) {
      hookBody(res, 400, 'fake Azure DevOps: a web hook needs an http(s) url');
      return null;
    }
    const password = text(consumer.basicAuthPassword) ?? '';
    if (password !== '' && target.startsWith('http:')) {
      send(res, recordedHttpRefusal.status, recordedHttpRefusal.body, recordedHttpRefusal.headers);
      return null;
    }
    return {
      id,
      eventType: event.id,
      resourceVersion: String(body.resourceVersion),
      projectId: text(publisher.projectId) ?? '',
      repositoryId: text(publisher.repository),
      branch: text(publisher.branch),
      url: target,
      username: text(consumer.basicAuthUsername) ?? '',
      password,
    };
  };

  /**
   * Identities, the ACL and the service hooks: true when the route is one of these (and answered).
   * `/vssps/…` is the identities host (Services); a Server answers identities on the collection.
   */
  const otherRoute = (
    req: RecordedRequest,
    res: ServerResponse,
    who: 'pat' | 'secret' | 'certificate',
    version: string,
  ): boolean => {
    const callerId = who === 'pat' ? patUser.id : principalUser!.id;
    const query = new URLSearchParams(req.query);
    const wrong = () => {
      const text = `fake Azure DevOps: this route is not asked at api-version ${version}`;
      wrapped(res, 400, text, 'VssInvalidPreviewVersionException');
      return true;
    };
    const json = (status: number, body: unknown) => {
      send(res, status, body, { 'content-type': JSON_7_0 });
      return true;
    };

    if (req.path.startsWith('/vssps/') || req.path === '/_apis/identities') {
      // Services answers on the vssps host only (probe item 20: 404 on the organisation); Server on the collection.
      const identitiesPath =
        deployment === 'services' ? '/vssps/_apis/identities' : '/_apis/identities';
      if (req.method !== 'GET' || req.path !== identitiesPath) {
        wrapped(res, 404, 'fake Azure DevOps: no such route', 'NotFound');
        return true;
      }
      if (version !== '7.0') return wrong();
      const value = (query.get('identityIds') ?? '')
        .split(',')
        .map((id) => userById(id.trim()))
        .filter((u): u is FakeAzureUser => u !== undefined)
        .map((u) => ({
          ...(u.id === principalUser?.id ? recordedPrincipalIdentity : recordedIdentity),
          id: u.id,
          descriptor: u.descriptor,
          subjectDescriptor: u.subjectDescriptor,
          providerDisplayName: u.displayName,
        }));
      return json(200, { count: value.length, value });
    }

    const acl = /^\/_apis\/accesscontrollists\/([^/]+)$/.exec(req.path);
    if (acl && req.method === 'GET') {
      if (version !== '7.0') return wrong();
      const descriptor = query.get('descriptors') ?? '';
      const user = userByDescriptor(descriptor);
      const ace = user ? ACE_BY_ROLE[user.role] : null;
      return json(200, {
        count: 1,
        value: [
          {
            ...recordedAcl,
            token: query.get('token') ?? '',
            acesDictionary: ace
              ? { [user!.descriptor]: { ...ace, descriptor: user!.descriptor } }
              : {},
            includeExtendedInfo: query.get('includeExtendedInfo') === 'true',
          },
        ],
      });
    }

    if (req.path === '/_apis/hooks/publishers/tfs/eventTypes' && req.method === 'GET') {
      if (version !== '7.0') return wrong();
      const value = eventTypes.map((e) => ({
        id: e.id,
        name: e.id,
        description: '',
        publisherId: 'tfs',
        supportedResourceVersions: e.supportedResourceVersions,
        inputDescriptors: [],
        url: `${url}/_apis/hooks/publishers/tfs/eventTypes/${e.id}`,
      }));
      return json(200, { count: value.length, value });
    }

    const hooks = /^\/_apis\/hooks\/subscriptions(?:\/([0-9a-fA-F-]{36}))?$/.exec(req.path);
    if (!hooks) return false;
    if (version !== '7.0') return wrong();
    const stamp = clock();
    if (!hooks[1] && req.method === 'GET') {
      const wanted = (name: string) => query.get(name) ?? '';
      const value = subscriptions
        .filter((s) => wanted('eventType') === '' || s.eventType === wanted('eventType'))
        .filter(() => ['', 'tfs'].includes(wanted('publisherId')))
        .filter(() => ['', 'webHooks'].includes(wanted('consumerId')))
        .filter(() => ['', 'httpRequest'].includes(wanted('consumerActionId')))
        .map((s) => subscriptionJson(s, callerId, stamp, stamp));
      return json(200, { count: value.length, value });
    }
    if (!hooks[1] && req.method === 'POST') {
      const made = subscriptionFrom(res, req, randomUUID());
      if (!made) return true;
      const subscription: FakeAzureSubscription = { ...made, status: 'enabled' };
      subscriptions.push(subscription);
      return json(200, subscriptionJson(subscription, callerId, stamp, stamp));
    }
    if (hooks[1] && req.method === 'PUT') {
      const index = subscriptions.findIndex((s) => s.id === hooks[1]!.toLowerCase());
      if (index < 0) {
        hookBody(
          res,
          404,
          `fake Azure DevOps: no subscription ${hooks[1]}`,
          'SubscriptionNotFoundException',
        );
        return true;
      }
      const made = subscriptionFrom(res, req, subscriptions[index]!.id);
      if (!made) return true;
      const status = jsonBodyOf(req)?.status;
      const replaced: FakeAzureSubscription = {
        ...made,
        status: typeof status === 'string' ? status : 'enabled',
      };
      subscriptions[index] = replaced;
      return json(200, subscriptionJson(replaced, callerId, stamp, stamp));
    }
    return false;
  };

  // ─── The CI setup (sub-plan 7): queues, build definitions and build policies ───
  type Json = Record<string, unknown>;
  const BUILD_POLICY_TYPE = '0609b952-1397-4640-95ec-e00a01b2c241';
  const JSON_PREVIEW = 'application/json; charset=utf-8; api-version=7.0-preview.1';
  const recordedQueueList = azureShape<{ body: { value: Json[] } }>('services', '26-queues').body
    .value;
  const recordedQueueOf = (hosted: boolean) =>
    recordedQueueList.find((q) => (q.pool as Json).isHosted === hosted && q.name !== 'Hosted')!;
  const recordedQueuePermissions = azureShape<{ body: Json }>(
    'services',
    '26-hosted-queue-permissions',
  ).body;
  const recordedAuthorizedPipeline = azureShape<{ body: { pipelines: Json[] } }>(
    'services',
    '8-queue-authorize-1',
  ).body.pipelines[0]!;
  const recordedDefinition = azureShape<{ body: Json }>('services', '26-definition-create').body;
  const recordedDefinitionList = azureShape<{ body: Json }>(
    'services',
    '26-definitions-search',
  ).body;
  const recordedPolicy = azureShape<{ body: Json }>('services', '26-policy-create').body;
  const recordedPolicyList = azureShape<{ body: Json }>('services', '26-policies-search').body;
  const recordedRootItems = azureShape<{ body: { value: Json[] } }>('services', '26-root-items')
    .body.value;
  const queueRows: FakeAzureQueue[] = [];
  const definitionRows: FakeAzureDefinition[] = [];
  const policyRows: FakeAzurePolicy[] = [];
  let queueCounter = 10;
  let poolCounter = 0;
  let definitionCounter = 0;
  let policyCounter = 0;

  const addQueueTo = (
    projectId: string,
    input: { name: string; poolName?: string; hosted?: boolean; open?: boolean },
  ): FakeAzureQueue => {
    queueCounter += 1;
    poolCounter += 1;
    const hosted = input.hosted ?? false;
    const queue: FakeAzureQueue = {
      id: queueCounter,
      projectId,
      name: input.name,
      poolId: poolCounter,
      poolName: input.poolName ?? input.name,
      hosted,
      open: input.open ?? hosted,
      pipelineIds: [],
    };
    queueRows.push(queue);
    return queue;
  };
  const queuesOf = (projectId: string): FakeAzureQueue[] => {
    if (!queueRows.some((q) => q.projectId === projectId)) {
      addQueueTo(projectId, { name: 'Default' });
      if (deployment === 'services') {
        addQueueTo(projectId, { name: 'Azure Pipelines', hosted: true, open: true });
      }
    }
    return queueRows.filter((q) => q.projectId === projectId);
  };
  const queueJson = (q: FakeAzureQueue): Json => {
    const recordedQueue = recordedQueueOf(q.hosted);
    return {
      ...recordedQueue,
      id: q.id,
      projectId: q.projectId,
      name: q.name,
      pool: { ...(recordedQueue.pool as Json), id: q.poolId, name: q.poolName, isHosted: q.hosted },
    };
  };
  const queuePermissionsJson = (q: FakeAzureQueue): Json => ({
    resource: { type: 'queue', id: String(q.id), name: q.name },
    ...(q.open
      ? {
          allPipelines: {
            ...(recordedQueuePermissions.allPipelines as Json),
            authorized: true,
          },
        }
      : {}),
    pipelines: q.pipelineIds.map((id) => ({
      ...recordedAuthorizedPipeline,
      id,
      authorized: true,
      authorizedOn: clock(),
    })),
  });
  const projectNameOf = (projectId: string) =>
    repositories.find((r) => r.projectId === projectId)?.projectName ?? projectId;

  type Variables = Record<string, { value?: string | null; isSecret?: boolean } & Json>;
  /** Variables as the answer shows them, and the secret values as they now stand. */
  const variablesOf = (
    sent: unknown,
    secrets: Record<string, string>,
  ): { shown: Variables; kept: Record<string, string> } => {
    const shown: Variables = {};
    const kept: Record<string, string> = {};
    for (const [name, variable] of Object.entries((sent ?? {}) as Variables)) {
      if (variable.isSecret === true) {
        const value = typeof variable.value === 'string' ? variable.value : secrets[name];
        if (value !== undefined) kept[name] = value;
        shown[name] = { ...variable, value: null, isSecret: true };
      } else {
        shown[name] = variable;
      }
    }
    return { shown, kept };
  };

  const buildRoute = (req: RecordedRequest, res: ServerResponse, version: string): boolean => {
    const route =
      /^\/([^/]+)\/_apis\/(distributedtask\/queues|pipelines\/pipelinePermissions\/queue\/(\d+)|build\/definitions(?:\/(\d+))?|policy\/configurations)$/.exec(
        req.path,
      );
    if (!route) return false;
    const projectId = decodeURIComponent(route[1]!).toLowerCase();
    const kind = route[2]!.split('/')[0]!;
    const preview = kind === 'distributedtask' || kind === 'pipelines';
    const wanted = preview ? '7.0-preview.1' : '7.0';
    const answerJson = (status: number, body: unknown) => {
      send(res, status, body, { 'content-type': preview ? JSON_PREVIEW : JSON_7_0 });
      return true;
    };
    const missing = (text: string, typeKey: string) => {
      wrapped(res, 404, text, typeKey);
      return true;
    };
    const bad = (text: string, typeKey = 'ArgumentException') => {
      wrapped(res, 400, `fake Azure DevOps: ${text}`, typeKey);
      return true;
    };
    if (version !== wanted) {
      const text = `fake Azure DevOps: this route is not asked at api-version ${version}`;
      wrapped(res, 400, text, 'VssInvalidPreviewVersionException');
      return true;
    }
    if (![...projectIds.values()].includes(projectId)) {
      return missing(
        `TF200016: The following project does not exist: ${projectId}.`,
        'ProjectDoesNotExistException',
      );
    }
    const query = new URLSearchParams(req.query);
    const queues = queuesOf(projectId);
    const web = `${url}/${projectId}/_build/definition?definitionId=`;
    const self = (id: number, revision: number) =>
      `${url}/${projectId}/_apis/build/Definitions/${id}?revision=${revision}`;

    if (kind === 'distributedtask' && req.method === 'GET') {
      const name = query.get('queueName');
      const value = queues.filter((q) => name === null || q.name === name).map(queueJson);
      return answerJson(200, { count: value.length, value });
    }

    if (kind === 'pipelines') {
      const queue = queues.find((q) => q.id === Number(route[3]));
      if (!queue) return missing('fake Azure DevOps: no such queue', 'NotFound');
      if (req.method === 'GET') return answerJson(200, queuePermissionsJson(queue));
      if (req.method === 'PATCH') {
        const changes = jsonBodyOf(req)?.pipelines;
        if (!Array.isArray(changes) || changes.length === 0) {
          return bad('a permission change is { pipelines: [{ id, authorized }] }');
        }
        for (const change of changes as Json[]) {
          const id = Number(change.id);
          if (!definitionRows.some((d) => d.projectId === projectId && d.id === id)) {
            return bad(`the pipeline ${String(change.id)} does not exist`);
          }
          queue.pipelineIds = queue.pipelineIds.filter((p) => p !== id);
          if (change.authorized === true) queue.pipelineIds.push(id);
        }
        return answerJson(200, queuePermissionsJson(queue));
      }
      return false;
    }

    if (kind === 'build') {
      const id = route[4] === undefined ? null : Number(route[4]);
      const own = definitionRows.filter((d) => d.projectId === projectId);
      if (id === null && req.method === 'GET') {
        const repositoryId = query.get('repositoryId')?.toLowerCase();
        const repositoryType = query.get('repositoryType');
        const value = own
          .filter(
            (d) =>
              (repositoryId === undefined || (d.body.repository as Json).id === repositoryId) &&
              (repositoryType === null || (d.body.repository as Json).type === repositoryType),
          )
          .map((d) => d.body);
        return answerJson(200, { ...recordedDefinitionList, count: value.length, value });
      }
      const current = id === null ? undefined : own.find((d) => d.id === id);
      if (id !== null && !current) {
        return missing(`The definition ${id} does not exist.`, 'DefinitionNotFoundException');
      }
      if (current && req.method === 'GET') return answerJson(200, current.body);

      if (req.method === 'POST' || req.method === 'PUT') {
        const body = jsonBodyOf(req);
        const name = body?.name;
        const yaml = (body?.process as Json | undefined)?.yamlFilename;
        const repoSent = body?.repository as Json | undefined;
        const queueSent = body?.queue as Json | undefined;
        if (!body || typeof name !== 'string' || typeof yaml !== 'string') {
          return bad('a definition needs a name and a process with a yamlFilename');
        }
        const repository = repositories.find(
          (r) => r.projectId === projectId && r.id === String(repoSent?.id).toLowerCase(),
        );
        if (!repository) return bad('the definition names no repository of the project');
        const queue = queues.find((q) => q.id === Number(queueSent?.id));
        if (!queue) return bad('the definition names no queue of the project');
        if (own.some((d) => d.body.name === name && d.id !== id)) {
          wrapped(
            res,
            409,
            `Build definition ${name} already exists.`,
            'DefinitionExistsException',
          );
          return true;
        }
        const { shown, kept } = variablesOf(body.variables, current?.secrets ?? {});
        const next = id ?? (definitionCounter += 1);
        const revision = Number(current?.body.revision ?? 0) + 1;
        const branch =
          typeof repoSent?.defaultBranch === 'string'
            ? repoSent.defaultBranch
            : (current?.body.repository as Json | undefined)?.defaultBranch;
        const stored: Json = {
          ...recordedDefinition,
          ...(current?.body ?? {}),
          ...body,
          variables: shown,
          process: { ...(recordedDefinition.process as Json), yamlFilename: yaml },
          repository: {
            ...(recordedDefinition.repository as Json),
            id: repository.id,
            type: 'TfsGit',
            name: repository.name,
            defaultBranch: branch,
          },
          queue: {
            ...(recordedDefinition.queue as Json),
            id: queue.id,
            name: queue.name,
            pool: { id: queue.poolId, name: queue.poolName, isHosted: queue.hosted },
          },
          id: next,
          revision,
          url: self(next, revision),
          uri: `vstfs:///Build/Definition/${next}`,
          _links: {
            ...(recordedDefinition._links as Json),
            self: { href: self(next, revision) },
            web: { href: `${web}${next}` },
          },
          project: {
            ...(recordedDefinition.project as Json),
            id: projectId,
            name: projectNameOf(projectId),
          },
          createdDate: current?.body.createdDate ?? clock(),
        };
        if (current) {
          current.body = stored;
          current.secrets = kept;
          return answerJson(200, current.body);
        }
        const row: FakeAzureDefinition = { id: next, projectId, body: stored, secrets: kept };
        definitionRows.push(row);
        return answerJson(200, row.body);
      }
      return false;
    }

    // policy/configurations
    const policyJson = (p: FakeAzurePolicy): Json => ({
      ...recordedPolicy,
      id: p.id,
      isEnabled: p.isEnabled,
      isBlocking: p.isBlocking,
      settings: p.settings,
      revision: 1,
      url: `${url}/${projectId}/_apis/policy/configurations/${p.id}`,
      type: { ...(recordedPolicy.type as Json), id: p.type },
    });
    if (req.method === 'GET') {
      const repositoryId = query.get('repositoryId')?.toLowerCase();
      const refName = query.get('refName');
      const policyType = query.get('policyType')?.toLowerCase();
      const value = policyRows
        .filter((p) => p.projectId === projectId)
        .filter((p) => policyType === undefined || p.type === policyType)
        .filter((p) =>
          (p.settings.scope as Json[]).some(
            (scope) =>
              (repositoryId === undefined || scope.repositoryId === repositoryId) &&
              (refName === null || scope.refName === refName),
          ),
        )
        .map(policyJson);
      return answerJson(200, { ...recordedPolicyList, count: value.length, value });
    }
    if (req.method === 'POST') {
      const body = jsonBodyOf(req);
      const settings = body?.settings as Json | undefined;
      const scope = settings?.scope;
      const type = String((body?.type as Json | undefined)?.id ?? '').toLowerCase();
      if (!body || !settings || !Array.isArray(scope) || scope.length === 0) {
        return bad('a policy needs a type and settings with a scope');
      }
      if (type !== BUILD_POLICY_TYPE) return bad(`the policy type ${type} is not known`);
      if (
        !definitionRows.some(
          (d) => d.projectId === projectId && d.id === Number(settings.buildDefinitionId),
        )
      ) {
        return bad('the policy names no build definition of the project');
      }
      if (typeof body.isEnabled !== 'boolean' || typeof body.isBlocking !== 'boolean') {
        return bad('a policy is enabled or not, blocking or not');
      }
      const policy: FakeAzurePolicy = {
        id: (policyCounter += 1),
        projectId,
        type,
        isEnabled: body.isEnabled,
        isBlocking: body.isBlocking,
        settings: {
          ...settings,
          scope: (scope as Json[]).map((s) => ({
            ...s,
            repositoryId: String(s.repositoryId).toLowerCase(),
            matchKind: 'Exact',
          })),
        },
      };
      policyRows.push(policy);
      return answerJson(200, policyJson(policy));
    }
    return false;
  };

  const rootItemsAnswer = (
    repository: FakeAzureRepository,
    version: string,
    versionType: string,
  ): { status: number; body: unknown } => {
    const commit = resolveCommit(repository.id, version, versionType);
    const files = commit ? commitOf(repository.id, commit)?.files : undefined;
    if (!commit || !files) {
      return {
        status: 404,
        body: {
          ...notFound,
          message: `TF401175: The commit ${version} does not exist.`,
          typeKey: 'GitCommitDoesNotExistException',
        },
      };
    }
    const root = recordedRootItems.find((e) => e.path === '/')!;
    const folder = recordedRootItems.find((e) => e.isFolder === true && e.path !== '/')!;
    const blob = recordedRootItems.find((e) => e.gitObjectType === 'blob')!;
    const entry = (template: Json, itemPath: string): Json => ({
      ...template,
      objectId: createHash('sha1').update(`${commit}:${itemPath}`).digest('hex'),
      commitId: commit,
      path: itemPath,
      url: `${url}/${repository.projectId}/_apis/git/repositories/${repository.id}/items?path=${encodeURIComponent(itemPath)}&versionType=Commit&version=${commit}`,
    });
    const top = new Map<string, boolean>();
    for (const filePath of [...files.keys()].sort()) {
      const [first, ...more] = filePath.split('/');
      top.set(first!, more.length > 0 || top.get(first!) === true);
    }
    const value = [
      entry(root, '/'),
      ...[...top].map(([name, isFolder]) => entry(isFolder ? folder : blob, `/${name}`)),
    ];
    return { status: 200, body: { count: value.length, value } };
  };

  const answer = (req: RecordedRequest, res: ServerResponse, inside: boolean): void => {
    if (!inside) {
      return wrapped(res, 404, 'fake Azure DevOps: no such collection', 'NotFound');
    }
    const who = authenticate(req.headers.authorization);
    if (who === 'none')
      return send(res, noCredential.status, noCredential.body, noCredential.headers);
    if (who === 'wrong') return send(res, wrongPat.status, wrongPat.body, wrongPat.headers);
    if (who !== 'pat' && !fake.identityAdded) return tf401444(res);
    const version = new URLSearchParams(req.query).get('api-version') ?? '';
    const other = otherRoute(req, res, who, version);
    if (other) return;
    if (buildRoute(req, res, version)) return;
    const one = /^\/_apis\/git\/repositories\/([^/]+)$/.exec(req.path);
    const route =
      req.method !== 'GET'
        ? null
        : req.path === '/_apis/connectionData'
          ? { wanted: /^7\.0-preview(\.1)?$/, name: 'connectionData' as const }
          : req.path === '/_apis/git/repositories'
            ? { wanted: /^7\.0$/, name: 'list' as const }
            : one
              ? { wanted: /^7\.0$/, name: 'repository' as const }
              : null;
    const git = /^(?:\/[^/]+)?\/_apis\/git\/repositories\/([^/]+)\/(.+)$/.exec(req.path);
    if (!route && git)
      return gitRoute(req, res, who, decodeURIComponent(git[1]!), git[2]!, version);
    if (!route) return wrapped(res, 404, 'fake Azure DevOps: no such route', 'NotFound');
    if (!route.wanted.test(version)) {
      const text = `fake Azure DevOps: this route is not asked at api-version ${version}`;
      return wrapped(res, 400, text, 'VssInvalidPreviewVersionException');
    }
    if (route.name === 'connectionData') return identityAnswer(res, who);
    if (route.name === 'list') {
      const value = repositories.map(repositoryJson);
      return send(
        res,
        200,
        { ...listEnvelope.body, count: value.length, value },
        { 'content-type': JSON_7_0 },
      );
    }
    const id = decodeURIComponent(one![1]!);
    const repository = repositories.find((r) => r.id === id.toLowerCase());
    if (repository) return send(res, 200, repositoryJson(repository), { 'content-type': JSON_7_0 });
    unknownRepository(res, id);
  };

  const handleApi = async (incoming: IncomingMessage, res: ServerResponse) => {
    // The identities host (Services): a prefix of this server, kept in the path of the request.
    const identitiesPrefix = `/vssps${basePath}`;
    const vssps =
      deployment === 'services' && (incoming.url ?? '').startsWith(`${identitiesPrefix}/`);
    const inside = vssps || (incoming.url ?? '').startsWith(`${basePath}/`);
    const read = await recorded(incoming, vssps ? identitiesPrefix : basePath);
    const req = vssps ? { ...read, path: `/vssps${read.path}` } : read;
    requests.push(req);
    const injected = injections.find(
      (i) => i.method === req.method && i.path.test(req.path) && i.answers.length > 0,
    );
    const given = injected?.answers.shift();
    if (!given) return answer(req, res, inside);
    await given.before?.();
    if (given.passThrough) {
      for (const [name, value] of Object.entries(given.headers ?? {})) res.setHeader(name, value);
      answer(req, res, inside);
    } else if (!given.hang) {
      send(res, given.status, given.body, given.headers);
    }
  };

  /** How the token request proves the principal, or why Entra refuses it. */
  const proofOf = (req: RecordedRequest): { how: 'secret' | 'certificate' } | EntraRefusal => {
    const tenant = /^\/([^/]+)\/oauth2\/v2\.0\/token$/.exec(req.path)?.[1];
    if (req.method !== 'POST' || !principal || tenant !== principal.tenantId) return 'tenant';
    const form = new URLSearchParams(req.body);
    if (form.get('grant_type') !== 'client_credentials') return 'grant';
    if (form.get('client_id') !== principal.clientId) return 'client';
    if (form.get('scope') !== ENTRA_SCOPE) return 'scope';
    const secret = form.get('client_secret');
    const assertion = form.get('client_assertion');
    if (secret !== null && assertion === null) {
      return principal.secret !== undefined && secret === principal.secret
        ? { how: 'secret' }
        : 'wrongSecret';
    }
    if (
      assertion === null ||
      secret !== null ||
      form.get('client_assertion_type') !== ASSERTION_TYPE
    ) {
      return 'proof';
    }
    const audience = `${tokenOrigin}${req.path}`;
    const problem = assertionProblem(assertion, {
      clientId: principal.clientId,
      audience,
      certificate,
      now: now(),
    });
    return problem ?? { how: 'certificate' };
  };

  const handleToken = async (incoming: IncomingMessage, res: ServerResponse) => {
    const req = await recorded(incoming, '');
    tokenRequests.push(req);
    const proof = proofOf(req);
    if (typeof proof === 'string') {
      const [status, error, code, text] = ENTRA_REFUSAL[proof];
      const at = new Date(now()).toISOString();
      return send(res, status, {
        error,
        error_description: `AADSTS${code}: ${text} Trace ID: ${randomUUID()} Correlation ID: ${randomUUID()} Timestamp: ${at}`,
        error_codes: [code],
        timestamp: at,
        trace_id: randomUUID(),
        correlation_id: randomUUID(),
        error_uri: `https://login.microsoftonline.com/error?code=${code}`,
      });
    }
    const token = `fake-entra-${randomBytes(24).toString('base64url')}`;
    tokens.set(token, { how: proof.how, expiresAt: now() + TOKEN_SECONDS * 1000 });
    send(res, 200, {
      token_type: 'Bearer',
      expires_in: TOKEN_SECONDS,
      ext_expires_in: TOKEN_SECONDS,
      access_token: token,
    });
  };

  const api = createServer((req, res) => void handleApi(req, res));
  url = `http://127.0.0.1:${await listen(api)}${basePath}`;
  const entra = principal
    ? createHttpsServer(
        { cert: TEST_SERVER_CERT_PEM, key: TEST_SERVER_KEY_PEM },
        (req, res) => void handleToken(req, res),
      )
    : null;
  if (entra) tokenOrigin = `https://127.0.0.1:${await listen(entra)}`;

  const fake: FakeAzureDevOps = {
    url,
    deployment,
    pat,
    patUser,
    principalUser,
    tokenUrl(tenantId) {
      if (!entra) throw new Error('fake Azure DevOps: no principal, so no token endpoint');
      return `${tokenOrigin}/${tenantId}/oauth2/v2.0/token`;
    },
    identityAdded: options.identityAdded ?? true,
    repositories,
    addRepository(input) {
      const projectId = projectIds.get(input.projectName) ?? randomUUID();
      projectIds.set(input.projectName, projectId);
      const repository: FakeAzureRepository = {
        id: (input.id ?? randomUUID()).toLowerCase(),
        name: input.name,
        projectId,
        projectName: input.projectName,
        defaultBranch: input.defaultBranch === undefined ? 'main' : input.defaultBranch,
        isDisabled: input.isDisabled ?? false,
      };
      repositories.push(repository);
      return repository;
    },
    addPullRequest(repositoryId, input = {}) {
      const repoId = repositoryId.toLowerCase();
      if (!repositories.some((r) => r.id === repoId)) {
        throw new Error(`fake Azure DevOps: no repository ${repositoryId}`);
      }
      const own = [...pullRequests.keys()].filter((k) => k.startsWith(`${repoId}#`)).length;
      const id = input.id ?? own + 1;
      const pr: FakeAzurePullRequest = {
        id,
        status: input.status ?? 'active',
        isDraft: input.isDraft ?? false,
        title: input.title ?? `Pull request ${id}`,
        sourceRefName: input.sourceRefName ?? `refs/heads/feature/${id}`,
        targetRefName: input.targetRefName ?? 'refs/heads/main',
        headSha:
          input.headSha === undefined
            ? createHash('sha1').update(`head-${repoId}-${id}`).digest('hex')
            : input.headSha,
        statusPolicy: input.statusPolicy ?? false,
        mergeStatus: input.mergeStatus === undefined ? 'succeeded' : input.mergeStatus,
        description: input.description ?? '',
        fork: input.fork ?? false,
        iterations: [],
        threads: [],
        statuses: [],
      };
      pullRequests.set(`${repoId}#${id}`, pr);
      return pr;
    },
    pullRequest(repositoryId, id) {
      const pr = pullRequests.get(`${repositoryId.toLowerCase()}#${id}`);
      if (!pr) throw new Error(`fake Azure DevOps: no pull request ${id} in ${repositoryId}`);
      return pr;
    },
    addIteration(repositoryId, prId, input) {
      const pr = fake.pullRequest(repositoryId, prId);
      const iteration: FakeAzureIteration = {
        id: pr.iterations.length + 1,
        sourceRefCommit: input.sourceRefCommit.toLowerCase(),
        commonRefCommit: input.commonRefCommit.toLowerCase(),
        targetRefCommit: (input.targetRefCommit ?? input.commonRefCommit).toLowerCase(),
        changes: input.changes ?? [],
        statuses: [],
      };
      pr.iterations.push(iteration);
      return iteration;
    },
    addFile(repositoryId, commit, filePath, content) {
      ensureCommit(repositoryId.toLowerCase(), commit).files.set(
        filePath.replace(/^\//, ''),
        Buffer.isBuffer(content) ? content : Buffer.from(content),
      );
    },
    addCommit(repositoryId, input = {}) {
      const repoId = repositoryId.toLowerCase();
      const id = (input.id ?? newCommitId(repoId)).toLowerCase();
      const parents = (input.parents ?? []).map((p) => p.toLowerCase());
      const commit = ensureCommit(repoId, id);
      commit.parents = parents;
      commit.files = new Map(parents[0] ? commitOf(repoId, parents[0])?.files : undefined);
      for (const [filePath, content] of Object.entries(input.files ?? {})) {
        fake.addFile(repoId, id, filePath, content);
      }
      return id;
    },
    setBranch(repositoryId, name, commit) {
      repoRefs(repositoryId.toLowerCase()).set(`refs/heads/${name}`, commit.toLowerCase());
    },
    branches(repositoryId) {
      return Object.fromEntries(
        [...repoRefs(repositoryId.toLowerCase())]
          .filter(([name]) => name.startsWith('refs/heads/'))
          .map(([name, sha]) => [name.slice('refs/heads/'.length), sha]),
      );
    },
    refs(repositoryId) {
      return Object.fromEntries(repoRefs(repositoryId.toLowerCase()));
    },
    fileAt(repositoryId, refOrSha, filePath) {
      const repoId = repositoryId.toLowerCase();
      const refs = repoRefs(repoId);
      const sha =
        refs.get(refOrSha) ?? refs.get(`refs/heads/${refOrSha}`) ?? refOrSha.toLowerCase();
      const content = commitOf(repoId, sha)?.files.get(filePath.replace(/^\//, ''));
      return content === undefined ? null : content.toString('utf8');
    },
    pullRequests(repositoryId) {
      const repoId = repositoryId.toLowerCase();
      return [...pullRequests].filter(([key]) => key.startsWith(`${repoId}#`)).map(([, p]) => p);
    },
    setMergeStatus(repositoryId, prId, mergeStatus) {
      fake.pullRequest(repositoryId, prId).mergeStatus = mergeStatus;
    },
    completePullRequest(repositoryId, prId) {
      fake.pullRequest(repositoryId, prId).status = 'completed';
    },
    addThread(repositoryId, prId, input = {}) {
      const pr = fake.pullRequest(repositoryId, prId);
      const positioned = input.filePath !== undefined && input.line !== undefined;
      return addThreadTo(pr, {
        status: input.status ?? 'active',
        threadContext: positioned
          ? {
              filePath: `/${input.filePath}`,
              rightFileStart: { line: input.line, offset: 1 },
              rightFileEnd: { line: input.line, offset: 2 },
            }
          : null,
        comments: input.comments ?? [{ content: 'A comment' }],
      });
    },
    addSystemThread(repositoryId, prId, content = 'Updated the source branch') {
      const pr = fake.pullRequest(repositoryId, prId);
      return addThreadTo(pr, {
        status: null,
        threadContext: null,
        comments: [{ content, commentType: 'system' }],
      });
    },
    addComment(repositoryId, prId, threadId, input) {
      const thread = fake.pullRequest(repositoryId, prId).threads.find((x) => x.id === threadId);
      if (!thread) throw new Error(`fake Azure DevOps: no thread ${threadId}`);
      const comment: FakeAzureComment = {
        id: Math.max(0, ...thread.comments.map((c) => c.id)) + 1,
        authorId: input.authorId ?? patUser.id,
        content: input.content,
        commentType: input.commentType ?? 'text',
        parentCommentId: input.parentCommentId ?? 0,
        publishedDate: input.publishedDate ?? clock(),
        isDeleted: input.isDeleted ?? false,
      };
      thread.comments.push(comment);
      return comment;
    },
    users,
    addUser: addUserTo,
    get identitiesUrl() {
      return deployment === 'services' ? `${new URL(url).origin}/vssps${basePath}` : url;
    },
    subscriptions,
    setSubscriptionStatus(id, status) {
      const subscription = subscriptions.find((s) => s.id === id.toLowerCase());
      if (!subscription) throw new Error(`fake Azure DevOps: no subscription ${id}`);
      subscription.status = status;
    },
    queues: queuesOf,
    addQueue(projectId, input) {
      queuesOf(projectId);
      return addQueueTo(projectId, input);
    },
    definitions: definitionRows,
    policies: policyRows,
    commitStatuses,
    requests,
    tokenRequests,
    inject(method, pathPattern, ...answers) {
      injections.push({ method, path: pathPattern, answers: [...answers] });
    },
    clearRequests() {
      requests.length = 0;
      tokenRequests.length = 0;
    },
    async close() {
      await closeServer(api);
      if (entra) await closeServer(entra);
    },
  };
  addUserTo({ ...patUser, role: 'owner', descriptor: PAT_DESCRIPTOR });
  if (principalUser) {
    addUserTo({ ...principalUser, role: 'contributor', descriptor: PRINCIPAL_DESCRIPTOR });
  }
  for (const input of options.repositories ?? []) fake.addRepository(input);
  return fake;
}
