/**
 * A weaker identity in the bench Qualor's Azure DevOps connection (`--qualor-identity contributor|
 * minimal-pat`, seed-qualor.mjs --identity): what items 19, 21, 24, 27 and 31 record instead of
 * failing. Each step's outcome (ok, or what was seen instead: Qualor's own fixed text where it has
 * one), Qualor's record of the connection (its problem and a connection test), and the identity's
 * own calls of the writes Qualor makes (Azure DevOps' status, typeKey and message, or a ref update's
 * word). The probe's own setup stays the main identity's. Nothing here runs for the bot.
 */
import type { AzureResponse } from '../client.js';
import {
  BUILD_POLICY,
  excerpt,
  gitPath,
  messageOf,
  refUpdateOf,
  remove,
  result,
  threadsPath,
  type ProbeContext,
  type ProbeResult,
  type Repo,
} from './common.js';
import { QualorApi } from './qualor-api.js';

// ---------------------------------------------------------------------------------------------
// Pure helpers (unit-tested)

/** A step of an item: whether it passed, and what was seen. */
export type Step = { what: string; pass: boolean; got: string };

/** The steps as a weaker identity's run records them. */
export function stepLines(steps: readonly Step[]): string[] {
  return steps.map((s) => `step ${s.pass ? 'ok' : 'NOT ok'} - ${s.what}: ${s.got}`);
}

const TYPE_KEY = /^[A-Za-z][A-Za-z0-9_.]{0,199}$/;

/** A `POST refs` answer: a list whose entries carry `success`. */
function isRefUpdateAnswer(json: unknown): boolean {
  const value = (json as { value?: unknown } | null)?.value;
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every((v) => typeof (v as { success?: unknown } | null)?.success === 'boolean')
  );
}

/**
 * Azure DevOps' answer in one line: a 2xx as its status (a ref update with its word: a 2xx can be
 * a refusal there), anything else as its status, its typeKey and its message.
 */
export function answerLine(res: { status: number; json: unknown }): string {
  if (res.status >= 200 && res.status < 300) {
    if (!isRefUpdateAnswer(res.json)) return `HTTP ${res.status}`;
    const u = refUpdateOf(res.json);
    return `HTTP ${res.status}, ${u.success ? 'succeeded' : 'NOT made'}, updateStatus ${u.updateStatus}`;
  }
  const type = (res.json as { typeKey?: unknown } | null)?.typeKey;
  return `HTTP ${res.status}${typeof type === 'string' && TYPE_KEY.test(type) ? ` ${type}` : ''}: ${messageOf(res.json)}`;
}

/** Whether Azure DevOps refused: not a 2xx, or a 2xx ref update it did not make. */
export function refusedAnswer(res: { status: number; json: unknown }): boolean {
  if (res.status < 200 || res.status >= 300) return true;
  return isRefUpdateAnswer(res.json) && !refUpdateOf(res.json).success;
}

/** What a Qualor answer that is not 2xx says: its code and its first message (Qualor's own text). */
export function qualorAnswerText(status: number, json: unknown): string {
  const p = (json ?? {}) as {
    code?: unknown;
    title?: unknown;
    detail?: unknown;
    errors?: { path?: unknown; message?: unknown }[];
  };
  const first = Array.isArray(p.errors) ? p.errors[0] : undefined;
  const message =
    first && typeof first.message === 'string'
      ? `${typeof first.path === 'string' ? `${first.path}: ` : ''}${first.message}`
      : typeof p.detail === 'string'
        ? p.detail
        : typeof p.title === 'string'
          ? p.title
          : '';
  return `HTTP ${status}${typeof p.code === 'string' ? ` ${p.code}` : ''}${message ? `: ${message.slice(0, 300)}` : ''}`;
}

/** Who Qualor acts as, for the texts: the bot's names as before, else the weaker identity's. */
export function identityLabel(
  target: 'services' | 'server',
  identity?: 'contributor' | 'minimal-pat',
): string {
  if (identity === 'contributor') {
    return target === 'server'
      ? "Qualor's contributor PAT identity (probe-user)"
      : 'the contributor service principal';
  }
  if (identity === 'minimal-pat') return "Qualor's minimal-PAT identity";
  return target === 'server' ? "Qualor's PAT identity" : 'the service principal';
}

/**
 * An item's answer under a weaker identity: `recorded`, with each step, the notes and what was
 * recorded of the refusals (Qualor's record, the identity's own calls).
 */
export function recordedResult(
  ctx: ProbeContext,
  header: string,
  steps: readonly Step[],
  notes: readonly string[],
  record: readonly string[],
): ProbeResult {
  for (const line of stepLines(steps)) ctx.log(line);
  const detail = [
    header,
    `Qualor's identity: ${ctx.qualorAs?.identity ?? 'bot'} (${identityLabel(ctx.target, ctx.qualorAs?.identity)}); the probe's own setup is the main identity's`,
    ...stepLines(steps),
    ...notes.map((n) => `note: ${n}`),
    ...record.map((r) => `recorded: ${r}`),
  ].join('\n\n');
  return result(ctx, 'recorded', detail);
}

// ---------------------------------------------------------------------------------------------
// Calls

/**
 * One call as the weaker identity: its outcome as a line, never a throw. `ok` is false for a
 * refusal (see {@link refusedAnswer}) and for no answer at all.
 */
export async function rightsCall(
  ctx: ProbeContext,
  what: string,
  method: string,
  path: string,
  body?: unknown,
  opts: { apiVersion?: string; contentType?: string } = {},
): Promise<{ line: string; ok: boolean; res?: AzureResponse }> {
  if (!ctx.qualorAs) return { line: `rights ${what}: not checked (bot)`, ok: false };
  try {
    const res = await ctx.qualorAs.client.request(method, path, body, opts);
    const ok = !refusedAnswer(res);
    return {
      line: `rights ${what}: ${ok ? 'ok' : 'refused'}, ${excerpt(answerLine(res), ctx.redaction, 400)}`,
      ok,
      res,
    };
  } catch (err) {
    return {
      line: `rights ${what}: no answer (${excerpt((err as Error).message, ctx.redaction, 200)})`,
      ok: false,
    };
  }
}

/** The bench Qualor's API in the shape the record reads (QualorApi.send). */
export type QualorSend = {
  send(method: string, path: string, body?: unknown): Promise<{ status: number; json: unknown }>;
};

/**
 * What the bench Qualor says of the connection: the problem it recorded from a failed job (code,
 * since when; Azure DevOps decorations record one), and a connection test of `projectRef` (ok, or
 * Qualor's code and fixed text, and the access it finds missing).
 */
export async function qualorConnectionRecord(
  api: QualorSend,
  organizationId: string,
  connectionId: string,
  projectRef?: string,
): Promise<string[]> {
  const lines: string[] = [];
  const listed = await api.send(
    'GET',
    `/api/v0/scm-connections?organizationId=${encodeURIComponent(organizationId)}&limit=100`,
  );
  const items = (listed.json as { items?: unknown } | null)?.items;
  const found = Array.isArray(items)
    ? (items.find((c) => (c as { id?: unknown } | null)?.id === connectionId) as
        { problem?: { code?: unknown; at?: unknown } | null } | undefined)
    : undefined;
  lines.push(
    found
      ? `Qualor's connection problem: ${found.problem ? `${String(found.problem.code)} since ${String(found.problem.at)}` : 'none'}`
      : `Qualor's connection: not read (HTTP ${listed.status})`,
  );
  if (projectRef !== undefined) {
    const tested = await api.send('POST', `/api/v0/scm-connections/${connectionId}/test`, {
      projectRef,
    });
    const t = tested.json as {
      ok?: unknown;
      problem?: { code?: unknown; message?: unknown } | null;
      missingAccess?: unknown;
    } | null;
    lines.push(
      tested.status === 200 && t
        ? `Qualor's connection test: ${t.ok === true ? 'ok' : `failed, ${String(t.problem?.code ?? '?')}: ${String(t.problem?.message ?? '')}`}; missingAccess ${JSON.stringify(t.missingAccess ?? null)}`
        : `Qualor's connection test: ${qualorAnswerText(tested.status, tested.json)}`,
    );
  }
  return lines;
}

/**
 * {@link qualorConnectionRecord} for an item that has no admin session of its own (item 19): it
 * signs in, finds organisation `orgKey` and its Azure DevOps connection to `scmUrl`.
 */
export async function benchQualorRecord(
  scmUrl: string,
  orgKey: string,
  projectRef: string,
): Promise<string[]> {
  const url = process.env['AZURE_PROBE_QUALOR_URL'];
  const password = process.env['AZURE_PROBE_QUALOR_ADMIN_PASSWORD'];
  if (!url || !password)
    return ["Qualor's record: not read (no AZURE_PROBE_QUALOR_URL or admin password)"];
  try {
    const api = new QualorApi(url);
    await api.login(password);
    const orgs = (await api.send('GET', '/api/v0/organizations?limit=100')).json as {
      items?: { id: string; key: string }[];
    } | null;
    const org = orgs?.items?.find((o) => o.key === orgKey);
    if (!org) return [`Qualor's record: no organisation ${orgKey}`];
    const conns = (
      await api.send('GET', `/api/v0/scm-connections?organizationId=${org.id}&limit=100`)
    ).json as { items?: { id: string; provider: string; baseUrl: string }[] } | null;
    const connection = conns?.items?.find(
      (c) => c.provider === 'azure' && c.baseUrl.replace(/\/+$/, '') === scmUrl,
    );
    if (!connection) return ["Qualor's record: no Azure DevOps connection to the target"];
    return await qualorConnectionRecord(api, org.id, connection.id, projectRef);
  } catch (err) {
    return [`Qualor's record: not read (${(err as Error).message.slice(0, 200)})`];
  }
}

// ---------------------------------------------------------------------------------------------
// The identity's own calls of the writes Qualor makes, per item (each created object is removed by
// the main identity at clean-up)

/** A status as Qualor posts one, under a genre no policy reads. */
const rightsStatus = (ctx: ProbeContext) => ({
  state: 'notApplicable',
  description: `Qualor probe item ${ctx.item}: rights check (${ctx.stamp})`,
  context: { genre: 'qualor-probe', name: `rights-${ctx.item}` },
});

/** Item 19 (decoration): the pull request, iteration and commit statuses and a thread. */
export async function decorationRights(
  ctx: ProbeContext,
  repo: Repo,
  prId: number,
  head: string | undefined,
): Promise<string[]> {
  const out: string[] = [];
  const status = rightsStatus(ctx);
  out.push(
    (
      await rightsCall(
        ctx,
        'a pull request status (POST …/pullRequests/{id}/statuses)',
        'POST',
        gitPath(ctx, repo, `/pullRequests/${prId}/statuses`),
        status,
      )
    ).line,
    (
      await rightsCall(
        ctx,
        "an iteration status (POST …/iterations/1/statuses, the Status check policy's kind)",
        'POST',
        gitPath(ctx, repo, `/pullRequests/${prId}/iterations/1/statuses`),
        status,
      )
    ).line,
  );
  if (head) {
    out.push(
      (
        await rightsCall(
          ctx,
          'a commit status (POST …/commits/{id}/statuses, a branch analysis)',
          'POST',
          gitPath(ctx, repo, `/commits/${head}/statuses`),
          status,
        )
      ).line,
    );
  }
  out.push(
    (
      await rightsCall(
        ctx,
        'a closed pull request thread (POST …/threads)',
        'POST',
        threadsPath(ctx, repo, prId),
        {
          comments: [
            {
              parentCommentId: 0,
              content: `Qualor probe item ${ctx.item}: rights check (${ctx.stamp})`,
              commentType: 1,
            },
          ],
          status: 4,
        },
      )
    ).line,
  );
  return out;
}

/** Item 21 (service hooks): reading and creating a webhook subscription of the project. */
export async function hookRights(
  ctx: ProbeContext,
  projectId: string,
  repositoryId: string,
): Promise<string[]> {
  const list = await rightsCall(
    ctx,
    'the service hook subscriptions (GET _apis/hooks/subscriptions)',
    'GET',
    '/_apis/hooks/subscriptions?publisherId=tfs&consumerId=webHooks&consumerActionId=httpRequest',
  );
  // No password: the recorder answers 401 to its deliveries; only the right to subscribe is asked.
  const made = await rightsCall(
    ctx,
    'a webhook subscription (POST _apis/hooks/subscriptions)',
    'POST',
    '/_apis/hooks/subscriptions',
    {
      publisherId: 'tfs',
      eventType: 'git.pullrequest.updated',
      resourceVersion: '1.0',
      consumerId: 'webHooks',
      consumerActionId: 'httpRequest',
      publisherInputs: { projectId, repository: repositoryId },
      consumerInputs: { url: `${ctx.hookBase.replace(/\/+$/, '')}/hooks/probe-${ctx.item}-rights` },
    },
  );
  const id = (made.res?.json as { id?: unknown } | null)?.id;
  if (made.ok && typeof id === 'string') {
    ctx.cleanup.add(`delete the rights check's subscription ${id}`, () =>
      remove(ctx.bot, `/_apis/hooks/subscriptions/${id}`, `subscription ${id}`),
    );
  }
  return [list.line, made.line];
}

/**
 * Item 24 (fix pull request): the writes of a fix in the fix repository: a new `qualor/fix/…`
 * branch by a push, a push to `refs/qualor/fix-tmp/…` (not a branch), the force-move of the branch
 * to it (not a fast-forward), and both deletes.
 */
export async function fixRights(
  ctx: ProbeContext,
  repo: Repo,
  mainHead: string,
): Promise<string[]> {
  const out: string[] = [];
  const zero = '0'.repeat(40);
  const branch = `refs/heads/qualor/fix/probe-rights-${ctx.stamp}`;
  const tmp = `refs/qualor/fix-tmp/probe-rights-${ctx.stamp}`;
  // Whatever the identity left, the main identity deletes (registered first: it runs last).
  for (const ref of [branch, tmp]) {
    ctx.cleanup.add(`delete ${ref} if left`, async () => {
      const filter = encodeURIComponent(ref.replace(/^refs\//, ''));
      const got = await ctx.bot.request('GET', gitPath(ctx, repo, `/refs?filter=${filter}`));
      const head = (
        got.json as { value?: { name: string; objectId: string }[] } | null
      )?.value?.find((r) => r.name === ref)?.objectId;
      if (!head) return;
      const res = await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
        { name: ref, oldObjectId: head, newObjectId: zero },
      ]);
      if (refusedAnswer(res)) throw new Error(`delete ${ref}: ${answerLine(res)}`);
    });
  }
  const push = (ref: string, file: string) => ({
    refUpdates: [{ name: ref, oldObjectId: zero }],
    commits: [
      {
        comment: `Qualor probe item ${ctx.item}: rights check (${ctx.stamp})`,
        parents: [mainHead],
        changes: [
          {
            changeType: 'add',
            item: { path: file },
            newContent: { content: `rights check ${ctx.stamp}\n`, contentType: 'rawtext' },
          },
        ],
      },
    ],
  });
  const commitOf = (res: AzureResponse | undefined): string | undefined => {
    const commits = (res?.json as { commits?: { commitId?: string }[] } | null)?.commits;
    return commits?.[commits.length - 1]?.commitId;
  };
  const created = await rightsCall(
    ctx,
    'a new qualor/fix/… branch by a push (Create branch, Contribute)',
    'POST',
    gitPath(ctx, repo, '/pushes'),
    push(branch, `/probe-rights-${ctx.stamp}-a.txt`),
  );
  const temp = await rightsCall(
    ctx,
    'a push to refs/qualor/fix-tmp/… (not a branch)',
    'POST',
    gitPath(ctx, repo, '/pushes'),
    push(tmp, `/probe-rights-${ctx.stamp}-b.txt`),
  );
  out.push(created.line, temp.line);
  const a = created.ok ? commitOf(created.res) : undefined;
  const b = temp.ok ? commitOf(temp.res) : undefined;
  if (a && b) {
    // B is A's sibling: moving the branch from A to B is not a fast-forward (Force push).
    const moved = await rightsCall(
      ctx,
      'the force-move of the branch to the temporary commit (POST refs, not a fast-forward: Force push)',
      'POST',
      gitPath(ctx, repo, '/refs'),
      [{ name: branch, oldObjectId: a, newObjectId: b }],
    );
    out.push(moved.line);
    const now = moved.ok ? b : a;
    out.push(
      (
        await rightsCall(
          ctx,
          'the delete of the temporary ref (POST refs to the zero id)',
          'POST',
          gitPath(ctx, repo, '/refs'),
          [{ name: tmp, oldObjectId: b, newObjectId: zero }],
        )
      ).line,
      (
        await rightsCall(
          ctx,
          'the delete of the qualor/fix/… branch it pushed (POST refs to the zero id)',
          'POST',
          gitPath(ctx, repo, '/refs'),
          [{ name: branch, oldObjectId: now, newObjectId: zero }],
        )
      ).line,
    );
  } else {
    out.push('rights the force-move and the deletes: not tried (a push above was refused)');
  }
  return out;
}

/**
 * Item 27 (CI setup): what the setup writes besides the branch: the agent queues it reads, a
 * pipeline (YAML definition), its authorisation on the queue, and a non-blocking Build validation
 * policy (on a probe branch).
 */
export async function setupRights(
  ctx: ProbeContext,
  repo: Repo,
  queueId: number,
  yamlFilename: string,
): Promise<string[]> {
  const out: string[] = [];
  const pid = repo.project.id;
  out.push(
    (
      await rightsCall(
        ctx,
        'the agent queues of the project (GET distributedtask/queues)',
        'GET',
        `/${pid}/_apis/distributedtask/queues`,
        undefined,
        { apiVersion: '7.0-preview.1' },
      )
    ).line,
  );
  const def = await rightsCall(
    ctx,
    'a YAML pipeline (POST build/definitions)',
    'POST',
    `/${ctx.project}/_apis/build/definitions`,
    {
      name: `Qualor probe item ${ctx.item} rights ${ctx.stamp}`,
      path: '\\',
      type: 'build',
      queue: { id: queueId },
      process: { type: 2, yamlFilename },
      repository: {
        id: repo.id,
        name: repo.name,
        type: 'TfsGit',
        defaultBranch: 'refs/heads/main',
      },
    },
  );
  out.push(def.line);
  const defId = (def.res?.json as { id?: unknown } | null)?.id;
  if (def.ok && typeof defId === 'number') {
    ctx.cleanup.add(`delete the rights check's pipeline ${defId}`, () =>
      remove(ctx.bot, `/${ctx.project}/_apis/build/definitions/${defId}`, `definition ${defId}`),
    );
    const permissions = `/${ctx.project}/_apis/pipelines/pipelinePermissions/queue/${queueId}`;
    const authorized = await rightsCall(
      ctx,
      "the pipeline's authorisation on the queue (PATCH pipelinePermissions/queue)",
      'PATCH',
      permissions,
      { pipelines: [{ id: defId, authorized: true }] },
      { apiVersion: '7.0-preview.1' },
    );
    out.push(authorized.line);
    if (authorized.ok) {
      // Runs before the definition's delete (newest first).
      ctx.cleanup.add(
        `take back the rights check's authorisation on queue ${queueId}`,
        async () => {
          await ctx.bot.request(
            'PATCH',
            permissions,
            { pipelines: [{ id: defId, authorized: false }] },
            { apiVersion: '7.0-preview.1' },
          );
        },
      );
    }
    const policy = await rightsCall(
      ctx,
      'a non-blocking Build validation policy (POST policy/configurations)',
      'POST',
      `/${ctx.project}/_apis/policy/configurations`,
      {
        isEnabled: true,
        isBlocking: false,
        type: { id: BUILD_POLICY },
        settings: {
          buildDefinitionId: defId,
          queueOnSourceUpdateOnly: false,
          manualQueueOnly: false,
          displayName: `Qualor probe item ${ctx.item} rights ${ctx.stamp}`,
          validDuration: 0,
          scope: [
            {
              repositoryId: repo.id,
              refName: `refs/heads/probe/${ctx.item}-rights-${ctx.stamp}`,
              matchKind: 'exact',
            },
          ],
        },
      },
    );
    out.push(policy.line);
    const policyId = (policy.res?.json as { id?: unknown } | null)?.id;
    if (policy.ok && typeof policyId === 'number') {
      ctx.cleanup.add(`delete the rights check's policy ${policyId}`, () =>
        remove(
          ctx.bot,
          `/${ctx.project}/_apis/policy/configurations/${policyId}`,
          `policy ${policyId}`,
        ),
      );
    }
  } else {
    out.push('rights the authorisation and the policy: not tried (no pipeline of its own)');
  }
  return out;
}

/**
 * Item 31 (Boards): the project list (`vso.project`), the work item types, a dry-run create, and a
 * real create with a tag the project does not have yet (Create tag definition).
 */
export async function boardsRights(
  ctx: ProbeContext,
  projectId: string,
  typeName: string,
  tag: string,
): Promise<string[]> {
  const out: string[] = [];
  const PATCH_JSON = 'application/json-patch+json';
  out.push(
    (
      await rightsCall(
        ctx,
        'the project list (GET _apis/projects)',
        'GET',
        '/_apis/projects?$top=5',
      )
    ).line,
    (
      await rightsCall(
        ctx,
        'the work item types (GET wit/workitemtypes)',
        'GET',
        `/${projectId}/_apis/wit/workitemtypes`,
      )
    ).line,
  );
  const newTag = `${tag}-rights-${ctx.stamp}`;
  const fields = (title: string) => [
    { op: 'add', path: '/fields/System.Title', value: title },
    { op: 'add', path: '/fields/System.Tags', value: `${tag}; ${newTag}` },
  ];
  const type = encodeURIComponent(typeName);
  out.push(
    (
      await rightsCall(
        ctx,
        'a dry-run work item (POST wit/workitems/$type?validateOnly=true)',
        'POST',
        `/${projectId}/_apis/wit/workitems/$${type}?validateOnly=true`,
        fields(`Qualor probe item ${ctx.item}: rights check, dry run (${ctx.stamp})`),
        { contentType: PATCH_JSON },
      )
    ).line,
  );
  const made = await rightsCall(
    ctx,
    `a work item with the new tag ${newTag} (POST wit/workitems/$type: Create tag definition)`,
    'POST',
    `/${projectId}/_apis/wit/workitems/$${type}`,
    fields(`Qualor probe item ${ctx.item}: rights check (${ctx.stamp})`),
    { contentType: PATCH_JSON },
  );
  out.push(made.line);
  const id = (made.res?.json as { id?: unknown } | null)?.id;
  if (made.ok && typeof id === 'number') {
    ctx.cleanup.add(`delete the rights check's tag ${newTag}`, async () => {
      await ctx.bot.request('DELETE', `/${projectId}/_apis/wit/tags/${encodeURIComponent(newTag)}`);
    });
    ctx.cleanup.add(`delete the rights check's work item ${id}`, () =>
      remove(ctx.bot, `/${projectId}/_apis/wit/workitems/${id}`, `work item ${id}`),
    );
  }
  return out;
}
