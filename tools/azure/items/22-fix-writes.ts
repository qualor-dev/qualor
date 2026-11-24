import { z } from 'zod';
import type { AzureResponse } from '../client.js';
import {
  answerOf,
  createdNumber,
  getPr,
  gitPath,
  messageOf,
  ok,
  prWithMerge,
  refHead,
  repoInfo,
  result,
  shape,
  threadsPath,
  waitFor,
  type ProbeContext,
  type ProbeItem,
  type Repo,
} from './common.js';

/** Azure DevOps's longest pull request description, in characters. */
export const DESCRIPTION_LIMIT = 4000;

const ZEROS = '0'.repeat(40);

/**
 * The test file's bytes: a BOM, CRLF lines and one non-ASCII line; line 2 carries `tag`, so each
 * version of the file differs on that one line (two versions that change it conflict).
 */
export function sampleBytes(tag: string): Buffer {
  const lines = [
    '// Qualor probe item 22: bytes must survive',
    `tag: ${tag}`,
    'Grüße, señor — naïve ✓',
    'last line',
    '',
  ];
  const crlf = lines.join(String.fromCharCode(13, 10));
  return Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(crlf, 'utf8')]);
}

/** A description of exactly `length` characters. */
export const descriptionOf = (length: number): string => 'd'.repeat(length);

/** `ancestor` when `base` is the common commit of base and target (base is an ancestor), else `diverged`. */
export function ancestryVerdict(
  base: string,
  commonCommit: string | undefined,
): 'ancestor' | 'diverged' {
  return commonCommit === base ? 'ancestor' : 'diverged';
}

/** The ref called exactly `name`: `refs?filter=` matches by prefix, so `<b>-2` comes with `<b>`. */
export function exactRef<T extends { name: string }>(refs: T[], name: string): T | undefined {
  return refs.find((r) => r.name === name);
}

const CommitsDiffSchema = z.object({ commonCommit: z.string().optional() }).loose();
const PushAnswerSchema = z.object({
  commits: z.array(z.object({ commitId: z.string() })).min(1),
  refUpdates: z.array(z.object({ name: z.string(), newObjectId: z.string() })).min(1),
});
const RefListSchema = z.object({
  value: z.array(z.object({ name: z.string(), objectId: z.string() })),
});
const RefUpdatesSchema = z.object({
  value: z.array(z.object({ success: z.boolean(), updateStatus: z.string() }).loose()),
});

const enc = encodeURIComponent;

/** One push of one commit that edits `path` with `bytes` (base64) or adds it; no `ok`: callers judge the answer. */
export async function pushBytes(
  ctx: ProbeContext,
  repo: Repo,
  refName: string,
  oldObjectId: string,
  parent: string,
  change: { changeType: 'add' | 'edit'; path: string; bytes: Buffer },
  comment: string,
): Promise<AzureResponse> {
  return ctx.bot.request('POST', gitPath(ctx, repo, '/pushes'), {
    refUpdates: [{ name: refName, oldObjectId }],
    commits: [
      {
        comment,
        parents: [parent],
        changes: [
          {
            changeType: change.changeType,
            item: { path: change.path },
            newContent: { content: change.bytes.toString('base64'), contentType: 'base64encoded' },
          },
        ],
      },
    ],
  });
}

/** The commit a successful push made. */
export function pushedCommit(res: AzureResponse, what: string): string {
  const push = shape(PushAnswerSchema, ok(res, what).json, what);
  return push.commits[push.commits.length - 1]?.commitId ?? '';
}

/** The raw bytes of `path` at a commit (`$format=octetStream`): the answer and the bytes. */
export async function readRaw(
  ctx: ProbeContext,
  repo: Repo,
  path: string,
  version: string,
  versionType: 'commit' | 'branch' = 'commit',
): Promise<{ res: AzureResponse; bytes: Buffer }> {
  const res = await ctx.bot.request(
    'GET',
    gitPath(
      ctx,
      repo,
      `/items?path=${enc(path)}&versionDescriptor.version=${enc(version)}` +
        `&versionDescriptor.versionType=${versionType}&$format=octetStream`,
    ),
  );
  // The client keeps a non-JSON body as its text (UTF-8 decoded, the BOM kept).
  const bytes = typeof res.json === 'string' ? Buffer.from(res.json, 'utf8') : Buffer.alloc(0);
  return { res, bytes };
}

const fieldOf = (json: unknown, key: string): unknown =>
  json && typeof json === 'object' ? (json as Record<string, unknown>)[key] : undefined;

/** What a failed-or-not answer says, for the detail: status, typeKey and message. */
function describeAnswer(res: AzureResponse): string {
  const type = fieldOf(res.json, 'typeKey');
  return `HTTP ${res.status}${typeof type === 'string' ? ` ${type}` : ''}: ${messageOf(res.json)}`;
}

export const item: ProbeItem = {
  id: 22,
  title: 'fix-pull-request writes: ancestry, raw read, base64 push, force-move, descriptions, refs',
  async run(ctx) {
    const repo = await repoInfo(ctx);
    const facts: string[] = [];
    const filePath = `/probe/item-22-${ctx.stamp}.txt`;
    const otherPath = `/probe/item-22-${ctx.stamp}-b.txt`;
    const fail = (what: string): never => {
      throw new Error(`${what}; see the recordings`);
    };

    const mainHead = await refHead(ctx, repo.defaultBranch);
    if (!mainHead) throw new Error(`no head for ${repo.defaultBranch}`);

    // The base branch: A adds the test file, B adds another file on top of A.
    const baseRef = `refs/heads/probe/22-base-${ctx.stamp}`;
    ctx.cleanup.add(`delete branch ${baseRef}`, () => deleteRef(ctx, repo, baseRef));
    const baseA = pushedCommit(
      await pushBytes(
        ctx,
        repo,
        baseRef,
        ZEROS,
        mainHead,
        { changeType: 'add', path: filePath, bytes: sampleBytes('base') },
        'Qualor probe item 22: base A',
      ),
      'push base A',
    );
    const baseB = pushedCommit(
      await pushBytes(
        ctx,
        repo,
        baseRef,
        baseA,
        baseA,
        { changeType: 'add', path: otherPath, bytes: Buffer.from('b\n') },
        'Qualor probe item 22: base B',
      ),
      'push base B',
    );

    // 22c: a new branch from A with an edit pushed as base64.
    const fixRef = `refs/heads/probe/22-fix-${ctx.stamp}`;
    ctx.cleanup.add(`delete branch ${fixRef}`, () => deleteRef(ctx, repo, fixRef));
    const fix1Bytes = sampleBytes('fix-1');
    const create = await pushBytes(
      ctx,
      repo,
      fixRef,
      ZEROS,
      baseA,
      { changeType: 'edit', path: filePath, bytes: fix1Bytes },
      'Qualor probe item 22: fix 1',
    );
    await ctx.record('push-new-branch', answerOf(create));
    const fix1 = pushedCommit(create, 'push new branch');
    const atFix1 = await readRaw(ctx, repo, filePath, fix1);
    const c = atFix1.bytes.equals(fix1Bytes) && (await refHead(ctx, fixRef)) === fix1;
    facts.push(
      `22c new branch with base64 edit: ${create.status}; file at the new commit equals the pushed bytes: ${c}`,
    );
    if (!c)
      fail(
        `22c: ${describeAnswer(create)}; file at the new commit has ${atFix1.bytes.length} bytes, pushed ${fix1Bytes.length}`,
      );

    // 22b: the raw read of the base commit: the exact bytes, record the headers and the size only.
    const rawBase = await readRaw(ctx, repo, filePath, baseA);
    await ctx.record('raw-read', {
      status: rawBase.res.status,
      contentType: rawBase.res.headers['content-type'] ?? null,
      contentDisposition: rawBase.res.headers['content-disposition'] ? 'present' : null,
      size: rawBase.bytes.length,
      expectedSize: sampleBytes('base').length,
    });
    const b = rawBase.res.status === 200 && rawBase.bytes.equals(sampleBytes('base'));
    facts.push(
      `22b raw read: HTTP ${rawBase.res.status}, ${rawBase.res.headers['content-type'] ?? 'no content-type'}, ${rawBase.bytes.length} bytes, equal to the pushed bytes (CRLF, BOM, non-ASCII): ${b}`,
    );
    if (!b)
      fail(
        `22b: ${describeAnswer(rawBase.res)}; ${rawBase.bytes.length} bytes against ${sampleBytes('base').length}`,
      );

    // 22a: ancestry. A is an ancestor of B; B and the fix commit diverged (the common commit is A).
    const diff = async (base: string, target: string) =>
      ctx.bot.request(
        'GET',
        gitPath(
          ctx,
          repo,
          `/diffs/commits?baseVersion=${base}&baseVersionType=commit&targetVersion=${target}&targetVersionType=commit&$top=1`,
        ),
      );
    const ancestor = await diff(baseA, baseB);
    await ctx.record('ancestry-ancestor', answerOf(ancestor));
    const diverged = await diff(baseB, fix1);
    await ctx.record('ancestry-diverged', answerOf(diverged));
    const common = (res: AzureResponse) =>
      shape(CommitsDiffSchema, ok(res, 'diffs/commits').json, 'diffs/commits').commonCommit;
    const a1 = ancestryVerdict(baseA, common(ancestor));
    const a2 = ancestryVerdict(baseB, common(diverged));
    facts.push(
      `22a ancestry: A to B (A is an ancestor) is ${a1}; B to the fix commit (diverged) is ${a2}; common commit of the diverged pair is A: ${common(diverged) === baseA}`,
    );
    if (a1 !== 'ancestor' || a2 !== 'diverged')
      fail('22a: the common commit does not tell ancestor from diverged');

    // 22d: move the fix branch onto a different commit of the base branch. First the single push
    // (recorded: Azure refuses it), then the two-step refresh: push to a temporary ref, move the branch.
    const fix2Bytes = sampleBytes('fix-2');
    const move = await pushBytes(
      ctx,
      repo,
      fixRef,
      fix1,
      baseB,
      { changeType: 'edit', path: filePath, bytes: fix2Bytes },
      'Qualor probe item 22: fix 2',
    );
    await ctx.record('push-force-move', answerOf(move));
    facts.push(
      `22d single push with oldObjectId = head and another parent: ${describeAnswer(move)}`,
    );
    if (move.status >= 200 && move.status < 300)
      fail('22d: the single push was accepted, the two-step is not needed');

    const refresh = async (name: string) => {
      const res = await pushBytes(
        ctx,
        repo,
        name,
        ZEROS,
        baseB,
        { changeType: 'edit', path: filePath, bytes: fix2Bytes },
        'Qualor probe item 22: fix 2',
      );
      // Registered before the answer is judged: a ref that was made is deleted at clean-up.
      ctx.cleanup.add(`delete ref ${name}`, () => deleteRef(ctx, repo, name));
      return res;
    };
    const tmpOther = `refs/qualor/fix-tmp/${ctx.stamp}`;
    let tmpRef = tmpOther;
    let tmpPush = await refresh(tmpRef);
    await ctx.record('push-tmp-ref-first', answerOf(tmpPush));
    const firstTried = describeAnswer(tmpPush);
    if (tmpPush.status >= 300) {
      tmpRef = `refs/heads/qualor/fix-tmp/${ctx.stamp}`;
      tmpPush = await refresh(tmpRef);
      await ctx.record('push-tmp-ref-branch', answerOf(tmpPush));
    }
    facts.push(
      `22d temporary ref: ${tmpOther} -> ${firstTried}; used ${tmpRef} (${tmpRef === tmpOther ? 'not a branch' : 'a branch name'}): ${describeAnswer(tmpPush)}`,
    );
    const fix2 = pushedCommit(tmpPush, 'push to the temporary ref');
    const moveRef = await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: fixRef, oldObjectId: fix1, newObjectId: fix2 },
    ]);
    await ctx.record('ref-move', answerOf(moveRef));
    const moveUpdate = RefUpdatesSchema.safeParse(moveRef.json);
    const moved =
      moveRef.status < 300 && moveUpdate.success && moveUpdate.data.value[0]?.success === true;
    const headAfter = await refHead(ctx, fixRef);
    const atFix2 = await readRaw(ctx, repo, filePath, fix2);
    facts.push(
      `22d non-fast-forward ref update of the branch: ${describeAnswer(moveRef)}${moveUpdate.success ? `; success=${String(moveUpdate.data.value[0]?.success)} updateStatus=${moveUpdate.data.value[0]?.updateStatus}` : ''}; ` +
        `head is the new commit: ${headAfter === fix2}; file equals the pushed bytes: ${atFix2.bytes.equals(fix2Bytes)}`,
    );
    if (!moved || headAfter !== fix2)
      fail(`22d: the ref update was refused: ${describeAnswer(moveRef)}`);
    const tmpDelete = await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: tmpRef, oldObjectId: fix2, newObjectId: ZEROS },
    ]);
    await ctx.record('ref-delete-tmp', answerOf(tmpDelete));
    facts.push(
      `22d delete of the temporary ref: ${describeAnswer(tmpDelete)}, gone: ${(await refHead(ctx, tmpRef)) === undefined}`,
    );

    // 22e: a push with the old head as oldObjectId.
    const stale = await pushBytes(
      ctx,
      repo,
      fixRef,
      fix1,
      baseB,
      { changeType: 'edit', path: filePath, bytes: sampleBytes('fix-3') },
      'Qualor probe item 22: stale',
    );
    await ctx.record('push-stale', answerOf(stale));
    facts.push(
      `22e stale push: ${describeAnswer(stale)}; head unchanged: ${(await refHead(ctx, fixRef)) === fix2}`,
    );

    // 22f: description limit, then the pull request's fields.
    const prBody = (description: string) => ({
      sourceRefName: fixRef,
      targetRefName: baseRef,
      title: `Qualor probe item 22 (${ctx.stamp})`,
      description,
    });
    const track = (res: AzureResponse): number => {
      const id = createdNumber(res, 'pullRequestId', 'create pull request');
      ctx.cleanup.add(`abandon pull request ${id}`, () => abandonIfActive(ctx, repo, id));
      return id;
    };
    const tooLong = await ctx.bot.request(
      'POST',
      gitPath(ctx, repo, '/pullrequests'),
      prBody(descriptionOf(DESCRIPTION_LIMIT + 1)),
    );
    await ctx.record('pr-description-4001', answerOf(tooLong));
    facts.push(
      `22f description of ${DESCRIPTION_LIMIT + 1} characters: ${describeAnswer(tooLong)}`,
    );
    if (tooLong.status >= 200 && tooLong.status < 300) {
      const id = track(tooLong);
      await abandonIfActive(ctx, repo, id);
    }
    const created = await ctx.bot.request(
      'POST',
      gitPath(ctx, repo, '/pullrequests'),
      prBody(descriptionOf(DESCRIPTION_LIMIT)),
    );
    await ctx.record('pr-description-4000', answerOf(created));
    facts.push(`22f description of ${DESCRIPTION_LIMIT} characters: HTTP ${created.status}`);
    const prId = track(ok(created, 'create pull request with 4000 characters'));
    const merged = await prWithMerge(ctx, prId);
    await ctx.record('pr-get', answerOf(merged.res));
    const pr = merged.res.json;
    const repoField = fieldOf(pr, 'repository');
    facts.push(
      `22f PR GET: mergeStatus ${String(fieldOf(pr, 'mergeStatus'))}, lastMergeSourceCommit ${fieldOf(pr, 'lastMergeSourceCommit') ? 'present' : 'absent'}, ` +
        `description ${String(fieldOf(pr, 'description')).length} characters, repository.id ${fieldOf(repoField, 'id') ? 'present' : 'absent'}, forkSource ${fieldOf(pr, 'forkSource') === undefined ? 'absent' : 'present'}`,
    );

    // 22g: find it by source and target.
    const find = ok(
      await ctx.bot.request(
        'GET',
        gitPath(
          ctx,
          repo,
          `/pullrequests?searchCriteria.sourceRefName=${enc(fixRef)}&searchCriteria.targetRefName=${enc(baseRef)}&searchCriteria.status=active`,
        ),
      ),
      'find pull request',
    );
    await ctx.record('pr-find', answerOf(find));
    const found = shape(
      z.object({
        count: z.number().optional(),
        value: z.array(z.object({ pullRequestId: z.number() }).loose()),
      }),
      find.json,
      'pull request list',
    );
    facts.push(
      `22g find: ${found.value.length} pull request(s), exactly the created one: ${found.value.length === 1 && found.value[0]?.pullRequestId === prId}`,
    );

    // 22h: a change on the base branch that conflicts with the fix branch.
    const conflictPush = await pushBytes(
      ctx,
      repo,
      baseRef,
      baseB,
      baseB,
      { changeType: 'edit', path: filePath, bytes: sampleBytes('base-2') },
      'Qualor probe item 22: conflicting base',
    );
    pushedCommit(conflictPush, 'push conflicting base change');
    let conflictRes: AzureResponse | undefined;
    const conflicted = await waitFor(
      async () => {
        const got = await getPr(ctx, prId);
        conflictRes = got.res;
        return fieldOf(got.res.json, 'mergeStatus') === 'conflicts' ? got : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 2000 },
    );
    if (conflictRes) await ctx.record('pr-conflict', answerOf(conflictRes));
    facts.push(
      `22h conflict: mergeStatus ${String(fieldOf(conflictRes?.json, 'mergeStatus'))} (polled up to 60 s), reached conflicts: ${conflicted !== undefined}`,
    );

    // 22i: close: PATCH title and description, a closed PR-level thread, then abandon.
    const patch = await ctx.bot.request('PATCH', gitPath(ctx, repo, `/pullrequests/${prId}`), {
      title: `Qualor probe item 22 (${ctx.stamp}) updated`,
      description: 'Updated by the probe.',
    });
    await ctx.record('pr-update', answerOf(patch));
    const thread = await ctx.bot.request('POST', threadsPath(ctx, repo, prId), {
      comments: [{ parentCommentId: 0, content: 'Closed by the Qualor probe.', commentType: 1 }],
      status: 'closed',
    });
    await ctx.record('pr-thread-closed', answerOf(thread));
    const abandon = await ctx.bot.request('PATCH', gitPath(ctx, repo, `/pullrequests/${prId}`), {
      status: 'abandoned',
    });
    await ctx.record('pr-abandon', answerOf(abandon));
    facts.push(
      `22i close: PATCH title and description HTTP ${patch.status}; PR-level thread with status closed HTTP ${thread.status} (status ${String(fieldOf(thread.json, 'status'))}); ` +
        `abandon HTTP ${abandon.status} (status ${String(fieldOf(abandon.json, 'status'))})`,
    );

    // 22h again: a pull request opened after the conflicting base change (the first kept its merge status).
    const late = track(
      ok(
        await ctx.bot.request(
          'POST',
          gitPath(ctx, repo, '/pullrequests'),
          prBody('Opened after the conflicting base change.'),
        ),
        'create the late pull request',
      ),
    );
    let lateRes: AzureResponse | undefined;
    const lateConflict = await waitFor(
      async () => {
        const got = await getPr(ctx, late);
        lateRes = got.res;
        return fieldOf(got.res.json, 'mergeStatus') === 'conflicts' ? got : undefined;
      },
      { timeoutMs: 60_000, intervalMs: 2000 },
    );
    if (lateRes) await ctx.record('pr-conflict-late', answerOf(lateRes));
    facts.push(
      `22h a pull request created after the base change: mergeStatus ${String(fieldOf(lateRes?.json, 'mergeStatus'))}, reached conflicts: ${lateConflict !== undefined}`,
    );
    await abandonIfActive(ctx, repo, late);

    // 22j: ref delete with a stale oldObjectId, the prefix match of the refs filter, the right delete.
    const sibling = `${fixRef}-2`;
    const sib = await pushBytes(
      ctx,
      repo,
      sibling,
      ZEROS,
      baseA,
      { changeType: 'edit', path: filePath, bytes: sampleBytes('sibling') },
      'Qualor probe item 22: sibling',
    );
    pushedCommit(sib, 'push sibling branch');
    ctx.cleanup.add(`delete branch ${sibling}`, () => deleteRef(ctx, repo, sibling));
    const listing = ok(
      await ctx.bot.request(
        'GET',
        gitPath(ctx, repo, `/refs?filter=${enc(fixRef.replace(/^refs\//, ''))}`),
      ),
      'refs listing',
    );
    await ctx.record('refs-prefix', answerOf(listing));
    const refs = shape(RefListSchema, listing.json, 'refs').value;
    facts.push(
      `22j refs?filter=heads/<b> with <b> and <b>-2: ${refs.length} refs, exact pick finds <b> at its head: ${exactRef(refs, fixRef)?.objectId === fix2}`,
    );
    const staleDelete = await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: fixRef, oldObjectId: fix1, newObjectId: ZEROS },
    ]);
    await ctx.record('ref-delete-stale', answerOf(staleDelete));
    const staleUpdate =
      staleDelete.status < 300 ? RefUpdatesSchema.safeParse(staleDelete.json) : undefined;
    facts.push(
      `22j delete with a stale oldObjectId: ${describeAnswer(staleDelete)}${staleUpdate?.success ? `; per update success=${String(staleUpdate.data.value[0]?.success)} updateStatus=${staleUpdate.data.value[0]?.updateStatus}` : ''}`,
    );
    const rightDelete = await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: fixRef, oldObjectId: fix2, newObjectId: ZEROS },
    ]);
    await ctx.record('ref-delete', answerOf(rightDelete));
    const rightUpdate = shape(
      RefUpdatesSchema,
      ok(rightDelete, 'delete branch').json,
      'ref update',
    );
    facts.push(
      `22j delete with the right head: HTTP ${rightDelete.status}, success=${String(rightUpdate.value[0]?.success)}, gone: ${(await refHead(ctx, fixRef)) === undefined}`,
    );

    return result(ctx, 'yes', facts.join('\n'));
  },
};

async function deleteRef(ctx: ProbeContext, repo: Repo, refName: string): Promise<void> {
  const head = await refHead(ctx, refName);
  if (!head) return;
  ok(
    await ctx.bot.request('POST', gitPath(ctx, repo, '/refs'), [
      { name: refName, oldObjectId: head, newObjectId: ZEROS },
    ]),
    `delete ${refName}`,
  );
}

async function abandonIfActive(ctx: ProbeContext, repo: Repo, id: number): Promise<void> {
  const got = await getPr(ctx, id);
  if (got.pr.status !== 'active') return;
  ok(
    await ctx.bot.request('PATCH', gitPath(ctx, repo, `/pullrequests/${id}`), {
      status: 'abandoned',
    }),
    `abandon pull request ${id}`,
  );
}
