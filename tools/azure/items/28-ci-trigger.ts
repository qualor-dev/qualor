import { z } from 'zod';
import { rec } from './19-decoration.js';
import { ensureRepository, headOf } from './24-fix-pr.js';
import { queueNamed } from './26-ci-setup.js';
import {
  BuildSchema,
  answerOf,
  createdNumber,
  deleteBranch,
  ok,
  pushFiles,
  repoInfo,
  result,
  shape,
  sleep,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** The kept repository of this item; its main holds the pipeline file alone. */
export const TRIGGER_REPOSITORY = 'qualor-probe-trigger';
const YAML_PATH = '.azure-pipelines/qualor.yml';
const HOSTED_QUEUE = 'Azure Pipelines';
const ZEROS = '0'.repeat(40);
/** How long a push may take to start a CI build before the answer is no. */
const FIRE_WAIT_MS = 5 * 60_000;
/** S2: the definition's age at its push. */
const S2_AGE_MS = 12 * 60_000;
/** S5: the S1 definition's age at the second push. */
const S5_AGE_MS = 15 * 60_000;
const POLL_MS = 5000;
const MAIN = 'refs/heads/main';
const API = { apiVersion: '7.0-preview.1' };

/** The pipeline file: one echo step on the hosted pool, CI on every branch. */
export function triggerYaml(): string {
  return [
    'trigger:',
    '  branches:',
    "    include: ['*']",
    'pool:',
    '  vmImage: ubuntu-latest',
    'steps:',
    '- script: echo probe',
    '',
  ].join('\n');
}

/** What the Build Definitions API gets: a YAML pipeline with the CI trigger the setup makes. */
export function definitionBody(
  name: string,
  queueId: number,
  repo: { id: string; name: string },
): Record<string, unknown> {
  return {
    name,
    path: '\\',
    type: 'build',
    queue: { id: queueId },
    process: { type: 2, yamlFilename: YAML_PATH },
    repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch: MAIN },
    triggers: [
      {
        triggerType: 'continuousIntegration',
        settingsSourceType: 2,
        branchFilters: [],
        pathFilters: [],
        batchChanges: false,
        maxConcurrentBuildsPerBranch: 1,
      },
    ],
  };
}

type Build = z.infer<typeof BuildSchema> & { queueTime?: string };
const ListedBuild = BuildSchema.extend({ queueTime: z.string().optional() });

/** The first build of the list that CI queued (any reason but a manual one), none otherwise. */
export function firstCiBuild(
  builds: readonly { id: number; reason?: string }[],
  ignoreIds: readonly number[] = [],
): { id: number; reason?: string } | undefined {
  return builds.find(
    (b) => !ignoreIds.includes(b.id) && b.reason !== undefined && b.reason !== 'manual',
  );
}

/** One scenario's outcome in words. */
export function describeFire(
  scenario: string,
  fired: { reason?: string; seconds: number } | undefined,
  waitedSeconds: number,
): string {
  return fired
    ? `${scenario}: fired yes, reason ${fired.reason ?? 'unknown'}, first seen ${fired.seconds} s after the push`
    : `${scenario}: fired no (nothing in ${waitedSeconds} s after the push)`;
}

type Outcome = { scenario: string; fired: boolean; text: string; defId: number };

export const item = {
  id: 28,
  title: 'when Azure DevOps Services honours the YAML CI trigger of a REST-created pipeline',
  async run(ctx: ProbeContext) {
    if (ctx.target !== 'services') {
      return result(ctx, 'no', 'item 28 runs on the Services target only');
    }
    const notes: string[] = [];
    const root = `/${ctx.project}/_apis`;
    const created = await ensureRepository(ctx, notes, TRIGGER_REPOSITORY);
    const rctx: ProbeContext = { ...ctx, repo: TRIGGER_REPOSITORY };
    if (!(await headOf(ctx, created.id, MAIN))) {
      const seeded = ok(
        await ctx.bot.request(
          'POST',
          `/${ctx.project}/_apis/git/repositories/${created.id}/pushes`,
          {
            refUpdates: [{ name: MAIN, oldObjectId: ZEROS }],
            commits: [
              {
                comment: 'Qualor probe item 28: the pipeline file',
                changes: [
                  {
                    changeType: 'add',
                    item: { path: `/${YAML_PATH}` },
                    newContent: { content: triggerYaml(), contentType: 'rawtext' },
                  },
                ],
              },
            ],
          },
        ),
        'seed main',
      );
      await rec(ctx, 'push-seed', answerOf(seeded));
      notes.push(`main of ${TRIGGER_REPOSITORY} seeded with ${YAML_PATH}`);
    }

    const repo = await repoInfo(rctx);
    const queues = shape(
      z.object({ value: z.array(z.object({ id: z.number(), name: z.string() })) }),
      ok(await ctx.bot.request('GET', `${root}/distributedtask/queues`, undefined, API), 'queues')
        .json,
      'queues',
    ).value;
    const hosted = queueNamed(queues, HOSTED_QUEUE);
    if (!hosted) return result(ctx, 'no', `no queue named ${HOSTED_QUEUE}`);

    const defs = `${root}/build/definitions`;
    const buildsOf = async (defId: number): Promise<Build[]> =>
      shape(
        z.object({ value: z.array(ListedBuild) }),
        ok(await ctx.bot.request('GET', `${root}/build/builds?definitions=${defId}`), 'builds')
          .json,
        'builds',
      ).value;
    const cancel = async (b: { id: number; status: string }) => {
      if (b.status === 'completed' || b.status === 'cancelling') return;
      await ctx.bot.request('PATCH', `${root}/build/builds/${b.id}`, { status: 'cancelling' });
    };

    /** Creates a scenario's definition; renames and deletes it at clean-up. */
    const create = async (scenario: string) => {
      const name = `probe-28-${scenario}-${ctx.stamp}`;
      const res = await ctx.bot.request('POST', defs, definitionBody(name, hosted.id, repo));
      ok(res, `create ${name}`);
      const id = createdNumber(res, 'id', 'definition');
      const at = Date.now();
      ctx.cleanup.add(`retire and delete definition ${name} (${id})`, async () => {
        for (const b of await buildsOf(id)) await cancel(b);
        const got = await ctx.bot.request('GET', `${defs}/${id}`);
        if (got.status === 404) return;
        ok(got, `get ${name}`);
        const body = got.json as Record<string, unknown>;
        ok(
          await ctx.bot.request('PUT', `${defs}/${id}`, {
            ...body,
            name: `probe-28 deleted ${ctx.stamp} ${id}`,
          }),
          `rename ${name}`,
        );
        const del = await ctx.bot.request('DELETE', `${defs}/${id}`);
        if (del.status !== 404) ok(del, `delete ${name}`);
      });
      return { id, name, at, res };
    };

    /** Pushes one commit to a probe branch (new from main, or the branch's own head). */
    const push = async (branch: string) => {
      const out = await pushFiles(rctx, branch, [
        { path: `/probe-28/${branch.replace(/\//g, '-')}-${Date.now()}.txt`, content: 'probe\n' },
      ]);
      return { at: Date.now(), ...out };
    };

    /** Polls a definition for 5 minutes after a push; cancels what it sees. */
    const watch = async (
      scenario: string,
      defId: number,
      pushedAt: number,
      ignoreIds: number[],
    ): Promise<Outcome> => {
      let fired: { id: number; reason?: string; seconds: number } | undefined;
      const cancelled = new Set<number>();
      const end = pushedAt + FIRE_WAIT_MS;
      for (;;) {
        const list = await buildsOf(defId);
        for (const b of list) {
          if (ignoreIds.includes(b.id) || cancelled.has(b.id)) continue;
          cancelled.add(b.id);
          await cancel(b);
        }
        const hit = firstCiBuild(list, ignoreIds);
        if (hit) {
          fired = { ...hit, seconds: Math.round((Date.now() - pushedAt) / 1000) };
          break;
        }
        if (Date.now() >= end) break;
        await sleep(POLL_MS);
      }
      const text = describeFire(scenario, fired, Math.round((Date.now() - pushedAt) / 1000));
      ctx.log(text);
      await rec(ctx, `${scenario.slice(0, 2).toLowerCase()}-outcome`, {
        scenario,
        fired: fired !== undefined,
        reason: fired?.reason ?? null,
        secondsAfterPush: fired?.seconds ?? null,
      });
      return { scenario, fired: fired !== undefined, text, defId };
    };

    const stamp = ctx.stamp;
    const wait = async (since: number, ms: number) => {
      const left = since + ms - Date.now();
      if (left > 0) await sleep(left);
    };

    // The four scenarios run side by side; each has its own definition and branch.
    const s1 = async (): Promise<Outcome & { createdAt: number; branch: string }> => {
      const d = await create('s1');
      await rec(ctx, 's1-definition-create', answerOf(d.res));
      const branch = `probe/28-s1-${stamp}`;
      const p = await push(branch);
      const out = await watch('S1 immediate', d.id, p.at, []);
      return { ...out, createdAt: d.at, branch };
    };
    const s2 = async (): Promise<Outcome> => {
      const d = await create('s2');
      await wait(d.at, S2_AGE_MS);
      const p = await push(`probe/28-s2-${stamp}`);
      return watch('S2 after 12 minutes', d.id, p.at, []);
    };
    const s3 = async (): Promise<Outcome> => {
      const d = await create('s3');
      const q = ok(
        await ctx.bot.request('POST', `${root}/build/builds`, {
          definition: { id: d.id },
          sourceBranch: MAIN,
        }),
        'queue the manual build',
      );
      const manual = createdNumber(q, 'id', 'manual build');
      await cancel({ id: manual, status: 'notStarted' });
      const p = await push(`probe/28-s3-${stamp}`);
      return watch('S3 after a manual run', d.id, p.at, [manual]);
    };
    const s4 = async (): Promise<Outcome> => {
      const d = await create('s4');
      const got = ok(await ctx.bot.request('GET', `${defs}/${d.id}`), 'get definition');
      const put = await ctx.bot.request('PUT', `${defs}/${d.id}`, got.json);
      ok(put, 'put the definition unchanged');
      const p = await push(`probe/28-s4-${stamp}`);
      return watch('S4 after a re-save', d.id, p.at, []);
    };

    const settled = await Promise.allSettled([s1(), s2(), s3(), s4()]);
    const facts: string[] = [...notes];
    const outs: (Outcome | undefined)[] = [];
    for (const [i, r] of settled.entries()) {
      if (r.status === 'fulfilled') {
        outs.push(r.value);
        facts.push(r.value.text);
      } else {
        outs.push(undefined);
        facts.push(`S${i + 1}: ERROR ${(r.reason as Error).message}`);
      }
    }
    const first = settled[0];
    if (first?.status === 'fulfilled' && !first.value.fired) {
      // S5: the S1 pipeline, once it is 15 minutes old, gets a second push on its own branch.
      await wait(first.value.createdAt, S5_AGE_MS);
      const p = await push(first.value.branch);
      const out = await watch('S5 second push at 15 minutes', first.value.defId, p.at, []);
      facts.push(out.text);
    }
    // The probe branches go at clean-up; make sure a failed push did not leave one.
    ctx.cleanup.add('delete the probe branches', async () => {
      for (const s of ['s1', 's2', 's3', 's4'])
        await deleteBranch(rctx, `refs/heads/probe/28-${s}-${stamp}`);
    });
    const all = outs.every((o) => o !== undefined);
    return result(ctx, all ? 'yes' : 'partly', facts.join('\n'));
  },
} satisfies ProbeItem;
