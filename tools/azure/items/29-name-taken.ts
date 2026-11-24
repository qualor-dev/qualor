import { z } from 'zod';
import { queueNamed } from './26-ci-setup.js';
import { retireDefinition } from './27-onboarding.js';
import {
  answerOf,
  createdNumber,
  ok,
  remove,
  repoInfo,
  result,
  shape,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** The setup's pipeline file; the definition needs no such file on main to be created. */
const YAML_PATH = '.azure-pipelines/qualor.yml';
const API = { apiVersion: '7.0-preview.1' };

/** What the setup sends for its pipeline, without variables: the name taken is all that counts. */
export function nameTakenBody(
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
    repository: { id: repo.id, name: repo.name, type: 'TfsGit', defaultBranch: 'refs/heads/main' },
  };
}

/** The status and `typeKey` of an answer: what the setup's `nameTaken` decides on. */
export function takenAnswer(status: number, json: unknown): { status: number; typeKey: string } {
  const type =
    json && typeof json === 'object' ? (json as Record<string, unknown>)['typeKey'] : undefined;
  return { status, typeKey: typeof type === 'string' ? type : 'none' };
}

/**
 * Item 29 (the sub-plan 7 review, FW2): what Azure DevOps answers a second pipeline create with a
 * name the project already has, in the same folder. The setup falls back to its second name on it,
 * so every second repository of a project goes through this answer. Main is never touched: a
 * definition may name a file main does not hold (item 26).
 */
export const item: ProbeItem = {
  id: 29,
  title: 'the answer to a second pipeline create with a name the project already has',
  async run(ctx: ProbeContext) {
    const repo = await repoInfo(ctx);
    const root = `/${repo.project.id}/_apis`;
    const defs = `${root}/build/definitions`;
    const queues = shape(
      z.object({ value: z.array(z.object({ id: z.number(), name: z.string() })) }),
      ok(await ctx.bot.request('GET', `${root}/distributedtask/queues`, undefined, API), 'queues')
        .json,
      'queues',
    ).value;
    const queue = queueNamed(queues, 'Azure Pipelines') ?? queueNamed(queues, 'Default');
    if (!queue)
      return result(ctx, 'no', 'the project has neither the hosted nor the Default queue');

    const name = `Qualor probe item 29 ${ctx.stamp}`;
    const definitionPath = (id: number) => `${defs}/${id}`;
    /** Renamed, then deleted: a soft-deleted definition may keep its name taken (item 27). */
    const track = (id: number) =>
      ctx.cleanup.add(`rename and delete definition ${id}`, async () => {
        const got = await ctx.bot.request('GET', definitionPath(id));
        if (got.status === 404) return;
        await retireDefinition(
          {
            get: async () =>
              shape(z.record(z.string(), z.unknown()), ok(got, `definition ${id}`).json, 'def'),
            put: async (defId, body) => {
              ok(await ctx.bot.request('PUT', definitionPath(defId), body), `rename ${defId}`);
            },
            remove: (defId) => remove(ctx.bot, definitionPath(defId), `definition ${defId}`),
          },
          id,
          ctx.stamp,
        );
      });

    const first = await ctx.bot.request('POST', defs, nameTakenBody(name, queue.id, repo));
    ok(first, 'create the first definition');
    track(createdNumber(first, 'id', 'first definition'));

    const second = await ctx.bot.request('POST', defs, nameTakenBody(name, queue.id, repo));
    if (second.status < 300) track(createdNumber(second, 'id', 'second definition'));
    await ctx.record('definition-name-taken', answerOf(second));
    const answer = takenAnswer(second.status, second.json);
    const facts = [
      `queue ${queue.name}; first create HTTP ${first.status}`,
      `second create with the same name in the same project and folder: HTTP ${answer.status}, typeKey ${answer.typeKey}`,
    ];
    return result(ctx, second.status >= 400 ? 'yes' : 'no', facts.join('\n'));
  },
};
