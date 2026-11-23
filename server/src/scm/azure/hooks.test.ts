import { describe, expect, it } from 'vitest';
import { ScmError } from '../provider';
import type { AzureSubscription } from './client';
import {
  generateHookPassword,
  HOOK_EVENT_VERSIONS,
  hookState,
  ownSubscriptions,
  projectHookState,
  subscribeProjects,
} from './hooks';

const URL_OF_QUALOR = 'https://qualor.example.com/api/v0/azure-devops/webhooks/c1';
const sub = (over: Partial<AzureSubscription>): AzureSubscription => ({
  id: '00000000-0000-4000-8000-000000000001',
  status: 'enabled',
  eventType: 'git.pullrequest.updated',
  resourceVersion: '1.0',
  projectId: 'p1',
  url: URL_OF_QUALOR,
  ...over,
});

describe('Azure DevOps hook helpers', () => {
  it('pins the two events and their newest versions', () => {
    expect(HOOK_EVENT_VERSIONS).toEqual({
      'ms.vss-code.git-pullrequest-comment-event': '2.0',
      'git.pullrequest.updated': '1.0',
    });
  });

  it('generates 43 base64url characters, never the same twice', () => {
    const a = generateHookPassword();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(generateHookPassword()).not.toBe(a);
  });

  it('own subscriptions share the url and are one of the two events', () => {
    const own = sub({});
    const ownComment = sub({ eventType: 'ms.vss-code.git-pullrequest-comment-event' });
    const otherUrl = sub({ url: `${URL_OF_QUALOR}2` });
    const otherEvent = sub({ eventType: 'git.pullrequest.created' });
    expect(ownSubscriptions([own, ownComment, otherUrl, otherEvent], URL_OF_QUALOR)).toEqual([
      own,
      ownComment,
    ]);
  });

  it.each([
    ['enabled', 'enabled'],
    ['onProbation', 'onProbation'],
    ['disabledByUser', 'disabled'],
    ['disabledBySystem', 'disabled'],
    ['disabledByInactiveIdentity', 'disabled'],
  ])('maps %s to %s', (status, state) => {
    expect(hookState(status)).toBe(state);
  });

  it('a project is missing without either event, else its worst state', () => {
    const comment = sub({ eventType: 'ms.vss-code.git-pullrequest-comment-event' });
    const updated = sub({});
    expect(projectHookState([], 'p1')).toBe('missing');
    expect(projectHookState([comment], 'p1')).toBe('missing');
    expect(projectHookState([comment, updated], 'P1')).toBe('enabled');
    expect(projectHookState([comment, sub({ status: 'onProbation' })], 'p1')).toBe('onProbation');
    expect(
      projectHookState(
        [sub({ ...comment, status: 'disabledByUser' }), sub({ status: 'onProbation' })],
        'p1',
      ),
    ).toBe('disabled');
    expect(projectHookState([comment, updated], 'p2')).toBe('missing');
  });
});

describe('subscribeProjects (fix round 1)', () => {
  const PROJECT = 'p1';
  const offered = [
    { id: 'ms.vss-code.git-pullrequest-comment-event', versions: ['2.0', '1.0'] },
    { id: 'git.pullrequest.updated', versions: ['1.0'] },
  ];
  const fail = (kind: ScmError['kind'], status: number | null, reason?: 'not_public') =>
    new ScmError(kind, 'fixed text', { status, ...(reason ? { reason } : {}) });
  const stub = (
    own: AzureSubscription[],
    over: { create?: () => Promise<unknown>; replace?: () => Promise<unknown> } = {},
  ) => {
    const calls: string[] = [];
    const client = {
      hookEventTypes: async () => offered,
      subscriptions: async () => own,
      createSubscription: async (i: { eventType: string }) => {
        calls.push(`create ${i.eventType}`);
        await over.create?.();
        return sub({});
      },
      replaceSubscription: async (id: string) => {
        calls.push(`replace ${id}`);
        await over.replace?.();
        return sub({});
      },
    };
    return { client: client as never, calls };
  };
  const input = (client: never) => ({
    client,
    url: URL_OF_QUALOR,
    password: 'x'.repeat(43),
    passwordKnownToAzure: true,
    projectIds: [PROJECT],
  });
  const comment = (over: Partial<AzureSubscription> = {}) =>
    sub({
      eventType: 'ms.vss-code.git-pullrequest-comment-event',
      resourceVersion: '2.0',
      ...over,
    });

  it('F4: with two own subscriptions of one event, replaces the first and leaves the other', async () => {
    const first = comment({ id: '00000000-0000-4000-8000-0000000000a1', status: 'onProbation' });
    const second = comment({ id: '00000000-0000-4000-8000-0000000000a2', status: 'onProbation' });
    const { client, calls } = stub([first, second, sub({})]);
    const result = await subscribeProjects(input(client));
    expect(calls).toEqual([`replace ${first.id}`]);
    expect(result.projects).toEqual([
      { projectId: PROJECT, comment: 'replaced', updated: 'unchanged' },
    ]);
  });

  it('F5: a 404 on the replace of an own subscription deleted meanwhile creates it again', async () => {
    const own = comment({ status: 'onProbation' });
    const { client, calls } = stub([own, sub({})], {
      replace: async () => {
        throw fail('not_found', 404);
      },
    });
    const result = await subscribeProjects(input(client));
    expect(calls).toEqual([
      `replace ${own.id}`,
      'create ms.vss-code.git-pullrequest-comment-event',
    ]);
    expect(result.projects[0]!.comment).toBe('created');
    expect(result.failure).toBeNull();
  });

  it('F5: another failure stops the loop and reports what was done before it', async () => {
    const { client } = stub([], {
      create: async () => {
        throw fail('transient', 503);
      },
    });
    const two = { ...input(client), projectIds: ['p1', 'p2'] };
    const result = await subscribeProjects(two);
    expect(result.projects).toEqual([]);
    expect(result.failure?.kind).toBe('transient');
    let n = 0;
    const later = stub([], {
      create: async () => {
        n += 1;
        if (n === 3) throw fail('transient', 503);
      },
    });
    const done = await subscribeProjects({ ...input(later.client), projectIds: ['p1', 'p2'] });
    expect(done.projects).toEqual([{ projectId: 'p1', comment: 'created', updated: 'created' }]);
    expect(done.failure).not.toBeNull();
    expect(done.wrote).toBe(true);
  });

  it('F8: Azure 400 and 403 are refused; a transport refusal is a failure', async () => {
    for (const status of [400, 403]) {
      const { client } = stub([], {
        create: async () => {
          throw fail(status === 400 ? 'refused' : 'auth', status);
        },
      });
      const result = await subscribeProjects(input(client));
      expect(result.projects).toEqual([
        { projectId: PROJECT, comment: 'refused', updated: 'refused' },
      ]);
      expect(result.failure).toBeNull();
    }
    const { client } = stub([], {
      create: async () => {
        throw fail('refused', null, 'not_public');
      },
    });
    const result = await subscribeProjects(input(client));
    expect(result.projects).toEqual([]);
    expect(result.failure?.reason).toBe('not_public');
  });

  it('F2: stale beats enabled, loses to onProbation, disabled and missing', () => {
    const comment2 = comment();
    const updated = sub({});
    expect(projectHookState([comment2, updated], 'p1', false)).toBe('stale');
    expect(projectHookState([comment2, sub({ status: 'onProbation' })], 'p1', false)).toBe(
      'onProbation',
    );
    expect(projectHookState([comment2, sub({ status: 'disabledByUser' })], 'p1', false)).toBe(
      'disabled',
    );
    expect(projectHookState([comment2], 'p1', false)).toBe('missing');
    expect(projectHookState([comment2, updated], 'p1', true)).toBe('enabled');
  });
});
