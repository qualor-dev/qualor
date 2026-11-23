import { describe, expect, it } from 'vitest';
import type { AzureSubscription } from './client';
import {
  generateHookPassword,
  HOOK_EVENT_VERSIONS,
  hookState,
  ownSubscriptions,
  projectHookState,
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
