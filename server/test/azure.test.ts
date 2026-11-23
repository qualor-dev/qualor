import { describe, expect, it } from 'vitest';
import { azureShape } from './fake-azure-devops';
import { deliverAzureEvent } from './azure';

interface Injected {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  payload?: string;
}

function stubApp() {
  const calls: Injected[] = [];
  const app = {
    inject: async (options: Injected) => {
      calls.push(options);
      return { statusCode: 204 };
    },
  };
  return { app, calls };
}

describe('deliverAzureEvent', () => {
  it('posts the recorded body as JSON to the connection route, with the Basic header', async () => {
    const { app, calls } = stubApp();
    const res = await deliverAzureEvent(
      app as never,
      'conn-1',
      'comment-created',
      {},
      { password: 'pw-1' },
    );
    expect(res).toEqual({ statusCode: 204 });
    const [call] = calls;
    expect(call?.method).toBe('POST');
    expect(call?.url).toBe('/api/v0/azure-devops/webhooks/conn-1');
    expect(call?.headers?.['content-type']).toBe('application/json');
    expect(call?.headers?.authorization).toBe(
      `Basic ${Buffer.from('qualor:pw-1').toString('base64')}`,
    );
    const recorded = azureShape<{ body: unknown }>('services', '9-event-comment-created').body;
    expect(JSON.parse(call!.payload!)).toEqual(recorded);
  });

  it('overrides nested fields without touching the rest, and sends no header without auth', async () => {
    const { app, calls } = stubApp();
    await deliverAzureEvent(app as never, 'c', 'comment-reply', {
      resource: { pullRequest: { pullRequestId: 77, repository: { id: 'r-1' } } },
      subscriptionId: 'sub-9',
    });
    const body = JSON.parse(calls[0]!.payload!) as {
      subscriptionId: string;
      eventType: string;
      resource: {
        pullRequest: {
          pullRequestId: number;
          title: string;
          repository: { id: string; name: string };
        };
      };
    };
    expect(body.subscriptionId).toBe('sub-9');
    expect(body.resource.pullRequest.pullRequestId).toBe(77);
    expect(body.resource.pullRequest.repository.id).toBe('r-1');
    expect(body.resource.pullRequest.repository.name).toBeTruthy();
    expect(body.resource.pullRequest.title).toBeTruthy();
    expect(body.eventType).toBe('ms.vss-code.git-pullrequest-comment-event');
    expect(calls[0]!.headers).not.toHaveProperty('authorization');
  });

  it('takes a user name, and reads the Server recordings when asked', async () => {
    const { app, calls } = stubApp();
    await deliverAzureEvent(
      app as never,
      'c',
      'pr-updated',
      {},
      { username: 'u', password: 'p' },
      'server',
    );
    expect(calls[0]!.headers?.authorization).toBe(`Basic ${Buffer.from('u:p').toString('base64')}`);
    const recorded = azureShape<{ body: unknown }>('server', '9-event-pr-updated').body;
    expect(JSON.parse(calls[0]!.payload!)).toEqual(recorded);
  });

  it('refuses an event name that is not a recording', async () => {
    const { app } = stubApp();
    await expect(deliverAzureEvent(app as never, 'c', '../x', {})).rejects.toThrow();
  });
});
