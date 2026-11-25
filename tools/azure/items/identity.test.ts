import { describe, expect, it } from 'vitest';
import type { AzureClient } from '../client.js';
import type { ProbeContext } from './common.js';
import {
  answerLine,
  identityLabel,
  qualorAnswerText,
  qualorConnectionRecord,
  recordedResult,
  refusedAnswer,
  stepLines,
  type QualorSend,
} from './identity.js';

describe('a weaker identity: step lines', () => {
  it('names each step ok or NOT ok with what was seen', () => {
    expect(
      stepLines([
        { what: 'the fix is open', pass: true, got: 'open' },
        { what: 'the setup run is done', pass: false, got: 'error permission_missing: text' },
      ]),
    ).toEqual([
      'step ok - the fix is open: open',
      'step NOT ok - the setup run is done: error permission_missing: text',
    ]);
  });
});

describe('a weaker identity: Azure DevOps answers', () => {
  it('reads a 2xx as its status, a ref update with its word', () => {
    expect(answerLine({ status: 201, json: { id: 7 } })).toBe('HTTP 201');
    const made = { value: [{ name: 'refs/heads/x', success: true, updateStatus: 'succeeded' }] };
    const refused = {
      value: [{ name: 'refs/heads/x', success: false, updateStatus: 'forcePushRequired' }],
    };
    expect(answerLine({ status: 200, json: made })).toBe(
      'HTTP 200, succeeded, updateStatus succeeded',
    );
    expect(answerLine({ status: 200, json: refused })).toBe(
      'HTTP 200, NOT made, updateStatus forcePushRequired',
    );
    expect(refusedAnswer({ status: 200, json: made })).toBe(false);
    expect(refusedAnswer({ status: 200, json: refused })).toBe(true);
    // A listing whose entries carry no `success` is no ref update.
    expect(refusedAnswer({ status: 200, json: { value: [{ id: 'a' }] } })).toBe(false);
  });

  it('reads a refusal as its status, typeKey and message; a typeKey of another shape is left out', () => {
    const denied = {
      status: 403,
      json: {
        typeKey: 'UnauthorizedRequestException',
        message: 'TF400813: The user is not authorized to access this resource.',
      },
    };
    expect(answerLine(denied)).toBe(
      'HTTP 403 UnauthorizedRequestException: TF400813: The user is not authorized to access this resource.',
    );
    expect(refusedAnswer(denied)).toBe(true);
    expect(answerLine({ status: 401, json: { typeKey: 'a b <c>', message: 'no' } })).toBe(
      'HTTP 401: no',
    );
  });
});

describe('a weaker identity: Qualor answers', () => {
  it("reads Qualor's code and its first message", () => {
    expect(
      qualorAnswerText(502, {
        code: 'SCM_UNAVAILABLE',
        title: 'Azure DevOps service hooks could not be written',
        detail: 'Azure DevOps refused the permission',
      }),
    ).toBe('HTTP 502 SCM_UNAVAILABLE: Azure DevOps refused the permission');
    expect(
      qualorAnswerText(422, { code: 'VALIDATION', errors: [{ path: 'body.x', message: 'bad' }] }),
    ).toBe('HTTP 422 VALIDATION: body.x: bad');
    expect(qualorAnswerText(500, null)).toBe('HTTP 500');
  });

  it("records the connection's problem and a connection test", async () => {
    const calls: string[] = [];
    const api: QualorSend = {
      send: (method, path) => {
        calls.push(`${method} ${path}`);
        if (method === 'GET') {
          return Promise.resolve({
            status: 200,
            json: {
              items: [
                { id: 'other', problem: null },
                { id: 'c1', problem: { code: 'permission_missing', at: '2026-11-25T10:00:00Z' } },
              ],
            },
          });
        }
        return Promise.resolve({
          status: 200,
          json: {
            ok: false,
            problem: { code: 'permission_missing', message: 'Azure DevOps refused a permission' },
            missingAccess: null,
          },
        });
      },
    };
    expect(await qualorConnectionRecord(api, 'o1', 'c1', 'r1')).toEqual([
      "Qualor's connection problem: permission_missing since 2026-11-25T10:00:00Z",
      "Qualor's connection test: failed, permission_missing: Azure DevOps refused a permission; missingAccess null",
    ]);
    expect(calls).toEqual([
      'GET /api/v0/scm-connections?organizationId=o1&limit=100',
      'POST /api/v0/scm-connections/c1/test',
    ]);
    expect(await qualorConnectionRecord(api, 'o1', 'other')).toEqual([
      "Qualor's connection problem: none",
    ]);
  });
});

describe('a weaker identity: the verdict', () => {
  it('keeps the bot texts and names the weaker identities', () => {
    expect(identityLabel('services')).toBe('the service principal');
    expect(identityLabel('server')).toBe("Qualor's PAT identity");
    expect(identityLabel('services', 'contributor')).toBe('the contributor service principal');
    expect(identityLabel('server', 'contributor')).toContain('probe-user');
    expect(identityLabel('services', 'minimal-pat')).toBe("Qualor's minimal-PAT identity");
  });

  it('answers recorded, with the steps, the notes and the record', () => {
    const logged: string[] = [];
    const ctx = {
      target: 'services',
      recordings: ['19-x.json'],
      qualorAs: { identity: 'contributor', client: {} as AzureClient },
      log: (line: string) => logged.push(line),
    } as unknown as ProbeContext;
    const res = recordedResult(
      ctx,
      'pull request 5',
      [
        { what: 'a', pass: true, got: 'fine' },
        { what: 'b', pass: false, got: 'refused' },
      ],
      ['n1'],
      ['rights x: refused, HTTP 403'],
    );
    expect(res.answer).toBe('recorded');
    expect(res.recordings).toEqual(['19-x.json']);
    expect(res.detail.split('\n\n')).toEqual([
      'pull request 5',
      "Qualor's identity: contributor (the contributor service principal); the probe's own setup is the main identity's",
      'step ok - a: fine',
      'step NOT ok - b: refused',
      'note: n1',
      'recorded: rights x: refused, HTTP 403',
    ]);
    expect(logged).toEqual(['step ok - a: fine', 'step NOT ok - b: refused']);
  });
});
