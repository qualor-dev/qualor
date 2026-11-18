import type { ServerResponse } from 'node:http';
import type { FixClaimAnswer, FixResultBody } from '@qualor/shared/fix';
import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { CliError, EXIT } from '../errors';
import { claimFix, sendFixResult } from './fix-client';
import type { ServerEndpoint } from './http';

const serve = useTestServers();
// Test secrets are assembled at runtime, so the repository's own gitleaks pass finds none here.
const TOKEN = ['qlr', 'prj', 'T0KEN', 'value'].join('_');
const FIX_ID = '0193a4c6-1c2e-7a3b-9f00-0000000000aa';
const SHA = 'a'.repeat(40);

const endpoint = (url: string): ServerEndpoint => ({ url, token: TOKEN, timeoutMs: 10_000 });

const ITEM = {
  id: FIX_ID,
  generation: 1,
  leaseToken: 'lease-1',
  family: 'js',
  packageName: 'qf-a',
  installedVersions: ['1.2.5'],
  vulnerabilities: [
    {
      id: 'CVE-2026-0001',
      severity: 'high',
      title: 'Prototype pollution',
      url: null,
      installedVersions: ['1.2.5'],
      fixedVersions: ['1.2.6'],
    },
  ],
  mainBranch: 'main',
  declinedTarget: null,
} satisfies FixClaimAnswer['items'][number];

const CLAIM = { projectKey: 'acme/app', families: ['js' as const], branch: 'main', revision: SHA };

const FAILURE: FixResultBody = {
  generation: 1,
  leaseToken: 'lease-1',
  failure: { code: 'package_manager', message: '`npm` exited with 1' },
};

async function exitOf(promise: Promise<unknown>): Promise<number> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof CliError) return err.exitCode;
    throw err;
  }
  throw new Error('expected a CliError');
}

describe('claimFix (R4, ruling F12)', () => {
  it('posts one claim with the families, max 1, the branch and the revision, as a streamed JSON body', async () => {
    const { url, requests } = await serve((_req, res) =>
      json(res, 200, { items: [ITEM], reason: null }),
    );
    const answer = await claimFix(endpoint(url), CLAIM);
    expect(answer).toEqual({ items: [ITEM], reason: null });
    expect(requests).toHaveLength(1);
    const [req] = requests;
    expect(req?.method).toBe('POST');
    expect(req?.url).toBe('/api/v0/projects/fixes/claim?projectKey=acme%2Fapp');
    expect(req?.headers['content-type']).toBe('application/json');
    expect(req?.headers['authorization']).toBe(`Bearer ${TOKEN}`);
    expect(req?.headers['content-length']).toBe(String(req?.body.length));
    expect(req?.headers['expect']).toBe('100-continue');
    expect(JSON.parse(req?.body.toString('utf8') ?? '')).toEqual({
      families: ['js'],
      max: 1,
      branch: 'main',
      revision: SHA,
    });
  });

  it('leaves out a revision that is not a full SHA-1 (the schema takes 40 hex digits)', async () => {
    const { url, requests } = await serve((_req, res) =>
      json(res, 200, { items: [], reason: null }),
    );
    await claimFix(endpoint(url), { ...CLAIM, revision: 'b'.repeat(64) });
    expect(JSON.parse(requests[0]?.body.toString('utf8') ?? '')).not.toHaveProperty('revision');
  });

  it('maps the refusals to the exit codes of qualor scan (R35)', async () => {
    const cases: [number, string | null, number][] = [
      [401, 'UNAUTHENTICATED', EXIT.AUTH],
      [403, 'TOKEN_NOT_ALLOWED', EXIT.AUTH],
      [409, 'NOT_MAIN_BRANCH', EXIT.USAGE],
      [404, 'PROJECT_NOT_FOUND', EXIT.SERVER],
      [404, null, EXIT.SERVER],
      [409, 'SOMETHING_ELSE', EXIT.SERVER],
      [500, 'INTERNAL', EXIT.SERVER],
    ];
    for (const [status, code, exit] of cases) {
      const { url } = await serve((_req, res) => {
        if (code === null) {
          res.writeHead(status, { 'content-type': 'text/plain', connection: 'close' });
          res.end('Not Found');
        } else problem(res, status, code);
      });
      expect(await exitOf(claimFix(endpoint(url), CLAIM)), `${status} ${code}`).toBe(exit);
    }
  });

  it('says a bare 404 needs Qualor 0.16, and names the branch on NOT_MAIN_BRANCH', async () => {
    const bare = await serve((_req, res) => {
      res.writeHead(404, { 'content-type': 'text/plain', connection: 'close' });
      res.end('Not Found');
    });
    await expect(claimFix(endpoint(bare.url), CLAIM)).rejects.toThrow(/Qualor 0\.16/);
    const branch = await serve((_req, res) => problem(res, 409, 'NOT_MAIN_BRANCH'));
    await expect(claimFix(endpoint(branch.url), { ...CLAIM, branch: 'feature' })).rejects.toThrow(
      /main branch.*feature|feature.*main branch/,
    );
  });

  it('is a server error for an answer that is not a claim answer', async () => {
    const { url } = await serve((_req, res) => json(res, 200, { items: 'nope' }));
    expect(await exitOf(claimFix(endpoint(url), CLAIM))).toBe(EXIT.SERVER);
  });
});

describe('sendFixResult (R6, R16, rulings T9b and T9d)', () => {
  it('puts the result as a streamed JSON body and answers accepted with the state, for any 202', async () => {
    for (const state of ['committing', 'failed', 'open']) {
      const { url, requests } = await serve((_req, res) => json(res, 202, { state }));
      expect(await sendFixResult(endpoint(url), FIX_ID, FAILURE, {})).toEqual({ accepted: state });
      const [req] = requests;
      expect(req?.method).toBe('PUT');
      expect(req?.url).toBe(`/api/v0/fixes/${FIX_ID}/result`);
      expect(req?.headers['content-type']).toBe('application/json');
      expect(JSON.parse(req?.body.toString('utf8') ?? '')).toEqual(FAILURE);
    }
  });

  it('answers stopped on 409 SCM_NOT_BOUND and FIX_MRS_NOT_ALLOWED (ruling T12f)', async () => {
    for (const code of ['SCM_NOT_BOUND', 'FIX_MRS_NOT_ALLOWED']) {
      const { url } = await serve((_req, res) => problem(res, 409, code));
      expect(await sendFixResult(endpoint(url), FIX_ID, FAILURE, {})).toEqual({
        stopped: expect.stringContaining(code),
      });
    }
  });

  it('answers lease_lost on 409 FIX_LEASE_LOST', async () => {
    const { url } = await serve((_req, res) => problem(res, 409, 'FIX_LEASE_LOST'));
    expect(await sendFixResult(endpoint(url), FIX_ID, FAILURE, {})).toBe('lease_lost');
  });

  it('answers refused with the rule and the file on 422 UPLOAD_REFUSED', async () => {
    const { url } = await serve((_req, res) =>
      json(res, 422, {
        type: 'urn:qualor:problem:upload_refused',
        title: 'A lockfile entry comes from a host the lockfile did not use.',
        status: 422,
        code: 'UPLOAD_REFUSED',
        reason: 'new_source',
        detail: 'package-lock.json',
      }),
    );
    const answer = await sendFixResult(endpoint(url), FIX_ID, FAILURE, {});
    expect(answer).toEqual({ refused: expect.stringContaining('new_source') });
    expect(answer).toEqual({ refused: expect.stringContaining('package-lock.json') });
  });

  it('retries a 503 three times, 10 s apart, and then gives up with exit 4 (R16)', async () => {
    const waits: number[] = [];
    const { url, requests } = await serve((_req, res) => problem(res, 503, 'SCM_UNAVAILABLE'));
    const sent = sendFixResult(endpoint(url), FIX_ID, FAILURE, {
      wait: async (ms) => {
        waits.push(ms);
      },
    });
    expect(await exitOf(sent)).toBe(EXIT.SERVER);
    expect(requests).toHaveLength(4);
    expect(waits).toEqual([10_000, 10_000, 10_000]);
  });

  it('waits the Retry-After of a 503 FIX_CHECK_BUSY, capped at 60 s (ruling T9b)', async () => {
    const waits: number[] = [];
    const answers = [
      (res: ServerResponse) =>
        json(
          res,
          503,
          { code: 'FIX_CHECK_BUSY', title: 'busy', status: 503 },
          { 'retry-after': '2' },
        ),
      (res: ServerResponse) => json(res, 202, { state: 'committing' }),
    ];
    const { url } = await serve((_req, res) => answers.shift()?.(res));
    const answer = await sendFixResult(endpoint(url), FIX_ID, FAILURE, {
      wait: async (ms) => {
        waits.push(ms);
      },
    });
    expect(answer).toEqual({ accepted: 'committing' });
    expect(waits).toEqual([2000]);

    const capped: number[] = [];
    const long = [
      (res: ServerResponse) =>
        json(res, 503, { code: 'SCM_UNAVAILABLE' }, { 'retry-after': '3600' }),
      (res: ServerResponse) => json(res, 202, { state: 'committing' }),
    ];
    const second = await serve((_req, res) => long.shift()?.(res));
    await sendFixResult(endpoint(second.url), FIX_ID, FAILURE, {
      wait: async (ms) => {
        capped.push(ms);
      },
    });
    expect(capped).toEqual([60_000]);
  });

  it('maps the other refusals: 401/403 exit 5, a missing fix or any other error exit 4', async () => {
    const cases: [number, string | null, number][] = [
      [401, 'UNAUTHENTICATED', EXIT.AUTH],
      [403, 'TOKEN_NOT_ALLOWED', EXIT.AUTH],
      [404, 'NOT_FOUND', EXIT.SERVER],
      [404, null, EXIT.SERVER],
      [409, 'SOMETHING_ELSE', EXIT.SERVER],
      [413, 'BODY_TOO_LARGE', EXIT.SERVER],
    ];
    for (const [status, code, exit] of cases) {
      const { url } = await serve((_req, res) => {
        if (code === null) {
          res.writeHead(status, { 'content-type': 'text/plain', connection: 'close' });
          res.end('Not Found');
        } else problem(res, status, code);
      });
      const sent = sendFixResult(endpoint(url), FIX_ID, FAILURE, {});
      expect(await exitOf(sent), `${status} ${code}`).toBe(exit);
    }
  });
});
