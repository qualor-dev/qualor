import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { FakeServer, me, page, provideFakeServer } from '../../testing/fake-server';
import { Api } from '../api/api';
import { ApiError } from '../api/errors';
import { SessionStore } from '../auth/session';
import { type Branch, branchTitle, findBranch } from './branches';

const branch = (id: string, overrides: Partial<Branch> = {}): Branch => ({
  id,
  projectId: 'p1',
  kind: 'branch',
  name: id,
  isMain: false,
  mrSourceBranch: null,
  mrTargetBranch: null,
  mrTitle: null,
  mrUrl: null,
  lastAnalysisId: null,
  lastAnalyzedAt: null,
  gateStatus: null,
  measures: {},
  ...overrides,
});

describe('findBranch', () => {
  let server: FakeServer;
  let api: Api;

  beforeEach(() => {
    server = new FakeServer();
    TestBed.configureTestingModule({
      providers: [provideRouter([]), provideFakeServer(server)],
    });
    TestBed.inject(SessionStore).set(me());
    api = TestBed.inject(Api);
  });

  it('pages through the branches until it finds the one asked for, or the main branch', async () => {
    server.on('GET', '/api/v0/projects/p1/branches', (request) =>
      request.query.get('cursor') === 'c2'
        ? { body: page([branch('b3'), branch('main', { isMain: true })]) }
        : { body: page([branch('b1'), branch('b2')], 'c2') },
    );
    expect((await findBranch(api, 'p1', 'b3')).id).toBe('b3');
    expect((await findBranch(api, 'p1', undefined)).id).toBe('main');
    expect(server.requestsTo('GET', '/api/v0/projects/p1/branches')[0]?.query.get('limit')).toBe(
      '500',
    );
  });

  it('gives up with "not found" after a bounded number of pages', async () => {
    let n = 0;
    server.on('GET', '/api/v0/projects/p1/branches', () => ({
      body: page([branch(`b${n}`)], `c${++n}`),
    }));
    const error = await findBranch(api, 'p1', 'missing').catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).code).toBe('NOT_FOUND');
    expect(server.requestsTo('GET', '/api/v0/projects/p1/branches')).toHaveLength(20);
  });
});

describe('branchTitle', () => {
  it('names a branch, or a merge request by its number and branches', () => {
    expect(branchTitle(branch('main'))).toBe('main');
    expect(
      branchTitle(
        branch('x', {
          kind: 'merge_request',
          name: '42',
          mrSourceBranch: 'feature/a',
          mrTargetBranch: 'main',
        }),
      ),
    ).toBe('!42 feature/a → main');
    expect(branchTitle(branch('x', { kind: 'merge_request', name: '7' }))).toBe('!7');
  });
});
