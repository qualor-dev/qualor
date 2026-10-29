import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../../test/fake-gitlab';
import { GitLabClient, GitLabError } from './client';

const SECRET = 'S3cret-value-0123456789';

async function failure(promise: Promise<unknown>): Promise<GitLabError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof GitLabError) return err;
    throw err;
  }
  throw new Error('expected a GitLabError');
}

describe('GitLab client: projects, files, merge requests and variables', () => {
  let fake: FakeGitLab;
  const client = (token?: string) =>
    new GitLabClient(
      { baseUrl: fake.url, token: token ?? fake.token, allowInternalHosts: true },
      { timeoutMs: 1_000 },
    );
  const last = () => fake.requests[fake.requests.length - 1]!;

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 7, path: 'acme/payments/api', languages: { Go: 20, TypeScript: 70.5 } });
    fake.addProject({ id: 8, path: 'acme/web', defaultBranch: 'develop' });
    fake.addProject({ id: 9, path: 'acme/empty', defaultBranch: null });
    fake.addProject({ id: 10, path: 'acme/old', archived: true });
    for (let n = 0; n < 101; n++) fake.addProject({ id: 100 + n, path: `bulk/p${n}` });
  });
  afterAll(() => fake.close());
  beforeEach(() => {
    fake.clearRequests();
    fake.accessLevel = 40;
  });

  describe('listProjects', () => {
    it('asks for Maintainer projects that are not archived, and maps them', async () => {
      const { projects } = await client().listProjects({ page: 1, perPage: 100, search: 'acme/' });
      expect(last().method).toBe('GET');
      expect(last().path).toBe('/projects');
      expect(Object.fromEntries(new URLSearchParams(last().query))).toEqual({
        membership: 'true',
        min_access_level: '40',
        archived: 'false',
        simple: 'true',
        per_page: '100',
        page: '1',
        search: 'acme/',
      });
      expect(projects).toEqual([
        { ref: '7', path: 'acme/payments/api', defaultBranch: 'main', archived: false },
        { ref: '8', path: 'acme/web', defaultBranch: 'develop', archived: false },
        { ref: '9', path: 'acme/empty', defaultBranch: null, archived: false },
      ]);
    });

    it('leaves search out when none is given and pages by x-next-page', async () => {
      const first = await client().listProjects({ page: 1, perPage: 100 });
      expect(new URLSearchParams(last().query).has('search')).toBe(false);
      expect(first.projects).toHaveLength(100);
      expect(first.hasMore).toBe(true);
      const second = await client().listProjects({ page: 2, perPage: 100 });
      expect(new URLSearchParams(last().query).get('page')).toBe('2');
      expect(second.projects).toHaveLength(4);
      expect(second.hasMore).toBe(false);
    });

    it('lists nothing below the Maintainer role', async () => {
      fake.accessLevel = 30;
      expect(await client().listProjects({ page: 1, perPage: 100 })).toEqual({
        projects: [],
        hasMore: false,
      });
    });

    it('reads archived when GitLab says it', async () => {
      fake.inject('GET', /^\/projects$/, {
        status: 200,
        body: [{ id: 1, path_with_namespace: 'a/b', default_branch: 'main', archived: true }],
      });
      const { projects } = await client().listProjects({ page: 1, perPage: 100 });
      expect(projects[0]).toMatchObject({ ref: '1', archived: true });
    });

    it('refuses an answer it cannot read', async () => {
      fake.inject('GET', /^\/projects$/, { status: 200, body: [{ id: 'x' }] });
      expect((await failure(client().listProjects({ page: 1, perPage: 100 }))).kind).toBe(
        'bad_answer',
      );
    });
  });

  it('languages: the one with the largest share first', async () => {
    expect(await client().languages('7')).toEqual(['TypeScript', 'Go']);
    expect(last().path).toBe('/projects/7/languages');
  });

  describe('fileText', () => {
    it('reads the raw file with an encoded path and the branch', async () => {
      fake.addFile(7, 'main', 'ci/.gitlab ci.yml', 'stages: [test]\n');
      expect(await client().fileText('7', 'ci/.gitlab ci.yml', 'main')).toBe('stages: [test]\n');
      expect(last().path).toBe('/projects/7/repository/files/ci%2F.gitlab%20ci.yml/raw');
      expect(last().query).toBe('ref=main');
    });

    it('answers null for a file that is not there', async () => {
      expect(await client().fileText('7', 'nope.yml', 'main')).toBeNull();
    });

    it('answers null for a branch that is not there', async () => {
      expect(await client().fileText('7', '.gitlab-ci.yml', 'ghost')).toBeNull();
    });

    it('keeps other failures', async () => {
      expect((await failure(client('wrong').fileText('7', 'a', 'main'))).kind).toBe('auth');
    });
  });

  describe('branches', () => {
    it('branchExists is true and false', async () => {
      expect(await client().branchExists('7', 'main')).toBe(true);
      expect(last().path).toBe('/projects/7/repository/branches/main');
      expect(await client().branchExists('7', 'feature/x')).toBe(false);
      expect(last().path).toBe('/projects/7/repository/branches/feature%2Fx');
    });

    it('createBranch posts the name and the ref to start from', async () => {
      await client().createBranch('8', 'qualor/setup', 'develop');
      expect(last().method).toBe('POST');
      expect(last().path).toBe('/projects/8/repository/branches');
      expect(JSON.parse(last().body)).toEqual({ branch: 'qualor/setup', ref: 'develop' });
      expect(fake.branches(8)).toContain('qualor/setup');
    });

    it('createBranch is refused for a branch that exists', async () => {
      const err = await failure(client().createBranch('8', 'develop', 'develop'));
      expect(err.status).toBe(400);
    });
  });

  describe('commitFiles', () => {
    it('posts branch, message and actions with file_path and content', async () => {
      await client().createBranch('7', 'qualor/setup', 'main');
      await client().commitFiles('7', {
        branch: 'qualor/setup',
        message: 'Add Qualor code analysis',
        actions: [
          { action: 'create', path: '.gitlab-ci.yml', content: 'a: 1\n' },
          { action: 'create', path: 'ci/x.yml', content: 'b: 2\n' },
        ],
      });
      const request = last();
      expect(request.method).toBe('POST');
      expect(request.path).toBe('/projects/7/repository/commits');
      expect(JSON.parse(request.body)).toEqual({
        branch: 'qualor/setup',
        commit_message: 'Add Qualor code analysis',
        actions: [
          { action: 'create', file_path: '.gitlab-ci.yml', content: 'a: 1\n' },
          { action: 'create', file_path: 'ci/x.yml', content: 'b: 2\n' },
        ],
      });
      expect(fake.file(7, 'qualor/setup', '.gitlab-ci.yml')).toBe('a: 1\n');
      await client().commitFiles('7', {
        branch: 'qualor/setup',
        message: 'Change',
        actions: [{ action: 'update', path: '.gitlab-ci.yml', content: 'a: 2\n' }],
      });
      expect(fake.file(7, 'qualor/setup', '.gitlab-ci.yml')).toBe('a: 2\n');
    });

    it('is refused for a file that exists on create, or a branch that is not there', async () => {
      const exists = await failure(
        client().commitFiles('7', {
          branch: 'qualor/setup',
          message: 'm',
          actions: [{ action: 'create', path: '.gitlab-ci.yml', content: 'x' }],
        }),
      );
      expect(exists.status).toBe(400);
      const nobranch = await failure(
        client().commitFiles('7', {
          branch: 'ghost',
          message: 'm',
          actions: [{ action: 'create', path: 'z', content: 'x' }],
        }),
      );
      expect(nobranch.status).toBe(400);
    });
  });

  describe('merge requests', () => {
    it('opens one and finds it again by its source branch', async () => {
      expect(await client().findOpenMergeRequest('7', 'qualor/setup')).toBeNull();
      const query = new URLSearchParams(last().query);
      expect(last().path).toBe('/projects/7/merge_requests');
      expect(query.get('state')).toBe('opened');
      expect(query.get('source_branch')).toBe('qualor/setup');

      const opened = await client().openMergeRequest('7', {
        source: 'qualor/setup',
        target: 'main',
        title: 'Add Qualor code analysis',
        description: 'Adds the pipeline.',
      });
      expect(last().method).toBe('POST');
      expect(last().path).toBe('/projects/7/merge_requests');
      expect(JSON.parse(last().body)).toEqual({
        source_branch: 'qualor/setup',
        target_branch: 'main',
        title: 'Add Qualor code analysis',
        description: 'Adds the pipeline.',
      });
      expect(opened.url).toMatch(/\/acme\/payments\/api\/-\/merge_requests\/\d+$/);
      expect(await client().findOpenMergeRequest('7', 'qualor/setup')).toEqual(opened);
    });

    it('is refused for a second merge request on the same branches', async () => {
      const err = await failure(
        client().openMergeRequest('7', {
          source: 'qualor/setup',
          target: 'main',
          title: 't',
          description: '',
        }),
      );
      expect(err.status).toBe(409);
    });
  });

  describe('CI/CD variables', () => {
    it('variable is null when missing and says masked and protected when set', async () => {
      expect(await client().variable('7', 'QUALOR_TOKEN')).toBeNull();
      expect(last().path).toBe('/projects/7/variables/QUALOR_TOKEN');
      fake.setVariable(7, 'QUALOR_URL', { value: 'u', masked: false, protected: true });
      expect(await client().variable('7', 'QUALOR_URL')).toEqual({
        masked: false,
        protected: true,
      });
    });

    it('putVariable creates a variable that is not there, sending masked and protected', async () => {
      await client().putVariable('7', {
        key: 'QUALOR_TOKEN',
        value: SECRET,
        masked: true,
        protected: false,
      });
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'GET /projects/7/variables/QUALOR_TOKEN',
        'POST /projects/7/variables',
      ]);
      expect(JSON.parse(last().body)).toEqual({
        key: 'QUALOR_TOKEN',
        value: SECRET,
        masked: true,
        protected: false,
      });
      expect(fake.variables(7).QUALOR_TOKEN).toEqual({
        value: SECRET,
        masked: true,
        protected: false,
      });
    });

    it('putVariable updates one that is there', async () => {
      await client().putVariable('7', {
        key: 'QUALOR_TOKEN',
        value: `${SECRET}-2`,
        masked: true,
        protected: false,
      });
      expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
        'GET /projects/7/variables/QUALOR_TOKEN',
        'PUT /projects/7/variables/QUALOR_TOKEN',
      ]);
      expect(JSON.parse(last().body)).toEqual({
        value: `${SECRET}-2`,
        masked: true,
        protected: false,
      });
      expect(fake.variables(7).QUALOR_TOKEN!.value).toBe(`${SECRET}-2`);
    });

    it('never puts the value in an error', async () => {
      fake.inject('POST', /\/variables$/, {
        status: 400,
        body: { message: { value: [`${SECRET} is not masked`] } },
      });
      const err = await failure(
        client().putVariable('7', { key: 'FRESH', value: SECRET, masked: true, protected: false }),
      );
      expect(err.status).toBe(400);
      expect(err.message).not.toContain(SECRET);
      expect(err.providerMessage ?? '').not.toContain(SECRET);
      expect(JSON.stringify(err)).not.toContain(SECRET);
    });

    it('a refused masked value (too short) is an error that does not repeat it', async () => {
      const err = await failure(
        client().putVariable('7', { key: 'SHORT', value: 'short', masked: true, protected: false }),
      );
      expect(err.status).toBe(400);
      expect(`${err.message} ${err.providerMessage}`).not.toContain('short');
    });
  });
});
