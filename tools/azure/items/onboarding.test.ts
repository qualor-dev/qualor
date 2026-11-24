import { describe, expect, it } from 'vitest';
import { AZURE_FILE } from '../../../server/src/onboarding/ci-setup';
import { azurePipeline } from '../../../server/src/onboarding/ci-templates';
import {
  SETUP_BRANCH as SERVER_SETUP_BRANCH,
  SETUP_TITLE as SERVER_SETUP_TITLE,
} from '../../../server/src/onboarding/setup-run';
import { azureStatusName } from '../../../server/src/scm/render';
import { FINDING_LINE } from './19-decoration.js';
import {
  changedFiles,
  definitionIdOf,
  definitionRecording,
  DefinitionSchema,
  HELLO_PATH,
  helloSource,
  imageOf,
  isKnownMain,
  judgeCiQueued,
  judgeDefinition,
  judgeMainPolicy,
  judgePending,
  judgePolicyOn,
  judgePrBuild,
  judgeQueue,
  judgeSetupItem,
  judgeSetupPr,
  mainBuildOf,
  PIPELINE_PATH,
  pinBenchImage,
  policiesToRemove,
  poolOf,
  problemText,
  probeSource,
  pushChanges,
  qualorStatus,
  refUpdatesSucceeded,
  resetChanges,
  SETUP_BRANCH,
  SETUP_TITLE,
  setupDefinitions,
  SetupRunSchema,
  mainWaits,
  retireDefinition,
  retiredName,
  staleRefs,
  toCancel,
  triggersText,
  tokensIn,
  treeFiles,
  type Build,
  type SetupItem,
} from './27-onboarding.js';

const REPO = '4427c1df-aedf-4e1f-8447-fa6e0000ecd2';
const OTHER_REPO = '11111111-2222-4333-8444-555555555555';
const BUILD_POLICY = '0609b952-1397-4640-95ec-e00a01b2c241';
const KEY = 'probe-org/qualor-probe-setup';

const setupYaml = (pool: { name: string } | { vmImage: 'ubuntu-latest' }, csharp = false) =>
  azurePipeline({ projectKey: KEY, version: '0.17.0', pool, csharp });

describe('item 27 constants', () => {
  it("are the server's: the branch, the title, the pipeline file", () => {
    expect(SETUP_BRANCH).toBe(SERVER_SETUP_BRANCH);
    expect(SETUP_TITLE).toBe(SERVER_SETUP_TITLE);
    expect(PIPELINE_PATH).toBe(`/${AZURE_FILE}`);
  });
});

describe('item 27 main', () => {
  it('holds one file with the empty function of items 19 and 21 on the finding line', () => {
    const lines = helloSource().split('\n');
    expect(lines[FINDING_LINE - 1]).toBe('export function emptyHandler() {');
    expect(lines[FINDING_LINE]).toBe('}');
    expect(helloSource().endsWith('\n')).toBe(true);
    // The same every run: no stamp.
    expect(helloSource()).toBe(helloSource());
    expect(HELLO_PATH).toBe('/src/hello.js');
  });

  it('the probe change is one small file with the stamp', () => {
    expect(probeSource('20261124120000')).toContain('(20261124120000)');
    expect(probeSource('x').endsWith('\n')).toBe(true);
  });

  it('lists the files of a tree, root and folders left out, sorted', () => {
    expect(
      treeFiles({
        count: 5,
        value: [
          { path: '/', isFolder: true, gitObjectType: 'tree' },
          { path: '/src', isFolder: true, gitObjectType: 'tree' },
          { path: '/src/hello.js', gitObjectType: 'blob' },
          { path: '/.azure-pipelines', gitObjectType: 'tree' },
          { path: '/.azure-pipelines/qualor.yml', gitObjectType: 'blob' },
        ],
      }),
    ).toEqual(['/.azure-pipelines/qualor.yml', '/src/hello.js']);
    expect(() => treeFiles({ nope: 1 })).toThrow(/unexpected shape/);
  });

  it('knows main as each run starts it, CRLF or not', () => {
    expect(isKnownMain([HELLO_PATH], helloSource())).toBe(true);
    expect(isKnownMain([HELLO_PATH], helloSource().replace(/\n/g, '\r\n'))).toBe(true);
    expect(isKnownMain([HELLO_PATH, '/.azure-pipelines/qualor.yml'], helloSource())).toBe(false);
    expect(isKnownMain([HELLO_PATH], 'other\n')).toBe(false);
    expect(isKnownMain([HELLO_PATH], null)).toBe(false);
    expect(isKnownMain([], null)).toBe(false);
  });

  it('the fast-forward reset deletes the rest and writes the hello file back', () => {
    expect(resetChanges(['/.azure-pipelines/qualor.yml', HELLO_PATH], helloSource())).toEqual([
      { changeType: 'delete', path: '/.azure-pipelines/qualor.yml' },
    ]);
    expect(resetChanges([HELLO_PATH], 'changed\n')).toEqual([
      { changeType: 'edit', path: HELLO_PATH },
    ]);
    expect(resetChanges(['/README.md'], null)).toEqual([
      { changeType: 'delete', path: '/README.md' },
      { changeType: 'add', path: HELLO_PATH },
    ]);
    expect(resetChanges([HELLO_PATH], helloSource())).toEqual([]);
  });

  it('a push carries the hello text for an add or edit and nothing for a delete', () => {
    expect(
      pushChanges([
        { changeType: 'delete', path: '/a' },
        { changeType: 'add', path: HELLO_PATH },
      ]),
    ).toEqual([
      { changeType: 'delete', item: { path: '/a' } },
      {
        changeType: 'add',
        item: { path: HELLO_PATH },
        newContent: { content: helloSource(), contentType: 'rawtext' },
      },
    ]);
  });

  it('reads a refs update answer', () => {
    expect(refUpdatesSucceeded({ value: [{ success: true, updateStatus: 'succeeded' }] })).toBe(
      true,
    );
    expect(
      refUpdatesSucceeded({ value: [{ success: false, updateStatus: 'rejectedByPolicy' }] }),
    ).toBe(false);
    expect(refUpdatesSucceeded({ value: [] })).toBe(false);
    expect(refUpdatesSucceeded(null)).toBe(false);
  });
});

describe('item 27 clearing an earlier run', () => {
  it('finds the setup branch, the probe branches and the temporary refs of the reset only', () => {
    const refs = [
      { name: 'refs/heads/main', objectId: 'a' },
      { name: 'refs/heads/qualor/setup', objectId: 'b' },
      { name: 'refs/heads/qualor/setup-2', objectId: 'c' },
      { name: 'refs/heads/probe/27-20261124120000', objectId: 'd' },
      { name: 'refs/heads/probe/26-20261124120000', objectId: 'e' },
      { name: 'refs/qualor/probe-tmp/27-20261124110000', objectId: 'f' },
      { name: 'refs/qualor/fix-tmp/20261124110000', objectId: 'g' },
    ];
    expect(staleRefs(refs).map((r) => r.name)).toEqual([
      'refs/heads/qualor/setup',
      'refs/heads/probe/27-20261124120000',
      'refs/qualor/probe-tmp/27-20261124110000',
    ]);
  });

  it('renames a pipeline before it deletes it: GET, PUT with the new name, then DELETE', async () => {
    const calls: string[] = [];
    let sent: Record<string, unknown> | undefined;
    const name = await retireDefinition(
      {
        get: (id) => {
          calls.push(`get ${id}`);
          return Promise.resolve({ id, name: 'Qualor', revision: 3, triggers: [{ x: 1 }] });
        },
        put: (id, body) => {
          calls.push(`put ${id}`);
          sent = body;
          return Promise.resolve();
        },
        remove: (id) => {
          calls.push(`delete ${id}`);
          return Promise.resolve();
        },
      },
      7,
      '20261124120000',
    );
    expect(calls).toEqual(['get 7', 'put 7', 'delete 7']);
    expect(name).toBe('Qualor deleted 20261124120000 7');
    expect(name).toBe(retiredName('20261124120000', 7));
    expect(sent).toEqual({ id: 7, name, revision: 3, triggers: [{ x: 1 }] });
  });

  it('deletes nothing when the rename is refused', async () => {
    const calls: string[] = [];
    await expect(
      retireDefinition(
        {
          get: (id) => Promise.resolve({ id, name: 'Qualor' }),
          put: () => Promise.reject(new Error('refused')),
          remove: (id) => {
            calls.push(`delete ${id}`);
            return Promise.resolve();
          },
        },
        7,
        's',
      ),
    ).rejects.toThrow('refused');
    expect(calls).toEqual([]);
  });

  it("takes the setup's pipelines of this repository by name, and lists others on the file", () => {
    const json = {
      value: [
        { id: 1, name: 'Qualor', repository: { id: REPO.toUpperCase() } },
        { id: 2, name: 'Qualor (qualor-probe-setup)', repository: { id: REPO } },
        { id: 3, name: 'Qualor', repository: { id: OTHER_REPO } },
        {
          id: 4,
          name: 'Hand made',
          repository: { id: REPO },
          process: { yamlFilename: '/.azure-pipelines/qualor.yml' },
        },
        {
          id: 5,
          name: 'Other file',
          repository: { id: REPO },
          process: { yamlFilename: 'azure-pipelines.yml' },
        },
      ],
    };
    expect(setupDefinitions(json, REPO)).toEqual({
      own: [
        { id: 1, name: 'Qualor' },
        { id: 2, name: 'Qualor (qualor-probe-setup)' },
      ],
      others: [{ id: 4, name: 'Hand made' }],
    });
  });

  it("removes the Build policies of the setup's pipelines and any named Qualor", () => {
    const json = {
      value: [
        { id: 10, type: { id: BUILD_POLICY }, settings: { buildDefinitionId: 1 } },
        {
          id: 11,
          type: { id: BUILD_POLICY },
          settings: { buildDefinitionId: 9, displayName: 'Qualor' },
        },
        {
          id: 12,
          type: { id: BUILD_POLICY },
          settings: { buildDefinitionId: 9, displayName: 'Mine' },
        },
        {
          id: 13,
          type: { id: 'cbdc66da-9728-4af8-aada-9a5a32e4a226' },
          settings: { displayName: 'Qualor' },
        },
      ],
    };
    expect(policiesToRemove(json, [1, 2], REPO)).toEqual([10]);
  });

  it('removes a policy named Qualor only when it applies to this repository', () => {
    const named = (id: number, repositoryId: string | null) => ({
      id,
      type: { id: BUILD_POLICY },
      settings: {
        buildDefinitionId: 9,
        displayName: 'Qualor',
        scope: [{ repositoryId, refName: 'refs/heads/main', matchKind: 'Exact' }],
      },
    });
    const json = {
      value: [named(11, REPO.toUpperCase()), named(12, OTHER_REPO), named(13, null)],
    };
    expect(policiesToRemove(json, [1], REPO)).toEqual([11]);
    // A policy of the setup's pipeline goes whatever its scope says.
    expect(
      policiesToRemove(
        { value: [{ ...named(14, OTHER_REPO), settings: { buildDefinitionId: 1 } }] },
        [1],
        REPO,
      ),
    ).toEqual([14]);
  });
});

const policy = (over: Record<string, unknown> = {}, settings: Record<string, unknown> = {}) => ({
  id: 22,
  isEnabled: true,
  isBlocking: false,
  type: { id: BUILD_POLICY },
  settings: {
    buildDefinitionId: 30,
    displayName: 'Qualor',
    scope: [{ repositoryId: REPO, refName: 'refs/heads/main', matchKind: 'Exact' }],
    ...settings,
  },
  ...over,
});

describe('item 27 policy on main', () => {
  const want = { definitionId: 30, repositoryId: REPO };

  it('passes one enabled, non-blocking Qualor policy for the pipeline on main exactly', () => {
    const got = judgeMainPolicy(
      { value: [policy(), policy({ id: 5 }, { buildDefinitionId: 7 })] },
      want,
    );
    expect(got.check.pass).toBe(true);
    expect(got.policyId).toBe(22);
  });

  it('fails a blocking, disabled, misnamed or misplaced one, two of them, or none', () => {
    for (const p of [
      policy({ isBlocking: true }),
      policy({ isEnabled: false }),
      policy({}, { displayName: 'Other' }),
      policy(
        {},
        { scope: [{ repositoryId: REPO, refName: 'refs/heads/dev', matchKind: 'exact' }] },
      ),
      policy(
        {},
        { scope: [{ repositoryId: REPO, refName: 'refs/heads/main', matchKind: 'prefix' }] },
      ),
    ]) {
      expect(judgeMainPolicy({ value: [p] }, want).check.pass).toBe(false);
    }
    expect(judgeMainPolicy({ value: [policy(), policy({ id: 23 })] }, want).check.pass).toBe(false);
    const none = judgeMainPolicy({ value: [] }, want);
    expect(none.check.pass).toBe(false);
    expect(none.policyId).toBeNull();
    expect(none.check.got).toContain('no Build validation policy');
  });
});

const setupItem = (over: Partial<SetupItem> = {}): SetupItem => ({
  ref: REPO,
  name: KEY,
  project: { id: '9a8b7c6d-0000-4000-8000-000000000001', key: KEY },
  projectOutcome: 'created',
  ciOutcome: 'merge_request',
  ciUrl: 'https://dev.azure.com/probe-org/probe-org/_git/qualor-probe-setup/pullrequest/40',
  ciReason: null,
  token: null,
  error: null,
  azure: {
    pipelineUrl: 'https://dev.azure.com/probe-org/probe-org/_build?definitionId=30',
    queue: 'authorized',
    policy: 'pending',
    policyError: null,
  },
  ...over,
});

describe('item 27 setup run', () => {
  it('parses the run answer and judges its one item', () => {
    const run = SetupRunSchema.parse({
      id: 'r',
      status: 'done',
      ciSetup: true,
      items: [setupItem()],
    });
    expect(judgeSetupItem(run).pass).toBe(true);
    expect(judgeSetupItem({ ...run, items: [setupItem({ projectOutcome: 'adopted' })] }).pass).toBe(
      true,
    );
    expect(judgeSetupItem({ ...run, status: 'running' }).pass).toBe(false);
    const snippet = judgeSetupItem({
      ...run,
      items: [setupItem({ ciOutcome: 'snippet', ciReason: 'foreign_pipeline', ciUrl: null })],
    });
    expect(snippet.pass).toBe(false);
    expect(snippet.got).toContain('snippet (foreign_pipeline)');
    const failed = judgeSetupItem({
      ...run,
      items: [
        setupItem({
          error: {
            code: 'pipeline_name_taken',
            message: 'Pipelines named Qualor and Qualor (qualor-probe-setup) already exist',
          },
        }),
      ],
    });
    expect(failed.pass).toBe(false);
    expect(failed.got).toContain('pipeline_name_taken');
    expect(judgeSetupItem({ ...run, items: [] }).pass).toBe(false);
  });

  it('the policy is pending before the merge and on after the main analysis', () => {
    expect(judgePending(setupItem()).pass).toBe(true);
    expect(judgePending(setupItem({ azure: null })).pass).toBe(false);
    const on = setupItem({
      azure: { pipelineUrl: null, queue: 'open', policy: 'on', policyError: null },
    });
    expect(judgePolicyOn(on).pass).toBe(true);
    const manual = judgePolicyOn(
      setupItem({
        azure: {
          pipelineUrl: null,
          queue: 'open',
          policy: 'manual',
          policyError: 'Needs Edit policies',
        },
      }),
    );
    expect(manual.pass).toBe(false);
    expect(manual.got).toBe('manual: Needs Edit policies');
    expect(judgePolicyOn(undefined).got).toBe('absent');
  });

  it('reads the pipeline id from its web URL and collects shown tokens', () => {
    expect(definitionIdOf('https://dev.azure.com/o/p/_build?definitionId=30')).toBe(30);
    expect(definitionIdOf('https://dev.azure.com/o/p/_build?x=1&definitionId=7&y=2')).toBe(7);
    expect(definitionIdOf(null)).toBeNull();
    expect(definitionIdOf('https://dev.azure.com/o/p/_build?definitionId=')).toBeNull();
    expect(tokensIn({ items: [{ token: 'qlr_secret' }, { token: null }, {}] })).toEqual([
      'qlr_secret',
    ]);
    expect(tokensIn(null)).toEqual([]);
  });

  it('says what a refused POST answered', () => {
    expect(
      problemText({
        code: 'VALIDATION_FAILED',
        errors: [{ path: 'body.ciSetup', message: 'The connection does not allow CI setup' }],
      }),
    ).toBe('VALIDATION_FAILED (body.ciSetup: The connection does not allow CI setup)');
    expect(problemText({ code: 'NOT_FOUND', title: 'Not found' })).toBe('NOT_FOUND (Not found)');
    expect(problemText(null)).toBe('no code');
  });
});

describe("item 27 the setup's pull request and file", () => {
  const pr = {
    status: 'active',
    title: SETUP_TITLE,
    sourceRefName: 'refs/heads/qualor/setup',
    targetRefName: 'refs/heads/main',
  };
  const added = { changeEntries: [{ changeType: 'add', item: { path: PIPELINE_PATH } }] };

  it('reads the pool of the file the setup writes', () => {
    expect(poolOf(setupYaml({ name: 'Default' }))).toBe('name: Default');
    expect(poolOf(setupYaml({ vmImage: 'ubuntu-latest' }))).toBe('vmImage: ubuntu-latest');
    expect(poolOf("pool:\n  name: 'My pool: Linux'\n")).toBe('name: My pool: Linux');
    expect(poolOf('steps: []\n')).toBeNull();
    expect(poolOf(null)).toBeNull();
  });

  it('passes a pull request that adds exactly the file, on the pool Default', () => {
    const checks = judgeSetupPr(pr, changedFiles(added), setupYaml({ name: 'Default' }));
    expect(checks.map((c) => c.pass)).toEqual([true, true, true]);
  });

  it('fails another pool, another file, a second file, or another title', () => {
    expect(
      judgeSetupPr(pr, changedFiles(added), setupYaml({ vmImage: 'ubuntu-latest' }))[2]?.pass,
    ).toBe(false);
    const two = changedFiles({
      changeEntries: [
        { changeType: 'add', item: { path: PIPELINE_PATH } },
        { changeType: 'add', item: { path: '/README.md' } },
      ],
    });
    expect(judgeSetupPr(pr, two, setupYaml({ name: 'Default' }))[1]?.pass).toBe(false);
    const edit = changedFiles({
      changeEntries: [{ changeType: 'edit', item: { path: PIPELINE_PATH } }],
    });
    expect(judgeSetupPr(pr, edit, setupYaml({ name: 'Default' }))[1]?.pass).toBe(false);
    expect(judgeSetupPr({ ...pr, title: 'Other' }, changedFiles(added), null)[0]?.pass).toBe(false);
    expect(judgeSetupPr(pr, changedFiles(added), null)[2]?.got).toBe('the file was not read');
  });

  it('leaves folders out of the iteration changes', () => {
    expect(
      changedFiles({
        changeEntries: [
          { changeType: 'add', item: { path: '/.azure-pipelines', isFolder: true } },
          { changeType: 'add', item: { path: PIPELINE_PATH, gitObjectType: 'blob' } },
        ],
      }),
    ).toEqual([{ path: PIPELINE_PATH, changeType: 'add' }]);
  });

  it("pins the bench's image on the setup's file and changes nothing else", () => {
    for (const csharp of [false, true]) {
      const text = setupYaml({ name: 'Default' }, csharp);
      const image = csharp ? 'qualor/scanner-dotnet' : 'qualor/scanner';
      expect(imageOf(text)).toBe(`${image}:0.17.0`);
      const pinned = pinBenchImage(text);
      expect(pinned).not.toBeNull();
      expect(imageOf(pinned)).toBe(`${image}:azure-dev`);
      const before = text.split('\n');
      const after = (pinned ?? '').split('\n');
      expect(after).toHaveLength(before.length);
      expect(after.filter((line, i) => line !== before[i])).toEqual([
        `  QUALOR_SCANNER_IMAGE: ${image}:azure-dev`,
      ]);
    }
    expect(pinBenchImage(setupYaml({ name: 'Default' }).replace(/\n/g, '\r\n'))).toContain(
      'qualor/scanner:azure-dev',
    );
    expect(pinBenchImage('steps: []\n')).toBeNull();
    expect(imageOf(null)).toBeNull();
  });
});

describe("item 27 the setup's pipeline", () => {
  const def = (variables: Record<string, unknown>, over: Record<string, unknown> = {}) =>
    DefinitionSchema.parse({
      id: 30,
      name: 'Qualor',
      process: { yamlFilename: '.azure-pipelines/qualor.yml', type: 2 },
      repository: { id: REPO, type: 'TfsGit' },
      queue: { id: 11, name: 'Default' },
      variables,
      ...over,
    });
  const want = { repositoryId: REPO, queueId: 11, qualorUrl: 'https://qualor.example.test/' };
  const good = {
    QUALOR_URL: { value: 'https://qualor.example.test' },
    QUALOR_TOKEN: { value: null, isSecret: true },
  };

  it('passes the file, the repository, the queue, the address and the secret', () => {
    const checks = judgeDefinition(def(good), want);
    expect(checks.map((c) => c.pass)).toEqual([true, true]);
    expect(checks[1]?.got).toBe(
      "QUALOR_URL set (the probe's Qualor address); QUALOR_TOKEN isSecret true, no value read back",
    );
    expect(judgeDefinition(def(good, { name: 'Qualor (qualor-probe-setup)' }), want)[0]?.pass).toBe(
      true,
    );
  });

  it('fails another name, queue or repository, and a token not secret or read back', () => {
    expect(judgeDefinition(def(good, { name: 'Other' }), want)[0]?.pass).toBe(false);
    expect(
      judgeDefinition(def(good, { queue: { id: 12, name: 'Azure Pipelines' } }), want)[0]?.pass,
    ).toBe(false);
    expect(judgeDefinition(def(good, { repository: { id: OTHER_REPO } }), want)[0]?.pass).toBe(
      false,
    );
    const plain = judgeDefinition(
      def({ ...good, QUALOR_TOKEN: { value: 'qlr_plain_value' } }),
      want,
    )[1];
    expect(plain?.pass).toBe(false);
    expect(plain?.got).not.toContain('qlr_plain_value');
    const readBack = judgeDefinition(
      def({ ...good, QUALOR_TOKEN: { value: 'qlr_read_back', isSecret: true } }),
      want,
    )[1];
    expect(readBack?.pass).toBe(false);
    expect(readBack?.got).toContain('a value read back');
    expect(readBack?.got).not.toContain('qlr_read_back');
    expect(judgeDefinition(def({ QUALOR_TOKEN: good.QUALOR_TOKEN }), want)[1]?.got).toContain(
      'QUALOR_URL absent',
    );
  });

  it('records a secret variable without its value', () => {
    const recorded = definitionRecording({
      id: 30,
      variables: {
        QUALOR_TOKEN: { value: 'qlr_never_recorded', isSecret: true, allowOverride: false },
        QUALOR_URL: { value: 'https://qualor.example.test' },
      },
    });
    expect(JSON.stringify(recorded)).not.toContain('qlr_never_recorded');
    expect(recorded).toEqual({
      id: 30,
      variables: {
        QUALOR_TOKEN: { value: null, isSecret: true, allowOverride: false },
        QUALOR_URL: { value: 'https://qualor.example.test' },
      },
    });
    expect(definitionRecording(null)).toBeNull();
    expect(definitionRecording({ id: 1 })).toEqual({ id: 1 });
  });

  it('the queue: authorised by the setup or open, as Azure DevOps reads it too', () => {
    expect(judgeQueue('authorized', { open: false, authorized: true }).pass).toBe(true);
    expect(judgeQueue('open', { open: true, authorized: false }).pass).toBe(true);
    expect(judgeQueue('manual', { open: false, authorized: false }).pass).toBe(false);
    expect(judgeQueue('authorized', { open: false, authorized: false }).pass).toBe(false);
    expect(judgeQueue(undefined, { open: true, authorized: false }).got).toContain('says nothing');
  });
});

const build = (over: Partial<Build>): Build => ({ id: 1, status: 'completed', ...over });

describe('item 27 builds', () => {
  it("takes the merge commit's build of main, else the newest of main", () => {
    const builds = [
      build({ id: 3, sourceBranch: 'refs/heads/qualor/setup' }),
      build({ id: 2, sourceBranch: 'refs/heads/main', sourceVersion: 'bbbb' }),
      build({ id: 1, sourceBranch: 'refs/heads/main', sourceVersion: 'AAAA' }),
    ];
    expect(mainBuildOf(builds, 'aaaa')?.id).toBe(1);
    expect(mainBuildOf(builds, 'cccc')?.id).toBe(2);
    expect(mainBuildOf(builds, undefined)?.id).toBe(2);
    expect(mainBuildOf([builds[0] as Build], 'aaaa')).toBeUndefined();
  });

  it('CI queued the main build: a build of main that no one queued by hand', () => {
    const ci = build({ id: 4, sourceBranch: 'refs/heads/main', reason: 'individualCI' });
    expect(judgeCiQueued(ci, true)).toEqual({
      what: 'CI queued the main build (the pipeline runs on pushes)',
      pass: true,
      got: 'build 4, reason individualCI; the image commit on qualor/setup started a CI build',
    });
    expect(judgeCiQueued({ ...ci, reason: 'manual' }, false).pass).toBe(false);
    const none = judgeCiQueued(undefined, false);
    expect(none.pass).toBe(false);
    expect(none.got).toBe(
      'no build of main within 5 min; the image commit on qualor/setup started no CI build either',
    );
  });

  it("cancels a branch's unfinished builds only", () => {
    const builds = [
      build({ id: 1, sourceBranch: 'refs/heads/qualor/setup', status: 'inProgress' }),
      build({ id: 2, sourceBranch: 'refs/heads/qualor/setup', status: 'notStarted' }),
      build({ id: 3, sourceBranch: 'refs/heads/qualor/setup', status: 'completed' }),
      build({ id: 4, sourceBranch: 'refs/heads/qualor/setup', status: 'cancelling' }),
      build({ id: 5, sourceBranch: 'refs/heads/main', status: 'inProgress' }),
    ];
    expect(toCancel(builds, 'refs/heads/qualor/setup').map((b) => b.id)).toEqual([1, 2]);
  });

  it('the policy queued a pull request build: a pullRequest build, or the evaluation names one', () => {
    const want = { prId: 41, policyId: 22 };
    const prBuild = build({
      id: 9,
      reason: 'pullRequest',
      sourceBranch: 'refs/pull/41/merge',
      status: 'inProgress',
    });
    expect(judgePrBuild([prBuild], [], want).pass).toBe(true);
    const ev = { status: 'queued', configuration: { id: 22 }, context: { buildId: 9 } };
    expect(judgePrBuild([], [ev], want).pass).toBe(true);
    expect(judgePrBuild([], [{ ...ev, context: {} }], want).pass).toBe(false);
    expect(
      judgePrBuild(
        [build({ reason: 'individualCI', sourceBranch: 'refs/heads/probe/27-x' })],
        [],
        want,
      ).pass,
    ).toBe(false);
    expect(
      judgePrBuild([build({ reason: 'pullRequest', sourceBranch: 'refs/pull/40/merge' })], [], want)
        .pass,
    ).toBe(false);
  });
});

describe('item 27 waits and triggers', () => {
  it('keeps the main build and analysis within 15 minutes, the analysis keeping its share', () => {
    const start = 1_000_000;
    const deadline = start + 15 * 60_000;
    expect(mainWaits(deadline, start)).toEqual({ buildMs: 13 * 60_000 });
    expect(mainWaits(deadline, deadline - 60_000)).toEqual({ buildMs: 0 });
    expect(mainWaits(deadline, deadline + 1)).toEqual({ buildMs: 0 });
  });

  it("says what triggers the pipeline has: the YAML's CI trigger, another, or none", () => {
    expect(
      triggersText([
        { triggerType: 'continuousIntegration', settingsSourceType: 2, branchFilters: [] },
      ]),
    ).toBe('continuousIntegration (settings from the YAML)');
    expect(
      triggersText([
        { triggerType: 'continuousIntegration', settingsSourceType: 1 },
        { triggerType: 'schedule' },
      ]),
    ).toBe('continuousIntegration (settings in the definition), schedule');
    expect(triggersText([])).toBe('none');
    expect(triggersText(undefined)).toBe('none');
  });
});

describe("item 27 Qualor's status", () => {
  it("is the server's status name for the key, not Azure Pipelines' codecoverage under the pipeline's name", () => {
    const name = azureStatusName(KEY);
    expect(name).toBe(KEY);
    const statuses = [
      { id: 1, state: 'pending', context: { name: 'codecoverage', genre: 'qualor' } },
      { id: 2, state: 'failed', context: { name, genre: 'qualor' } },
      { id: 3, context: { name, genre: 'qualor' } },
      { id: 4, state: 'succeeded', context: { name, genre: 'other' } },
    ];
    expect(qualorStatus(statuses, KEY)?.id).toBe(2);
    expect(
      qualorStatus(
        [...statuses, { id: 5, state: 'succeeded', context: { name, genre: 'qualor' } }],
        KEY,
      )?.id,
    ).toBe(5);
    expect(qualorStatus([statuses[0] as (typeof statuses)[number]], KEY)).toBeUndefined();
    expect(
      qualorStatus([{ id: 6, state: 'notSet', context: { name, genre: 'qualor' } }], KEY),
    ).toBeUndefined();
  });

  it('names the status as the server does for a key it changes (azureStatusName)', () => {
    const key = 'Probe Org/qualor-probe-setup';
    const name = azureStatusName(key);
    expect(name).not.toBe(key);
    const statuses = [
      { id: 1, state: 'failed', context: { name: key, genre: 'qualor' } },
      { id: 2, state: 'succeeded', context: { name, genre: 'qualor' } },
    ];
    expect(qualorStatus(statuses, key)?.id).toBe(2);
  });
});
