import { describe, expect, it } from 'vitest';
import { parse, parseAllDocuments, parseDocument, type YAMLMap } from 'yaml';
import { editIsSound, minorOf, planCiSetup, type CiPlan, type CiSetupInput } from './ci-setup';

const URL_ = 'https://qualor.acme.io';
/** The project's key: not the repository's path, as when `acme/app` was taken. */
const KEY = 'acme/app-2';

function input(
  over: Partial<Omit<CiSetupInput, 'existing'>> & {
    existing?: Partial<CiSetupInput['existing']>;
  } = {},
): CiSetupInput {
  const { existing, ...rest } = over;
  return {
    provider: 'gitlab',
    host: 'cloud',
    serverUrl: URL_,
    projectKey: KEY,
    version: '0.14.3',
    csharp: false,
    defaultBranch: 'main',
    existing: {
      gitlabCi: null,
      workflowFiles: [],
      workflowQualor: null,
      tokenSecretSet: false,
      ...existing,
    },
    ...rest,
  };
}

function change(plan: CiPlan) {
  if (plan.kind !== 'change') throw new Error(`expected change, got ${plan.kind}:${plan.reason}`);
  return plan;
}

function gl(gitlabCi: string | null, over: Partial<Omit<CiSetupInput, 'existing'>> = {}): CiPlan {
  return planCiSetup(input({ ...over, existing: { gitlabCi } }));
}

function glFile(
  gitlabCi: string | null,
  over: Partial<Omit<CiSetupInput, 'existing'>> = {},
): string {
  const plan = change(gl(gitlabCi, over));
  expect(plan.files).toHaveLength(1);
  expect(plan.files[0]?.path).toBe('.gitlab-ci.yml');
  return plan.files[0]?.content ?? '';
}

/** `after` is `before` with one contiguous chunk inserted; returns that chunk. */
function inserted(before: string, after: string): string {
  let p = 0;
  while (p < before.length && before[p] === after[p]) p++;
  let s = 0;
  while (s < before.length - p && before[before.length - 1 - s] === after[after.length - 1 - s])
    s++;
  expect(p + s).toBe(before.length);
  return after.slice(p, after.length - s);
}

describe('minorOf', () => {
  it('returns major.minor', () => {
    expect(minorOf('0.14.3')).toBe('0.14');
    expect(minorOf('0.14.0-rc.1')).toBe('0.14');
    expect(minorOf('1.2.3+build')).toBe('1.2');
    expect(minorOf('0.14')).toBe('0.14');
  });
});

describe('GitLab cloud', () => {
  it('creates the file when missing', () => {
    const plan = change(gl(null));
    expect(plan.files).toEqual([
      {
        path: '.gitlab-ci.yml',
        update: false,
        content:
          "include:\n  - component: gitlab.com/qualor/qualor/qualor@0.14\n    inputs:\n      image-tag: '0.14'\n      args: '--project-key acme/app-2'\n",
      },
    ]);
    expect(plan.secrets).toEqual([{ name: 'QUALOR_TOKEN' }]);
    expect(plan.variables).toEqual([{ key: 'QUALOR_URL', value: URL_ }]);
    expect(plan.description).toMatch(/QUALOR_TOKEN/);
    expect(plan.description).toMatch(/remove/i);
  });

  it('never writes the server URL into the file', () => {
    expect(glFile(null)).not.toContain(URL_);
    expect(glFile('stages: [test]\n')).not.toContain(URL_);
  });

  it('treats an empty or comment-only file like a new one but marks it as an update', () => {
    const plan = change(gl('# only a comment\n'));
    expect(plan.files[0]?.update).toBe(true);
    const out = plan.files[0]?.content ?? '';
    expect(out.startsWith('# only a comment\n')).toBe(true);
    expect(parse(out).include[0].component).toBe('gitlab.com/qualor/qualor/qualor@0.14');
    expect(parse(glFile('')).include).toHaveLength(1);
  });

  it('adds an include key at the end and keeps the file byte-identical otherwise', () => {
    const before = [
      '# CI for acme',
      'stages:   [build,   test]  # the order',
      '',
      'variables:',
      '  FOO: "bar"   # quoted',
      '',
      'build:',
      '  stage: build',
      '  script:',
      '    - make   # compile',
      '',
    ].join('\n');
    const out = glFile(before);
    const added = inserted(before, out);
    expect(added).toContain('include:');
    expect(out.startsWith(before)).toBe(true);
    expect(parse(out).include).toEqual([
      {
        component: 'gitlab.com/qualor/qualor/qualor@0.14',
        inputs: { 'image-tag': '0.14', args: '--project-key acme/app-2' },
      },
    ]);
  });

  it('adds the missing final newline before appending', () => {
    const out = glFile('stages: [test]');
    expect(out.startsWith('stages: [test]\n')).toBe(true);
    expect(parse(out).include).toHaveLength(1);
  });

  it('appends to a block list with its indentation and keeps comments', () => {
    const before = [
      'include:',
      '  - local: ci/a.yml   # first',
      '  # a comment between',
      '  - project: acme/ci',
      '    file: b.yml',
      '',
      'test:',
      '  script: [ls]',
      '',
    ].join('\n');
    const out = glFile(before);
    const added = inserted(before, out);
    expect(added).toBe(
      [
        '  - component: gitlab.com/qualor/qualor/qualor@0.14',
        '    inputs:',
        "      image-tag: '0.14'",
        "      args: '--project-key acme/app-2'",
        '',
      ].join('\n'),
    );
    expect(out.indexOf(added)).toBe(before.indexOf('\n\ntest:') + 1);
    expect(parse(out).include).toHaveLength(3);
  });

  it('appends to a block list written without indentation', () => {
    const before = 'include:\n- local: a.yml\nstages: [test]\n';
    const out = glFile(before);
    inserted(before, out);
    expect(out).toContain('\n- component: gitlab.com/qualor/qualor/qualor@0.14\n  inputs:\n');
    expect(parse(out).include).toHaveLength(2);
  });

  it('appends to a block list at the end of the file, with or without a final newline', () => {
    const before = 'include:\n  - local: a.yml # c\n';
    const out = glFile(before);
    inserted(before, out);
    expect(parse(out).include).toHaveLength(2);
    expect(parse(glFile('include:\n  - local: a.yml')).include).toHaveLength(2);
  });

  it('appends to a block list whose last item is a block scalar', () => {
    const before = 'include:\n  - local: a.yml\n  - |\n    text\nstages: [test]\n';
    const out = glFile(before);
    inserted(before, out);
    expect(parse(out).include).toHaveLength(3);
    expect(out.endsWith('stages: [test]\n')).toBe(true);
  });

  it('appends to a flow list on one line, with a trailing comma, and an empty one', () => {
    const one = glFile('include: [ {local: a.yml}, "b.yml" ]  # list\nstages: [test]\n');
    expect(one.startsWith('include: [ {local: a.yml}, "b.yml"')).toBe(true);
    expect(one).toContain('  # list\nstages: [test]\n');
    expect(parse(one).include).toHaveLength(3);

    const multi = 'include: [\n  {local: a.yml},\n  b.yml, # keep\n]\n';
    const m = glFile(multi);
    inserted(multi, m);
    expect(parse(m).include).toHaveLength(3);
    expect(m).toContain('# keep');

    const empty = glFile('include: []\n');
    inserted('include: []\n', empty);
    expect(parse(empty).include).toHaveLength(1);
  });

  it('turns a single string include into a list with the old entry first', () => {
    const before = "stages: [test]\ninclude: 'ci/base.yml'  # base\nbuild:\n  script: [x]\n";
    const out = glFile(before);
    const doc = parse(out);
    expect(doc.include[0]).toBe('ci/base.yml');
    expect(doc.include[1].component).toBe('gitlab.com/qualor/qualor/qualor@0.14');
    expect(out).toContain('# base');
    expect(out).toContain('build:\n  script: [x]\n');
    const plain = parse(glFile('include: ci/base.yml\n'));
    expect(plain.include[0]).toBe('ci/base.yml');
    expect(plain.include).toHaveLength(2);
  });

  it('turns a block map include into a list with the old entry first', () => {
    const before = [
      'include:',
      '  project: acme/ci   # shared',
      '  ref: main',
      '  file: base.yml',
      'stages: [test]',
      '',
    ].join('\n');
    const out = glFile(before);
    const doc = parse(out);
    expect(doc.include[0]).toEqual({ project: 'acme/ci', ref: 'main', file: 'base.yml' });
    expect(doc.include[1].component).toBe('gitlab.com/qualor/qualor/qualor@0.14');
    expect(out).toContain('# shared');
    expect(out.endsWith('stages: [test]\n')).toBe(true);
    expect(doc.stages).toEqual(['test']);
  });

  it('turns a flow map include into a list with the old entry first', () => {
    const out = glFile('include: { local: a.yml }  # one\nstages: [test]\n');
    const doc = parse(out);
    expect(doc.include[0]).toEqual({ local: 'a.yml' });
    expect(doc.include).toHaveLength(2);
    expect(out).toContain('# one');
  });

  it('handles a deeper-indented block map include', () => {
    const before = 'include:\n    local: a.yml\n    rules:\n      - if: $X\nstages: [test]\n';
    const doc = parse(glFile(before));
    expect(doc.include).toHaveLength(2);
    expect(doc.include[0]).toEqual({ local: 'a.yml', rules: [{ if: '$X' }] });
  });

  it('keeps a realistic large file byte-identical outside the insertion', () => {
    const before = `# Acme web app pipeline.
# Owner: platform team

workflow:
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

default:
  image: node:20-alpine
  before_script:
    - npm ci --cache .npm --prefer-offline   # fast installs
  cache:
    key:
      files: [package-lock.json]
    paths:
      - .npm/

include:
  - local: ci/security.yml
  - template: Security/SAST.gitlab-ci.yml   # GitLab's SAST
  - project: acme/shared-ci
    ref: v3
    file: /templates/deploy.yml

stages:
  - build
  - test
  - deploy

variables:
  NODE_ENV: "production"
  DEPLOY_ENV: 'staging'

build:
  stage: build
  script:
    - npm run build
    - |
      echo "multi
      line"
  artifacts:
    paths: [dist/]
    expire_in: 1 week

unit:
  stage: test
  script:
    - npm test -- --ci
  coverage: '/All files[^|]*\\|[^|]*\\s+([\\d\\.]+)/'

deploy:
  stage: deploy
  script:
    - ./deploy.sh "$DEPLOY_ENV"
  environment:
    name: $DEPLOY_ENV
  when: manual
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
`;
    const out = glFile(before);
    const added = inserted(before, out);
    expect(added).toContain('component: gitlab.com/qualor/qualor/qualor@0.14');
    expect(added).not.toContain('stage:');
    const doc = parse(out);
    expect(doc.include).toHaveLength(4);
    expect(doc.include[3].inputs).toEqual({
      'image-tag': '0.14',
      args: '--project-key acme/app-2',
    });
    expect(Object.keys(doc)).toEqual(Object.keys(parse(before)));
  });

  it('adds a stage input when stages has no test', () => {
    const doc = parse(glFile('stages:\n  - build\n  - deploy\n'));
    expect(doc.include[0].inputs).toEqual({
      'image-tag': '0.14',
      stage: 'deploy',
      args: '--project-key acme/app-2',
    });
    expect(parse(glFile('stages: [prepare, ship]\n')).include[0].inputs.stage).toBe('ship');
  });

  it('adds no stage input when test is listed, or stages is absent', () => {
    expect(parse(glFile('stages: [build, test]\n')).include[0].inputs).toEqual({
      'image-tag': '0.14',
      args: '--project-key acme/app-2',
    });
    expect(parse(glFile('job:\n  script: [x]\n')).include[0].inputs).toEqual({
      'image-tag': '0.14',
      args: '--project-key acme/app-2',
    });
  });

  it('sets dotnet: true and the dotnet image for C#', () => {
    const doc = parse(glFile(null, { csharp: true }));
    expect(doc.include[0].inputs).toEqual({
      'image-tag': '0.14',
      args: '--project-key acme/app-2',
      dotnet: true,
      image: 'qualor/scanner-dotnet',
      'build-command': 'dotnet build --no-incremental',
    });
    const d = change(gl(null, { csharp: true })).description;
    expect(d).toMatch(/build command/i);
    expect(d).toMatch(/merge request/);
    expect(d).not.toMatch(/pull request/);
  });

  it('accepts local:, project: and remote: includes as normal', () => {
    const before = [
      'include:',
      '  - local: a.yml',
      '  - project: acme/other',
      '    file: x.yml',
      '  - remote: https://example.com/ci.yml',
      '',
    ].join('\n');
    expect(gl(before).kind).toBe('change');
  });
});

describe('include edge shapes and the guard', () => {
  it('appends after a dash with a comment or content on the next line', () => {
    for (const before of [
      'include:\n  - # shared\n    local: a.yml\nstages: [test]\n',
      'include:\n  -\n    local: a.yml\nstages: [test]\n',
    ]) {
      const out = glFile(before);
      inserted(before, out);
      const doc = parse(out);
      expect(doc.include).toHaveLength(2);
      expect(doc.include[0]).toEqual({ local: 'a.yml' });
    }
  });

  it('appends to an empty multi-line flow list', () => {
    const before = 'include: [\n]\nstages: [test]\n';
    const out = glFile(before);
    inserted(before, out);
    expect(parse(out).include).toHaveLength(1);
  });

  it('the guard accepts a sound edit and rejects bad ones', () => {
    const before = parseDocument('include:\n  - local: a.yml\nx: 1\n').contents as YAMLMap;
    const ok = 'include:\n  - local: a.yml\n  - local: b.yml\nx: 1\n';
    expect(editIsSound(before, ok, 'include')).toBe(true);
    expect(
      editIsSound(before, 'include:\n  - local: a.yml\n  - # c\n  local: b\nx: 1\n', 'include'),
    ).toBe(false);
    expect(editIsSound(before, 'include:\n  - local: a.yml\nx: 1\n', 'include')).toBe(false);
    expect(editIsSound(before, 'include:\n  - local: a.yml\n  - local: b.yml\n', 'include')).toBe(
      false,
    );
    expect(editIsSound(before, 'include:\n  - local: a.yml\nx: 1\nqualor: {}\n', 'job')).toBe(true);
    expect(editIsSound(before, 'include:\n  - local: a.yml\nx: 1\n', 'job')).toBe(false);
  });
});

describe('scalar quoting', () => {
  it.each(['2', '1.0', '2024', 'true', 'yes', 'No', 'off', 'null', '~', '0x1F', '1e3'])(
    'quotes %s',
    (v) => {
      const stage = parse(glFile(`stages: [build, '${v}']\n`)).include[0].inputs.stage;
      expect(stage).toBe(v);
      const wf =
        change(planCiSetup(input({ provider: 'github', defaultBranch: v }))).files[0]?.content ??
        '';
      expect(parse(wf).on.push.branches).toEqual([v]);
    },
  );
});

describe('GitLab already set up and unsupported', () => {
  it('detects a Qualor component include in any include shape', () => {
    const shapes = [
      'include:\n  - component: gitlab.com/qualor/qualor/qualor@0.13\n    inputs:\n      image-tag: "0.13"\n',
      'include: [{component: gitlab.com/qualor/qualor/qualor@0.13}]\n',
      'include:\n  component: gitlab.com/qualor/qualor/qualor@0.13\n',
      'include: gitlab.com/qualor/qualor/qualor@0.13\n',
    ];
    for (const s of shapes) {
      expect(gl(s)).toMatchObject({ kind: 'snippet', reason: 'already_set_up' });
    }
  });

  it('detects a qualor job and a set token', () => {
    expect(gl('qualor:\n  script: [qualor scan]\n')).toMatchObject({
      kind: 'snippet',
      reason: 'already_set_up',
    });
    expect(planCiSetup(input({ existing: { tokenSecretSet: true } }))).toMatchObject({
      kind: 'snippet',
      reason: 'already_set_up',
    });
  });

  it('detects an existing qualor workflow file on GitHub', () => {
    const base = { provider: 'github' as const };
    expect(
      planCiSetup(
        input({
          ...base,
          existing: {
            workflowQualor: 'name: qualor\n',
            workflowFiles: ['.github/workflows/qualor.yml'],
          },
        }),
      ),
    ).toMatchObject({ kind: 'snippet', reason: 'already_set_up' });
    expect(
      planCiSetup(
        input({ ...base, existing: { workflowFiles: ['.github/workflows/qualor-dotnet.yml'] } }),
      ),
    ).toMatchObject({ kind: 'snippet', reason: 'already_set_up' });
    expect(
      planCiSetup(input({ ...base, existing: { workflowFiles: ['.github/workflows/ci.yml'] } }))
        .kind,
    ).toBe('change');
  });

  it('gives a snippet that is valid YAML', () => {
    const plan = gl('qualor:\n  script: [x]\n');
    if (plan.kind !== 'snippet') throw new Error('expected snippet');
    expect(plan.snippet).toContain('gitlab.com/qualor/qualor/qualor@0.14');
    expect(() => parse(plan.snippet)).not.toThrow();
  });

  it.each([
    ['anchor', 'base: &b\n  image: x\njob:\n  <<: *b\n  script: [a]\n'],
    ['alias only', 'x: &a [1]\ny: *a\n'],
    ['several documents', 'a: 1\n---\nb: 2\n'],
    ['parse error', 'a: [1, 2\nb: : :\n'],
    ['duplicate keys', 'a: 1\na: 2\n'],
    ['list root', '- a\n- b\n'],
    ['scalar root', 'just text\n'],
    ['flow map root', '{ a: 1 }\n'],
    ['tagged include', 'include: !reference [.x, include]\n'],
  ])('shows a snippet for %s', (_name, text) => {
    const plan = gl(text);
    expect(plan).toMatchObject({ kind: 'snippet', reason: 'yaml_unsupported' });
    if (plan.kind === 'snippet') expect(() => parse(plan.snippet)).not.toThrow();
  });

  it('is fine with unknown tags elsewhere in the file', () => {
    const before = 'a:\n  script:\n    - !reference [.setup, script]\n';
    expect(glFile(before).startsWith(before)).toBe(true);
  });

  it('reports already_set_up before unsupported', () => {
    expect(gl('x: &a 1\ny: *a\nqualor:\n  script: [x]\n')).toMatchObject({
      reason: 'already_set_up',
    });
  });
});

describe('GitLab self-managed', () => {
  const sm = { host: 'self-hosted' as const };

  it('creates a file with the plain job', () => {
    const plan = change(gl(null, sm));
    const content = plan.files[0]?.content ?? '';
    const doc = parse(content);
    expect(doc.qualor.stage).toBe('test');
    expect(doc.qualor.image).toEqual({ name: 'qualor/scanner:0.14.3', entrypoint: [''] });
    expect(doc.qualor.variables).toEqual({ GIT_DEPTH: '0' });
    expect(doc.qualor.script).toHaveLength(1);
    expect(doc.qualor.script[0]).toContain(
      'qualor scan --project-key acme/app-2 --gitlab-code-quality gl-code-quality-report.json',
    );
    expect(doc.qualor.script[0]).toContain('--gitlab-sast gl-sast-report.json');
    expect(doc.qualor.script[0]).toContain(
      '--gitlab-dependency-scanning gl-dependency-scanning-report.json',
    );
    expect(doc.qualor.artifacts.reports.codequality).toBe('gl-code-quality-report.json');
    expect(doc.qualor.artifacts.when).toBe('always');
    expect(doc.qualor.rules).toEqual([
      { if: '$CI_PIPELINE_SOURCE == "merge_request_event"' },
      { if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH' },
    ]);
    expect(doc.include).toBeUndefined();
    expect(content).not.toContain(URL_);
    expect(plan.variables).toEqual([{ key: 'QUALOR_URL', value: URL_ }]);
    expect(plan.description).toMatch(/upgrade|edit/i);
  });

  it('appends the job to an existing file and keeps it byte-identical', () => {
    const before = '# hi\nstages: [build, deploy]\n\nbuild:\n  script: [make]   # x\n';
    const out = glFile(before, sm);
    expect(inserted(before, out)).toContain('qualor:');
    const doc = parse(out);
    expect(doc.qualor.stage).toBe('deploy');
    expect(doc.build.script).toEqual(['make']);
  });

  it('uses the dotnet variant for C#', () => {
    const doc = parse(glFile(null, { ...sm, csharp: true }));
    expect(doc.qualor.image.name).toBe('qualor/scanner-dotnet:0.14.3');
    expect(doc.qualor.script.slice(0, 2)).toEqual([
      'qualor dotnet begin',
      'dotnet build --no-incremental',
    ]);
    expect(doc.qualor.script[2]).toContain(
      'qualor dotnet end --project-key acme/app-2 --gitlab-code-quality',
    );
    expect(doc.qualor.after_script).toEqual(['qualor dotnet abort']);
  });

  it('also guards unsupported files', () => {
    expect(gl('a: &x 1\nb: *x\n', sm)).toMatchObject({ reason: 'yaml_unsupported' });
  });
});

describe('GitHub', () => {
  const gh = { provider: 'github' as const };
  function wf(over: Partial<Omit<CiSetupInput, 'existing'>> = {}) {
    const plan = change(planCiSetup(input({ ...gh, ...over })));
    expect(plan.files).toHaveLength(1);
    expect(plan.files[0]).toMatchObject({ path: '.github/workflows/qualor.yml', update: false });
    expect(plan.secrets).toEqual([{ name: 'QUALOR_TOKEN' }]);
    expect(plan.variables).toEqual([]);
    return {
      plan,
      content: plan.files[0]?.content ?? '',
      doc: parse(plan.files[0]?.content ?? ''),
    };
  }
  const CHECKOUT = 'actions/checkout@11d5960a326750d5838078e36cf38b85af677262';

  it('cloud non-C#: the scan-action workflow', () => {
    const { doc, content } = wf();
    expect(doc.name).toBe('qualor');
    expect(doc.on).toEqual({ pull_request: null, push: { branches: ['main'] } });
    expect(doc.permissions).toEqual({ contents: 'read' });
    const job = doc.jobs.qualor;
    expect(job.if).toBe(
      "github.event_name == 'push' || github.event.pull_request.head.repo.full_name == github.repository",
    );
    expect(job['runs-on']).toBe('ubuntu-latest');
    expect(job.container).toBeUndefined();
    expect(job.steps[0].uses).toBe(CHECKOUT);
    expect(job.steps[0].with).toEqual({
      'fetch-depth': 0,
      'persist-credentials': false,
      ref: '${{ github.event.pull_request.head.sha || github.sha }}',
    });
    expect(job.steps[1]).toEqual({
      uses: 'qualor-dev/scan-action@v0.14',
      with: {
        'server-url': URL_,
        'project-key': KEY,
        token: '${{ secrets.QUALOR_TOKEN }}',
      },
    });
    expect(content).not.toContain('vars.');
  });

  it('uses the default branch', () => {
    expect(wf({ defaultBranch: 'develop' }).doc.on.push.branches).toEqual(['develop']);
    expect(wf({ defaultBranch: 'release/2024 x' }).doc.on.push.branches).toEqual([
      'release/2024 x',
    ]);
  });

  it('cloud C#: the dotnet container layout with the token on the end step only', () => {
    const { doc } = wf({ csharp: true });
    const job = doc.jobs.qualor;
    expect(job.container).toEqual({
      image: 'qualor/scanner-dotnet:0.14.3',
      options: '--user 1001',
    });
    expect(job.steps.map((s: { run?: string }) => s.run)).toEqual([
      undefined,
      'qualor dotnet begin',
      'dotnet build --no-incremental',
      'qualor dotnet end',
      'qualor dotnet abort',
    ]);
    expect(job.steps[3].env).toEqual({
      QUALOR_URL: URL_,
      QUALOR_PROJECT_KEY: KEY,
      QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}',
    });
    expect(job.steps[2].env).toBeUndefined();
    expect(job.steps[4].if).toBe('failure() || cancelled()');
  });

  it('GHES non-C#: the container layout', () => {
    const job = wf({ host: 'self-hosted' }).doc.jobs.qualor;
    expect(job.container).toEqual({ image: 'qualor/scanner:0.14.3', options: '--user 1001' });
    expect(job.steps[1]).toEqual({
      run: 'qualor scan',
      env: {
        QUALOR_URL: URL_,
        QUALOR_PROJECT_KEY: KEY,
        QUALOR_TOKEN: '${{ secrets.QUALOR_TOKEN }}',
      },
    });
  });

  it('GHES C#: the dotnet container layout', () => {
    const job = wf({ host: 'self-hosted', csharp: true }).doc.jobs.qualor;
    expect(job.container.image).toBe('qualor/scanner-dotnet:0.14.3');
    expect(job.steps[3].env.QUALOR_URL).toBe(URL_);
    expect(job.steps[3].env.QUALOR_PROJECT_KEY).toBe(KEY);
  });

  it('GHES uses a Linux self-hosted runner and the tag-pinned checkout; cloud keeps the SHA pin', () => {
    for (const csharp of [false, true]) {
      const g = wf({ host: 'self-hosted', csharp });
      const job = g.doc.jobs.qualor;
      expect(job['runs-on']).toEqual(['self-hosted', 'linux']);
      expect(job.steps[0].uses).toBe('actions/checkout@v4');
      expect(g.plan.description).toMatch(/Linux runner with Docker/);
      const c = wf({ csharp });
      expect(c.doc.jobs.qualor['runs-on']).toBe('ubuntu-latest');
      expect(c.doc.jobs.qualor.steps[0].uses).toBe(CHECKOUT);
    }
  });

  it('describes the change', () => {
    const { plan } = wf();
    expect(plan.description).toMatch(/QUALOR_TOKEN/);
    expect(plan.description).toMatch(/remove|delete/i);
    expect(wf({ host: 'self-hosted' }).plan.description).toMatch(/version/i);
    expect(wf({ csharp: true }).plan.description).toMatch(/build command/i);
  });
});

describe('the project key', () => {
  const variants = (['github', 'gitlab'] as const).flatMap((provider) =>
    (['cloud', 'self-hosted'] as const).flatMap((host) =>
      [false, true].map((csharp) => ({ provider, host, csharp })),
    ),
  );

  /** Where each variant names the key: the Action's input, the step's env, the scan's flag. */
  function keyOf(content: string, v: (typeof variants)[number]): string | undefined {
    const doc = parse(content);
    if (v.provider === 'github') {
      const steps = doc.jobs.qualor.steps as {
        with?: Record<string, string>;
        env?: Record<string, string>;
      }[];
      if (v.host === 'cloud' && !v.csharp) return steps[1]?.with?.['project-key'];
      const scan = steps.find((s) => s.env?.['QUALOR_TOKEN'] !== undefined);
      return scan?.env?.['QUALOR_PROJECT_KEY'];
    }
    if (v.host === 'cloud') {
      const args = (doc.include as { inputs: { args?: string } }[]).at(-1)?.inputs.args;
      return /^--project-key (\S+)$/.exec(args ?? '')?.[1];
    }
    const script = (doc.qualor.script as string[]).join('\n');
    return /--project-key (\S+)/.exec(script)?.[1];
  }

  it.each(variants)('is written into the file and the snippet: %o', (v) => {
    const plan = change(planCiSetup(input(v)));
    expect(keyOf(plan.files[0]?.content ?? '', v)).toBe(KEY);
    const snippet = planCiSetup(input({ ...v, existing: { tokenSecretSet: true } }));
    if (snippet.kind !== 'snippet') throw new Error('expected snippet');
    expect(keyOf(snippet.snippet, v)).toBe(KEY);
  });

  it('is written into every include shape GitLab gets', () => {
    for (const before of [
      'include:\n  - local: a.yml\n',
      'include: [ {local: a.yml} ]\n',
      'include: []\n',
      'include: ci/base.yml\n',
      'include:\n  local: a.yml\n',
      'include: { local: a.yml }\n',
    ]) {
      const inputs = (parse(glFile(before)).include as { inputs?: { args?: string } }[]).at(
        -1,
      )?.inputs;
      expect(inputs?.args, before).toBe('--project-key acme/app-2');
    }
  });

  it('is quoted where YAML or the shell would read it otherwise', () => {
    for (const key of ['acme/app:2', 'yes', '2024', 'a.b_c:d']) {
      const gh = change(planCiSetup(input({ provider: 'github', projectKey: key })));
      expect(parse(gh.files[0]?.content ?? '').jobs.qualor.steps[1].with['project-key']).toBe(key);
      const ghes = change(
        planCiSetup(input({ provider: 'github', host: 'self-hosted', projectKey: key })),
      );
      expect(parse(ghes.files[0]?.content ?? '').jobs.qualor.steps[1].env.QUALOR_PROJECT_KEY).toBe(
        key,
      );
      expect(parse(glFile(null, { projectKey: key })).include[0].inputs.args).toBe(
        `--project-key ${key}`,
      );
      expect(
        parse(glFile('include: [ {local: a.yml} ]\n', { projectKey: key })).include[1].inputs.args,
      ).toBe(`--project-key ${key}`);
    }
    // A key that starts with a dash is still the flag's value, not another flag.
    expect(parse(glFile(null, { projectKey: '-x' })).include[0].inputs.args).toBe(
      '--project-key=-x',
    );
    const job = parse(glFile(null, { host: 'self-hosted', projectKey: '-x' })).qualor;
    expect(job.script[0]).toContain('qualor scan --project-key=-x --gitlab-code-quality');
  });

  it('names the project in the description', () => {
    for (const provider of ['github', 'gitlab'] as const) {
      expect(change(planCiSetup(input({ provider }))).description).toContain('`acme/app-2`');
    }
  });
});

describe('every generated YAML parses', () => {
  it.each(
    (['github', 'gitlab'] as const).flatMap((provider) =>
      (['cloud', 'self-hosted'] as const).flatMap((host) =>
        [false, true].map((csharp) => ({ provider, host, csharp })),
      ),
    ),
  )('%o', (v) => {
    const plan = change(planCiSetup(input(v)));
    for (const f of plan.files) {
      const docs = parseAllDocuments(f.content);
      expect(docs).toHaveLength(1);
      expect(docs[0]?.errors).toEqual([]);
      expect(docs[0]?.warnings).toEqual([]);
    }
    const snip = planCiSetup(input({ ...v, existing: { tokenSecretSet: true } }));
    if (snip.kind !== 'snippet') throw new Error('expected snippet');
    expect(parseAllDocuments(snip.snippet)[0]?.errors).toEqual([]);
  });
});
