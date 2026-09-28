import { spawnSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { PLAIN_HTTP, signImageArgs } from './cosign';
import { PUBLISH_OPTIONS, REKOR_FOR_REAL_RELEASES, REQUIRED_SECRETS } from './publish';

interface Step {
  uses?: string;
  run?: string;
  env?: Record<string, string>;
  with?: Record<string, unknown>;
}
interface Job {
  if?: string;
  needs?: string | string[];
  environment?: string | { name: string };
  permissions?: Record<string, string>;
  steps: Step[];
}
interface Workflow {
  on: Record<
    string,
    { inputs?: Record<string, { required?: boolean; type?: string; default?: unknown }> }
  >;
  permissions?: Record<string, string>;
  jobs: Record<string, Job>;
}

const read = (f: string): string => readFileSync(f, 'utf8');
const release = parse(read('.github/workflows/release.yml')) as Workflow;
const WORKFLOWS = readdirSync('.github/workflows').filter((f) => /\.ya?ml$/.test(f));
/** Anything that publishes, logs in to a registry or signs for real. */
const PUBLISHING =
  /docker\s+(login|push)|helm\s+(push|registry\s+login)|buildx[^\n]*(--push|type=registry|push=true)|imagetools\s+create|cosign\s+(sign|attest|upload|attach|copy)|gh\s+release|(npm|pnpm|yarn)\s+publish|release:publish|skopeo|crane\s+(push|copy|cp|tag)|oras\s+(push|login|attach|cp|copy|tag)/;
const PINNED = /^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/;
/** release.md §11: the exact condition of the publish job, compared as a whole. */
const PUBLISH_IF =
  "github.event_name == 'workflow_dispatch' && inputs.publish && github.ref_type == 'tag' && " +
  "github.ref_name == format('v{0}', inputs.version) && " +
  "inputs.confirm == format('publish v{0}', inputs.version)";
/** Any reference to a secret or to the job token, in any spelling. */
const SECRET_REF = /\bsecrets\s*(?:\.|\[)|\btoJSON\(\s*secrets\s*\)|\bgithub\.token\b/;
/** The only actions a workflow may use: checkout, setup, cache and artifacts; none publishes. */
const ALLOWED_ACTIONS = [
  'actions/checkout',
  'pnpm/action-setup',
  'actions/setup-node',
  'oven-sh/setup-bun',
  'actions/setup-java',
  'actions/cache',
  'actions/upload-artifact',
  'actions/download-artifact',
];
/** Actions release.yml's publish job may use besides those; none today (publish.ts does it all). */
const PUBLISH_JOB_ACTIONS: string[] = [];
/** Actions that publish, log in or release; refused everywhere but PUBLISH_JOB_ACTIONS. */
const PUBLISHING_ACTION =
  /^(?:docker\/(?:login|build-push|setup-buildx|metadata)-action|softprops\/action-gh-release|ncipollo\/release-action|actions\/(?:create-release|upload-release-asset|github-script)|sigstore\/cosign-installer|goreleaser\/|helm\/chart-releaser-action|JS-DevTools\/npm-publish|pypa\/gh-action-pypi-publish|aws-actions\/amazon-ecr-login|azure\/docker-login|google-github-actions\/)/;
const actionName = (uses: string): string => uses.replace(/@.*$/, '');
const workflowFiles = (): [string, Workflow][] =>
  WORKFLOWS.map((f) => [f, parse(read(`.github/workflows/${f}`)) as Workflow]);

describe('the publish gate (release.md §11, §15 item 7)', () => {
  it('starts release.yml only by hand: workflow_dispatch and nothing else', () => {
    expect(Object.keys(release.on)).toEqual(['workflow_dispatch']);
    const inputs = release.on['workflow_dispatch']?.inputs ?? {};
    expect(inputs['version']).toMatchObject({ required: true, type: 'string' });
    expect(inputs['publish']).toMatchObject({ type: 'boolean', default: false });
    expect(inputs['confirm']).toMatchObject({ type: 'string', default: '' });
    expect(release.permissions).toEqual({ contents: 'read' });
  });

  it('publishes only from the gated job', () => {
    expect(Object.keys(release.jobs)).toEqual(['dry-run', 'publish']);
    const p = release.jobs['publish'];
    expect(p?.environment).toBe('release');
    expect(p?.needs).toBe('dry-run');
    // The whole condition, exactly: nothing added (no "||", no "|| true") and nothing dropped.
    expect(p?.if?.replace(/\s+/g, ' ').trim()).toBe(PUBLISH_IF);
    expect(p?.permissions).toEqual({ contents: 'write' });
    // No OIDC token: no keyless signing and no Rekor identity.
    expect(read('.github/workflows/release.yml')).not.toContain('id-token');
    const steps = p?.steps.map((s) => s.run ?? '') ?? [];
    expect(steps.filter((s) => PUBLISHING.test(s))).toEqual(['pnpm release:publish']);
    const publishStep = p?.steps.find((s) => s.run === 'pnpm release:publish');
    expect(Object.keys(publishStep?.env ?? {}).sort()).toEqual(
      ['GH_TOKEN', 'QUALOR_RELEASE_CONFIRM', ...REQUIRED_SECRETS].sort(),
    );
    expect(publishStep?.env?.['QUALOR_RELEASE_CONFIRM']).toBe('${{ inputs.confirm }}');
    expect(publishStep?.env?.['GH_TOKEN']).toBe('${{ github.token }}');
    for (const s of REQUIRED_SECRETS) expect(publishStep?.env?.[s]).toBe(`\${{ secrets.${s} }}`);
    // Only the publish job has an environment or write permission.
    expect(release.jobs['dry-run']?.environment).toBeUndefined();
    expect(release.jobs['dry-run']?.permissions).toBeUndefined();
  });

  it('checks out every tag, so releasedVersions() sees the released versions', () => {
    for (const [name, job] of Object.entries(release.jobs)) {
      const checkout = job.steps.find((s) => s.uses?.startsWith('actions/checkout@'));
      expect(checkout?.with?.['fetch-depth'], name).toBe(0);
    }
  });

  it('references secrets and the job token only in the publish step, in any spelling', () => {
    const found: string[] = [];
    for (const [f, wf] of workflowFiles()) {
      const { jobs, ...top } = wf;
      if (SECRET_REF.test(JSON.stringify(top))) found.push(`${f}: top level`);
      for (const [name, job] of Object.entries(jobs)) {
        const { steps, ...rest } = job;
        if (SECRET_REF.test(JSON.stringify(rest))) found.push(`${f}: ${name}`);
        for (const s of steps) {
          const allowed =
            f === 'release.yml' && name === 'publish' && s.run === 'pnpm release:publish';
          if (!allowed && SECRET_REF.test(JSON.stringify(s))) {
            found.push(`${f}: ${name}: ${s.run ?? s.uses ?? ''}`);
          }
        }
      }
    }
    expect(found).toEqual([]);
    for (const sample of [
      '${{ secrets.X }}',
      "${{ secrets['X'] }}",
      '${{ secrets [ "X" ] }}',
      '${{ toJSON(secrets) }}',
      '${{ github.token }}',
    ]) {
      expect(SECRET_REF.test(sample), sample).toBe(true);
    }
    expect(SECRET_REF.test('the compose stack with secrets generated for this run')).toBe(false);
  });

  it('never interpolates an expression into a script, nor into a github-script script', () => {
    const scriptProblems = (wf: Workflow): string[] =>
      Object.values(wf.jobs).flatMap((job) =>
        job.steps.flatMap((s) => {
          const script = typeof s.with?.['script'] === 'string' ? s.with['script'] : '';
          return [s.run ?? '', script].filter((t) => t.includes('${{'));
        }),
      );
    for (const [f, wf] of workflowFiles()) expect(scriptProblems(wf), f).toEqual([]);
    // The check reaches actions/github-script's `script:` input.
    const sample = {
      on: {},
      jobs: {
        j: {
          steps: [
            {
              uses: 'actions/github-script@0000000000000000000000000000000000000000',
              with: { script: 'core.info("${{ github.event.issue.title }}")' },
            },
          ],
        },
      },
    } as unknown as Workflow;
    expect(scriptProblems(sample)).toHaveLength(1);
  });

  it('checks out without persisting the job token, in every workflow', () => {
    for (const [f, wf] of workflowFiles()) {
      for (const [name, job] of Object.entries(wf.jobs)) {
        for (const s of job.steps.filter((x) => x.uses?.startsWith('actions/checkout@'))) {
          expect(s.with?.['persist-credentials'], `${f}: ${name}`).toBe(false);
        }
      }
    }
    expect(read('.github/workflows/ci.yml')).toContain('persist-credentials: false');
  });

  it('uses only non-publishing actions; a publishing action is refused', () => {
    const found: string[] = [];
    for (const [f, wf] of workflowFiles()) {
      for (const [name, job] of Object.entries(wf.jobs)) {
        const allowed = [
          ...ALLOWED_ACTIONS,
          ...(f === 'release.yml' && name === 'publish' ? PUBLISH_JOB_ACTIONS : []),
        ];
        for (const s of job.steps) {
          if (s.uses !== undefined && !allowed.includes(actionName(s.uses))) {
            found.push(`${f}: ${name}: ${s.uses}`);
          }
        }
      }
    }
    expect(found).toEqual([]);
    for (const a of ALLOWED_ACTIONS) expect(a).not.toMatch(PUBLISHING_ACTION);
    for (const a of [
      'docker/login-action',
      'docker/build-push-action',
      'softprops/action-gh-release',
      'ncipollo/release-action',
      'actions/create-release',
      'actions/upload-release-asset',
      'sigstore/cosign-installer',
      'goreleaser/goreleaser-action',
      'JS-DevTools/npm-publish',
    ]) {
      expect(a, a).toMatch(PUBLISHING_ACTION);
      expect(ALLOWED_ACTIONS, a).not.toContain(a);
    }
    for (const a of PUBLISH_JOB_ACTIONS) expect(a).not.toMatch(PUBLISHING_ACTION);
  });

  it('gives an environment to the publish job only, and "release" nowhere else', () => {
    const found: string[] = [];
    for (const [f, wf] of workflowFiles()) {
      for (const [name, job] of Object.entries(wf.jobs)) {
        if (job.environment !== undefined) found.push(`${f}: ${name}`);
      }
    }
    expect(found).toEqual(['release.yml: publish']);
  });

  it('publishes nowhere else: no other workflow, no dry-run step, no GitLab job', () => {
    for (const f of WORKFLOWS.filter((w) => w !== 'release.yml')) {
      expect(read(`.github/workflows/${f}`), f).not.toMatch(PUBLISHING);
    }
    for (const s of release.jobs['dry-run']?.steps ?? [])
      expect(s.run ?? '').not.toMatch(PUBLISHING);
    expect(read('.gitlab-ci.yml')).not.toMatch(PUBLISHING);
  });

  it('pins every action of every workflow to a commit SHA', () => {
    for (const f of WORKFLOWS) {
      const wf = parse(read(`.github/workflows/${f}`)) as Workflow;
      for (const job of Object.values(wf.jobs)) {
        for (const s of job.steps) {
          if (s.uses !== undefined) expect(s.uses, `${f}: ${s.uses}`).toMatch(PINNED);
        }
      }
    }
  });

  it('tracks no private key, and keeps .tmp/ out of git', () => {
    const files = spawnSync('git', ['ls-files'], { encoding: 'utf8' }).stdout.split('\n');
    expect(files.filter((f) => /(^|\/)cosign\.key$|\.key$/.test(f))).toEqual([]);
    const marker = (kind: string) => ['ENCRYPTED', kind, 'PRIVATE', 'KEY'].join(' ');
    const grep = spawnSync(
      'git',
      ['grep', '-l', '-e', marker('SIGSTORE'), '-e', marker('COSIGN'), '--', '.', ':!docs'],
      { encoding: 'utf8' },
    );
    expect(grep.stdout.trim()).toBe('');
    expect(read('.gitignore').split(/\r?\n/)).toContain('.tmp/');
  });

  it('has release:publish go through the gate first', () => {
    const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> })
      .scripts;
    expect(scripts['release:publish']).toBe('tsx tools/release/publish.ts');
    const source = read('tools/release/publish.ts');
    const body = source.slice(source.indexOf('export async function publish('));
    expect(body.indexOf('publishGateProblems(')).toBeGreaterThan(-1);
    expect(body.indexOf('publishGateProblems(')).toBeLessThan(body.indexOf('exec('));
    expect(body.indexOf('publishGateProblems(')).toBeLessThan(body.indexOf('releasedVersions('));
  });
});

/**
 * Ruling R-REGOPTS: the registry options have no defaults, and the only modules that push, log in
 * to a registry or upload a signature are registry.ts (the dry run's loopback registry) and
 * publish.ts (the gated release).
 */
describe('registry options and uploads (ruling R-REGOPTS)', () => {
  it('has no default registry options: every call site says offline and plainHttp', () => {
    const cosign = read('tools/release/cosign.ts');
    expect(cosign).toMatch(/^\s+offline: boolean;$/m);
    expect(cosign).toMatch(/^\s+plainHttp: boolean;$/m);
    expect(cosign).not.toMatch(/RegistryOptions\s*=/);
    expect(cosign).not.toMatch(/offline\?|plainHttp\?|=== false|!== false/);
    const ref = `qualor/server@sha256:${'a'.repeat(64)}`;
    // @ts-expect-error R-REGOPTS: the options are required.
    expect(() => signImageArgs('/k', ref)).toThrow();
    // @ts-expect-error R-REGOPTS: plainHttp is required too.
    expect(signImageArgs('/k', ref, { offline: true })).toBeDefined();
  });

  it('never gives release:publish a plain-HTTP or insecure-registry flag', () => {
    expect(PUBLISH_OPTIONS).toEqual({ offline: !REKOR_FOR_REAL_RELEASES, plainHttp: false });
    const args = signImageArgs('/k', `qualor/server@sha256:${'a'.repeat(64)}`, PUBLISH_OPTIONS);
    for (const flag of PLAIN_HTTP) expect(args).not.toContain(flag);
    const source = read('tools/release/publish.ts');
    for (const bad of [
      'PLAIN_HTTP',
      'DRY_RUN_OPTIONS',
      'plainHttp: true',
      '--plain-http',
      '--allow-insecure-registry',
      '--allow-http-registry',
      'insecure',
    ]) {
      expect(source, bad).not.toContain(bad);
    }
  });

  it('keeps Rekor off for real releases until that is decided', () => {
    expect(REKOR_FOR_REAL_RELEASES).toBe(false);
    expect(PUBLISH_OPTIONS.offline).toBe(true);
  });

  /** Every way a tracked file could push, log in or upload (shell text and argv arrays). */
  /** A quote of any kind: a template literal can hold an argument too. */
  const Q = '[`\'"]';
  const UPLOADS: [string, RegExp][] = [
    ['docker push', /\bdocker\s+(?:image\s+)?push\b/],
    ['docker login', /\bdocker\s+login\b/],
    ['helm push', /\bhelm\s+push\b/],
    ['helm registry login', /\bhelm\s+registry\s+login\b/],
    ['buildx --push', /--push(?![\w-])/],
    ['buildx registry output', /\btype=registry\b|\bpush=true\b/],
    ['imagetools create', /\bimagetools\b/],
    ['gh release', /\bgh\s+release\b/],
    ['npm publish', /\b(?:npm|pnpm|yarn)\s+(?:--?[\w-]+(?:[ =][^\s-]\S*)?\s+)*publish\b/],
    ['skopeo', /\bskopeo\b/],
    ['crane', /\bcrane\s+(?:push|copy|cp|tag|append|mutate|delete|auth|rebase|flatten|index)\b/],
    ['oras', /\boras\s+(?:push|login|attach|cp|copy|tag|manifest|blob|repo)\b/],
    ['cosign upload', /\bcosign\s+(?:sign|attest|upload|attach|copy)\b(?!-)/],
    [
      'a push or login argv',
      new RegExp(
        `${Q}(?:docker|helm)${Q},\\s*\\[\\s*(?:${Q}(?:image|registry)${Q},\\s*)?${Q}(?:push|login)${Q}`,
      ),
    ],
    [
      'a release or publish argv',
      new RegExp(
        `${Q}(?:gh|npm|pnpm|yarn|skopeo|crane|oras)${Q},\\s*\\[\\s*${Q}(?:release|publish|push|copy|cp|login|attach)${Q}`,
      ),
    ],
    [
      'a cosign upload argv',
      new RegExp(`${Q}cosign${Q},\\s*\\[\\s*${Q}(?:sign|attest|upload|attach|copy)${Q}`),
    ],
    ['a cosign upload builder', /(?<!function\s)\b(?:signImageArgs|attestArgs)\(/],
    // Only the literal `offline: true` keeps Rekor off; any other value or a shorthand may not.
    [
      'a Rekor upload',
      /(?:^|[{,])\s*offline:\s*(?!true\b|boolean\b)[^\s,}]|\{[^{}\n]*\boffline\s*[,}]/m,
    ],
  ];
  /** The two modules that may upload. */
  const UPLOADERS = ['tools/release/registry.ts', 'tools/release/publish.ts'];
  /**
   * Tests that only build or assert argument lists, with fake executors: each is exempt only
   * from the patterns it needs, and none may import a real executor (run, runTool, spawn).
   * gating.test.ts holds a sample of every pattern.
   */
  const ARGV_ONLY_TESTS: Record<string, string[]> = {
    'tools/release/cosign.test.ts': ['a cosign upload builder', 'a Rekor upload'],
    'tools/release/registry.test.ts': ['a cosign upload builder', 'docker push'],
    'tools/release/publish.test.ts': [],
    'tools/release/gating.test.ts': UPLOADS.map(([what]) => what),
  };
  const SCANNED = /\.(?:[cm]?[jt]sx?|sh|bash|py|ya?ml|json|toml)$|(?:^|\/)Dockerfile[^/]*$/;

  /** Comments may name the commands; code may not. */
  function code(file: string, text: string): string {
    if (/\.[cm]?[jt]sx?$/.test(file)) {
      return text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
    }
    if (/\.json$/.test(file)) return text;
    return text.replace(/(^|\s)#.*$/gm, '$1');
  }

  it('pushes, logs in and uploads only in registry.ts and publish.ts', () => {
    const files = spawnSync('git', ['ls-files'], { encoding: 'utf8' })
      .stdout.split('\n')
      .filter((f) => SCANNED.test(f) && !f.startsWith('docs/') && f !== 'pnpm-lock.yaml')
      .filter((f) => existsSync(f));
    expect(files).toContain('tools/release/dry-run.ts');
    const found: string[] = [];
    for (const f of files) {
      if (UPLOADERS.includes(f)) continue;
      const exempt = ARGV_ONLY_TESTS[f] ?? [];
      const text = code(f, read(f));
      for (const [what, pattern] of UPLOADS) {
        if (!exempt.includes(what) && pattern.test(text)) found.push(`${f}: ${what}`);
      }
    }
    expect(found).toEqual([]);
    // The exempt tests run nothing: no real executor is imported.
    for (const f of Object.keys(ARGV_ONLY_TESTS)) {
      const text = read(f);
      expect(text, f).not.toMatch(/import\s*\{[^}]*\b(?:run|runTool|spawn|exec|execFile)\b[^}]*\}/);
      if (f !== 'tools/release/gating.test.ts') {
        expect(text, f).not.toMatch(/node:child_process/);
      }
    }
    // The two uploaders really are where the uploads are.
    expect(UPLOADS.some(([, p]) => p.test(code(UPLOADERS[0]!, read(UPLOADERS[0]!))))).toBe(true);
    expect(UPLOADS.some(([, p]) => p.test(code(UPLOADERS[1]!, read(UPLOADERS[1]!))))).toBe(true);
  });

  it('catches every form of an upload the scan is meant to catch', () => {
    for (const sample of [
      'docker push qualor/server:0.1.0',
      'docker image push x',
      'docker login -u me',
      'helm push chart.tgz oci://x',
      'helm registry login x',
      'docker buildx build --push .',
      'docker buildx imagetools create -t x y',
      'cosign sign --key k x',
      'cosign attest --key k x',
      'cosign upload blob x',
      "run('docker', ['push', ref])",
      "run('docker', ['login', '-u', u])",
      "runTool('helm', [\n 'push', chart])",
      "runTool('helm', ['registry', 'login', host])",
      "runTool('cosign', ['sign', ref])",
      "runTool('cosign', signImageArgs(k, ref, o))",
      'signBlobArgs(k, f, b, { offline: false })',
      'signBlobArgs(k, f, b, { offline: REKOR })',
      'signBlobArgs(k, f, b, { offline })',
      'signBlobArgs(k, f, b, { plainHttp: false, offline })',
      'gh release create v1 a.tgz',
      "run('gh', ['release', 'upload', tag, f])",
      'run(`gh`, [`release`, `create`])',
      'run(`docker`, [`push`, ref])',
      'npm publish --access public',
      'pnpm --filter @qualor/cli publish',
      'yarn publish',
      "run('npm', ['publish'])",
      'docker buildx build --output type=registry .',
      'docker buildx build -o type=image,push=true .',
      'skopeo copy docker://a docker://b',
      'crane push x.tar ref',
      'oras push ref f',
      "run('oras', ['push', ref])",
    ]) {
      expect(
        UPLOADS.some(([, p]) => p.test(sample)),
        sample,
      ).toBe(true);
    }
    for (const sample of [
      'cosign sign-blob --key k f',
      'cosign verify --key k x',
      'git push',
      "github.event_name == 'push'",
      'export function signImageArgs(key: string)',
      'signBlobArgs(k, f, b, { offline: true })',
      '  offline: boolean;',
      'pnpm release:publish',
      'pnpm install --frozen-lockfile',
      'a crane of paper',
    ]) {
      expect(
        UPLOADS.some(([, p]) => p.test(sample)),
        sample,
      ).toBe(false);
    }
  });
});
