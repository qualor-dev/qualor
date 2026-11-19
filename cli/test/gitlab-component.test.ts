import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';
import { parseCommandLine } from '../src/args';

/**
 * scm.md §10: `templates/qualor.yml` is a GitLab CI/CD component (the CI/CD catalog layout:
 * `templates/<name>.yml`, a `spec: inputs:` header, then the job). GitLab itself is not run here:
 * the opt-in real-GitLab check lints it with GitLab's own CI lint.
 */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const COMPONENT = path.join(ROOT, 'templates', 'qualor.yml');
const INTERPOLATION = /\$\[\[\s*inputs\.([a-z0-9_-]+)\s*\]\]/g;
/** The path the component will have once published to the CI/CD catalog (it is not yet). */
const FUTURE_PATH = 'gitlab.com/qualor/qualor/qualor@<version>';

interface Input {
  default?: unknown;
  type?: string;
  description?: string;
}

function load() {
  const text = readFileSync(COMPONENT, 'utf8');
  const docs = parseAllDocuments(text);
  expect(docs.map((d) => d.errors)).toEqual([[], []]);
  const [header, body] = docs.map((d) => d.toJS() as Record<string, unknown>);
  const inputs = (header?.['spec'] as { inputs: Record<string, Input> }).inputs;
  const bodyText = text.slice(text.indexOf('\n---\n') + 5);
  return { text, header: header ?? {}, inputs, body: body ?? {}, bodyText };
}

/** The job as GitLab would see it with `values` for the inputs. */
function interpolate(text: string, values: Record<string, string>): Record<string, unknown> {
  const resolved = text.replace(INTERPOLATION, (_, name: string) => {
    const value = values[name];
    if (value === undefined) throw new Error(`no value for input ${name}`);
    return value;
  });
  const [doc] = parseAllDocuments(resolved);
  return doc?.toJS() as Record<string, unknown>;
}

const DEFAULTS = {
  stage: 'test',
  image: 'qualor/scanner',
  'image-tag': '0.3.0',
  'job-name': 'qualor',
  args: '',
  'allow-failure': 'false',
  dotnet: 'false',
  'build-command': 'dotnet build --no-incremental',
  fix: 'false',
  'fix-image': '',
  'fix-args': '',
};

/** The first line of `script`, trimmed, that starts with `prefix` (the script is one multi-line
 * block scalar holding the dotnet/else shell branches, plan 2D ruling D8). */
function scriptLine(script: string, prefix: string): string {
  const line = script
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith(prefix));
  if (line === undefined) throw new Error(`no line starting with "${prefix}" in:\n${script}`);
  return line;
}

describe('the GitLab CI/CD component (scm.md §10)', () => {
  it('declares typed inputs, with only image-tag required, and uses exactly those', () => {
    const { header, inputs, bodyText } = load();
    // The header holds `spec` only (the catalog's component format).
    expect(Object.keys(header)).toEqual(['spec']);
    expect(Object.keys(inputs)).toEqual([
      'stage',
      'image',
      'image-tag',
      'job-name',
      'args',
      'allow-failure',
      'dotnet',
      'build-command',
      'fix',
      'fix-image',
      'fix-args',
    ]);
    expect(
      Object.entries(inputs)
        .filter(([, i]) => !('default' in i))
        .map(([n]) => n),
    ).toEqual(['image-tag']);
    expect(inputs['allow-failure']).toMatchObject({ type: 'boolean', default: false });
    expect(inputs['dotnet']).toMatchObject({ type: 'boolean', default: false });
    expect(inputs['build-command']).toMatchObject({
      type: 'string',
      default: 'dotnet build --no-incremental',
    });
    expect(inputs['fix']).toMatchObject({ type: 'boolean', default: false });
    expect(inputs['fix-image']).toMatchObject({ type: 'string', default: '' });
    expect(inputs['fix-args']).toMatchObject({ type: 'string', default: '' });
    expect(inputs).toMatchObject({
      stage: { type: 'string', default: 'test' },
      image: { type: 'string', default: 'qualor/scanner' },
      'image-tag': { type: 'string' },
      'job-name': { type: 'string', default: 'qualor' },
      args: { type: 'string', default: '' },
    });
    for (const input of Object.values(inputs)) {
      expect(input.description).toBeTruthy();
      // A default matches its declared type, as GitLab checks.
      if ('default' in input) expect(typeof input.default).toBe(input.type);
    }
    const used = new Set([...bodyText.matchAll(INTERPOLATION)].map((m) => m[1]));
    expect([...used].sort()).toEqual(Object.keys(inputs).sort());
  });

  it('takes no secret as an input: the token comes from a masked CI/CD variable', () => {
    const { text, inputs } = load();
    for (const name of Object.keys(inputs)) {
      expect(name).not.toMatch(/token|secret|password|credential|url/i);
    }
    expect(text).toMatch(/QUALOR_TOKEN \(masked, not protected\)/);
    expect(text).not.toMatch(/qlr_|masked and protected/);
  });

  it('runs the scanner image with its tag, full history, the three reports kept always', () => {
    const { bodyText } = load();
    const jobs = interpolate(bodyText, DEFAULTS);
    // The fix job pair is always declared; its first rule switches it off unless fix is true.
    expect(Object.keys(jobs)).toEqual(['qualor', 'qualor-fix-cli', 'qualor-fix']);
    const job = jobs['qualor'] as Record<string, unknown>;
    expect(job).toMatchObject({
      stage: 'test',
      image: { name: 'qualor/scanner:0.3.0', entrypoint: [''] },
      variables: {
        GIT_DEPTH: '0',
        QUALOR_TRIVY_CACHE_DIR: '$CI_PROJECT_DIR/.qualor/trivy',
      },
      // The scanner's vulnerability database archive, kept between pipelines (also on failure).
      cache: { key: 'qualor-trivy-db', paths: ['.qualor/trivy/'], when: 'always' },
      allow_failure: false,
      artifacts: {
        when: 'always',
        reports: {
          codequality: 'gl-code-quality-report.json',
          sast: 'gl-sast-report.json',
          dependency_scanning: 'gl-dependency-scanning-report.json',
        },
      },
      rules: [
        { if: '$CI_PIPELINE_SOURCE == "merge_request_event"' },
        { if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH' },
        { if: '$CI_COMMIT_TAG' },
      ],
    });
    // The instance's default expiry: a fixed one would drop the target branch's reports, which
    // the merge request comparison needs, after that long.
    expect(job['artifacts']).not.toHaveProperty('expire_in');
    // No secret in the component: the token and URL come from CI/CD variables.
    expect(JSON.stringify(job)).not.toMatch(/QUALOR_TOKEN|QUALOR_URL|qlr_/);
    // Another image and job name take effect.
    const other = interpolate(bodyText, {
      ...DEFAULTS,
      image: 'registry.acme.test/qualor/scanner',
      'job-name': 'quality',
      stage: 'verify',
    });
    expect(other['quality']).toMatchObject({
      stage: 'verify',
      image: { name: 'registry.acme.test/qualor/scanner:0.3.0' },
    });
  });

  it('also runs in tag pipelines, where the scan records a version (the UI panel shows this rule)', () => {
    const { text, bodyText } = load();
    // The rule exactly as Project → Settings → Vulnerability monitoring shows it.
    expect(bodyText).toContain('rules:\n    - if: $CI_PIPELINE_SOURCE');
    expect(bodyText).toMatch(/^ {4}- if: \$CI_COMMIT_TAG$/m);
    for (const dotnet of ['false', 'true']) {
      const job = interpolate(bodyText, { ...DEFAULTS, dotnet })['qualor'] as {
        rules: { if: string }[];
      };
      expect(job.rules).toContainEqual({ if: '$CI_COMMIT_TAG' });
    }
    // The header says what a tag pipeline does.
    expect(text).toMatch(/on[\s#]+tags/);
    expect(text).toMatch(/records[\s#]+a[\s#]+version/);
  });

  it('runs qualor dotnet begin, the build and end when dotnet is true (scm.md §10, ruling D8)', () => {
    const { inputs, bodyText } = load();
    expect(inputs['dotnet']).toMatchObject({ type: 'boolean', default: false });
    expect(inputs['build-command']).toMatchObject({
      type: 'string',
      default: 'dotnet build --no-incremental',
    });
    // The uninterpolated component: GitLab replaces $[[ inputs.x ]] before the script ever runs.
    expect(bodyText).toContain('qualor dotnet begin');
    expect(bodyText).toContain('$[[ inputs.build-command ]]');
    expect(bodyText).toMatch(
      /qualor dotnet end --gitlab-code-quality gl-code-quality-report\.json --gitlab-sast gl-sast-report\.json --gitlab-dependency-scanning gl-dependency-scanning-report\.json \$\[\[ inputs\.args \]\]/,
    );
    expect(bodyText).toMatch(/qualor scan --gitlab-code-quality/);
    // The resolved job with dotnet: true takes the dotnet branch, build-command between begin and end.
    const job = interpolate(bodyText, { ...DEFAULTS, dotnet: 'true' })['qualor'] as {
      script: string[];
    };
    expect(job.script).toHaveLength(1);
    const script = job.script[0]!;
    expect(script).toContain('if [ "true" = "true" ]; then');
    expect(scriptLine(script, 'qualor dotnet begin')).toBe('qualor dotnet begin');
    expect(scriptLine(script, 'dotnet build --no-incremental')).toBe(
      'dotnet build --no-incremental',
    );
    expect(script).toMatch(
      /qualor dotnet end --gitlab-code-quality gl-code-quality-report\.json --gitlab-sast gl-sast-report\.json --gitlab-dependency-scanning gl-dependency-scanning-report\.json/,
    );
    // A custom build-command takes effect too.
    const custom = interpolate(bodyText, {
      ...DEFAULTS,
      dotnet: 'true',
      'build-command': 'dotnet build --no-incremental -c Release',
    })['qualor'] as { script: string[] };
    expect(scriptLine(custom.script[0]!, 'dotnet build')).toBe(
      'dotnet build --no-incremental -c Release',
    );
  });

  it('cleans up with qualor dotnet abort in after_script when a dotnet build failed (scm.md §10)', () => {
    const { bodyText } = load();
    const dotnet = interpolate(bodyText, { ...DEFAULTS, dotnet: 'true' })['qualor'] as {
      after_script: string[];
    };
    // after_script runs even when the script failed; after a successful `end` the session
    // directory is gone, so the guard makes it do nothing.
    expect(dotnet.after_script).toHaveLength(1);
    const cleanup = dotnet.after_script[0]!;
    expect(cleanup).toContain('if [ "true" = "true" ] && [ -d .qualor/dotnet ]; then');
    const [program, ...argv] = scriptLine(cleanup, 'qualor dotnet abort').split(/\s+/);
    expect(program).toBe('qualor');
    expect(parseCommandLine(argv)).toEqual({ name: 'dotnet-abort' });
    // With dotnet: false the same YAML resolves to a guard that is never true: a no-op.
    const plain = interpolate(bodyText, DEFAULTS)['qualor'] as { after_script: string[] };
    expect(plain.after_script).toHaveLength(1);
    expect(plain.after_script[0]).toContain(
      'if [ "false" = "true" ] && [ -d .qualor/dotnet ]; then',
    );
    // No secret reaches the cleanup: abort never uploads.
    expect(cleanup).not.toMatch(/QUALOR_TOKEN|QUALOR_URL/);
  });

  it('passes arguments the CLI accepts, writing the files the artifacts name', () => {
    const { bodyText } = load();
    const job = interpolate(bodyText, {
      ...DEFAULTS,
      args: '--sarif osv.sarif',
      'allow-failure': 'true',
    })['qualor'] as {
      script: string[];
      allow_failure: boolean;
      artifacts: { reports: Record<string, string> };
    };
    expect(job.allow_failure).toBe(true);
    expect(job.script).toHaveLength(1);
    // dotnet defaults to false: the script's else branch runs plain `qualor scan`.
    const [program, ...argv] = scriptLine(job.script[0]!, 'qualor scan').split(/\s+/);
    expect(program).toBe('qualor');
    const command = parseCommandLine(argv);
    expect(command).toMatchObject({
      name: 'scan',
      flags: {
        gitlabCodeQuality: job.artifacts.reports['codequality'],
        gitlabSast: job.artifacts.reports['sast'],
        gitlabDependencyScanning: job.artifacts.reports['dependency_scanning'],
        sarif: ['osv.sarif'],
      },
    });
    // Relative names: the CLI writes them in the checkout (scm.md §9), where GitLab collects them.
    for (const file of Object.values(job.artifacts.reports)) {
      expect(path.isAbsolute(file)).toBe(false);
    }
  });

  it('says that SAST needs GitLab Ultimate and that paths are relative to the repository root', () => {
    const { text } = load();
    for (const doc of [text, readFileSync(path.join(ROOT, 'README.md'), 'utf8')]) {
      expect(doc).toMatch(/GitLab[\s#]+Ultimate[\s#]+only/);
      expect(doc).toMatch(/repository[\s#]+root/);
    }
  });

  it('documents the include with the catalog path', () => {
    const { text } = load();
    for (const doc of [text, readFileSync(path.join(ROOT, 'README.md'), 'utf8')]) {
      expect(doc).toContain(`component: ${FUTURE_PATH}`);
    }
  });

  describe('the optional fix job pair (0.16 fix MRs, §6.6)', () => {
    type Rule = { if: string; when?: string; variables?: Record<string, string> };
    type FixJob = {
      image: { name: string; entrypoint: string[] };
      variables?: Record<string, string>;
      needs?: string[];
      allow_failure?: boolean;
      script: string[];
      artifacts?: { paths: string[]; expire_in: string };
      rules: Rule[];
    };
    const jobs = (values: Record<string, string>) => {
      const all = interpolate(load().bodyText, { ...DEFAULTS, ...values });
      return { cli: all['qualor-fix-cli'] as FixJob, fix: all['qualor-fix'] as FixJob };
    };
    const ON = { fix: 'true' };

    it('declares fix, fix-image and fix-args, and the two jobs', () => {
      const { inputs, bodyText } = load();
      expect(inputs['fix']).toMatchObject({ type: 'boolean', default: false });
      expect(inputs['fix-image']).toMatchObject({ type: 'string', default: '' });
      expect(inputs['fix-args']).toMatchObject({ type: 'string', default: '' });
      expect(bodyText).toMatch(/^qualor-fix-cli:$/m);
      expect(bodyText).toMatch(/^qualor-fix:$/m);
    });

    it('qualor-fix-cli saves the binary of the scanner image for a day', () => {
      const { cli } = jobs({ ...ON, image: 'acme/scanner', 'image-tag': '0.16.0' });
      expect(cli.image).toEqual({ name: 'acme/scanner:0.16.0', entrypoint: [''] });
      expect(cli.script).toEqual(['cp /usr/local/bin/qualor qualor-bin']);
      expect(cli.artifacts).toEqual({ paths: ['qualor-bin'], expire_in: '1 day' });
    });

    it('qualor-fix needs the saved binary, may fail, and runs in the fix image', () => {
      const { fix } = jobs(ON);
      expect(fix.needs).toEqual(['qualor-fix-cli']);
      expect(fix.allow_failure).toBe(true);
      expect(fix.image).toEqual({ name: '$QUALOR_FIX_IMAGE', entrypoint: [''] });
      expect(fix.variables).toEqual({ QUALOR_FIX_IMAGE: '' });
      expect(jobs({ ...ON, 'fix-image': 'registry.acme.test/ci/node:22' }).fix.variables).toEqual({
        QUALOR_FIX_IMAGE: 'registry.acme.test/ci/node:22',
      });
    });

    it('is switched off with fix: false: the first rule of both jobs is when: never', () => {
      for (const job of Object.values(jobs({ fix: 'false' }))) {
        expect(job.rules[0]).toEqual({ if: '"false" != "true"', when: 'never' });
      }
      for (const job of Object.values(jobs(ON))) {
        expect(job.rules[0]).toEqual({ if: '"true" != "true"', when: 'never' });
      }
    });

    it('runs only on the default branch, schedules included', () => {
      const { cli, fix } = jobs(ON);
      expect(cli.rules[1]).toEqual({ if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH' });
      expect(fix.rules[2]).toEqual({ if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH' });
      for (const job of [cli, fix]) {
        expect(JSON.stringify(job.rules)).not.toMatch(/merge_request|CI_COMMIT_TAG|schedule/);
      }
    });

    it('with an empty fix-image, the second rule sets the scanner image and tag (R36)', () => {
      const { fix } = jobs({ ...ON, image: 'acme/scanner', 'image-tag': '0.16.0' });
      expect(fix.rules[1]).toEqual({
        if: '$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && "" == ""',
        variables: { QUALOR_FIX_IMAGE: 'acme/scanner:0.16.0' },
      });
      // With a fix-image, that rule cannot match and the job variable stays.
      const own = jobs({ ...ON, 'fix-image': 'node:22' }).fix;
      expect(own.rules[1]!.if).toBe('$CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH && "node:22" == ""');
    });

    it('checks for musl before it runs the binary, which takes the CLI-accepted fix-args', () => {
      const { fix } = jobs({ ...ON, 'fix-args': '--max 3 --timeout 1h' });
      expect(fix.script).toHaveLength(2);
      expect(fix.script[0]).toContain(
        'if [ -e /lib/ld-musl-x86_64.so.1 ] || [ -e /lib/ld-musl-aarch64.so.1 ]; then echo "qualor fix needs a glibc image (Debian, Ubuntu, RHEL); this image uses musl" >&2; exit 2; fi',
      );
      const line = fix.script[1]!;
      expect(line.startsWith('./qualor-bin fix')).toBe(true);
      const [, ...argv] = line.split(/\s+/);
      expect(parseCommandLine(argv)).toMatchObject({
        name: 'fix',
        flags: { max: 3, timeoutSeconds: 3600 },
      });
      // The default (empty) fix-args is accepted too.
      const [, ...plain] = jobs(ON).fix.script[1]!.trim().split(/\s+/);
      expect(parseCommandLine(plain)).toMatchObject({ name: 'fix' });
      expect(fix.script.join('\n')).not.toMatch(/QUALOR_TOKEN|QUALOR_URL|qlr_/);
    });
  });
});
