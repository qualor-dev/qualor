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
    expect(Object.keys(jobs)).toEqual(['qualor']);
    const job = jobs['qualor'] as Record<string, unknown>;
    expect(job).toMatchObject({
      stage: 'test',
      image: { name: 'qualor/scanner:0.3.0', entrypoint: [''] },
      variables: { GIT_DEPTH: '0' },
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
});
