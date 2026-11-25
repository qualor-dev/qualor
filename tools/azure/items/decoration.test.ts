import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { buildRedactionTable } from './common.js';
import {
  benchDotnetDockerYaml,
  benchProject,
  benchScmUrl,
  benchDotnetTaskYaml,
  benchUploadYaml,
  forbiddenIn,
  markerKind,
  qualorIdentityName,
  statusPolicySettings,
  threadStatusName,
} from './19-decoration.js';

const example = (file: string): string =>
  readFileSync(
    fileURLToPath(new URL(`../../../integrations/azure-devops/${file}`, import.meta.url)),
    'utf8',
  );

describe('item 19 pipelines', () => {
  it('the main flow uploads: the bench image, no dry run, no scm step', () => {
    const yaml = benchUploadYaml(example('qualor-docker.yml'));
    expect(yaml).toContain('QUALOR_SCANNER_IMAGE: qualor/scanner:azure-dev');
    expect(yaml).toContain('trigger: none');
    expect(yaml).toContain('name: Default');
    expect(yaml).not.toContain('--dry-run');
    expect(yaml).not.toContain('QUALOR_SCM');
    expect(yaml).toContain('-e QUALOR_URL -e QUALOR_TOKEN');
  });

  it('the .NET docker form dry-runs at end only, on the dotnet image', () => {
    const yaml = benchDotnetDockerYaml(example('qualor-dotnet-docker.yml'));
    expect(yaml).toContain('QUALOR_SCANNER_IMAGE: qualor/scanner-dotnet:azure-dev');
    expect(yaml.match(/--dry-run/g)).toHaveLength(1);
    expect(yaml).toMatch(/dotnet end --dry-run --output \/src\/\.qualor\/report\.json/);
    expect(yaml).toContain('QUALOR_SCM=');
  });

  it('the .NET task form keeps dotnet: true and gets the tag and the dry run once', () => {
    const yaml = benchDotnetTaskYaml(example('qualor-dotnet.yml'));
    expect(yaml).toContain('imageTag: azure-dev');
    expect(yaml).toContain('dotnet: true');
    expect(yaml.match(/arguments:/g)).toHaveLength(1);
    expect(yaml.match(/inputs:/g)).toHaveLength(1);
  });
});

describe('item 19 Status check policy', () => {
  const scope = {
    repositoryId: '4427c1df-aedf-4e1f-8447-fa6e0000ecd2',
    refName: 'refs/heads/probe/19-x-target',
  };
  const sp = '7c429e0c-e3c7-43e0-8633-fa6e0000136d';

  it('checks qualor/<project key> as the guide says: genre qualor, the key as the name', () => {
    const settings = statusPolicySettings({ projectKey: 'bench', authorId: sp, ...scope }, 'x');
    expect(settings).toMatchObject({ statusGenre: 'qualor', statusName: 'bench' });
    expect(`${settings.statusGenre}/${settings.statusName}`).toBe('qualor/bench');
  });

  it("accepts only the service principal's statuses (the guide's Authorized identity)", () => {
    const settings = statusPolicySettings({ projectKey: 'bench', authorId: sp, ...scope }, 'x');
    expect(settings).toMatchObject({
      authorId: sp,
      invalidateOnSourceUpdate: true,
      policyApplicability: null,
      defaultDisplayName: 'x',
      scope: [{ ...scope, matchKind: 'exact' }],
    });
  });

  it('refuses a key whose status name the server would change', () => {
    for (const key of ['a b', 'k'.repeat(256), '']) {
      expect(() => statusPolicySettings({ projectKey: key, authorId: sp, ...scope }, 'x')).toThrow(
        /AZURE_PROBE_QUALOR_PROJECT_KEY/,
      );
    }
  });
});

describe('item 19 readers', () => {
  const id = '0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0';
  it('reads Qualor markers from the first line only', () => {
    expect(markerKind(`<!-- qualor:summary ${id} -->\nbody`)).toBe('summary');
    expect(markerKind(`<!-- qualor:issue ${id} -->`)).toBe('issue');
    expect(markerKind(`<!-- qualor:fixed ${id} ${'a'.repeat(40)} -->\nFixed`)).toBe('fixed');
    expect(markerKind(`text\n<!-- qualor:issue ${id} -->`)).toBeNull();
    expect(markerKind(undefined)).toBeNull();
  });

  it('names thread statuses, numeric or not', () => {
    expect(threadStatusName(4)).toBe('closed');
    expect(threadStatusName('fixed')).toBe('fixed');
    expect(threadStatusName(undefined)).toBe('none');
  });

  it('flags what no recording may hold', () => {
    expect(forbiddenIn('clean text', 'acme')).toEqual([]);
    const header = `Authorization: Basic ${Buffer.from('qualor:0123456789abcdef').toString('base64')}`;
    expect(forbiddenIn(`X-Amz-Signature ${header} in ACME`, 'acme')).toEqual([
      'X-Amz-',
      'a Basic or Bearer credential',
      'the organisation name',
    ]);
    expect(forbiddenIn('Bearer abcdefghijklmnopqrstuvwxyz0123456789', undefined)).toEqual([
      'a Basic or Bearer credential',
    ]);
  });

  it('lets prose through that only says Basic or Bearer', () => {
    expect(
      forbiddenIn('Basic input validation is missing; the Bearer token is checked.', 'acme'),
    ).toEqual([]);
  });

  it("flags the model key's first 8 characters without naming them", () => {
    expect(forbiddenIn('a sk-ant-a1b2 b', undefined, 'sk-ant-a')).toEqual(['the model key']);
    expect(forbiddenIn('nothing here', undefined, 'sk-ant-a')).toEqual([]);
    expect(forbiddenIn('sk-ant', undefined, 'short')).toEqual([]);
  });

  it('redacts the bench Qualor host and token', () => {
    const table = buildRedactionTable({
      AZURE_PROBE_QUALOR_URL: 'https://qualor.16.192.106.23.sslip.io',
      AZURE_PROBE_QUALOR_TOKEN: 'qlr_secret_value_123456',
    });
    expect(table.hosts).toContain('qualor.16.192.106.23.sslip.io');
    expect(table.secrets).toContain('qlr_secret_value_123456');
  });
});

describe('the bench Qualor per target', () => {
  it('Services keeps its projects and token keys', () => {
    expect(benchProject('services', 'main', {})).toEqual({
      key: 'bench',
      tokenEnv: 'AZURE_PROBE_QUALOR_TOKEN',
    });
    expect(benchProject('services', 'fix', {})).toEqual({
      key: 'bench-fix',
      tokenEnv: 'AZURE_PROBE_QUALOR_FIX_TOKEN',
    });
    expect(benchProject('services', 'boards', {})).toEqual({
      key: 'bench-boards',
      tokenEnv: 'AZURE_PROBE_QUALOR_BOARDS_TOKEN',
    });
    expect(
      benchProject('services', 'fix', { AZURE_PROBE_QUALOR_FIX_PROJECT_KEY: 'other-fix' }).key,
    ).toBe('other-fix');
  });

  it('Server has projects and token keys of its own', () => {
    expect(benchProject('server', 'main', {})).toEqual({
      key: 'bench-server',
      tokenEnv: 'AZURE_PROBE_SERVER_QUALOR_TOKEN',
    });
    expect(benchProject('server', 'fix', {})).toEqual({
      key: 'bench-server-fix',
      tokenEnv: 'AZURE_PROBE_SERVER_QUALOR_FIX_TOKEN',
    });
    expect(benchProject('server', 'boards', {})).toEqual({
      key: 'bench-server-boards',
      tokenEnv: 'AZURE_PROBE_SERVER_QUALOR_BOARDS_TOKEN',
    });
    // A Services key in the environment never names a Server project.
    expect(benchProject('server', 'main', { AZURE_PROBE_QUALOR_PROJECT_KEY: 'bench' }).key).toBe(
      'bench-server',
    );
  });

  it("the Server tokens are redacted, the projects' keys are not", () => {
    const table = buildRedactionTable({
      AZURE_PROBE_SERVER_QUALOR_TOKEN: 'qlr_server_secret_123456',
      AZURE_PROBE_SERVER_QUALOR_PROJECT_KEY: 'bench-server',
    });
    expect(table.secrets).toContain('qlr_server_secret_123456');
    expect(table.secrets).not.toContain('bench-server');
  });

  it("the connection's address of each target, without a trailing slash", () => {
    const env = {
      AZURE_PROBE_SERVICES_URL: 'https://dev.azure.com/acme/',
      AZURE_PROBE_SERVER_URL: 'https://ado.example.invalid/DefaultCollection/',
    };
    expect(benchScmUrl('services', env)).toBe('https://dev.azure.com/acme');
    expect(benchScmUrl('server', env)).toBe('https://ado.example.invalid/DefaultCollection');
    expect(() => benchScmUrl('server', {})).toThrow(/AZURE_PROBE_SERVER_URL/);
  });

  it("names Qualor's identity per target", () => {
    expect(qualorIdentityName('services')).toBe('the service principal');
    expect(qualorIdentityName('server')).toBe("Qualor's PAT identity");
  });
});
