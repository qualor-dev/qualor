import { describe, expect, it } from 'vitest';
import { isCredentialsFile, isSecretRule, llmIneligibility } from './eligibility';

const rule = { engineId: 'eslint', cwe: [] as number[], tags: [] as string[] };
const issue = { status: 'open', path: 'src/a.ts', startLine: 2, hasSnippet: true };

describe('eligibility (llm.md §5.2)', () => {
  it('knows secret rules', () => {
    expect(isSecretRule({ ...rule, engineId: 'gitleaks' })).toBe(true);
    expect(isSecretRule({ ...rule, cwe: [798] })).toBe(true);
    expect(isSecretRule({ ...rule, tags: ['Secret'] })).toBe(true);
    expect(isSecretRule({ ...rule, cwe: [79] })).toBe(false);
  });

  it('knows secret rules by the tag secrets and by the engine in any case', () => {
    expect(isSecretRule({ ...rule, tags: ['secrets'] })).toBe(true);
    expect(isSecretRule({ ...rule, tags: ['Secrets'] })).toBe(true);
    expect(isSecretRule({ ...rule, engineId: 'Gitleaks' })).toBe(true);
    expect(isSecretRule({ ...rule, tags: ['secretary', 'security'] })).toBe(false);
  });

  it.each([
    '.env',
    'app/.env.production',
    'certs/server.pem',
    'keys/id_rsa',
    'x/id_ed25519.pub',
    '.npmrc',
    'deploy/prod.tfvars',
    'infra/terraform.tfstate',
    'config/credentials.json',
    'A/B/.ENV',
    '.git-credentials',
    // spec §5.2 names id_rsa*, credentials* and *.tfstate: any suffix, not only a dot one
    'keys/id_rsa_old',
    'keys/id_ecdsa-backup',
    'secrets/credentials_prod.json',
    'infra/terraform.tfstate.backup',
    'x/cert.P12',
    'x/app.keystore',
    '.pypirc',
    'home/.netrc',
    // Fail closed: no source-extension exemption for the spec's prefixes (review 1-3, L3).
    '.env.ts',
    'app/.env.js',
    'config/credentials.js',
    'src/Credentials.java',
    'docs/credentials.md.txt.ts',
    'keys/id_rsa.ts',
    // More credential stores, and backups of key files.
    'x/y.env',
    'x/.envrc',
    'x/.env-prod',
    'x/key.ppk',
    'x/.pgpass',
    'x/.htpasswd',
    'x/kubeconfig',
    'x/prod.kubeconfig',
    'home/.kube/config',
    'home/.docker/config.json',
    'x/.dockercfg',
    'deploy/secrets.yml',
    'deploy/Secrets.YAML',
    'keys/server.key.bak',
    'keys/server.pem.old',
    'x/prod.auto.tfvars.json',
    'a/.aws/credentials',
    // A trailing space or an invisible character does not hide the name.
    '.env ',
    'x/.env\u200b',
    'x/cred.p12 ',
    // Any format character (\p{Cf}), not only a listed few: bidi isolates, the Arabic letter
    // mark, tag characters; and variation selectors.
    'x/.e\u2066nv\u2069',
    'x/id\u061c_rsa',
    'x/.env\u{e0001}',
    'x/server.k\ufe0fey',
  ])('knows the credentials file %s', (path) => {
    expect(isCredentialsFile(path)).toBe(true);
  });

  it.each([
    'src/env.ts',
    'src/key.ts',
    'src/environment.ts',
    'src/keyboard.ts',
    'src/secrets.ts',
    'config/docker/config.json',
    'src/kube/config.ts',
    'docs/pem.md',
  ])('lets %s through', (path) => {
    expect(isCredentialsFile(path)).toBe(false);
  });

  it('decides per feature', () => {
    expect(llmIneligibility('explain', issue, rule)).toBeNull();
    expect(llmIneligibility('explain', { ...issue, status: 'closed' }, rule)).toBeNull();
    expect(llmIneligibility('triage', { ...issue, status: 'wont_fix' }, rule)).toBe('not_open');
    expect(llmIneligibility('fix', { ...issue, hasSnippet: false }, rule)).toBe('no_snippet');
    expect(llmIneligibility('fix', { ...issue, startLine: null }, rule)).toBe('no_location');
    expect(llmIneligibility('explain', issue, { ...rule, engineId: 'gitleaks' })).toBe(
      'secret_rule',
    );
    expect(llmIneligibility('explain', { ...issue, path: '.env' }, rule)).toBe('credentials_file');
  });
});
