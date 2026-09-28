import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { useTempDirs, writeTree } from '../../test/tmp';
import { silentLogger } from '../log';
import { redactUrl, renderSettings } from './render';
import { loadSettings } from './settings';

const tmp = useTempDirs();

describe('renderSettings', () => {
  it('prints every default and redacts the token and URL credentials', () => {
    const settings = loadSettings({
      cwd: tmp(),
      env: {
        QUALOR_URL: 'https://ci:hunter2@qualor.acme.test/base?private_token=abc',
        QUALOR_TOKEN: 'qlr_pat_supersecret',
      },
      flags: {},
      log: silentLogger,
    });
    const text = renderSettings(settings);
    expect(text).not.toContain('qlr_pat_supersecret');
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain('private_token=abc');
    const doc = parse(text) as {
      server: { url: string; token: string };
      analyzers: { pmd: { timeoutSeconds: number } };
      gate: { wait: boolean };
    };
    expect(doc.server.token).toBe('«redacted»');
    expect(doc.server.url).toBe('https://«redacted»@qualor.acme.test/base?«redacted»');
    expect(doc.analyzers.pmd.timeoutSeconds).toBe(900);
    expect(doc.gate.wait).toBe(true);
  });

  it('leaves a plain URL alone', () => {
    expect(redactUrl('https://qualor.acme.test')).toBe('https://qualor.acme.test');
  });

  it('redacts the token value wherever it appears in the document, not just server.token', () => {
    const root = tmp();
    // A literal (not `${VAR}`-interpolated) value that happens to equal the token: this is
    // the case `denySecretRefs` (settings.ts) cannot catch, since there is no reference to
    // deny, so only this value-based pass in `renderSettings` defends against it.
    writeTree(root, {
      'qualor.yml': 'version: 1\nproject:\n  version: qlr_pat_leaked_elsewhere\n',
    });
    const settings = loadSettings({
      cwd: root,
      env: { QUALOR_TOKEN: 'qlr_pat_leaked_elsewhere' },
      flags: {},
      log: silentLogger,
    });
    const text = renderSettings(settings);
    expect(text).not.toContain('qlr_pat_leaked_elsewhere');
    expect(text).toContain('project:');
  });
});
