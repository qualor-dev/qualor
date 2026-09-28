import { describe, expect, it } from 'vitest';
import { signTest, T0, testPayload, testSigner } from '../../test/license';
import type { PluginReport } from '../plugins/contract';
import { bootLicenseLog } from './boot-log';
import { DAY_MS, licenseState } from './state';

const KEY_HASH = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08';

const loaded: PluginReport = {
  name: 'qualor-enterprise',
  state: 'loaded',
  features: ['llm.fix-quota'],
  error: null,
};
const failed: PluginReport = {
  name: 'broken.js',
  state: 'failed',
  features: [],
  error: 'did not register within 10 s',
};

describe('bootLicenseLog (enterprise.md §6)', () => {
  it('states the edition and the loaded plugins; never the key, its hash, the customer or the licence id', () => {
    const license = testPayload();
    const key = signTest(testSigner(), license);
    const verification = { ok: true as const, kid: 'test-a', license };
    const line = bootLicenseLog(
      { source: 'environment', keyHash: KEY_HASH, verification },
      licenseState(verification, T0),
      [loaded],
    );
    expect(line.level).toBe('info');
    expect(line.message).toBe('running as the enterprise edition');
    expect(line.fields).toEqual({
      licence: 'active',
      edition: 'enterprise',
      source: 'environment',
      expires: license.expires,
      plugins: ['qualor-enterprise'],
    });
    const text = JSON.stringify(line);
    for (const secret of [...key.split('.').slice(1), KEY_HASH, license.id, license.customer]) {
      expect(text).not.toContain(secret);
    }
  });

  it('names failed plugins apart from the loaded ones', () => {
    const license = testPayload();
    const verification = { ok: true as const, kid: 'test-a', license };
    const line = bootLicenseLog(
      { source: 'uploaded', keyHash: KEY_HASH, verification },
      licenseState(verification, T0),
      [failed, loaded],
    );
    expect(line.fields).toMatchObject({
      plugins: ['qualor-enterprise'],
      failedPlugins: ['broken.js'],
    });
  });

  it('logs a rejected key as an error with its reason, as the community edition', () => {
    const verification = { ok: false as const, reason: 'malformed' as const };
    const line = bootLicenseLog(
      { source: 'file', keyHash: KEY_HASH, verification },
      licenseState(verification, T0),
      [],
    );
    expect(line).toEqual({
      level: 'error',
      message: 'licence key rejected',
      fields: {
        licence: 'invalid',
        edition: 'community',
        source: 'file',
        reason: 'malformed',
        plugins: [],
      },
    });
  });

  it('logs no licence as the community edition', () => {
    const line = bootLicenseLog(
      { source: null, keyHash: null, verification: null },
      licenseState(null, T0),
      [],
    );
    expect(line).toEqual({
      level: 'info',
      message: 'running as the community edition',
      fields: { licence: 'none', edition: 'community', source: null, plugins: [] },
    });
  });

  it('logs an expired licence as the community edition, without the customer', () => {
    const license = testPayload({ expires: '2026-10-02T00:00:00Z' });
    const verification = { ok: true as const, kid: 'test-a', license };
    const line = bootLicenseLog(
      { source: 'environment', keyHash: KEY_HASH, verification },
      licenseState(verification, new Date(T0.getTime() + 30 * DAY_MS)),
      [],
    );
    expect(line.level).toBe('info');
    expect(line.fields).toEqual({
      licence: 'expired',
      edition: 'community',
      source: 'environment',
      expires: license.expires,
      plugins: [],
    });
    expect(JSON.stringify(line)).not.toContain(license.customer);
  });
});
