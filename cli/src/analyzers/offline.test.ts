import { describe, expect, it } from 'vitest';
import { DEAD_PROXY_URL, deadProxyEnv } from './offline';

describe('deadProxyEnv', () => {
  it('sends every proxied HTTP(S) request to 127.0.0.1:9 and exempts no host', () => {
    expect(DEAD_PROXY_URL).toBe('http://127.0.0.1:9');
    expect(deadProxyEnv('linux')).toEqual({
      HTTP_PROXY: DEAD_PROXY_URL,
      HTTPS_PROXY: DEAD_PROXY_URL,
      ALL_PROXY: DEAD_PROXY_URL,
      NO_PROXY: '',
      http_proxy: DEAD_PROXY_URL,
      https_proxy: DEAD_PROXY_URL,
      all_proxy: DEAD_PROXY_URL,
      no_proxy: '',
    });
    // Windows names are case-insensitive: one spelling each.
    expect(deadProxyEnv('win32')).toEqual({
      HTTP_PROXY: DEAD_PROXY_URL,
      HTTPS_PROXY: DEAD_PROXY_URL,
      ALL_PROXY: DEAD_PROXY_URL,
      NO_PROXY: '',
    });
  });
});
