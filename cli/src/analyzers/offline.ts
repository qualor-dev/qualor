/**
 * A proxy nobody listens on: 127.0.0.1:9 (discard). Every HTTP(S) request of a tool that honours
 * the proxy variables fails there instead of leaving the machine.
 */
export const DEAD_PROXY_URL = 'http://127.0.0.1:9';

/**
 * Offline defence in depth for the non-JVM analyzers (the environment counterpart of ruling V5's
 * JVM properties). The CLI already never passes a registry id, a URL or a rule that loads other
 * rules, and the tools run with their metrics and version checks off; these variables catch
 * anything left: Semgrep (Python `requests`), OpenGrep and Gitleaks (Go) all honour them, and
 * their `git` subprocesses do too. `NO_PROXY` is emptied so no host (not even localhost) is
 * exempt. Python prefers the lower-case names and Go the upper-case ones, so POSIX gets both;
 * Windows names are case-insensitive, so it gets one spelling each. A DNS lookup can still
 * happen before the proxy is used, with some clients: this is not a network sandbox.
 */
export function deadProxyEnv(platform: NodeJS.Platform = process.platform): Record<string, string> {
  const upper = {
    HTTP_PROXY: DEAD_PROXY_URL,
    HTTPS_PROXY: DEAD_PROXY_URL,
    ALL_PROXY: DEAD_PROXY_URL,
    NO_PROXY: '',
  };
  if (platform === 'win32') return upper;
  return {
    ...upper,
    http_proxy: DEAD_PROXY_URL,
    https_proxy: DEAD_PROXY_URL,
    all_proxy: DEAD_PROXY_URL,
    no_proxy: '',
  };
}
