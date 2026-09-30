import path from 'node:path';
import { executable, isInside } from './binary';
import type { AnalyzerContext } from './types';

/**
 * Ruling V5: system properties every JVM analyzer (PMD, SpotBugs) gets, as defence in depth for
 * the offline guarantee. A repository ruleset's XPath (`doc()`, `doc-available()`,
 * `unparsed-text()`) or a classpath entry could otherwise open a URL; every HTTP, HTTPS and SOCKS
 * connection now goes to a proxy on 127.0.0.1:9 (discard, nothing listens), and the empty
 * `http.nonProxyHosts` removes the default exemption of localhost. They must come after any
 * CI-supplied `-D` of the same name: for a duplicate `-D` the last one wins.
 */
export const DEAD_PROXY_PROPERTIES: readonly string[] = [
  '-Dhttp.proxyHost=127.0.0.1',
  '-Dhttp.proxyPort=9',
  '-Dhttps.proxyHost=127.0.0.1',
  '-Dhttps.proxyPort=9',
  '-DsocksProxyHost=127.0.0.1',
  '-DsocksProxyPort=9',
  '-Dhttp.nonProxyHosts=',
];

/**
 * The `java` SpotBugs and detekt run on: `$JAVA_HOME/bin/java` when `JAVA_HOME` is absolute and
 * lies outside the repository (as the SpotBugs and PMD launchers would pick it), else the `java`
 * from `PATH` or the scanner image (ruling V3). A `JAVA_HOME` inside the checkout is never used.
 */
export function javaBinary(
  ctx: Pick<AnalyzerContext, 'env' | 'root' | 'resolveBinary'>,
): string | null {
  const key = Object.keys(ctx.env).find((k) =>
    process.platform === 'win32' ? k.toUpperCase() === 'JAVA_HOME' : k === 'JAVA_HOME',
  );
  const home = key === undefined ? undefined : ctx.env[key];
  if (home !== undefined && path.isAbsolute(home)) {
    const java = path.join(home, 'bin', process.platform === 'win32' ? 'java.exe' : 'java');
    if (executable(java) && !isInside(ctx.root, java)) return java;
  }
  return ctx.resolveBinary('java');
}
