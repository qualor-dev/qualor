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
