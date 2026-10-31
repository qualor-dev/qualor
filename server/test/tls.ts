import tls from 'node:tls';
import { TEST_CA_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from '../../cli/test/tls';

/**
 * The test CA and the server certificate it signed for 127.0.0.1 and localhost (cli/test/tls.ts),
 * for an https test server.
 */
export { TEST_CA_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM };

/**
 * Makes this process's TLS clients trust the test CA too (for code that takes no `ca` option, such
 * as http/outbound.ts), and answers the function that puts the previous trust back: call it in
 * `afterAll`.
 */
export function trustTestCa(): () => void {
  const before = tls.getCACertificates('default');
  tls.setDefaultCACertificates([...before, TEST_CA_PEM]);
  return () => tls.setDefaultCACertificates(before);
}
