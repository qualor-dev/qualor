import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq } from 'drizzle-orm';
import { encryptionKey, encryptSecret } from '../src/crypto/secrets';
import type { Db } from '../src/db/client';
import { projects, scmConnections } from '../src/db/schema';
import { SCM_TOKEN_AAD, type ScmConnectionRow } from '../src/scm/connections';

/*
 * Azure DevOps sub-plan 2, Task 2: what the tests of the "not available yet" arms share until the
 * Azure DevOps client and its fake exist (Task 5) and connections are made through the API (Task
 * 6). Each such test points an Azure connection at a listener that records whatever reaches it,
 * and checks that nothing did.
 */

/** A repository id as Azure DevOps names one (a GUID); any will do for a stub. */
const AZURE_REPOSITORY = '0f6c1a5e-3b0d-4c39-9a51-fa6e00000001';

export interface RecordingListener {
  /** `http://127.0.0.1:<port>`: list `host` in `scmInternalHosts`, so a request would get through. */
  url: string;
  host: string;
  /** Every request that reached it, method and path. */
  requests: { method: string; url: string }[];
  close(): Promise<void>;
}

/** An HTTP listener on 127.0.0.1 that answers 500 to every request and records it. */
export async function recordingListener(): Promise<RecordingListener> {
  const requests: RecordingListener['requests'] = [];
  const server = createServer((req, res) => {
    requests.push({ method: req.method ?? '', url: req.url ?? '' });
    res.writeHead(500, { 'content-type': 'application/json' }).end('{}');
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    host: `127.0.0.1:${port}`,
    requests,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/**
 * An Azure DevOps Server connection with a PAT on `baseUrl`, inserted as migration 0034 allows it
 * (the API's Azure arm arrives in Task 6, ruling 2), with the switches set as given.
 */
export async function azureConnection(
  db: Db,
  input: {
    organizationId: string;
    baseUrl: string;
    secretKey: string;
    fixMrsAllowed?: boolean;
    ciSetupAllowed?: boolean;
  },
): Promise<ScmConnectionRow> {
  const [row] = await db
    .insert(scmConnections)
    .values({
      organizationId: input.organizationId,
      provider: 'azure',
      baseUrl: input.baseUrl,
      tokenEnc: encryptSecret(encryptionKey(input.secretKey), 'azure-pat-test', SCM_TOKEN_AAD),
      azureAuth: 'pat',
      fixMrsAllowed: input.fixMrsAllowed ?? false,
      ciSetupAllowed: input.ciSetupAllowed ?? false,
    })
    .returning();
  if (!row) throw new Error('no Azure DevOps connection inserted');
  return row;
}

/** Maps the project to the connection as stored, with `ref` (an Azure repository id). */
export async function mapToAzure(
  db: Db,
  projectId: string,
  connectionId: string,
  ref: string = AZURE_REPOSITORY,
): Promise<void> {
  await db
    .update(projects)
    .set({ scmConnectionId: connectionId, scmProjectRef: ref })
    .where(eq(projects.id, projectId));
}
