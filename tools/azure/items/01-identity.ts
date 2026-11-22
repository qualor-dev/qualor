import type { AzureClient } from '../client.js';
import {
  addIdentity,
  answerOf,
  ConnectionDataSchema,
  InterruptedError,
  nameKind,
  ok,
  result,
  shape,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** connectionData is a preview route on Server (7.0 answers VssInvalidPreviewVersionException). */
export const CONNECTION_DATA_VERSION = '7.0-preview';

/** The kind of identity a descriptor names (its prefix), never the identity itself. */
const descriptorKind = (d: string | undefined): string => (d ? (d.split(';')[0] ?? '') : 'absent');

/** connectionData with `client`, recorded as `1-connectiondata-<kind>`; one line on who it is. */
export async function whoAmI(
  ctx: ProbeContext,
  client: AzureClient,
  kind: string,
  record = true,
): Promise<string> {
  const res = ok(
    await client.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: CONNECTION_DATA_VERSION,
    }),
    `connectionData (${kind})`,
  );
  const data = shape(ConnectionDataSchema, res.json, `connectionData (${kind})`);
  // An Entra identity is new to the table: its names are redacted before anything is written.
  addIdentity(ctx.redaction, data.authenticatedUser);
  if (data.authorizedUser) addIdentity(ctx.redaction, data.authorizedUser);
  if (record) await ctx.record(`connectiondata-${kind}`, answerOf(res));
  const u = data.authenticatedUser;
  const descriptor = descriptorKind(u.descriptor);
  if (/anonymous|unauthenticated/i.test(descriptor) || !u.providerDisplayName) {
    throw new Error(`${kind}: connectionData answered for no identity (${descriptor})`);
  }
  return (
    `${kind}: authenticatedUser ${u.id}, descriptor kind ${descriptor}, ` +
    `providerDisplayName is ${nameKind(u.providerDisplayName)}, ` +
    `properties.Account is ${nameKind(u.properties?.Account?.$value)}, ` +
    `deploymentType ${data.deploymentType ?? 'absent'}`
  );
}

export const item: ProbeItem = {
  id: 1,
  title: 'connectionData names the identity of each credential kind',
  async run(ctx) {
    // The PAT kind with the PAT itself: with `--auth secret` the main identity is Entra's.
    const lines = [await whoAmI(ctx, ctx.pat, 'pat')];
    let failed = 0;
    if (!ctx.entra) {
      lines.push(
        'secret: skipped (server has no Entra)',
        'certificate: skipped (server has no Entra)',
      );
    } else {
      for (const kind of ['secret', 'certificate'] as const) {
        try {
          lines.push(await whoAmI(ctx, ctx.entra(kind), kind));
        } catch (err) {
          if (err instanceof InterruptedError) throw err;
          failed++;
          lines.push(`${kind}: failed: ${(err as Error).message}`);
        }
      }
    }
    lines.push(`connectionData api-version ${CONNECTION_DATA_VERSION} (preview route).`);
    return result(ctx, failed === 0 ? 'yes' : 'partly', lines.join('\n\n'));
  },
};
