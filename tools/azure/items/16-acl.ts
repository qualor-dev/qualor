import { z } from 'zod';
import type { AzureClient } from '../client.js';
import { CONNECTION_DATA_VERSION } from './01-identity.js';
import {
  answerOf,
  ConnectionDataSchema,
  ok,
  repoInfo,
  result,
  shape,
  type ProbeContext,
  type ProbeItem,
} from './common.js';

/** The Git Repositories security namespace and its Contribute bit. */
const GIT_NAMESPACE = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87';
const CONTRIBUTE = 4;

const AclSchema = z.object({
  value: z.array(
    z.object({
      token: z.string(),
      acesDictionary: z.record(
        z.string(),
        z.object({
          descriptor: z.string(),
          allow: z.number(),
          deny: z.number(),
          extendedInfo: z
            .object({ effectiveAllow: z.number().optional(), effectiveDeny: z.number().optional() })
            .loose()
            .optional(),
        }),
      ),
    }),
  ),
});

async function descriptorOf(client: AzureClient, who: string): Promise<string> {
  const res = ok(
    await client.request('GET', '/_apis/connectionData', undefined, {
      apiVersion: CONNECTION_DATA_VERSION,
    }),
    `connectionData (${who})`,
  );
  const d = shape(ConnectionDataSchema, res.json, `connectionData (${who})`).authenticatedUser
    .descriptor;
  if (!d) throw new Error(`${who} has no descriptor`);
  return d;
}

/**
 * Where an identity's Contribute comes from: its own entry (`explicit`), only its groups or
 * inheritance (`groups`: effectiveAllow has the bit, the entry's allow does not), or nowhere.
 * Only `groups` shows that the effective bit includes group memberships.
 */
export function contributeSource(
  allow: number,
  effectiveAllow: number,
): 'groups' | 'explicit' | 'none' {
  if ((effectiveAllow & CONTRIBUTE) === 0) return 'none';
  return (allow & CONTRIBUTE) !== 0 ? 'explicit' : 'groups';
}

export type ContributeSource = ReturnType<typeof contributeSource>;

/**
 * The item's answer. yes: another identity's effective Contribute is read, some identity's
 * Contribute is shown to come through groups (the second user's, or on services the integration
 * identity's own), and the reader lacks Contribute (or that half is skipped, services). partly:
 * effective Contribute is read but no group part is shown, or the reader half is missing. no else.
 */
export function aclAnswer(
  user: ContributeSource | undefined,
  reader: boolean | 'skipped' | undefined,
  integration?: ContributeSource,
): 'yes' | 'partly' | 'no' {
  const userRead = user === 'groups' || user === 'explicit';
  if (!userRead || reader === false) return 'no';
  const groupShown = user === 'groups' || integration === 'groups';
  return groupShown && (reader === true || reader === 'skipped') ? 'yes' : 'partly';
}

type Entry = { allow: number | undefined; effective: number | undefined; token: string };

/**
 * The entry's allow and effectiveAllow of `descriptor` on the repository's token (else the
 * project's), asked as bot.
 */
async function effectiveAllow(ctx: ProbeContext, descriptor: string, who: string): Promise<Entry> {
  const repo = await repoInfo(ctx);
  for (const [token, call] of [
    [`repoV2/${repo.project.id}/${repo.id}`, `acl-${who}`],
    [`repoV2/${repo.project.id}`, `acl-${who}-project`],
  ] as const) {
    const res = ok(
      await ctx.bot.request(
        'GET',
        `/_apis/accesscontrollists/${GIT_NAMESPACE}?token=${encodeURIComponent(token)}` +
          `&descriptors=${encodeURIComponent(descriptor)}&includeExtendedInfo=true`,
      ),
      `access control list (${who})`,
    );
    await ctx.record(call, answerOf(res));
    const acl = shape(AclSchema, res.json, `access control list (${who})`);
    const ace = acl.value
      .flatMap((a) => Object.values(a.acesDictionary))
      .find((e) => e.descriptor.toLowerCase() === descriptor.toLowerCase());
    if (ace?.extendedInfo?.effectiveAllow !== undefined) {
      return {
        allow: ace.allow,
        effective: ace.extendedInfo.effectiveAllow,
        token: token.split('/').length > 2 ? 'repository' : 'project',
      };
    }
  }
  return { allow: undefined, effective: undefined, token: 'none' };
}

const sourceOf = (e: Entry) =>
  e.effective === undefined ? undefined : contributeSource(e.allow ?? 0, e.effective);

function has(e: Entry): string {
  const source = sourceOf(e);
  if (source === undefined) return 'no entry';
  const bits = `allow ${String(e.allow)}, effectiveAllow ${e.effective}`;
  if (source === 'none') return `no Contribute (${bits})`;
  if (source === 'groups') return `Contribute through groups or inheritance only (${bits})`;
  return `Contribute, but in its own entry too (${bits}): the group part is not shown`;
}

export const item: ProbeItem = {
  id: 16,
  title:
    "the Git ACL with extended info shows another identity's effective Contribute (group included)",
  async run(ctx) {
    const user = await effectiveAllow(ctx, await descriptorOf(ctx.user, 'user'), 'user');
    const who =
      ctx.target === 'server'
        ? 'probe-user (Contributor through a group)'
        : "the second user (the maintainer's PAT)";
    const lines = [`${who}: ${has(user)} on the ${user.token} token`];
    const userSource = sourceOf(user);
    let readerOk: boolean | undefined;
    // The Services bench has no reader identity: that half is skipped, not failed.
    const readerSkipped = !ctx.reader && ctx.target === 'services';
    if (ctx.reader) {
      const reader = await effectiveAllow(ctx, await descriptorOf(ctx.reader, 'reader'), 'reader');
      readerOk = sourceOf(reader) === 'none';
      lines.push(`probe-reader (Reader): ${has(reader)} on the ${reader.token} token`);
    } else if (readerSkipped) {
      lines.push('reader: skipped (no reader identity on services)');
    } else {
      lines.push('probe-reader: no reader credential on this target');
    }
    // On services the second user's own entry allows Contribute; the service principal holds it
    // through its group only, the case the design relies on (a Contributor through a group).
    let integrationSource: ContributeSource | undefined;
    if (ctx.target === 'services') {
      const integration = await effectiveAllow(
        ctx,
        await descriptorOf(ctx.bot, 'integration'),
        'integration',
      );
      integrationSource = sourceOf(integration);
      lines.push(
        `the integration identity (the service principal): ${has(integration)} on the ${integration.token} token`,
      );
    }
    lines.push(
      `asked as the probe's main identity: GET _apis/accesscontrollists/${GIT_NAMESPACE} (7.0)`,
    );
    // yes only where an effective Contribute is shown to come through groups.
    const readerHalf = readerSkipped ? 'skipped' : readerOk;
    return result(ctx, aclAnswer(userSource, readerHalf, integrationSource), lines.join('\n\n'));
  },
};
