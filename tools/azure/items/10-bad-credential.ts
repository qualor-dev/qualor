import { randomInt, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AzureClient, AzureProbeError, rawRequest, type RawResponse } from '../client.js';
import type { RedactionTable } from '../record.js';
import { answerOf, excerpt, result, shape, type ProbeContext, type ProbeItem } from './common.js';

/** Azure DevOps's error body (WrappedException); `$id` is reported, not required. */
const WrappedException = z.object({
  message: z.string(),
  typeName: z.string(),
  typeKey: z.string(),
  errorCode: z.number(),
  eventId: z.number(),
});

/** A credential that has the form of a classic PAT (52 base32 characters) and is nobody's. */
function wrongPat(): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  return Array.from({ length: 52 }, () => alphabet[randomInt(alphabet.length)]).join('');
}

/** What a client can tell from an answer: a failure it sees, or something that looks like success. */
function verdict(raw: RawResponse): { seen: boolean; text: string } {
  const contentType = raw.headers['content-type'];
  const body = raw.text.length ? `${raw.text.length}-byte body` : 'empty body';
  const type = `${contentType ?? 'no content type'}, ${body}`;
  const html = /text\/html/i.test(contentType ?? '');
  const twoXx = raw.status >= 200 && raw.status < 300;
  if (twoXx && html) return { seen: true, text: `HTTP ${raw.status} ${type} (a 2xx HTML page)` };
  if (twoXx) return { seen: false, text: `HTTP ${raw.status} ${type} (looks like success)` };
  return { seen: true, text: `HTTP ${raw.status} ${type}` };
}

const recorded = (raw: RawResponse, table: RedactionTable) => ({
  status: raw.status,
  contentType: raw.headers['content-type'] ?? null,
  wwwAuthenticate: raw.headers['www-authenticate'] ?? null,
  location: raw.headers['location'] ?? null,
  tfsServiceError: raw.headers['x-tfs-serviceerror'] ?? null,
  first200: excerpt(raw.text, table),
});

export const item: ProbeItem = {
  id: 10,
  title: 'a bad credential gets an answer a client recognises (401, or a 2xx HTML page)',
  async run(ctx: ProbeContext) {
    const path = '/_apis/projects?$top=1&api-version=7.0';
    const url = new URL(ctx.baseUrl.replace(/\/+$/, '') + path);
    const wrong = wrongPat();
    ctx.redaction.secrets.push(wrong, Buffer.from(`:${wrong}`).toString('base64'));
    const opts = ctx.caPem ? { caPem: ctx.caPem } : {};
    const accept = { accept: 'application/json' };

    const withWrong = await rawRequest(
      'GET',
      url,
      { ...accept, authorization: `Basic ${Buffer.from(`:${wrong}`).toString('base64')}` },
      undefined,
      opts,
    );
    await ctx.record('wrong-pat', recorded(withWrong, ctx.redaction));
    const without = await rawRequest('GET', url, accept, undefined, opts);
    await ctx.record('no-credential', recorded(without, ctx.redaction));

    // What the probe's own client makes of the wrong PAT.
    let clientSees: string;
    try {
      const res = await new AzureClient(ctx.baseUrl, { kind: 'pat', pat: wrong }, opts).request(
        'GET',
        '/_apis/projects?$top=1',
      );
      clientSees = `status ${res.status}`;
    } catch (err) {
      clientSees = err instanceof AzureProbeError ? err.code : (err as Error).message;
    }
    await ctx.record('client-wrong-pat', { outcome: clientSees });

    // The error body of a valid credential asking for something that does not exist.
    const missing = await ctx.bot.request('GET', `/_apis/git/repositories/${randomUUID()}`);
    await ctx.record('not-found', answerOf(missing));
    const body = shape(WrappedException, missing.json, `error body (HTTP ${missing.status})`);
    const hasId = typeof (missing.json as Record<string, unknown>)['$id'] === 'string';

    const a = verdict(withWrong);
    const b = verdict(without);
    const detail = [
      `wrong PAT: ${a.text}; the probe's client sees ${clientSees}`,
      `no credential: ${b.text}`,
      `error body (HTTP ${missing.status}, ${missing.headers['content-type'] ?? 'none'}): ` +
        `WrappedException with typeKey ${body.typeKey}, errorCode ${body.errorCode}, ` +
        `eventId ${body.eventId}, $id ${hasId ? 'present' : 'absent'}`,
    ].join('\n\n');
    const errorStatus = missing.status >= 400 && missing.status < 500;
    return result(ctx, a.seen && b.seen && errorStatus ? 'yes' : 'no', detail);
  },
};
