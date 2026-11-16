import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { captureIO } from '../../test/io';
import { useTempDirs } from '../../test/tmp';
import type { UploadSbomFlags } from '../args';
import { CliError, EXIT } from '../errors';
import { createLogger } from '../log';
import { runUploadSbom } from './upload-sbom';

const tmp = useTempDirs();
const serve = useTestServers();
const TOKEN = 'qlr_prj_secret';

const answer = {
  version: { id: '0192a4c6-1c2e-7a3b-9f00-0000000000aa', label: '1.4.0', source: 'sbom' },
  format: 'CycloneDX 1.7',
  subject: 'acme/shop:1.4.0',
  distribution: { family: 'debian', version: '12.15' },
  packages: 10,
  osPackages: 8,
  skipped: { noPurl: 1, unsupportedType: 3, duplicate: 2 },
  warnings: [{ code: 'NO_DISTRO', message: 'something odd' }],
  monitoring: { enabled: true, recheckQueued: true },
};

async function run(
  flags: Partial<UploadSbomFlags>,
  env: Record<string, string>,
  files: Record<string, string> = {},
) {
  const dir = tmp();
  writeFileSync(path.join(dir, 'bom.json'), '{"bomFormat":"CycloneDX"}');
  for (const [name, text] of Object.entries(files)) writeFileSync(path.join(dir, name), text);
  const cap = captureIO({ cwd: dir, env });
  const log = createLogger('info', cap.io.stderr);
  let code: number;
  try {
    code = await runUploadSbom({ file: 'bom.json', ...flags }, cap.io, log);
  } catch (err) {
    // As main() does: a CliError is logged and its exit code returned.
    if (!(err instanceof CliError)) throw err;
    log.error(err.message);
    code = err.exitCode;
  }
  return { code, out: cap.stdout(), err: cap.stderr() };
}

describe('runUploadSbom', () => {
  it('prints what was stored on 201 and exits 0', async () => {
    const { url, requests } = await serve((_req, res) => json(res, 201, answer));
    const r = await run({ projectKey: 'acme/shop' }, { QUALOR_URL: url, QUALOR_TOKEN: TOKEN });
    expect(r.code).toBe(EXIT.OK);
    for (const s of [
      '1.4.0',
      'created',
      'CycloneDX 1.7',
      '10 packages',
      '8 operating-system',
      'debian 12.15',
      '1 without a package URL',
      '3 of an unsupported type',
      '2 duplicates',
      'NO_DISTRO',
      're-check',
    ]) {
      expect(r.out).toContain(s);
    }
    expect(requests).toHaveLength(1);
  });

  it('says replaced on 200 and strips control characters from the file-derived text', async () => {
    const { url } = await serve((_req, res) =>
      json(res, 200, {
        ...answer,
        subject: 'evil\u001b[31m-red',
        warnings: [{ code: 'W', message: 'bad\u001b]0;title\u0007msg' }],
        monitoring: { enabled: false, recheckQueued: false },
      }),
    );
    const r = await run({ projectKey: 'a/b' }, { QUALOR_URL: url, QUALOR_TOKEN: TOKEN });
    expect(r.code).toBe(0);
    expect(r.out).toContain('replaced');
    // eslint-disable-next-line no-control-regex
    expect(r.out).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f]/);
    expect(r.out).not.toContain('[31m');
    expect(r.out).not.toContain('title');
  });

  it('exits 4 on 409 with the problem title and detail, and 5 on 403', async () => {
    const s409 = await serve((_req, res) =>
      json(res, 409, {
        title: 'Label taken',
        detail: 'Use another label',
        code: 'VERSION_LABEL_TAKEN',
        status: 409,
      }),
    );
    const a = await run({ projectKey: 'a/b' }, { QUALOR_URL: s409.url, QUALOR_TOKEN: TOKEN });
    expect(a.code).toBe(4);
    expect(a.err).toContain('Use another label');
    const s403 = await serve((_req, res) => problem(res, 403, 'TOKEN_NOT_ALLOWED'));
    const b = await run({ projectKey: 'a/b' }, { QUALOR_URL: s403.url, QUALOR_TOKEN: TOKEN });
    expect(b.code).toBe(5);
  });

  it('exits 2 for a missing file', async () => {
    const { url } = await serve((_req, res) => json(res, 201, answer));
    const r = await run(
      { projectKey: 'a/b', file: 'nope.json' },
      { QUALOR_URL: url, QUALOR_TOKEN: TOKEN },
    );
    expect(r.code).toBe(2);
    expect(r.err).toContain('nope.json');
  });

  it('exits 2 when there is no project key, no server or no token', async () => {
    const { url } = await serve((_req, res) => json(res, 201, answer));
    expect((await run({}, { QUALOR_URL: url, QUALOR_TOKEN: TOKEN })).code).toBe(2);
    const noServer = await run({ projectKey: 'a/b' }, { QUALOR_TOKEN: TOKEN });
    expect(noServer.code).toBe(2);
    // upload-sbom has no --dry-run: the message does not offer it (t12m2).
    expect(noServer.err).toContain('a server URL');
    expect(noServer.err).not.toContain('--dry-run');
    expect((await run({ projectKey: 'a/b' }, { QUALOR_URL: url })).code).toBe(2);
  });

  it('exits 2 for a server URL that is only in qualor.yml (Q-B9) and sends nothing', async () => {
    const { url, requests } = await serve((_req, res) => json(res, 201, answer));
    const r = await run(
      { projectKey: 'a/b' },
      { QUALOR_TOKEN: TOKEN },
      { 'qualor.yml': `version: 1\nserver:\n  url: ${url}\n` },
    );
    expect(r.code).toBe(2);
    expect(requests).toHaveLength(0);
  });

  it('exits 4 for an unreachable server', async () => {
    const r = await run(
      { projectKey: 'a/b' },
      { QUALOR_URL: 'http://127.0.0.1:1', QUALOR_TOKEN: TOKEN },
    );
    expect(r.code).toBe(4);
    expect(r.err).not.toContain(TOKEN);
  });

  it('takes the project key from qualor.yml', async () => {
    const { url, requests } = await serve((_req, res) => json(res, 201, answer));
    const r = await run(
      {},
      { QUALOR_URL: url, QUALOR_TOKEN: TOKEN },
      { 'qualor.yml': 'version: 1\nproject:\n  key: from/yml\n' },
    );
    expect(r.code).toBe(0);
    expect(requests[0]?.url).toContain('projectKey=from%2Fyml');
  });
});
