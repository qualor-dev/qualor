import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';

const tmp = useTempDirs();
const SETTINGS = pathToFileURL(path.join(import.meta.dirname, 'settings.ts')).href;

/** What the child reports: the loaded token or the error, and whether descriptor 3 is still open. */
const CHILD = `import { fstatSync } from 'node:fs';
import { loadSettings } from ${JSON.stringify(SETTINGS)};
const silent = { error() {}, warn() {}, info() {}, debug() {} };
const out = {};
try {
  out.token = loadSettings({ cwd: process.cwd(), env: process.env, flags: {}, log: silent }).token;
} catch (err) {
  out.exitCode = err.exitCode;
  out.message = err.message;
}
try {
  fstatSync(3);
  out.fdOpen = true;
} catch {
  out.fdOpen = false;
}
process.stdout.write(JSON.stringify(out));
`;

/** Runs `loadSettings` in a child node process whose descriptor 3 is a pipe holding `content`. */
function viaPipe(content: string, env: Record<string, string>): Promise<Record<string, unknown>> {
  const script = path.join(tmp(), 'child.mts');
  writeFileSync(script, CHILD);
  const proc = spawn(process.execPath, ['--import', 'tsx', script], {
    cwd: path.join(import.meta.dirname, '..', '..'),
    env: { PATH: process.env['PATH'] ?? '', ...env },
    stdio: ['ignore', 'pipe', 'inherit', 'pipe'],
  });
  let stdout = '';
  proc.stdout?.on('data', (chunk: Buffer) => (stdout += chunk.toString('utf8')));
  const pipe = proc.stdio[3] as NodeJS.WritableStream;
  pipe.on('error', () => undefined); // the child closes its end once it has read the token
  pipe.end(content);
  return new Promise((resolve) =>
    proc.on('close', () => resolve(JSON.parse(stdout) as Record<string, unknown>)),
  );
}

// Node hands a child extra descriptors on POSIX only; the Linux container run covers the rest.
describe.runIf(process.platform !== 'win32')('QUALOR_TOKEN_FD on a real pipe', () => {
  it('reads the token, ignores QUALOR_TOKEN and closes the descriptor', async () => {
    const seen = await viaPipe('qlr_prj_frompipe\n', {
      QUALOR_TOKEN_FD: '3',
      QUALOR_TOKEN: 'qlr_prj_fromenv',
    });
    expect(seen).toEqual({ token: 'qlr_prj_frompipe', fdOpen: false });
  });

  it('an empty pipe is exit 2 and the descriptor is closed', async () => {
    const seen = await viaPipe('\n', { QUALOR_TOKEN_FD: '3' });
    expect(seen).toEqual({ exitCode: 2, message: 'QUALOR_TOKEN_FD 3 is empty', fdOpen: false });
  });

  it('a bad number is exit 2', async () => {
    const seen = await viaPipe('qlr_prj_x', { QUALOR_TOKEN_FD: 'three' });
    expect(seen).toMatchObject({ exitCode: 2 });
  });
});
