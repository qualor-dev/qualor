import { execFileSync } from 'node:child_process';
import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../cli/test/tmp';

const tmp = useTempDirs();
const SCRIPT = path.join(__dirname, 'qualor-entrypoint.sh');
const TOKEN = `qlr_prj_${process.pid}_${Date.now()}`;

/** The stand-in `qualor`: reports what it and a child of it (an analyzer) can see, as JSON. */
const STAND_IN = `#!/usr/bin/env node
const fs = require('node:fs');
const cp = require('node:child_process');
const token = fs.readFileSync(__dirname + '/token.txt', 'utf8');
const fd = process.env.QUALOR_TOKEN_FD;
const out = {
  args: process.argv.slice(2),
  ownEnvironHasToken: fs.readFileSync('/proc/self/environ', 'utf8').includes(token),
  envHasToken: Object.values(process.env).some((v) => v === token),
  fd: fd ?? null,
  fdContent: fd === undefined ? null : fs.readFileSync(Number(fd), 'utf8').trim(),
};
const grandchild = \`
  const environ = require('node:fs').readFileSync('/proc/' + process.ppid + '/environ', 'utf8');
  process.stdout.write(JSON.stringify(environ.includes(process.argv[1])));
\`;
out.grandchildFindsToken = JSON.parse(
  cp.execFileSync(process.execPath, ['-e', grandchild, token], { encoding: 'utf8' }),
);
process.stdout.write(JSON.stringify(out));
`;

/** Runs a copy of the script whose `exec /usr/local/bin/qualor` runs the stand-in instead. */
function run(env: Record<string, string>, args: string[]): Record<string, unknown> {
  const dir = tmp();
  const standIn = path.join(dir, 'qualor');
  writeFileSync(standIn, STAND_IN);
  // Not in the environment: the stand-in's own /proc/self/environ must not hold the token.
  writeFileSync(path.join(dir, 'token.txt'), TOKEN);
  chmodSync(standIn, 0o755);
  const original = readFileSync(SCRIPT, 'utf8');
  const copy = original.replaceAll('/usr/local/bin/qualor', standIn);
  expect(copy).not.toBe(original);
  const script = path.join(dir, 'qualor-entrypoint');
  writeFileSync(script, copy);
  const stdout = execFileSync('/bin/sh', [script, ...args], {
    env: { PATH: process.env['PATH'] ?? '', ...env },
    encoding: 'utf8',
  });
  return JSON.parse(stdout) as Record<string, unknown>;
}

describe.runIf(process.platform === 'linux')('qualor-entrypoint', () => {
  it('hands the token over on descriptor 3 and out of every environment', () => {
    const seen = run({ QUALOR_TOKEN: TOKEN }, ['scan', '--no-wait']);
    expect(seen).toMatchObject({
      args: ['scan', '--no-wait'],
      ownEnvironHasToken: false,
      envHasToken: false,
      fd: '3',
      fdContent: TOKEN,
      grandchildFindsToken: false,
    });
  });

  it('changes nothing when there is no token', () => {
    for (const env of [{}, { QUALOR_TOKEN: '' }] as Record<string, string>[]) {
      const seen = run(env, ['fix']);
      expect(seen).toMatchObject({ args: ['fix'], fd: null, fdContent: null });
    }
  });
});
