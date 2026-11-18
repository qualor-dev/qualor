import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { createLogger, type Logger } from '../log';
import { createToolRunner, MissingToolError, toolFailure, type ToolResult } from './runner';

const tmp = useTempDirs();
// Test secrets are assembled at runtime, so the repository's own gitleaks pass finds none here.
const NPM_SECRET = ['npm', 'S3CR3T', 'v4lue'].join('_');
const PROJECT_TOKEN = ['qlr', 'prj', 'T0KEN', 'value'].join('_');

function spy(): { log: Logger; lines: string[] } {
  const lines: string[] = [];
  return { log: createLogger('debug', (text) => lines.push(text)), lines };
}

const result = (r: Partial<ToolResult>): ToolResult => ({
  exitCode: 1,
  timedOut: false,
  stdout: '',
  stderr: '',
  ...r,
});

describe('toolFailure', () => {
  it('names the tool and its exit code, then the scrubbed tail of its stderr', () => {
    const f = toolFailure(
      'npm',
      result({ exitCode: 1, stderr: `npm ERR! token ${NPM_SECRET}\n` }),
      [NPM_SECRET],
    );
    expect(f.code).toBe('package_manager');
    expect(f.message).toBe('`npm` exited with 1: npm ERR! token [redacted]');
  });

  it('is a timeout when the tool timed out', () => {
    const f = toolFailure('go', result({ exitCode: null, timedOut: true }), []);
    expect(f).toEqual({ code: 'timeout', message: '`go` did not finish in time' });
  });

  it('keeps the message, head included, within 2 KiB however long stderr is', () => {
    const stderr = `${'é'.repeat(5000)}\nthe last line\n`;
    const f = toolFailure('mvn', result({ exitCode: 1, stderr }), []);
    expect(Buffer.byteLength(f.message)).toBeLessThanOrEqual(2048);
    expect(f.message.startsWith('`mvn` exited with 1: ')).toBe(true);
    expect(f.message.endsWith('the last line')).toBe(true);
  });
});

describe('createToolRunner', () => {
  it('runs a tool from PATH without a shell, with the tool environment, in the given directory', async () => {
    const cwd = tmp();
    const { log } = spy();
    const run = createToolRunner({
      env: { ...process.env, QUALOR_TOKEN: PROJECT_TOKEN, NPM_TOKEN: NPM_SECRET } as Record<
        string,
        string
      >,
      root: tmp(),
      log,
    });
    const r = await run(
      'node',
      [
        '-e',
        'process.stdout.write(JSON.stringify({ cwd: process.cwd(), q: process.env.QUALOR_TOKEN ?? null, n: process.env.NPM_TOKEN ?? null, extra: process.env.EXTRA ?? null }))',
      ],
      { cwd, env: { EXTRA: 'yes', QUALOR_URL: 'https://smuggled.example' }, timeoutMs: 30_000 },
    );
    expect(r.exitCode).toBe(0);
    const seen = JSON.parse(r.stdout) as Record<string, string | null>;
    expect(seen).toEqual({ cwd: expect.any(String), q: null, n: NPM_SECRET, extra: 'yes' });
  });

  it('replaces the known secrets in stderr and never logs a tool’s output', async () => {
    const { log, lines } = spy();
    const run = createToolRunner({
      env: { ...process.env, NPM_TOKEN: NPM_SECRET } as Record<string, string>,
      root: tmp(),
      log,
      secrets: [PROJECT_TOKEN],
    });
    const r = await run(
      'node',
      ['-e', 'console.error(process.env.NPM_TOKEN + " " + process.env.LEAK); process.exit(3)'],
      { cwd: tmp(), env: { LEAK: PROJECT_TOKEN }, timeoutMs: 30_000 },
    );
    expect(r.exitCode).toBe(3);
    expect(r.stderr).not.toContain(NPM_SECRET);
    expect(r.stderr).not.toContain(PROJECT_TOKEN);
    expect(r.stderr).toContain('[redacted]');
    expect(lines.join('')).not.toContain(NPM_SECRET);
    expect(lines.join('')).not.toContain(PROJECT_TOKEN);
  });

  it('stops a tool at its timeout', async () => {
    const run = createToolRunner({
      env: { ...process.env } as Record<string, string>,
      root: tmp(),
      log: spy().log,
    });
    const r = await run('node', ['-e', 'setInterval(() => {}, 1000)'], {
      cwd: tmp(),
      timeoutMs: 300,
    });
    expect(r.timedOut).toBe(true);
    expect(toolFailure('node', r, []).code).toBe('timeout');
  });

  it('does not start a tool when no time is left', async () => {
    const run = createToolRunner({
      env: { ...process.env } as Record<string, string>,
      root: tmp(),
      log: spy().log,
    });
    const r = await run('node', ['-e', 'process.exit(0)'], { cwd: tmp(), timeoutMs: 0 });
    expect(r).toEqual({ exitCode: null, timedOut: true, stdout: '', stderr: '' });
  });

  it('throws MissingToolError for a tool that is not on PATH', async () => {
    const run = createToolRunner({ env: { PATH: tmp() }, root: tmp(), log: spy().log });
    const failed = run('yarn', ['install'], { cwd: tmp(), timeoutMs: 1000 });
    await expect(failed).rejects.toBeInstanceOf(MissingToolError);
    await expect(failed).rejects.toMatchObject({ tool: 'yarn' });
  });
});
