import { createServer } from 'node:http';
import { existsSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { parseConfig } from '@qualor/shared';
import { expect, it } from 'vitest';
import { describeWithRubocop } from '../../test/analyzers';
import { useTempDirs, writeTree } from '../../test/tmp';
import { discoverFiles } from '../discovery/discover';
import { silentLogger } from '../log';
import { Warnings } from '../warnings';
import { fileLines, normalizeCaptures } from './normalize';
import { rubocopAnalyzer } from './rubocop';
import { runAnalyzers } from './runner';

const tmp = useTempDirs();

async function scan(
  root: string,
  env: NodeJS.ProcessEnv = process.env,
  settings: object = {},
  tempRoot?: string,
) {
  const config = parseConfig({ version: 1, ...settings });
  const files = discoverFiles({ root, config, warnings: new Warnings(), log: silentLogger });
  const [capture] = await runAnalyzers([rubocopAnalyzer], {
    root,
    config,
    files,
    log: silentLogger,
    env,
    ...(tempRoot !== undefined && { tempRoot }),
  });
  if (capture === undefined) throw new Error('no capture');
  const out = normalizeCaptures([capture], {
    repoRoot: root,
    readLines: fileLines(root),
    knownPaths: new Set(files.map((f) => f.path)),
    log: silentLogger,
  });
  return {
    capture,
    keys: out.findings
      .map((f) => `${f.ruleId} ${f.location?.path}:${f.location?.startLine}`)
      .sort(),
  };
}

/** Every file below `dir`, relative, with its bytes. */
/** Ruby code that writes `ran-<who>` into `dir`: a marker that shows when something runs it. */
function rubyWrites(dir: string, who: string): string {
  const file = path.join(dir, `ran-${who}`);
  return `File.write(${JSON.stringify(file)}, "x")\n`;
}

function snapshot(dir: string): Map<string, string> {
  return new Map(
    readdirSync(dir, { recursive: true, withFileTypes: true })
      .filter((d) => d.isFile())
      .map((d) => {
        const p = path.join(d.parentPath, d.name);
        return [path.relative(dir, p), readFileSync(p, 'latin1')] as const;
      }),
  );
}

describeWithRubocop()('RuboCop on untrusted checkouts (real RuboCop, plan 9B)', () => {
  it('reads no configuration of the checkout, runs nothing of it, fetches nothing and writes nothing', async () => {
    const root = tmp();
    let requests = 0;
    const server = createServer((_req, res) => {
      requests++;
      res.end('Lint/UselessAssignment:\n  Enabled: false\n');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const port = (server.address() as AddressInfo).port;
    // Each marker writes ran-<who> into the repository root if anything runs it.
    const marker = (who: string) => rubyWrites(root, who);
    try {
      writeTree(root, {
        'app/a.rb': 'def f\n  x = 1\nend\n',
        '.rubocop.yml':
          `<% ${marker('erb').trim()} %>\nrequire:\n  - ./evil_require.rb\nplugins:\n  - ./evil_plugin.rb\n` +
          `inherit_from:\n  - http://127.0.0.1:${port}/remote.yml\ninherit_gem:\n  rubocop-rails-omakase: rubocop.yml\n` +
          'Lint/UselessAssignment:\n  Enabled: false\nStyle/StringLiterals:\n  Enabled: true\n',
        '.rubocop_todo.yml': `<% ${marker('todo').trim()} %>\n`,
        'app/.rubocop.yml': `<% ${marker('sub').trim()} %>\n`,
        '.rubocop': `--require ${path.join(root, 'evil_opts.rb')}\n`,
        'evil_require.rb': marker('require'),
        'evil_plugin.rb': marker('plugin'),
        'evil_opts.rb': marker('opts'),
        'evil_rubyopt.rb': marker('rubyopt'),
        Gemfile: marker('gemfile'),
        'x.gemspec': `${marker('gemspec')}Gem::Specification.new { |s| s.name = "x" }\n`,
        'bin/rubocop': `#!/bin/sh\ntouch ${JSON.stringify(path.join(root, 'ran-bin'))}\n`,
      });
      const before = snapshot(root);
      const { capture, keys } = await scan(root, {
        ...process.env,
        PATH: `${path.join(root, 'bin')}${path.delimiter}${process.env['PATH'] ?? ''}`,
        RUBYOPT: `-r${path.join(root, 'evil_rubyopt.rb')}`,
        RUBYLIB: root,
        RUBOCOP_OPTS: `--require ${path.join(root, 'evil_opts.rb')}`,
        GEM_HOME: root,
        BUNDLE_GEMFILE: path.join(root, 'Gemfile'),
      });
      expect(capture.status, capture.reason ?? '').toBe('ok');
      // qualor-default only: the project's disable and its Style cop have no effect.
      expect(keys).toEqual(['Lint/UselessAssignment app/a.rb:2']);
      expect(readdirSync(root).filter((n) => n.startsWith('ran-'))).toEqual([]);
      expect(requests).toBe(0);
      expect(snapshot(root)).toEqual(before);
      expect(
        existsSync(path.join(root, '.rubocop-http---127-0-0-1-' + String(port) + '-remote-yml')),
      ).toBe(false);
    } finally {
      server.close();
    }
  });

  it('reads no configuration above the checkout or the work directory, nor of the user', async () => {
    // RuboCop looks upwards from its --config file for the topmost .rubocop.yml (its
    // AllCops/Exclude) unless --ignore-parent-exclusion: the work directory sits below `outer`
    // here, as it would below a TMPDIR inside the checkout, and the checkout below it too.
    const outer = tmp();
    const marker = (who: string) => rubyWrites(outer, who);
    const hostile = (who: string) =>
      `<% ${marker(who).trim()} %>\nAllCops:\n  Exclude:\n    - '**/*'\n`;
    writeTree(outer, {
      '.rubocop.yml': hostile('outer'),
      '.rubocop': `--require ${path.join(outer, 'evil_opts.rb')}\n`,
      'evil_opts.rb': marker('opts'),
      Gemfile: marker('gemfile'),
      'gems.rb': marker('gems'),
      '.config/.rubocop.yml': hostile('dotconfig'),
      '.config/rubocop/config.yml': hostile('dotconfig-xdg'),
      'repo/.rubocop.yml': hostile('repo'),
      'repo/.config/.rubocop.yml': hostile('repo-dotconfig'),
      'repo/Gemfile': marker('repo-gemfile'),
      'repo/app/a.rb': 'def f\n  x = 1\nend\n',
      'tmp/.rubocop.yml': hostile('tmp'),
      'home/.rubocop.yml': hostile('home'),
      'home/.config/rubocop/config.yml': hostile('home-xdg'),
      'xdg/rubocop/config.yml': hostile('xdg'),
    });
    const root = path.join(outer, 'repo');
    const { capture, keys } = await scan(
      root,
      { ...process.env, HOME: path.join(outer, 'home'), XDG_CONFIG_HOME: path.join(outer, 'xdg') },
      {},
      path.join(outer, 'tmp'),
    );
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(readdirSync(outer).filter((n) => n.startsWith('ran-'))).toEqual([]);
    // An Exclude of any of those files would have hidden this finding.
    expect(keys).toEqual(['Lint/UselessAssignment app/a.rb:2']);
  });

  it('drops parse errors, honours directives, keeps cops outside the selection out, and lints awkward names', async () => {
    const root = tmp();
    const names = ['a b.rb', 'c#d.rb', 'e%f.rb', '-dash.rb', '@at.rb', 'ü.rb'];
    const unused = 'def f\n  y = 2\nend\n';
    writeTree(root, {
      'broken.rb': 'def f(:\n  1\nend\n',
      'old.rb': 'case x\nwhen 1: puts 1\nend\n',
      'crlf.rb': 'def g\r\n  z = 3\r\nend\r\n',
      // Raw bytes (writeTree writes a Uint8Array as is): 0xFF 0xFE inside a string literal are
      // invalid UTF-8 on disk, not their UTF-8 encodings. RuboCop reports that file as
      // Lint/Syntax ("Invalid byte sequence in utf-8."), as Ruby refuses it too, so it is
      // dropped; under a binary magic comment the same bytes parse.
      'bytes.rb': Buffer.concat([
        Buffer.from('def h\n  s = "'),
        Buffer.from([0xff, 0xfe]),
        Buffer.from('"\nend\n'),
      ]),
      'binary.rb': Buffer.concat([
        Buffer.from('# encoding: binary\ndef h\n  s = "'),
        Buffer.from([0xff, 0xfe]),
        Buffer.from('"\nend\n'),
      ]),
      'data.rb': 'x = 1\n__END__\nnot ruby (\n',
      'directive.rb':
        'def g\n  z = 3 # rubocop:disable Lint/UselessAssignment\nend\n' +
        // RuboCop reports Metrics/ParameterLists after this enable (fact F6); the converter drops it.
        '# rubocop:enable Metrics/ParameterLists\ndef h(a, b, c, d, e, f)\n  w = 4\nend\n',
      'endless.rb': 'def ok = 1\n',
      Rakefile: unused,
      ...Object.fromEntries(names.map((n) => [n, unused])),
    });
    const { capture, keys } = await scan(root);
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(keys).toEqual(
      [
        'Lint/UselessAssignment crlf.rb:2',
        'Lint/UselessAssignment binary.rb:3',
        // A top-level assignment nothing reads (fact F6); the __END__ data is ignored.
        'Lint/UselessAssignment data.rb:1',
        'Lint/UselessAssignment directive.rb:6',
        'Lint/UselessAssignment Rakefile:2',
        ...names.map((n) => `Lint/UselessAssignment ${n}:2`),
      ].sort(),
    );
  });

  it('never passes a symlinked .rb, even one pointing outside the repository', async () => {
    const root = tmp();
    const outside = path.join(tmp(), 'secret.rb');
    writeFileSync(outside, 'def f\n  y = 2\nend\n');
    // No local assignment: RuboCop reports nothing on ok.rb, so any finding would be the link's.
    writeTree(root, { 'ok.rb': 'puts 1\n' });
    try {
      symlinkSync(outside, path.join(root, 'link.rb'), 'file');
    } catch {
      return; // no file symlinks on this host
    }
    const { capture, keys } = await scan(root);
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(keys).toEqual([]);
  });

  // Targets before 3.3 parse with the parser gem, 3.3 and later with Prism (fact F6): one run of each.
  it.each([[3.3], ['2.7']])('runs with targetRubyVersion %s', async (targetRubyVersion) => {
    const root = tmp();
    writeTree(root, { 'a.rb': 'def f\n  y = 2\nend\n' });
    const { capture, keys } = await scan(root, process.env, {
      analyzers: { rubocop: { targetRubyVersion } },
    });
    expect(capture.status, capture.reason ?? '').toBe('ok');
    expect(keys).toEqual(['Lint/UselessAssignment a.rb:2']);
  });
});
