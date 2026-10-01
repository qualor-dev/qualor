import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import {
  normalizeTargetRuby,
  RUBOCOP_VERSION,
  rubocopSelection,
  rubocopVersionSupported,
} from '@qualor/shared';
import { MAX_ANALYZED_BYTES } from '../discovery/discover';
import { isInside } from './binary';
import { copyCheckedFiles } from './checked-copy';
import { deadProxyEnv } from './offline';
import { rubocopCrashWarnings, rubocopFailureDetail, rubocopJsonToSarif } from './rubocop-json';
import type { Analyzer, AnalyzerContext, Preparation } from './types';

/** Where the qualor/scanner image installs the RuboCop pass (config.md §4, plan 9B). */
export const DEFAULT_RUBOCOP_DIR = '/opt/qualor/rubocop';

const NOT_INSTALLED =
  'RuboCop is not installed (the qualor/scanner image keeps it in /opt/qualor/rubocop)';

/**
 * config.md §6: the only inherited variables RuboCop sees (matched without case). Ruby reads
 * RUBYOPT (`-r` loads a file) and RUBYLIB, RubyGems GEM_*, RuboCop RUBOCOP_OPTS and XDG_*: none of
 * them may reach it.
 */
export const RUBOCOP_KEPT_ENV: ReadonlySet<string> = new Set([
  'PATH',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'SYSTEMROOT',
  'WINDIR',
]);

/** A path the runner's file list (one per line) cannot hold. */
const LINE_BREAK = /[\r\n]/;

/** The install's VERSION line: `rubocop 1.91.0 ruby 4.0.7`. */
export function parseRubocopVersion(text: string): string | null {
  return /^rubocop (\d+\.\d+\.\d+) ruby \d+\.\d+\.\d+$/.exec(text.trim())?.[1] ?? null;
}

/**
 * The configuration Qualor writes (config.md §6): every cop off but the selected ones, no pending
 * cops, no plugin suggestions, the target Ruby. Cop names and the target are validated by the
 * config schema (RUBOCOP_SELECTOR, RUBOCOP_TARGET_RUBIES), so they are written bare.
 */
export function rubocopConfigYaml(cops: readonly string[], targetRuby: string): string {
  const lines = [
    '# Written by Qualor (config.md §6): the only RuboCop configuration this scan reads.',
    'AllCops:',
    '  DisabledByDefault: true',
    '  NewCops: disable',
    '  SuggestExtensions: false',
    `  TargetRubyVersion: ${targetRuby}`,
    '  Exclude: []',
  ];
  for (const cop of cops) lines.push(`${cop}:`, '  Enabled: true');
  return `${lines.join('\n')}\n`;
}

/** The install, or why it cannot be used (a missing install is a skip: ruling G6). */
function rubocopInstall(
  ctx: AnalyzerContext,
): { ruby: string; script: string; version: string } | { skip: string } | { unavailable: string } {
  const dir = ctx.env['QUALOR_RUBOCOP_DIR'] || DEFAULT_RUBOCOP_DIR;
  if (!path.isAbsolute(dir) || isInside(ctx.root, dir)) {
    return { unavailable: 'QUALOR_RUBOCOP_DIR must be an absolute path outside the repository' };
  }
  const ruby = path.join(dir, 'ruby', 'bin', 'ruby');
  const script = path.join(dir, 'run.rb');
  if (!existsSync(ruby) || !existsSync(script)) return { skip: NOT_INSTALLED };
  const versionFile = path.join(dir, 'VERSION');
  let version: string | null;
  try {
    version = parseRubocopVersion(readFileSync(versionFile, 'utf8'));
  } catch {
    version = null;
  }
  if (version === null) return { unavailable: `${versionFile} does not name a RuboCop version` };
  return { ruby, script, version };
}

async function prepare(ctx: AnalyzerContext): Promise<Preparation> {
  const settings = ctx.config.analyzers.rubocop;
  const ruby = ctx.files.filter((f) => f.language === 'ruby');
  if (ruby.length === 0) return { skip: 'no Ruby files in scope' };
  const found = rubocopInstall(ctx);
  if (!('ruby' in found)) return found;
  if (!rubocopVersionSupported(found.version)) {
    const minor = RUBOCOP_VERSION.split('.').slice(0, 2).join('.');
    return {
      skip: `RuboCop ${found.version} is not supported: this Qualor runs RuboCop ${minor}.x (the qualor/scanner image's ${RUBOCOP_VERSION})`,
    };
  }
  const cops = rubocopSelection(settings.select, settings.ignore);
  if (cops.length === 0)
    return { skip: 'no RuboCop cop is selected (analyzers.rubocop select minus ignore)' };

  const breaks = ruby.filter((f) => LINE_BREAK.test(f.path)).length;
  if (breaks > 0)
    ctx.log.warn(`rubocop: ${breaks} Ruby file(s) whose path has a line break were left out`);
  const large = ruby.filter((f) => f.size > MAX_ANALYZED_BYTES).length;
  if (large > 0) ctx.log.warn(`rubocop: ${large} Ruby file(s) larger than 1 MiB were left out`);
  const candidates = ruby.filter((f) => !LINE_BREAK.test(f.path) && f.size <= MAX_ANALYZED_BYTES);
  const input = path.join(ctx.workDir, 'src');
  mkdirSync(input, { recursive: true });
  const files = copyCheckedFiles(ctx.root, candidates, input);
  const leftOut = candidates.length - files.length;
  if (leftOut > 0) {
    ctx.log.warn(
      `rubocop: ${leftOut} Ruby file(s) not analysed (a link, or a file that cannot be read)`,
    );
  }
  if (files.length === 0) return { skip: 'no Ruby file in scope that RuboCop can be given' };

  const config = path.join(ctx.workDir, 'rubocop.yml');
  const list = path.join(ctx.workDir, 'rubocop-files.txt');
  const out = path.join(ctx.workDir, 'rubocop.json');
  const cache = path.join(ctx.workDir, 'rubocop-cache');
  writeFileSync(config, rubocopConfigYaml(cops, normalizeTargetRuby(settings.targetRubyVersion)));
  writeFileSync(list, files.map((f) => `${f.path}\n`).join(''));
  const own: Record<string, string> = { ...deadProxyEnv(), HOME: ctx.workDir, LC_ALL: 'C.UTF-8' };
  const selected = new Set(cops);
  return {
    run: {
      command: found.ruby,
      args: [found.script, config, list, out, cache],
      // The checked copy: RuboCop reports paths relative to it (the repository's own), and no
      // `.rubocop` options file or configuration of the checkout is next to them.
      cwd: input,
      env: own,
      dropEnv: (name) => !Object.hasOwn(own, name) && !RUBOCOP_KEPT_ENV.has(name.toUpperCase()),
      sarifPath: out,
      // 0: no offense; 1: offenses; 2: an error (config.md §6).
      okExitCodes: [0, 1],
      version: found.version,
      transform: (output) =>
        rubocopJsonToSarif(output, { version: found.version, cops: selected, log: ctx.log }),
      failureDetail: (_code, stderr) => rubocopFailureDetail(stderr, ctx.workDir),
      configWarnings: (stderr) => rubocopCrashWarnings(stderr, input),
    },
  };
}

export const rubocopAnalyzer: Analyzer = {
  id: 'rubocop',
  languages: ['ruby'],
  ruleLanguages: ['ruby'],
  prepare,
};
