import { execFileSync } from 'node:child_process';
import { ESLint } from 'eslint';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const eslint = new ESLint({ cwd: root });
const RULES = new Set([
  'no-restricted-imports',
  'no-restricted-syntax',
  '@typescript-eslint/no-restricted-imports',
]);

async function violations(filePath: string, code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: path.join(root, filePath) });
  return (result?.messages ?? []).filter((m) => RULES.has(m.ruleId ?? '')).map((m) => m.message);
}

describe('module boundaries', () => {
  it.each([
    ['cli/src/a.ts', "import x from '@qualor/enterprise';"],
    ['server/src/a.ts', "import x from '../../enterprise/src/sso';"],
    ['packages/shared/src/a.ts', "import x from '@qualor/enterprise/sso';"],
    ['cli/src/a.ts', "import x from '@qualor/server';"],
    ['cli/src/a.ts', "import x from '../../server/src/db';"],
    ['ui/src/a.ts', "import x from '@qualor/server';"],
    ['packages/shared/src/a.ts', "import x from '@qualor/cli';"],
    ['cli/src/a.ts', "import x from '../../server';"],
    ['cli/src/a.ts', "import x from '../../server/';"],
    ['cli/src/a.ts', "import x from '../../server/index';"],
    ['cli/src/a.ts', "import x from '../../server/index.js';"],
    ['ui/src/deep/a.ts', "import x from '../../../server';"],
    ['cli/src/a.ts', "import x from '../../enterprise';"],
    ['server/src/a.ts', "import x from '../../enterprise/index.ts';"],
    ['packages/shared/src/a.ts', "import x from '../../../cli';"],
    ['packages/shared/src/a.ts', "import x from '../../../ui/index';"],
    ['server/src/a.ts', "import x from '@qualor/ui';"],
    ['server/src/http/a.ts', "import x from '../../../ui/src/app/app';"],
    ['server/src/a.ts', "import x from '../../ui/dist/browser/main.js';"],
    ['server/src/a.ts', "import x from '../../ui';"],
    ['server/src/a.ts', "import x from '../../ui/src';"],
    ['server/src/a.ts', "import x from '../../ui/e2e/seed-data';"],
    ['server/scripts/e2e/a.ts', "import x from '../../../ui/tools/templates';"],
    ['server/src/a.ts', "import x from '../../ui/angular.json';"],
    // Final review M-3: server/src never imports the CLI.
    ['server/src/a.ts', "import x from '@qualor/cli';"],
    ['server/src/a.ts', "import x from '../../cli';"],
    ['server/src/import/a.ts', "import x from '../../../cli/src/import/issues';"],
    ['server/src/routes/a.ts', "import x from '../../../cli/test/fake-sonarqube';"],
    // enterprise.md §12: dynamic imports and require() of enterprise/, anywhere in core.
    ['server/src/a.ts', "const x = await import('../../enterprise/dist/plugin.js');"],
    ['server/src/a.ts', 'const x = await import(`../../enterprise/${String(1)}`);'],
    ['cli/src/a.ts', "const x = require('../../enterprise/src/plugin');"],
    ['ui/src/a.ts', "const x = await import('@qualor/enterprise');"],
    ['packages/shared/src/a.ts', "const x = await import('../../../enterprise');"],
    // Every form of reaching enterprise/src from core: static, dynamic, require, type-only.
    ['server/src/a.ts', "import { plugin as x } from '../../enterprise/src/plugin';"],
    ['server/src/a.ts', "const x = await import('../../enterprise/src/plugin');"],
    ['server/src/a.ts', "const x = require('../../enterprise/src/plugin');"],
    ['server/test/a.ts', 'const x = require(`../../enterprise/src/plugin`);'],
    ['server/src/a.ts', "import type { Plugin as x } from '../../enterprise/src/plugin';"],
    ['cli/src/a.ts', "import { type Plugin as x } from '../../enterprise/src/plugin';"],
    ['server/src/a.ts', "type x = typeof import('../../enterprise/src/plugin');"],
    ['server/src/a.ts', "import x = require('../../enterprise/src/plugin');"],
    ['ui/src/a.ts', "export * from '../../enterprise/src/plugin';\nconst x = 1;"],
    ['server/src/a.ts', "export { plugin } from '../../enterprise/src/plugin';\nconst x = 1;"],
    ['packages/shared/src/a.ts', "export type { Plugin } from '@qualor/enterprise';\nconst x = 1;"],
    // The loader is the only import() expression in server/src.
    ['server/src/routes/a.ts', "const x = await import(String('url'));"],
    ['server/src/plugins/other.ts', "const x = await import('./contract');"],
    // enterprise/src may import core only as types.
    ['enterprise/src/a.ts', "import { buildApp as x } from '@qualor/server';"],
    [
      'enterprise/src/a.ts',
      "import { PLUGIN_API_VERSION as x } from '@qualor/server/plugin-contract';",
    ],
    [
      'enterprise/src/a.ts',
      "import { verifyLicenseKey as x } from '../../server/src/license/verify';",
    ],
  ])('%s rejects %s', async (file, code) => {
    // A case may hit two rules (a dynamic import of enterprise/ in server/src is also a
    // non-loader import()), so at least one.
    const found = await violations(file, `${code}\nexport default x;\n`);
    expect(found.length).toBeGreaterThanOrEqual(1);
    // Core naming enterprise/ is caught by the enterprise rule itself, not only by the
    // loader-only import() rule.
    if (/enterprise/.test(code) && !file.startsWith('enterprise/')) {
      expect(found.some((m) => m.includes('never import enterprise/'))).toBe(true);
    }
  });

  it.each([
    // Even the loader may not name enterprise/: EE7, the image's QUALOR_PLUGIN_PATHS is the link.
    ['server/src/plugins/loader.ts', "const x = await import('/app/enterprise/plugin.js');"],
    ['server/src/a.test.ts', "const x = await import('../../enterprise/src/plugin');"],
    ['server/test/a.ts', "const x = await import('../../enterprise/src/plugin');"],
    ['cli/src/a.ts', "const x = require.resolve('../../enterprise/src/plugin');"],
    // Task 6 review I-1: in any case, and through a template's escapes.
    ['server/test/a.ts', 'const x = require(`../../ENTERPRISE/src/plugin`);'],
    ['cli/test/a.ts', 'const x = require(`../../\\x65nterprise/src/plugin`);'],
    ['ui/src/a.ts', "const x = await import('../../Enterprise/src/plugin');"],
    ['packages/shared/test/a.ts', 'const x = require.resolve(`../../\\x65nterprise/x`);'],
    // Final review A M-2: core sources never name an enterprise/ path in any string.
    ['server/src/a.ts', "const x = new Worker('/app/enterprise/worker.js');"],
    [
      'server/src/a.ts',
      "import { fork } from 'node:child_process';\nconst x = fork(String.raw`C:\\app\\enterprise\\plugin.js`);",
    ],
    ['cli/src/a.ts', "const x = import.meta.resolve('../../enterprise/src/plugin.js');"],
    ['packages/shared/src/a.ts', "const x = ['..', 'enterprise/dist'].join('/');"],
    ['ui/src/a.ts', 'const x = `${String(1)}/ENTERPRISE/plugin.js`;'],
  ])('%s rejects %s as an enterprise import', async (file, code) => {
    const found = await violations(file, `${code}\nexport default x;\n`);
    expect(found.length).toBeGreaterThanOrEqual(1);
    for (const message of found) expect(message).toContain('never import enterprise/');
  });

  it.each([
    // Task 6 review I-1: a specifier the rules cannot read, and a require of one's own.
    ['cli/src/a.ts', "const p = String('m');\nconst x = await import(p);"],
    ['ui/src/a.ts', 'const x = await import(`./${String(1)}`);'],
    ['packages/shared/src/a.ts', "const x = require(String('m'));"],
    ['cli/src/a.ts', "const x = require.resolve(String('m'));"],
    ['server/src/plugins/loader.ts', "const x = require(String('m'));"],
    ['cli/src/a.ts', "import { createRequire } from 'node:module';\nconst x = createRequire('/');"],
    ['server/src/a.ts', "import module from 'node:module';\nconst x = module.createRequire('/');"],
    ['ui/src/a.ts', "const x = module.require('m');"],
    ['packages/shared/src/a.ts', "const x = globalThis.require('m');"],
    ['server/src/a.ts', 'const x = process.mainModule;'],
    // Task 6 review I-2: enterprise/src reaches core as types only, in every form.
    ['enterprise/src/a.ts', "import { buildApp as x } from '../../server/src';"],
    ['enterprise/src/a.ts', "import x from '../../server';"],
    ['enterprise/src/a.ts', "import x from '../../server/scripts/bundle';"],
    ['enterprise/src/a.ts', "const x = await import('@qualor/server');"],
    ['enterprise/src/a.ts', "const x = require('../../server/src/app');"],
    ['enterprise/src/a.ts', "const x = await import(`../../server/src/${'app'}`);"],
    // Task 11 review I-2: no runtime dependency on shared code or the database library.
    ['enterprise/src/a.ts', "import { VERSION as x } from '@qualor/shared';"],
    ['enterprise/src/a.ts', "import x from '../../packages/shared/src/index';"],
    ['enterprise/src/a.ts', "import { eq as x } from 'drizzle-orm';"],
  ])('%s rejects %s', async (file, code) => {
    expect(await violations(file, `${code}\nexport default x;\n`)).not.toEqual([]);
  });

  it('keeps every core source a .ts file, which the rules above see (Task 6 review I-1)', () => {
    const tracked = execFileSync('git', ['ls-files', 'cli', 'ui', 'packages', 'server'], {
      cwd: root,
      encoding: 'utf8',
    }).split('\n');
    // ESLint lints **/*.ts only: code in any other extension would escape every rule above.
    const core = /^(cli\/src|ui\/src|packages\/[^/]+\/src|server\/src|server\/scripts)\//;
    const otherCode = /\.(js|mjs|cjs|jsx|tsx|mts|cts)$/;
    expect(tracked.filter((f) => core.test(f) && otherCode.test(f))).toEqual([]);
  });

  it.each([
    ['cli/src/a.ts', "import { VERSION } from '@qualor/shared';"],
    ['server/src/a.ts', "import { VERSION } from '@qualor/shared';"],
    ['enterprise/src/a.ts', "import type { VERSION } from '@qualor/shared';"],
    ['enterprise/src/a.ts', "import type { SQL as VERSION } from 'drizzle-orm';"],
    ['enterprise/src/a.ts', "import type { VERSION } from '@qualor/server';"],
    // 4C: zod, the one runtime dependency of the enterprise package (external in its bundle).
    ['enterprise/src/a.ts', "import { z as VERSION } from 'zod';"],
    ['server/src/a.ts', "const VERSION = 'the enterprise edition';"],
    ['server/src/a.test.ts', "const VERSION = '../../enterprise/dist/plugin.js';"],
    [
      'cli/src/parse/grammars.ts',
      "import { createRequire } from 'node:module';\nconst VERSION = createRequire('/');",
    ],
    ['ui/src/a.ts', "import { VERSION } from 'react-dom/server';"],
    ['cli/src/a.ts', "import { VERSION } from './server-client';"],
    ['server/src/http/a.ts', "import { VERSION } from './ui';"],
    ['server/src/routes/a.ts', "import { VERSION } from '../http/ui';"],
    ['cli/src/a.ts', "import { VERSION } from '../../packages/shared/src/index';"],
    ['server/test/a.ts', "import { VERSION } from '../../cli/test/fake-sonarqube';"],
    ['server/src/plugins/loader.ts', "const VERSION = await import(String('url'));"],
    ['server/src/a.test.ts', "const VERSION = await import('./a');"],
    [
      'enterprise/src/a.ts',
      "import type { QualorPlugin as VERSION } from '@qualor/server/plugin-contract';",
    ],
    [
      'enterprise/src/a.ts',
      "import { type QualorPlugin as VERSION } from '../../server/src/plugins/contract';",
    ],
    ['ui/src/a.ts', "const VERSION = () => import('./settings/tokens.page');"],
    ['cli/src/a.ts', "const VERSION = await import('./commands/scan');"],
  ])('%s allows %s', async (file, code) => {
    expect(await violations(file, `${code}\nexport default VERSION;\n`)).toHaveLength(0);
  });
});
