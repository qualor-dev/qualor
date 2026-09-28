import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';
import { defineConfig } from 'eslint/config';

const noEnterprise = {
  group: ['@qualor/enterprise', '@qualor/enterprise/*', '**/enterprise/**'],
  message: 'Core must never import enterprise/ (brief §2.4); use the plugin interface.',
};
const noServer = {
  group: ['@qualor/server', '@qualor/server/*', '**/server/src/**'],
  message: 'Only packages/shared may be shared with the server (brief §5.7).',
};
const noApps = {
  group: [
    '@qualor/cli',
    '@qualor/cli/*',
    '@qualor/ui',
    '@qualor/ui/*',
    '**/cli/src/**',
    '**/ui/src/**',
  ],
  message: 'packages/shared must not depend on applications.',
};
/**
 * Relative imports of an application's package root or its index (e.g. '../../server',
 * '../../server/index.js'), which the directory globs above do not cover. Only relative
 * specifiers are matched, so package subpaths such as 'react-dom/server' stay allowed. With
 * `index: false` only the bare root is matched (the group glob already covers its contents).
 */
const relativeRoot = (names, message, { index = true } = {}) => ({
  regex: `^(\\.{1,2}/)+(.+/)?(${names.join('|')})(/${index ? '(index(\\.[cm]?[jt]sx?)?)?' : ''})?$`,
  message,
});
/** The server serves the built UI directory (QUALOR_UI_DIR); it never imports UI code. */
const noUiMessage =
  'The server never imports UI code; it serves the directory QUALOR_UI_DIR names.';
const noUi = { group: ['@qualor/ui', '@qualor/ui/*'], message: noUiMessage };
/**
 * Anything under a `ui` directory reached by climbing (`../../ui`, `../../ui/src/…`,
 * `../../ui/angular.json`); the server's own `./ui` and `../http/ui` stay allowed.
 */
const noUiRelative = { regex: '^(\\.\\./)+ui(/.*)?$', message: noUiMessage };
const noEnterpriseRoot = relativeRoot(['enterprise'], noEnterprise.message, { index: false });
const noServerRoot = relativeRoot(['server'], noServer.message);
const noAppsRoot = relativeRoot(['cli', 'ui'], noApps.message);
/**
 * Final review M-3: the server's code never imports the CLI (its tests under server/test may,
 * for the fake SonarQube and the end-to-end import).
 */
const noCli = {
  group: ['@qualor/cli', '@qualor/cli/*', '**/cli/**'],
  message: 'server/src never imports the CLI; only server/test may, for test helpers.',
};
const noCliRoot = relativeRoot(['cli'], noCli.message);
const restrict = (...patterns) => ({ 'no-restricted-imports': ['error', { patterns }] });

/**
 * enterprise.md §12: import(), require() and `typeof import()` of enterprise/, which
 * no-restricted-imports does not see (it covers static imports, `import type`, re-exports and
 * `import x = require()`). Matches any string or template text mentioning enterprise.
 */
// Case-insensitive, and on a template's cooked text too (`\x65nterprise`, `ENTERPRISE`).
const enterpriseText = '/enterprise/i';
const noEnterpriseDynamic = [
  `ImportExpression > Literal[value=${enterpriseText}]`,
  `ImportExpression > TemplateLiteral > TemplateElement[value.raw=${enterpriseText}]`,
  `ImportExpression > TemplateLiteral > TemplateElement[value.cooked=${enterpriseText}]`,
  `CallExpression[callee.name='require'] > Literal[value=${enterpriseText}]`,
  `CallExpression[callee.name='require'] > TemplateLiteral > TemplateElement[value.raw=${enterpriseText}]`,
  `CallExpression[callee.name='require'] > TemplateLiteral > TemplateElement[value.cooked=${enterpriseText}]`,
  `CallExpression[callee.object.name='require'] > Literal[value=${enterpriseText}]`,
  `CallExpression[callee.object.name='require'] > TemplateLiteral > TemplateElement[value.cooked=${enterpriseText}]`,
  `TSImportType Literal[value=${enterpriseText}]`,
].map((selector) => ({ selector, message: noEnterprise.message }));
const onlyLoaderImports = {
  selector: 'ImportExpression',
  message: 'Only server/src/plugins/loader.ts may use import() in server/src (enterprise.md §12).',
};

/**
 * Task 6 review I-1: a specifier the rules above cannot read (a variable, a call, a template with
 * `${…}`) could name enterprise/ at run time. In core, import(), require() and require.resolve()
 * take a string literal or a template without expressions; the loader's import(url) is the one
 * exception (enterprise.md §12).
 */
const readableSpecifier =
  ":not([arguments.0.type='Literal']):not([arguments.0.type='TemplateLiteral'][arguments.0.expressions.length=0])";
const noComputedSpecifier = [
  {
    selector:
      "ImportExpression:not([source.type='Literal']):not([source.type='TemplateLiteral'][source.expressions.length=0])",
    message:
      'import() in core takes a string literal (enterprise.md §12); only the plugin loader imports a computed path.',
  },
  {
    selector: `CallExpression[callee.name='require']${readableSpecifier}`,
    message: 'require() in core takes a string literal (enterprise.md §12).',
  },
  {
    selector: `CallExpression[callee.object.name='require'][callee.property.name='resolve']${readableSpecifier}`,
    message: 'require.resolve() in core takes a string literal (enterprise.md §12).',
  },
];
/** Ways to get a require function the rules above do not see (Task 6 review I-1). */
const requireMessage =
  'Core code never makes its own require (createRequire, module.require, globalThis.require): enterprise.md §12.';
const noRequireFactories = [
  "ImportSpecifier[imported.name='createRequire']",
  "MemberExpression[property.name='createRequire']",
  "MemberExpression[object.name='module'][property.name='require']",
  "MemberExpression[object.name='globalThis'][property.name='require']",
  "MemberExpression[property.name='mainModule']",
].map((selector) => ({ selector, message: requireMessage }));
/**
 * Final review A M-2: core sources never name an enterprise/ path at all, in any string (a
 * Worker, child_process.fork, import.meta.resolve, a path join). esquery regexes cannot hold a
 * bare slash, hence `[/]`; `\\` is a backslash.
 */
const enterprisePath = String.raw`/(^|[/]|\\)enterprise([/]|\\)/i`;
const noEnterprisePath = [
  `Literal[value=${enterprisePath}]`,
  `TemplateElement[value.cooked=${enterprisePath}]`,
  `TemplateElement[value.raw=${enterprisePath}]`,
].map((selector) => ({
  selector,
  message: `${noEnterprise.message} Core never names an enterprise/ path (EE7).`,
}));
/** The application sources of core (not their tests): enterprise.md §12. */
const CORE_SOURCES = [
  'cli/src/**/*.ts',
  'ui/src/**/*.ts',
  'packages/*/src/**/*.ts',
  'server/src/**/*.ts',
];
const TESTS = ['**/*.test.ts', '**/*.spec.ts'];

/** Task 6 review I-2, Task 11 review I-2: what enterprise/src may import, and only as types. */
const enterpriseTypeOnly =
  'enterprise/src imports core with `import type` only (enterprise.md §12).';
const enterpriseNoRuntime =
  'enterprise/src takes core, @qualor/shared and drizzle-orm as types only: it gets them from the plugin context at run time, and its one runtime dependency is zod (enterprise.md §13).';
const serverPath = String.raw`/^@qualor[/]server|(^|[/]|\\)server([/]|\\|$)/`;
const syntax = (...selectors) => ({ 'no-restricted-syntax': ['error', ...selectors] });

export default defineConfig(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.tmp/**',
      '**/.angular/**',
      'fixtures/**',
      'coverage/**',
      'ui/src/app/api/schema.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.strict,
  {
    languageOptions: { globals: { ...globals.node } },
    rules: {
      '@typescript-eslint/consistent-type-imports': 'error',
      // Also in fixtures/ts-basic: the dogfood exit test adds one `==` and expects the gate to fail.
      eqeqeq: 'error',
    },
  },
  {
    files: ['cli/**/*.ts'],
    rules: restrict(noEnterprise, noEnterpriseRoot, noServer, noServerRoot),
  },
  {
    files: ['ui/**/*.ts'],
    rules: restrict(noEnterprise, noEnterpriseRoot, noServer, noServerRoot),
  },
  {
    // The Angular app runs in the browser; decorated classes (components, pipes) may be empty.
    files: ['ui/src/**/*.ts'],
    languageOptions: { globals: { ...globals.browser } },
    rules: {
      '@typescript-eslint/no-extraneous-class': ['error', { allowWithDecorator: true }],
    },
  },
  {
    files: ['server/**/*.ts'],
    rules: restrict(noEnterprise, noEnterpriseRoot, noUi, noUiRelative),
  },
  {
    files: ['server/src/**/*.ts'],
    rules: restrict(noEnterprise, noEnterpriseRoot, noUi, noUiRelative, noCli, noCliRoot),
  },
  {
    files: ['packages/**/*.ts'],
    rules: restrict(noEnterprise, noEnterpriseRoot, noServer, noServerRoot, noApps, noAppsRoot),
  },
  {
    files: ['cli/**/*.ts', 'ui/**/*.ts', 'packages/**/*.ts', 'server/**/*.ts'],
    rules: syntax(...noEnterpriseDynamic),
  },
  {
    // Core's application sources (a later block with the same rule replaces this one's list).
    files: CORE_SOURCES,
    ignores: TESTS,
    rules: syntax(
      ...noEnterpriseDynamic,
      ...noComputedSpecifier,
      ...noRequireFactories,
      ...noEnterprisePath,
    ),
  },
  {
    files: ['server/src/**/*.ts'],
    ignores: TESTS,
    rules: syntax(
      ...noEnterpriseDynamic,
      ...noComputedSpecifier,
      ...noRequireFactories,
      ...noEnterprisePath,
      onlyLoaderImports,
    ),
  },
  {
    // The one import() of core, of a path from QUALOR_PLUGIN_PATHS (enterprise.md §12).
    files: ['server/src/plugins/loader.ts'],
    rules: syntax(
      ...noEnterpriseDynamic,
      ...noComputedSpecifier.slice(1),
      ...noRequireFactories,
      ...noEnterprisePath,
    ),
  },
  {
    // It resolves the path of a grammar's .wasm file from a fixed map; it imports nothing.
    files: ['cli/src/parse/grammars.ts'],
    rules: syntax(
      ...noEnterpriseDynamic,
      ...noComputedSpecifier,
      ...noRequireFactories.filter((r) => !r.selector.includes('createRequire')),
      ...noEnterprisePath,
    ),
  },
  {
    // enterprise.md §12: the enterprise bundle takes everything from the plugin context at run
    // time; it imports core for types only, so it never carries a second copy of core. Its one
    // runtime dependency is zod (4C), external in the bundle (enterprise.md §13).
    files: ['enterprise/src/**/*.ts'],
    rules: {
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: [
                '@qualor/server',
                '@qualor/server/*',
                '**/server/src',
                '**/server/src/**',
                '**/server/**',
              ],
              allowTypeImports: true,
              message: enterpriseTypeOnly,
            },
            { ...relativeRoot(['server'], enterpriseTypeOnly), allowTypeImports: true },
            {
              group: [
                '@qualor/shared',
                '@qualor/shared/*',
                '**/packages/**',
                'drizzle-orm',
                'drizzle-orm/*',
              ],
              allowTypeImports: true,
              message: enterpriseNoRuntime,
            },
          ],
        },
      ],
      'no-restricted-syntax': [
        'error',
        ...[
          `ImportExpression > Literal[value=${serverPath}]`,
          `ImportExpression > TemplateLiteral > TemplateElement[value.cooked=${serverPath}]`,
          `CallExpression[callee.name='require'] > Literal[value=${serverPath}]`,
          `CallExpression[callee.name='require'] > TemplateLiteral > TemplateElement[value.cooked=${serverPath}]`,
          `CallExpression[callee.object.name='require'] > Literal[value=${serverPath}]`,
        ].map((selector) => ({ selector, message: enterpriseTypeOnly })),
      ],
    },
  },
  {
    files: [
      '**/*.test.ts',
      '**/*.spec.ts',
      'packages/*/test/**/*.ts',
      'server/test/**/*.ts',
      'cli/test/**/*.ts',
    ],
    rules: { '@typescript-eslint/no-non-null-assertion': 'off' },
  },
);
