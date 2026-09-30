// bundled.mjs — the stylelint packages Qualor bundles, by the config key that may name them
// (plan 8D). cli/src/analyzers/stylelint-config.ts has the same lists (STYLELINT_BUNDLED);
// run.test.ts checks they match. MIT.
export const BUNDLED = Object.freeze({
  extends: Object.freeze([
    'stylelint-config-recommended',
    'stylelint-config-recommended-scss',
    'stylelint-config-standard',
    'stylelint-config-standard-scss',
  ]),
  plugins: Object.freeze(['stylelint-scss']),
  customSyntax: Object.freeze(['postcss-scss']),
});
