import { describe, expect, it } from 'vitest';
import sonarjsKeys from '../../rules/sonarjs-keys.json' with { type: 'json' };
import {
  currentHelpUri,
  qualorRuleHelpUri,
  ruleHelpUri,
  SONARJS_TYPESCRIPT_ONLY_KEYS,
  sonarCloudRuleUri,
  sonarjsHelpUri,
} from './help-uri';

const cloud = (key: string) =>
  `https://sonarcloud.io/organizations/sonarsource/rules?open=${key.replace(':', '%3A')}&rule_key=${key.replace(':', '%3A')}`;

describe('rule documentation links', () => {
  it("links a SonarSource rule to SonarCloud's public rule browser", () => {
    expect(sonarCloudRuleUri('javascript', 'S3776')).toBe(
      'https://sonarcloud.io/organizations/sonarsource/rules?open=javascript%3AS3776&rule_key=javascript%3AS3776',
    );
  });

  it('links a SonarJS rule under javascript:, a TypeScript-only one under typescript:', () => {
    expect(sonarjsHelpUri('S3776')).toBe(cloud('javascript:S3776'));
    expect(sonarjsHelpUri('S4323')).toBe(cloud('typescript:S4323'));
    expect(sonarjsHelpUri('not a key')).toBeNull();
    expect(sonarjsHelpUri('S0')).toBeNull();
  });

  it('knows TypeScript-only keys of the bundled plugin only', () => {
    const bundled = new Set<string>(sonarjsKeys);
    expect([...SONARJS_TYPESCRIPT_ONLY_KEYS].filter((k) => !bundled.has(k))).toEqual([]);
  });

  it('links a Qualor rule to its page in qualor-rules', () => {
    expect(qualorRuleHelpUri('go/sql-injection')).toBe(
      'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/go/sql-injection.md',
    );
    expect(qualorRuleHelpUri('js/xss')).toBe(
      'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/js/xss.md',
    );
    for (const bad of ['go/../x', 'rust/x', 'go/Sql', 'go.sql-injection', '', 'go/x/y']) {
      expect(qualorRuleHelpUri(bad)).toBeNull();
    }
  });

  it('replaces the dead rules.sonarsource.com links, with or without a trailing slash', () => {
    expect(currentHelpUri('https://rules.sonarsource.com/javascript/RSPEC-3776')).toBe(
      cloud('javascript:S3776'),
    );
    expect(currentHelpUri('https://rules.sonarsource.com/javascript/RSPEC-3776/')).toBe(
      cloud('javascript:S3776'),
    );
    expect(currentHelpUri('https://rules.sonarsource.com/javascript/RSPEC-4323')).toBe(
      cloud('typescript:S4323'),
    );
    expect(currentHelpUri('https://rules.sonarsource.com/typescript/RSPEC-1871')).toBe(
      cloud('javascript:S1871'),
    );
    expect(currentHelpUri('https://rules.sonarsource.com/csharp/RSPEC-2325')).toBe(
      cloud('csharpsquid:S2325'),
    );
    expect(currentHelpUri('https://rules.sonarsource.com/vbnet/RSPEC-1481')).toBe(
      cloud('vbnet:S1481'),
    );
  });

  it('leaves other links alone, rules.sonarsource.com ones it cannot map too', () => {
    for (const uri of [
      'https://eslint.org/docs/latest/rules/eqeqeq',
      'https://rules.sonarsource.com/cobol/RSPEC-1',
      'https://rules.sonarsource.com/javascript/RSPEC-1?x=1',
      'https://rules.sonarsource.com/javascript/',
      'https://evil.example/https://rules.sonarsource.com/javascript/RSPEC-1',
      'https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/printf',
    ]) {
      expect(currentHelpUri(uri)).toBe(uri);
    }
  });

  it('fixes the go vet analyzers whose package has another name', () => {
    const passes = 'https://pkg.go.dev/golang.org/x/tools/go/analysis/passes';
    expect(currentHelpUri(`${passes}/copylocks`)).toBe(`${passes}/copylock`);
    expect(currentHelpUri(`${passes}/composites`)).toBe(`${passes}/composite`);
  });

  it("gives the link a rule's stored one maps to, or a Qualor rule's page", () => {
    expect(
      ruleHelpUri('sonarjs:S3776', 'https://rules.sonarsource.com/javascript/RSPEC-3776'),
    ).toBe(cloud('javascript:S3776'));
    expect(ruleHelpUri('eslint:eqeqeq', 'https://eslint.org/docs/latest/rules/eqeqeq')).toBe(
      'https://eslint.org/docs/latest/rules/eqeqeq',
    );
    expect(ruleHelpUri('qualor:go/sql-injection', null)).toBe(
      'https://github.com/qualor-dev/qualor-rules/blob/main/docs/rules/go/sql-injection.md',
    );
    expect(ruleHelpUri('qualor:go/sql-injection', 'https://example.com/own')).toBe(
      'https://example.com/own',
    );
    expect(ruleHelpUri('qualor:not-a-rule', null)).toBeNull();
    expect(ruleHelpUri('eslint:eqeqeq', null)).toBeNull();
  });
});
