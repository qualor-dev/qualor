import { describe, expect, it } from 'vitest';
import { providerOfSnippet } from './setup-result';

describe('providerOfSnippet', () => {
  it('tells the provider by the first line, as server/src/onboarding/ci-templates.ts writes it', () => {
    expect(providerOfSnippet('include:\n  - component: x')).toBe('gitlab');
    expect(providerOfSnippet('qualor:\n  stage: test')).toBe('gitlab');
    expect(providerOfSnippet('name: qualor\non: push')).toBe('github');
  });

  it('gives null for any other text, never a default provider', () => {
    expect(providerOfSnippet('')).toBeNull();
    expect(providerOfSnippet('stages:\n  - test')).toBeNull();
    expect(providerOfSnippet('  name: qualor')).toBeNull();
  });
});
