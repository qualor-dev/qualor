import { describe, expect, it } from 'vitest';
import {
  githubBaseUrlProblem,
  githubGraphqlUrl,
  githubHostKind,
  githubWebBase,
  parseRepoRef,
} from './url';

describe('GitHub base URLs (github.md §2.2)', () => {
  it.each([
    ['https://api.github.com', null],
    ['https://api.octo.ghe.com', null],
    ['https://ghe.corp/api/v3', null],
    ['https://ghe.corp/github/api/v3', null],
    ['https://github.com', 'Use https://api.github.com'],
    ['https://www.github.com', 'Use https://api.github.com'],
    ['https://api.github.com/v3', 'Use https://api.github.com'],
    ['https://ghe.corp', expect.stringContaining('/api/v3')],
    ['https://ghe.corp/api', expect.stringContaining('/api/v3')],
  ])('%s', (url, problem) => {
    expect(githubBaseUrlProblem(url)).toEqual(problem);
  });

  it.each([
    ['https://api.github.com', 'https://github.com'],
    ['https://api.octo.ghe.com', 'https://octo.ghe.com'],
    ['https://ghe.corp/api/v3', 'https://ghe.corp'],
    ['https://ghe.corp/github/api/v3', 'https://ghe.corp/github'],
    ['http://127.0.0.1:8080/api/v3', 'http://127.0.0.1:8080'],
  ])('web base of %s', (api, web) => {
    expect(githubWebBase(api)).toBe(web);
  });
});

describe('GitHub GraphQL endpoint (ruling T5)', () => {
  it.each([
    ['https://api.github.com', 'https://api.github.com/graphql'],
    ['https://api.acme.ghe.com', 'https://api.acme.ghe.com/graphql'],
    ['https://ghe.example.com/api/v3', 'https://ghe.example.com/api/graphql'],
    ['https://ghe.corp/github/api/v3', 'https://ghe.corp/github/api/graphql'],
    ['http://127.0.0.1:8080/api/v3', 'http://127.0.0.1:8080/api/graphql'],
  ])('the GraphQL endpoint of %s is %s', (base, url) => {
    expect(githubGraphqlUrl(base)).toBe(url);
  });
});

describe('owner/repo (github.md §2.3)', () => {
  it('accepts owner/repo only', () => {
    expect(parseRepoRef('acme/api')).toEqual({ owner: 'acme', repo: 'api' });
    expect(parseRepoRef('Acme-1/my.repo_2')).toEqual({ owner: 'Acme-1', repo: 'my.repo_2' });
    for (const bad of [
      '123',
      'acme',
      'acme/api/x',
      'acme/..',
      'acme/.',
      '-acme/api',
      'acme/a b',
      `${'a'.repeat(40)}/x`,
      'acme/',
    ])
      expect(parseRepoRef(bad)).toBeNull();
  });
});

describe('which GitHub a base URL is', () => {
  it.each([
    ['https://api.github.com', 'cloud'],
    ['https://api.octo.ghe.com', 'cloud'],
    ['https://ghe.corp/api/v3', 'enterprise-server'],
    ['http://127.0.0.1:8080/api/v3', 'enterprise-server'],
  ] as const)('%s is %s', (base, kind) => {
    expect(githubHostKind(base)).toBe(kind);
  });
});
