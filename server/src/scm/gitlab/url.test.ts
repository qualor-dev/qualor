import { describe, expect, it } from 'vitest';
import { gitlabHostKind } from './url';

describe('GitLab host kind', () => {
  it.each([
    ['https://gitlab.com', 'gitlab.com'],
    ['https://gitlab.example.com', 'self-managed'],
    ['https://gitlab.com.evil.test', 'self-managed'],
    ['https://corp.test/gitlab', 'self-managed'],
    ['http://127.0.0.1:8080', 'self-managed'],
  ])('%s is %s', (base, kind) => {
    expect(gitlabHostKind(base)).toBe(kind);
  });
});
