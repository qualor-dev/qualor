import { describe, expect, it } from 'vitest';
import { GitLabError } from './gitlab/client';
import { ScmError } from './provider';

describe('ScmError (plan 2C ruling GH11)', () => {
  it('keeps the provider message out of every serialisation', () => {
    const err = new ScmError('refused', 'GitHub answered HTTP 422', {
      status: 422,
      providerMessage: 'secret-ish text',
    });
    expect(err.providerMessage).toBe('secret-ish text');
    expect(JSON.stringify(err)).not.toContain('secret-ish');
    expect(Object.keys(err)).not.toContain('providerMessage');
    expect(err.reason).toBe('other');
  });

  it('is the base of GitLabError, whose gitlabMessage still reads', () => {
    const err = new GitLabError('not_found', 'x', { gitlabMessage: '404 Project Not Found' });
    expect(err).toBeInstanceOf(ScmError);
    expect(err.name).toBe('GitLabError');
    expect(err.gitlabMessage).toBe('404 Project Not Found');
    expect(err.reason).toBe('http');
  });
});
