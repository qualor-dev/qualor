import { fixFailureText, fixPreconditionText, noFixText } from './fix-text';

const MET = {
  scmBound: true,
  provider: 'gitlab',
  fixMrsAllowed: true,
  monitoringOn: true,
} as const;

describe('fixFailureText', () => {
  it.each(['package_manager', 'upload_refused', 'unplanned_change'])(
    'shows the server message of %s as it is',
    (code) => {
      expect(fixFailureText({ code, message: 'npm ERR! <b>not found</b>' })).toBe(
        'npm ERR! <b>not found</b>',
      );
    },
  );

  it('has a sentence of its own for every other code, never the server message', () => {
    for (const code of [
      'manifest_unsupported',
      'missing_tool',
      'verify_failed',
      'timeout',
      'scm_permission',
      'scm_refused',
      'scm_unavailable',
      'scm_not_bound',
      'fixes_disabled',
    ]) {
      const text = fixFailureText({ code, message: 'SERVER TEXT' });
      expect(text).not.toBe('');
      expect(text).not.toContain('SERVER TEXT');
    }
  });

  it('says the fix failed for an unknown code or an empty message', () => {
    expect(fixFailureText({ code: 'brand_new', message: 'x' })).toBe('The fix failed.');
    expect(fixFailureText({ code: 'package_manager', message: '' })).toBe('The fix failed.');
  });
});

describe('noFixText', () => {
  it('has a sentence for each reason, and one for an unknown reason', () => {
    const texts = [
      'no_fixed_version',
      'declined',
      'several_lines',
      'not_installed',
      'unresolvable',
      'other',
    ].map(noFixText);
    expect(new Set(texts).size).toBe(6);
  });
});

describe('fixPreconditionText', () => {
  it('is null when all are met', () => {
    expect(fixPreconditionText({ ...MET, lastClaimAt: null })).toBeNull();
  });

  it('names the first unmet one: the repository, the connection, then monitoring', () => {
    const all = { ...MET, lastClaimAt: null };
    expect(
      fixPreconditionText({ ...all, scmBound: false, fixMrsAllowed: false, monitoringOn: false }),
    ).toBe('The project is not mapped to a repository.');
    expect(fixPreconditionText({ ...all, fixMrsAllowed: false, monitoringOn: false })).toBe(
      'An organisation admin must allow fix MRs on the connection.',
    );
    expect(fixPreconditionText({ ...all, monitoringOn: false })).toBe(
      'Vulnerability monitoring is off for this project.',
    );
  });
});
