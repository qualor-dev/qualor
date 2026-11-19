import { fixFailureText, fixPreconditionText, fixReasonText, noFixText } from './fix-text';

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

  it.each([
    ['manifest_unsupported', "Qualor cannot edit this project's dependency files automatically."],
    ['missing_tool', "The fix job's image does not have the package manager this fix needs."],
    ['verify_failed', "The package manager's result still holds a vulnerable version."],
    ['timeout', 'The fix job ran out of time.'],
  ])('shows the CLI message of %s after its own sentence (ruling FW12)', (code, sentence) => {
    expect(fixFailureText({ code, message: 'pnpm-workspace.yaml has <b>catalog:</b>' })).toBe(
      `${sentence} pnpm-workspace.yaml has <b>catalog:</b>`,
    );
    expect(fixFailureText({ code, message: '  ' })).toBe(sentence);
  });

  it('has a sentence of its own for every SCM code, never the server message', () => {
    for (const code of [
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

describe('fixReasonText (ruling FW12)', () => {
  it('reads a no-fix reason as one whatever the state: an open MR whose refresh found no fix', () => {
    for (const code of [
      'no_fixed_version',
      'declined',
      'several_lines',
      'not_installed',
      'unresolvable',
    ]) {
      expect(fixReasonText('open', { code, message: 'x' })).toBe(noFixText(code));
      expect(fixReasonText('no_fix', { code, message: 'x' })).toBe(noFixText(code));
    }
    expect(fixReasonText('open', { code: 'no_fixed_version', message: '' })).not.toBe(
      'The fix failed.',
    );
  });

  it('reads any other code as a failure', () => {
    const failure = { code: 'package_manager', message: 'npm ERR! 404' };
    expect(fixReasonText('open', failure)).toBe('npm ERR! 404');
    expect(fixReasonText('failed', failure)).toBe('npm ERR! 404');
    expect(fixReasonText('no_fix', { code: 'brand_new', message: '' })).toBe(
      noFixText('brand_new'),
    );
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
      'An organization admin must allow fix MRs on the connection.',
    );
    expect(fixPreconditionText({ ...all, monitoringOn: false })).toBe(
      'Vulnerability monitoring is off for this project.',
    );
  });
});
