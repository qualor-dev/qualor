import { describe, expect, it } from 'vitest';
import { JiraError, type JiraErrorCode } from './client';
import {
  BACKGROUND_PROBLEM_CODES,
  backgroundCodeOf,
  CREDENTIAL_PROBLEM_CODES,
  isCredentialProblem,
  JIRA_PROBLEM_CODES,
  JIRA_PROBLEM_TEXT,
  problemCodeOf,
  type JiraProblemCode,
} from './problems';

const ERROR_CODES: Record<JiraErrorCode, { test: JiraProblemCode; background: string | null }> = {
  token_refused: { test: 'token_refused', background: 'token_refused' },
  captcha: { test: 'captcha', background: 'captcha' },
  redirected: { test: 'redirected', background: 'redirected' },
  not_public: { test: 'not_public', background: 'not_public' },
  unresolved: { test: 'unresolved', background: 'unreachable' },
  timeout: { test: 'timeout', background: 'timeout' },
  unreachable: { test: 'unreachable', background: 'unreachable' },
  permission_missing: { test: 'permission_missing', background: null },
  not_found: { test: 'not_found', background: null },
  rate_limited: { test: 'rate_limited', background: null },
  field_refused: { test: 'http_error', background: null },
  limit_reached: { test: 'http_error', background: null },
  server_error: { test: 'http_error', background: 'unreachable' },
  http_error: { test: 'http_error', background: null },
  bad_answer: { test: 'bad_answer', background: null },
  budget: { test: 'bad_answer', background: null },
};

describe('Jira problem codes', () => {
  it.each(Object.entries(ERROR_CODES))('%s maps to its Test and background codes', (code, want) => {
    const err = new JiraError(code as JiraErrorCode);
    expect(problemCodeOf(err)).toBe(want.test);
    expect(backgroundCodeOf(err)).toBe(want.background);
  });

  it('has a fixed text for every Test code', () => {
    expect(Object.keys(JIRA_PROBLEM_TEXT).sort()).toEqual([...JIRA_PROBLEM_CODES].sort());
    for (const text of Object.values(JIRA_PROBLEM_TEXT)) expect(text.length).toBeGreaterThan(10);
  });

  it('pins the four texts the guide quotes', () => {
    expect(JIRA_PROBLEM_TEXT.no_projects).toBe(
      'The account sees no Jira projects. A scoped API token works only through the API URL https://api.atlassian.com/ex/jira/<cloud id>: set it, or give the account access to a project.',
    );
    expect(JIRA_PROBLEM_TEXT.token_refused).toBe(
      'Jira refused the token (HTTP 401). A Jira Cloud API token lives at most 365 days: create a new one and save it here.',
    );
    expect(JIRA_PROBLEM_TEXT.captcha).toBe(
      'Jira locked the account after failed sign-ins (CAPTCHA). A Jira administrator must reset the lockout before Qualor can sign in again.',
    );
    expect(JIRA_PROBLEM_TEXT.redirected).toBe(
      'Jira answered with a redirect, usually a sign-in proxy or a wrong address. Use the address of Jira itself.',
    );
  });

  it('records only codes that have a Test text', () => {
    for (const code of BACKGROUND_PROBLEM_CODES) expect(JIRA_PROBLEM_CODES).toContain(code);
  });

  it('knows the six credential problems', () => {
    const at = '2026-11-17T10:00:00.000Z';
    for (const code of BACKGROUND_PROBLEM_CODES) {
      expect(isCredentialProblem({ code, message: 'x', at })).toBe(
        (CREDENTIAL_PROBLEM_CODES as readonly string[]).includes(code),
      );
    }
    expect(isCredentialProblem(null)).toBe(false);
    expect(CREDENTIAL_PROBLEM_CODES).toHaveLength(6);
  });
});
