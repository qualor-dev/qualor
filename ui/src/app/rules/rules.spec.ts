import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import {
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { isRuleKey, ProfilePage, type ProfileRule } from './profile.page';
import { isReservedProfileName, type Profile, ProfilesPage } from './profiles.page';
import { type Rule, RulesPage } from './rules.page';

function setup(admin = true): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin }));
  return server;
}

function profile(id: string, name: string, overrides: Partial<Profile> = {}): Profile {
  return {
    id,
    organizationId: ORG_ID,
    name,
    language: 'typescript',
    parentId: null,
    isDefault: false,
    isBuiltin: false,
    unknownRules: 'activate',
    createdAt: '',
    updatedAt: '',
    ...overrides,
  };
}

function profileRule(key: string, overrides: Partial<ProfileRule> = {}): ProfileRule {
  return {
    rule: {
      key,
      name: `Rule ${key}`,
      engine: 'eslint',
      languages: ['typescript'],
      defaultSeverity: 'medium',
      quality: 'reliability',
      kind: 'issue',
    },
    active: true,
    severityOverride: null,
    source: 'default',
    sourceProfileId: null,
    ...overrides,
  };
}

function rule(key: string, helpUri: string | null): Rule {
  return {
    key,
    engine: 'eslint',
    engineRuleId: key,
    name: `Rule ${key}`,
    descriptionMd: '<script>alert(1)</script> `==`',
    helpUri,
    languages: ['typescript'],
    defaultSeverity: 'medium',
    quality: 'reliability',
    kind: 'issue',
    tags: [],
    cwe: [],
    status: 'ready',
    origin: 'reported',
    createdAt: '',
    updatedAt: '',
  };
}

function button(root: HTMLElement, text: string, scope: ParentNode = root): HTMLButtonElement {
  return [...scope.querySelectorAll<HTMLButtonElement>('button')].find(
    (b) => b.textContent?.trim() === text,
  )!;
}

function type(root: HTMLElement, selector: string, value: string, event = 'input'): void {
  const element = root.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!;
  element.value = value;
  element.dispatchEvent(new Event(event));
}

describe('RulesPage', () => {
  it('shows descriptions as text and links only to http(s) documentation', async () => {
    const server = setup();
    server.on('GET', '/api/v0/rules', {
      body: page([rule('eslint:a', 'https://eslint.org/a'), rule('eslint:b', 'javascript:x')]),
    });
    const fixture = TestBed.createComponent(RulesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(server.requestsTo('GET', '/api/v0/rules')[0]?.query.get('organizationId')).toBe(ORG_ID);
    expect(root.querySelector('.prose-text')?.textContent).toBe('<script>alert(1)</script> `==`');
    expect(root.querySelector('script')).toBeNull();
    expect(
      [...root.querySelectorAll('a[target="_blank"]')].map((a) => a.getAttribute('href')),
    ).toEqual(['https://eslint.org/a']);
    expect(root.querySelector('a[target="_blank"]')?.getAttribute('rel')).toBe(
      'noopener noreferrer',
    );
  });

  it('searches on submit and filters by quality and severity', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/rules', { body: page([]) });
    const fixture = TestBed.createComponent(RulesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('No rule matches.');
    type(root, '#rules-search', '  eqeqeq ');
    await settle(fixture);
    // Typing alone asks nothing; the search is sent with the form.
    expect(server.requestsTo('GET', '/api/v0/rules')).toHaveLength(1);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    type(root, '#rules-quality', 'security', 'change');
    await settle(fixture);
    type(root, '#rules-severity', 'high', 'change');
    await settle(fixture);
    const last = server.requestsTo('GET', '/api/v0/rules').at(-1)!.query;
    expect(last.get('q')).toBe('eqeqeq');
    expect(last.get('quality')).toBe('security');
    expect(last.get('severity')).toBe('high');
    expect(last.get('organizationId')).toBe(ORG_ID);
  });
});

describe('ProfilesPage', () => {
  it('groups profiles by language and creates one inheriting from a parent', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', {
      body: page([
        profile('p1', 'Qualor way', { isBuiltin: true, isDefault: true }),
        profile('p2', 'Payments TypeScript', { parentId: 'p1' }),
        profile('p3', 'Qualor way', { language: 'java', isBuiltin: true, isDefault: true }),
      ]),
    });
    server.on('POST', '/api/v0/quality-profiles', {
      status: 201,
      body: profile('p9', 'Strict TS'),
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const ts = root.querySelector('[aria-labelledby="profiles-typescript"]');
    expect(
      [...(ts?.querySelectorAll('tbody tr') ?? [])].map((tr) =>
        tr.children[1]?.textContent?.trim(),
      ),
    ).toEqual(['–', 'Qualor way']);
    expect(root.querySelector('[aria-labelledby="profiles-java"] tbody')?.children).toHaveLength(1);
    const name = root.querySelector<HTMLInputElement>('#profile-name')!;
    name.value = 'Strict TS';
    name.dispatchEvent(new Event('input'));
    const parent = root.querySelector<HTMLSelectElement>('#profile-parent')!;
    parent.value = 'p2';
    parent.dispatchEvent(new Event('change'));
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-profiles')[0]?.body).toEqual({
      organizationId: ORG_ID,
      name: 'Strict TS',
      language: 'typescript',
      parentId: 'p2',
    });
    expect(TestBed.inject(Router).url).toBe('/profiles/p9');
  });

  it('offers as parents only profiles a child can still inherit from (three levels)', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', {
      body: page([
        profile('p1', 'Root'),
        profile('p2', 'Child', { parentId: 'p1' }),
        profile('p3', 'Grandchild', { parentId: 'p2' }),
        profile('p4', 'Java', { language: 'java' }),
      ]),
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const choices = () =>
      [...root.querySelectorAll<HTMLOptionElement>('#profile-parent option')].map((o) => o.value);
    expect(choices()).toEqual(['', 'p1', 'p2']);
    type(root, '#profile-language', 'java', 'change');
    await settle(fixture);
    expect(choices()).toEqual(['', 'p4']);
  });

  it('refuses the reserved built-in name before asking, and shows a 422 next to its field', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', { body: page([]) });
    server.on('POST', '/api/v0/quality-profiles', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.name', message: '"Qualor way" is reserved for the built-in profiles' },
      ]),
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#profile-name', 'QUALOR-way');
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#profile-name-error')?.textContent).toContain(
      'This name is reserved for the built-in profiles.',
    );
    expect(root.querySelector('#profile-name')?.getAttribute('aria-invalid')).toBe('true');
    expect(server.requestsTo('POST', '/api/v0/quality-profiles')).toHaveLength(0);
    // A name the server refuses for a reason the page does not know still lands on the field.
    type(root, '#profile-name', 'Payments');
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-profiles')).toHaveLength(1);
    expect(root.querySelector('#profile-name-error')?.textContent).toContain(
      'This name cannot be used.',
    );
    expect(root.textContent).not.toContain('is reserved for the built-in profiles"');
  });

  it('shows a 422 on the parent next to its field and a limit as an alert', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', { body: page([profile('p1', 'Root')]) });
    let answer = {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.parentId', message: 'Profiles inherit at most 3 levels deep' },
      ]),
    };
    server.on('POST', '/api/v0/quality-profiles', () => answer);
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#profile-name', 'Deep');
    type(root, '#profile-parent', 'p1', 'change');
    await settle(fixture);
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#profile-parent-error')?.textContent).toContain(
      'This profile cannot be the parent',
    );
    answer = { status: 409, body: problem(409, 'PROFILE_LIMIT_REACHED') };
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#profile-parent-error')).toBeNull();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This organization has as many quality profiles as it can have.',
    );
  });

  it('asks before deleting and explains a profile others inherit from', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', { body: page([profile('p2', 'Payments')]) });
    server.on('DELETE', '/api/v0/quality-profiles/p2', {
      status: 409,
      body: problem(409, 'PROFILE_HAS_CHILDREN'),
    });
    const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false);
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Delete').click();
    await settle(fixture);
    expect(confirm).toHaveBeenCalledWith('Delete the quality profile "Payments"?');
    expect(server.requestsTo('DELETE', '/api/v0/quality-profiles/p2')).toHaveLength(0);
    confirm.mockReturnValueOnce(true);
    button(root, 'Delete').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', '/api/v0/quality-profiles/p2')).toHaveLength(1);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'Other profiles inherit from this one; delete them first.',
    );
    confirm.mockRestore();
  });

  it('copies a built-in profile and offers no change to a member', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', {
      body: page([profile('p1', 'Qualor way', { isBuiltin: true, isDefault: true })]),
    });
    server.on('POST', '/api/v0/quality-profiles/p1/copy', {
      status: 201,
      body: profile('p5', 'Qualor way (copy)'),
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const row = root.querySelector('[aria-labelledby="profiles-typescript"] tbody tr')!;
    expect([...row.querySelectorAll('button')].map((b) => b.textContent?.trim())).toEqual(['Copy']);
    button(root, 'Copy', row).click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/quality-profiles/p1/copy')[0]?.body).toEqual({
      name: 'Qualor way (copy)',
    });
    expect(TestBed.inject(Router).url).toBe('/profiles/p5');

    TestBed.inject(SessionStore).set(me({ admin: false }));
    await settle(fixture);
    expect(root.querySelectorAll('button')).toHaveLength(0);
    expect(root.querySelector('form')).toBeNull();
  });
});

describe('isReservedProfileName', () => {
  it('matches the built-in name in any case, spacing or punctuation', () => {
    for (const name of [
      'Qualor way',
      'qualorway',
      'QUALOR-WAY',
      'Qualor_way',
      'Qualor.way',
      'Ｑualor way',
      'Qualor​way',
    ]) {
      expect(isReservedProfileName(name)).toBe(true);
    }
    expect(isReservedProfileName('Qualor way (copy)')).toBe(false);
    expect(isReservedProfileName('Payments')).toBe(false);
  });
});

describe('ProfilePage', () => {
  it('switches a rule off with PUT and lets a set rule inherit again', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments TypeScript') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([
        profileRule('eslint:eqeqeq'),
        profileRule('eslint:no-console', { active: false, source: 'profile' }),
      ]),
    });
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aeqeqeq', {
      body: profileRule('eslint:eqeqeq', { active: false, source: 'profile' }),
    });
    server.on('DELETE', '/api/v0/quality-profiles/p2/rules/eslint%3Ano-console', { status: 204 });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    root.querySelector<HTMLInputElement>('input[aria-label="Active: eslint:eqeqeq"]')!.click();
    await settle(fixture);
    expect(
      server.requestsTo('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aeqeqeq')[0]?.body,
    ).toEqual({ active: false, severityOverride: null });
    const rows = [...root.querySelectorAll('tbody tr')];
    expect(rows[0]?.textContent).toContain('Set here');
    const inherit = [...root.querySelectorAll('button')].filter((b) =>
      b.textContent?.includes('Inherit again'),
    );
    inherit[1]!.click();
    await settle(fixture);
    expect(
      server.requestsTo('DELETE', '/api/v0/quality-profiles/p2/rules/eslint%3Ano-console'),
    ).toHaveLength(1);
  });

  it('keeps a built-in profile read-only', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p1', {
      body: profile('p1', 'Qualor way', { isBuiltin: true }),
    });
    server.on('GET', '/api/v0/quality-profiles/p1/rules', {
      body: page([profileRule('eslint:a')]),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p1');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector<HTMLInputElement>('tbody input')?.disabled).toBe(true);
    expect(root.querySelector('tbody select')).toBeNull();
    expect(root.textContent).toContain('A built-in profile cannot change.');
  });

  it('keeps a custom profile read-only for a member', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([profileRule('eslint:a', { source: 'profile', severityOverride: 'high' })]),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector<HTMLInputElement>('tbody input')?.disabled).toBe(true);
    expect(root.querySelector('tbody select')).toBeNull();
    expect(root.querySelector('tbody')?.textContent).toContain('High');
    expect(button(root, 'Inherit again')).toBeUndefined();
    expect(root.querySelector('#profile-rule-key')).toBeNull();
  });

  it('overrides a severity, and lists every rule the profile could decide on request', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([profileRule('eslint:eqeqeq')]),
    });
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aeqeqeq', {
      body: profileRule('eslint:eqeqeq', { severityOverride: 'blocker', source: 'profile' }),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, 'select[aria-label="Severity: eslint:eqeqeq"]', 'blocker', 'change');
    await settle(fixture);
    expect(
      server.requestsTo('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aeqeqeq')[0]?.body,
    ).toEqual({ active: true, severityOverride: 'blocker' });
    expect(
      server.requestsTo('GET', '/api/v0/quality-profiles/p2/rules')[0]?.query.get('scope'),
    ).toBe('default');
    const all = [...root.querySelectorAll<HTMLInputElement>('form input[type="checkbox"]')][0]!;
    all.click();
    await settle(fixture);
    expect(
      server.requestsTo('GET', '/api/v0/quality-profiles/p2/rules').at(-1)?.query.get('scope'),
    ).toBe('all');
  });

  it('decides a rule by its key even before any report named it (ruling X5)', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', { body: page([]) });
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Ano-eval', {
      body: profileRule('eslint:no-eval', { active: false, source: 'profile' }),
    });
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/gitleaks%3Ageneric-api-key', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'params.ruleKey', message: 'A typescript profile does not decide gitleaks rules' },
      ]),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const form = root.querySelector('#profile-rule-key')!.closest('form')!;
    // Not `<engine>:<rule id>`: refused before asking.
    type(root, '#profile-rule-key', 'no-eval');
    await settle(fixture);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#profile-rule-key-error')?.textContent).toContain(
      'Enter a rule key such as eslint:no-eval.',
    );
    expect(server.requests.filter((r) => r.method === 'PUT')).toHaveLength(0);

    type(root, '#profile-rule-key', ' eslint:no-eval ');
    root.querySelector<HTMLInputElement>('#profile-rule-active')!.click();
    await settle(fixture);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(
      server.requestsTo('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Ano-eval')[0]?.body,
    ).toEqual({ active: false, severityOverride: null });
    expect(root.querySelector('#profile-rule-key-error')).toBeNull();
    // The row is placed in the list as the PUT answered it; nothing is loaded again.
    expect(server.requestsTo('GET', '/api/v0/quality-profiles/p2/rules')).toHaveLength(1);
    expect(root.querySelector('tbody tr[data-key="eslint:no-eval"]')?.textContent).toContain(
      'Set here',
    );
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'eslint:no-eval is now inactive in this profile.',
    );

    type(root, '#profile-rule-key', 'gitleaks:generic-api-key');
    await settle(fixture);
    form.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('#profile-rule-key-error')?.textContent).toContain(
      'This profile cannot decide this rule.',
    );
    expect(root.textContent).not.toContain('does not decide gitleaks rules');
  });

  it('puts a refused change back and says why', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([profileRule('eslint:eqeqeq')]),
    });
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aeqeqeq', {
      status: 409,
      body: problem(409, 'PROFILE_RULE_LIMIT_REACHED'),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const box = () => root.querySelector<HTMLInputElement>('tbody input[type="checkbox"]')!;
    box().click();
    await settle(fixture);
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'This profile sets as many rules itself as it can.',
    );
    expect(box().checked).toBe(true);
  });
});

describe('profiles and rules: focus, in-place updates, announcements (fix round 1)', () => {
  const key = (n: number) => `eslint:r${String(n).padStart(3, '0')}`;

  /** A profile with 120 rules on two pages; `r110` is set in the profile until inherited. */
  function manyRules(server: FakeServer, state: { inherited: boolean }): void {
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    const row = (n: number) =>
      profileRule(
        key(n),
        n === 110 && !state.inherited ? { source: 'profile', active: false } : {},
      );
    server.on('GET', '/api/v0/quality-profiles/p2/rules', (request) => {
      const q = request.query.get('q');
      if (q) {
        const n = Number(q.slice('eslint:r'.length));
        return { body: page([row(n)]) };
      }
      const from = request.query.get('cursor') === 'c1' ? 100 : 0;
      const count = from === 0 ? 100 : 20;
      return {
        body: page(
          Array.from({ length: count }, (_, i) => row(from + i)),
          from === 0 ? 'c1' : null,
        ),
      };
    });
  }

  it('lets a rule on the second page inherit again without reloading the list', async () => {
    const server = setup();
    const state = { inherited: false };
    manyRules(server, state);
    server.on('DELETE', `/api/v0/quality-profiles/p2/rules/${encodeURIComponent(key(110))}`, () => {
      state.inherited = true;
      return { status: 204 };
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Load more').click();
    await settle(fixture);
    expect(root.querySelectorAll('tbody tr[data-key]')).toHaveLength(120);
    const target = root.querySelector(`tr[data-key="${key(110)}"]`)!;
    const other = root.querySelector(`tr[data-key="${key(50)}"]`)!;
    const inherit = button(root, 'Inherit again', target);
    inherit.focus();
    inherit.click();
    await settle(fixture);
    // Both pages stay, with the same row elements; only the rule itself was asked for again.
    expect(root.querySelectorAll('tbody tr[data-key]')).toHaveLength(120);
    expect(root.querySelector(`tr[data-key="${key(110)}"]`)).toBe(target);
    expect(root.querySelector(`tr[data-key="${key(50)}"]`)).toBe(other);
    const lists = server.requestsTo('GET', '/api/v0/quality-profiles/p2/rules');
    expect(lists.map((r) => r.query.get('q') ?? r.query.get('cursor'))).toEqual([
      null,
      'c1',
      key(110),
    ]);
    expect(target.textContent).not.toContain('Set here');
    expect(target.querySelector<HTMLInputElement>('input')?.checked).toBe(true);
    // The button is gone: focus is on the same rule's checkbox, and the change is announced.
    expect(document.activeElement).toBe(target.querySelector('input'));
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      `${key(110)} follows the parent profile again.`,
    );
  });

  it('moves focus to the next row when the inherited rule leaves the list', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    let gone = false;
    server.on('GET', '/api/v0/quality-profiles/p2/rules', (request) => ({
      body: page(
        request.query.get('q')
          ? []
          : [
              profileRule('eslint:a'),
              ...(gone ? [] : [profileRule('eslint:b', { source: 'profile' })]),
              profileRule('eslint:c'),
            ],
      ),
    }));
    server.on('DELETE', '/api/v0/quality-profiles/p2/rules/eslint%3Ab', () => {
      gone = true;
      return { status: 204 };
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const inherit = button(root, 'Inherit again');
    inherit.focus();
    inherit.click();
    await settle(fixture);
    expect(root.querySelector('tr[data-key="eslint:b"]')).toBeNull();
    expect(document.activeElement).toBe(root.querySelector('tr[data-key="eslint:c"] input'));
  });

  it('keeps focus on a switched rule, ignores input while busy, and announces the result', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([profileRule('eslint:a'), profileRule('eslint:b')]),
    });
    let release: () => void = () => undefined;
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Aa', async () => {
      await new Promise<void>((resolve) => (release = resolve));
      return { body: profileRule('eslint:a', { active: false, source: 'profile' }) };
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const a = root.querySelector<HTMLInputElement>('tr[data-key="eslint:a"] input')!;
    const b = root.querySelector<HTMLInputElement>('tr[data-key="eslint:b"] input')!;
    a.focus();
    a.click();
    await settle(fixture);
    expect(a.disabled).toBe(false);
    expect(a.getAttribute('aria-disabled')).toBe('true');
    // A second change while the first runs is ignored and put back.
    b.click();
    await settle(fixture);
    expect(b.checked).toBe(true);
    expect(server.requests.filter((r) => r.method === 'PUT')).toHaveLength(1);
    release();
    await settle(fixture);
    expect(document.activeElement).toBe(a);
    expect(a.checked).toBe(false);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'eslint:a is now inactive in this profile.',
    );
  });

  it('sends the severity a rule has now when switching it, and says the setting stops inheriting', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p3', { body: profile('p3', 'Child') });
    server.on('GET', '/api/v0/quality-profiles/p3/rules', {
      body: page([
        profileRule('eslint:a', {
          source: 'inherited',
          severityOverride: 'blocker',
          sourceProfileId: 'p2',
        }),
      ]),
    });
    server.on('PUT', '/api/v0/quality-profiles/p3/rules/eslint%3Aa', {
      body: profileRule('eslint:a', {
        active: false,
        severityOverride: 'blocker',
        source: 'profile',
      }),
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p3');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.textContent).toContain('Setting a rule here keeps the severity it has now');
    root.querySelector<HTMLInputElement>('tbody input')!.click();
    await settle(fixture);
    expect(
      server.requestsTo('PUT', '/api/v0/quality-profiles/p3/rules/eslint%3Aa')[0]?.body,
    ).toEqual({ active: false, severityOverride: 'blocker' });
  });

  it('resets the page when another profile opens, and ignores the late answer for the old one', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles/p2', { body: profile('p2', 'Payments') });
    server.on('GET', '/api/v0/quality-profiles/p3', { body: profile('p3', 'Other') });
    server.on('GET', '/api/v0/quality-profiles/p2/rules', {
      body: page([profileRule('eslint:a')]),
    });
    server.on('GET', '/api/v0/quality-profiles/p3/rules', {
      body: page([profileRule('eslint:z')]),
    });
    let release: () => void = () => undefined;
    server.on('PUT', '/api/v0/quality-profiles/p2/rules/eslint%3Ano-eval', async () => {
      await new Promise<void>((resolve) => (release = resolve));
      return { body: profileRule('eslint:no-eval', { source: 'profile' }) };
    });
    const fixture = TestBed.createComponent(ProfilePage);
    fixture.componentRef.setInput('profileId', 'p2');
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    type(root, '#profile-rules-search', 'abc');
    type(root, '#profile-rule-key', 'eslint:no-eval');
    await settle(fixture);
    root.querySelector('#profile-rule-key')!.closest('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    fixture.componentRef.setInput('profileId', 'p3');
    await settle(fixture);
    release();
    await settle(fixture);
    expect(root.querySelector('h1')?.textContent).toBe('Other');
    expect(root.querySelector<HTMLInputElement>('#profile-rules-search')!.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#profile-rule-key')!.value).toBe('');
    expect(root.querySelector('tr[data-key="eslint:no-eval"]')).toBeNull();
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
  });

  it('checks rule keys against the server bound of 553 characters in all', () => {
    expect(isRuleKey(`${'a'.repeat(40)}:${'x'.repeat(512)}`)).toBe(true);
    expect(isRuleKey(`eslint:${'x'.repeat(546)}`)).toBe(true);
    expect(isRuleKey(`eslint:${'x'.repeat(547)}`)).toBe(false);
    expect(isRuleKey('eslint:')).toBe(false);
    expect(isRuleKey('ESLint:x')).toBe(false);
    expect(isRuleKey('eslint:a\u0000b')).toBe(false);
  });

  it('reports a refused profile copy as the copy failing, not on the New-profile form', async () => {
    const server = setup();
    server.on('GET', '/api/v0/quality-profiles', { body: page([profile('p2', 'Payments')]) });
    server.on('POST', '/api/v0/quality-profiles/p2/copy', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path: 'body.name', message: 'Reserved' }]),
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    button(root, 'Copy').click();
    await settle(fixture);
    expect(root.querySelector('#profile-name-error')).toBeNull();
    expect(root.querySelector('[role="alert"]')?.textContent).toContain(
      'The copy could not be named after this profile.',
    );
  });

  it('announces a new default profile and keeps focus in its row', async () => {
    const server = setup();
    let isDefault = false;
    server.on('GET', '/api/v0/quality-profiles', () => ({
      body: page([profile('p2', 'Payments', { isDefault })]),
    }));
    server.on('POST', '/api/v0/quality-profiles/p2/set-default', () => {
      isDefault = true;
      return { body: profile('p2', 'Payments', { isDefault: true }) };
    });
    const fixture = TestBed.createComponent(ProfilesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const row = root.querySelector('tr[data-key="p2"]')!;
    const makeDefault = button(root, 'Make default', row);
    makeDefault.focus();
    makeDefault.click();
    await settle(fixture);
    expect(root.querySelector('tr[data-key="p2"]')).toBe(row);
    expect(document.activeElement).toBe(button(root, 'Copy', row));
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Payments is now the default TypeScript profile.',
    );
  });

  it('announces how many rules a search shows', async () => {
    const server = setup(false);
    server.on('GET', '/api/v0/rules', (request) => ({
      body: page(request.query.get('q') ? [rule('eslint:a', null)] : []),
    }));
    const fixture = TestBed.createComponent(RulesPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelector('[role="status"]')?.textContent).toContain('No rule matches.');
    type(root, '#rules-search', 'a');
    root.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('1 rule shown.');
  });
});
