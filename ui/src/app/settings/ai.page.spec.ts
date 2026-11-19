import { ApplicationRef } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import {
  CONFIGURED,
  EMPTY,
  KEY,
  organizationsFixture,
  render,
  setup,
  testAnswer,
  type,
} from '../../testing/ai-settings';
import { type FakeServer, me, ORG_ID, page, problem, settle } from '../../testing/fake-server';
import type { Organization } from '../api/types';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { LeaveConfirm } from '../shared/leave-confirm';
import { unsavedChangesGuard } from '../shared/unsaved-changes';
import { AiSettingsPage } from './ai.page';
import { instanceStatusLines } from './ai/instance-status';
import type { LlmBody, LlmSettings } from './ai/llm-body';
import { settingsRoutes } from './settings.routes';

type Fixture = { whenStable(): Promise<unknown> };
type Stored = LlmSettings['organizations'][string];

const RESEARCH = '0190a6c2-0000-7000-8000-000000000002';
const DEFAULT_ORG: Organization = {
  id: ORG_ID,
  key: 'default',
  name: 'Default',
  deleting: false,
  createdAt: '',
  updatedAt: '',
};
const RESEARCH_ORG: Organization = {
  id: RESEARCH,
  key: 'research',
  name: 'Research',
  deleting: false,
  createdAt: '',
  updatedAt: '',
};
const ONE_MODEL_PASSED = {
  at: '2026-10-26T14:02:00.000Z',
  userId: '0190a6c2-0000-7000-8000-00000000000a',
  models: [
    {
      tier: 'standard',
      model: 'qwen2.5-coder',
      ok: true,
      toolCalling: 'supported',
      problemCode: null,
    },
  ],
};

/** A price pair as the server stores it: no cached input price, null, when the body gave none (R49). */
const storedPair = (pair: {
  inputUsdPerMTok: number;
  outputUsdPerMTok: number;
  cachedInputUsdPerMTok?: number | null;
}) => ({
  inputUsdPerMTok: pair.inputUsdPerMTok,
  outputUsdPerMTok: pair.outputUsdPerMTok,
  cachedInputUsdPerMTok: pair.cachedInputUsdPerMTok ?? null,
});

/** An organisation's stored entry: allowed with Explain and Suggest triage, as CONFIGURED's. */
function stored(over: Partial<Stored> = {}): Stored {
  return { ...(CONFIGURED.organizations[ORG_ID] as Stored), ...over };
}
/** CONFIGURED, with AI review on in Default and confirmed for the provider, and other changes. */
function configured(over: Partial<LlmSettings> = {}): LlmSettings {
  return {
    ...CONFIGURED,
    organizations: {
      [ORG_ID]: stored({ reviewStatus: { enabled: true, consentCurrent: true } }),
    },
    lastTest: ONE_MODEL_PASSED,
    ...over,
  } as LlmSettings;
}

/**
 * Answers `PUT /system/llm` as the server stores a body: its fields in place of the stored ones,
 * the provider and what organisations' admins own as they were; `GET` answers what is stored.
 * `hold` holds the first answer back until the returned function lets it go; `failFirst` answers
 * the first with a 500 and stores nothing of it.
 */
function storeBodies(
  server: FakeServer,
  first: LlmSettings,
  { hold = false, failFirst = false } = {},
): () => void {
  let settings = first;
  let release: () => void = () => undefined;
  const held = hold ? new Promise<void>((resolve) => (release = resolve)) : Promise.resolve();
  let answered = 0;
  server.on('GET', '/api/v0/system/llm', () => ({ body: settings }));
  server.on('PUT', '/api/v0/system/llm', async (request) => {
    const body = request.body as LlmBody;
    if (answered++ === 0) {
      await held;
      if (failFirst) return { status: 500, body: problem(500, 'INTERNAL') };
    }
    settings = {
      ...settings,
      organizations: Object.fromEntries(
        Object.entries(body.organizations).map(([id, entry]) => [
          id,
          {
            ...stored(),
            ...settings.organizations[id],
            enabled: entry.enabled,
            features: entry.features,
            excludedProjectIds: entry.excludedProjectIds,
          },
        ]),
      ),
      excludePaths: body.excludePaths,
      budgets: {
        ...body.budgets,
        reviewTokensPerOrganizationPerDay: body.budgets.reviewTokensPerOrganizationPerDay ?? null,
      },
      pricing: body.pricing && {
        ...storedPair(body.pricing),
        strong: body.pricing.strong ? storedPair(body.pricing.strong) : null,
        fast: body.pricing.fast ? storedPair(body.pricing.fast) : null,
      },
      storePrompts: body.storePrompts,
      promptRetentionDays: body.promptRetentionDays,
    };
    return { body: settings };
  });
  return release;
}

const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();
const field = (root: HTMLElement, id: string) => root.querySelector<HTMLInputElement>(`#${id}`)!;
const button = (within: Element, name: string) =>
  [...within.querySelectorAll<HTMLElement>('button, a')].find((b) => text(b) === name);
/** The Status card's lines, each in words: its label, state, sentence, sub and action. */
const status = (root: HTMLElement) =>
  [...root.querySelectorAll('q-status-list li')].map((li) => text(li));
const statusLine = (root: HTMLElement, key: string) =>
  root.querySelector<HTMLElement>(`q-status-list li[data-key="${key}"]`)!;
const puts = (server: FakeServer) =>
  server.requestsTo('PUT', '/api/v0/system/llm').map((r) => r.body as LlmBody);
const footOf = (root: HTMLElement, section: string) =>
  text(root.querySelector(`section#${section} .foot-status`));

async function click(fixture: Fixture, target: HTMLElement | null | undefined) {
  target!.click();
  await settle(fixture);
}
async function fill(fixture: Fixture, root: HTMLElement, id: string, value: string) {
  type(root, `#${id}`, value);
  await settle(fixture);
}
/** Adds a path never sent, as the Data and privacy section's Add does. */
async function addPath(fixture: Fixture, root: HTMLElement, path: string) {
  await fill(fixture, root, 'ai-exclude-add', path);
  await click(fixture, button(root.querySelector('section#data')!, 'Add'));
}

/** Renders while a navigation waits for its guard, which waits for the person's answer. */
async function renderWhileNavigating(): Promise<void> {
  const app = TestBed.inject(ApplicationRef);
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve));
    app.tick();
  }
}

/** Lets `scrollIntoView` be called, which the test DOM lacks, for the rest of the test. */
function catchScrolls() {
  const scroll = vi.fn();
  const original = Element.prototype.scrollIntoView;
  Element.prototype.scrollIntoView = scroll;
  onTestFinished(() => {
    Element.prototype.scrollIntoView = original;
  });
  return scroll;
}

describe('AiSettingsPage: what it shows', () => {
  it('asks nothing of the server for a user who is not an instance admin', async () => {
    const server = setup(CONFIGURED);
    TestBed.inject(SessionStore).set(me());
    const { root } = await render();
    expect(text(root.querySelector('h2'))).toBe('AI provider');
    expect(root.textContent).toContain('Only instance admins connect the AI provider.');
    expect(server.requests.filter((r) => r.path.startsWith('/api/v0/system/llm'))).toEqual([]);
    expect(root.querySelector('q-status-list')).toBeNull();
  });

  it('works without the organizations, counts those the settings hold, and reads them again on Try again', async () => {
    const server = setup(configured());
    storeBodies(server, configured());
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen3-coder',
        latencyMs: 12,
        toolCalling: 'supported',
        problem: null,
      }),
    });
    server.on('GET', '/api/v0/organizations', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    // The Organizations section says so in place of its table, and the status counts.
    const organizations = root.querySelector('section#organizations')!;
    const alert = organizations.querySelector('[role="alert"]');
    expect(text(alert)).toBe('The organizations could not be loaded. Try again');
    expect(organizations.querySelector('table')).toBeNull();
    expect(text(statusLine(root, 'organizations'))).toBe(
      'Organizations 1 organization may use AI Manage',
    );
    expect(text(statusLine(root, 'review'))).toBe('AI review On in 1 organization');
    // Limits and Data and privacy work as usual.
    await fill(fixture, root, 'ai-budget-explain', '300');
    await click(fixture, button(root.querySelector('section#limits')!, 'Save limits'));
    expect(puts(server)[0]).toMatchObject({ budgets: { explainPerDay: 300 } });

    // The provider still saves, after its question, which counts the organizations it pauses.
    await fill(fixture, root, 'ai-model', 'qwen3-coder');
    await click(fixture, button(root.querySelector('section#provider')!, 'Save and test'));
    expect(text(root.querySelector('#ai-pause-dialog h2'))).toBe(
      'Pause AI review in 1 organization?',
    );
    expect(puts(server)).toHaveLength(1);
    await click(
      fixture,
      button(root.querySelector('#ai-pause-dialog')!, 'Save and pause AI review'),
    );
    expect(puts(server)).toHaveLength(2);
    expect(puts(server)[1]?.provider).toMatchObject({ model: 'qwen3-coder' });

    // Try again reads them, and the table comes back.
    server.on('GET', '/api/v0/organizations', { body: page([DEFAULT_ORG]) });
    await click(fixture, button(alert!, 'Try again'));
    expect(organizations.querySelector('[role="alert"]')).toBeNull();
    expect(text(organizations.querySelector('tbody th'))).toBe('Default default');
    expect(text(statusLine(root, 'organizations').querySelector('.badge'))).toBe(
      '1 of 1 may use AI',
    );
  });

  it('keeps saying the organizations could not be loaded while Try again fails', async () => {
    const server = setup(configured());
    server.on('GET', '/api/v0/organizations', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    const before = server.requestsTo('GET', '/api/v0/organizations').length;
    await click(
      fixture,
      button(root.querySelector('section#organizations [role="alert"]')!, 'Try again'),
    );
    expect(server.requestsTo('GET', '/api/v0/organizations').length).toBeGreaterThan(before);
    expect(text(root.querySelector('section#organizations [role="alert"]'))).toBe(
      'The organizations could not be loaded. Try again',
    );
  });

  it('opens with the status, and shows only Status and Provider before a provider is saved', async () => {
    const server = setup(EMPTY);
    const { root } = await render();
    expect(text(root.querySelector('h2'))).toBe('AI provider');
    expect(text(root.querySelector('.settings-head p'))).toBe(
      "Connect the model that Qualor's AI features use, choose which organizations may use it, and set what it may spend. Nothing is sent to the provider for an organization you have not allowed.",
    );
    expect(status(root)).toEqual([
      'Provider Not connected',
      'Organizations None may use AI',
      'AI review Off everywhere',
    ]);
    expect(root.querySelector('q-ai-provider-section section#provider')).not.toBeNull();
    for (const id of ['organizations', 'limits', 'data']) {
      expect(root.querySelector(`section#${id}`), id).toBeNull();
    }
    expect(root.querySelector('nav.page-index')).toBeNull();
    expect(text(root.querySelector('.ai-sections > p.muted'))).toBe(
      'Once a provider is saved: Organizations · Limits · Data and privacy.',
    );
    // It never reads every project of the instance.
    expect(server.requestsTo('GET', '/api/v0/projects')).toEqual([]);
  });

  it('says the status of a configured provider', async () => {
    setup(configured());
    const { root } = await render();
    expect(status(root)).toEqual([
      'Provider Connected OpenAI-compatible at ollama:11434 · 1 model Tested Oct 26, 2026: the model connects and can call tools. Test again',
      'Organizations 1 of 1 may use AI Default Manage',
      'AI review On in Default',
      'Limits Set Assistant: 1,000,000 tokens a day per organization · AI review: no cap (each organization admin may set up to 1,000,000,000 a day)',
      'Prices Not set Costs are not counted, and cost limits count nothing. Enter prices',
    ]);
    expect(statusLine(root, 'provider').querySelector('.badge')?.classList).toContain(
      'badge-passed',
    );
    // The sections in their order, and the index that leads to them.
    expect(
      [...root.querySelector('.ai-sections')!.children].map((el) => el.tagName.toLowerCase()),
    ).toEqual([
      'q-status-list',
      'q-ai-provider-section',
      'q-ai-organizations-section',
      'q-ai-limits-section',
      'q-ai-data-section',
    ]);
    const index = root.querySelector('nav.page-index')!;
    expect(text(index.querySelector(`#${index.getAttribute('aria-labelledby')}`))).toBe(
      'On this page',
    );
    expect([...index.querySelectorAll('a')].map((a) => text(a))).toEqual([
      'Provider',
      'Organizations',
      'Limits',
      'Data and privacy',
    ]);
    expect(root.querySelector('.ai-sections > p.muted')).toBeNull();
    // The data go to the provider's host.
    expect(text(root.querySelector('#ai-data-sent-help'))).toBe(
      'To ollama:11434, for the organizations you allow.',
    );
  });

  it('says a Test that failed, and one that has not run since the provider changed', async () => {
    setup(
      configured({
        lastTest: {
          ...ONE_MODEL_PASSED,
          models: [
            {
              ...ONE_MODEL_PASSED.models[0]!,
              ok: false,
              toolCalling: 'not_checked',
              problemCode: 'PROVIDER_REFUSED_KEY',
            },
          ],
        } as LlmSettings['lastTest'],
      }),
    );
    const first = await render();
    const failed = statusLine(first.root, 'provider');
    expect(text(failed.querySelector('.badge'))).toBe('Test failed');
    expect(failed.querySelector('.badge')?.classList).toContain('badge-failed');
    expect(text(failed.querySelector('.st-sub'))).toBe(
      'Tested Oct 26, 2026: the test failed for qwen2.5-coder.',
    );

    TestBed.resetTestingModule();
    setup(configured({ lastTest: null }));
    const second = await render();
    expect(text(statusLine(second.root, 'provider').querySelector('.badge'))).toBe('Connected');
    expect(text(statusLine(second.root, 'provider').querySelector('.st-sub'))).toBe(
      'Not tested since the provider changed.',
    );
  });

  it('opens on the section the address names', async () => {
    const scroll = catchScrolls();
    setup(configured(), ['llm.auto-fix'], [{ path: 'settings', children: settingsRoutes }]);
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/settings/ai#limits', AiSettingsPage);
    await settle(harness.fixture);
    const root = harness.routeNativeElement!;
    expect(scroll.mock.contexts.at(-1)).toBe(root.querySelector('section#limits'));
    expect(document.activeElement).toBe(root.querySelector('#ai-limits-heading'));
    // The index leads to the others: a plain click scrolls there and focuses the heading.
    const index = root.querySelector('nav.page-index')!;
    expect(index.querySelector('a')?.getAttribute('href')).toBe('/settings/ai#provider');
    await click(harness.fixture, button(index, 'Data and privacy'));
    expect(document.activeElement).toBe(root.querySelector('#ai-data-heading'));
  });
});

describe('instanceStatusLines', () => {
  const lines = (
    settings: LlmSettings,
    organizations: readonly Organization[] | null = [DEFAULT_ORG],
  ) => instanceStatusLines(settings, organizations, 'en-US');
  const lineOf = (
    settings: LlmSettings,
    key: string,
    organizations?: readonly Organization[] | null,
  ) => lines(settings, organizations).find((l) => l.key === key)!;

  it('names the provider’s kind, host and models, and what its last Test found of each', () => {
    const three = {
      ...configured().provider!,
      strongModel: 'qwen-strong',
      fastModel: 'qwen-fast',
    };
    const tested = (calls: string[]) => ({
      ...ONE_MODEL_PASSED,
      models: ['qwen2.5-coder', 'qwen-strong', 'qwen-fast']
        .slice(0, calls.length)
        .map((model, i) => ({
          tier: (['standard', 'strong', 'fast'] as const)[i]!,
          model,
          ok: true,
          toolCalling: calls[i]!,
          problemCode: null,
        })),
    });
    const all = lineOf(
      configured({
        provider: three,
        lastTest: tested(['supported', 'supported', 'supported']),
      } as Partial<LlmSettings>),
      'provider',
    );
    expect([all.tone, all.state, all.text, all.sub]).toEqual([
      'ok',
      'Connected',
      'OpenAI-compatible at ollama:11434 · 3 models',
      'Tested Oct 26, 2026: all 3 models connect and can call tools.',
    ]);
    expect(all.action).toMatchObject({ id: 'test', label: 'Test again' });
    const without = lineOf(
      configured({
        provider: three,
        lastTest: tested(['supported', 'not_supported', 'not_supported']),
      } as Partial<LlmSettings>),
      'provider',
    );
    expect([without.tone, without.sub]).toEqual([
      'ok',
      'Tested Oct 26, 2026: qwen-strong and qwen-fast cannot call tools.',
    ]);
    const unknown = lineOf(
      configured({
        lastTest: tested(['not_checked']) as LlmSettings['lastTest'],
      } as Partial<LlmSettings>),
      'provider',
    );
    expect(unknown.sub).toBe('Tested Oct 26, 2026: the model connects.');
    const anthropic = lineOf(
      configured({
        provider: {
          ...configured().provider!,
          kind: 'anthropic',
          baseUrl: 'https://api.anthropic.com',
          model: 'claude-sonnet-5-5',
        },
        lastTest: null,
      }),
      'provider',
    );
    expect(anthropic.text).toBe('Anthropic at api.anthropic.com · 1 model');
    // No provider: nothing to test.
    expect(lineOf(EMPTY as unknown as LlmSettings, 'provider')).toMatchObject({
      tone: 'off',
      state: 'Not connected',
      action: null,
    });
  });

  it('counts the organisations that may use AI, and names three of them', () => {
    const orgs = organizationsFixture(5);
    const allowed = (n: number) =>
      configured({
        organizations: Object.fromEntries(
          orgs
            .slice(0, n)
            .map((o) => [
              o.id,
              stored({ reviewStatus: { enabled: false, consentCurrent: false } }),
            ]),
        ),
      });
    expect(lineOf(allowed(5), 'organizations', orgs)).toMatchObject({
      tone: 'ok',
      state: '5 of 5 may use AI',
      sub: 'Org 1, Org 2, Org 3, and 2 more',
      action: { id: 'manage', label: 'Manage', ariaLabel: 'Manage organizations' },
    });
    expect(lineOf(allowed(3), 'organizations', orgs).sub).toBe('Org 1, Org 2, and Org 3');
    expect(lineOf(allowed(0), 'organizations', orgs)).toMatchObject({
      tone: 'off',
      state: 'None may use AI',
      sub: null,
    });
  });

  it('says where AI review is on or paused, in the server’s order of reasons', () => {
    const orgs = [DEFAULT_ORG, RESEARCH_ORG];
    const review = (
      def: Partial<Stored>,
      research: Partial<Stored> | null,
      over: Partial<LlmSettings> = {},
    ) =>
      lineOf(
        configured({
          organizations: {
            [ORG_ID]: stored(def),
            ...(research === null ? {} : { [RESEARCH]: stored(research) }),
          },
          ...over,
        }),
        'review',
        orgs,
      );
    const on = { reviewStatus: { enabled: true, consentCurrent: true } };
    const paused = { reviewStatus: { enabled: true, consentCurrent: false } };
    expect(review(on, null)).toMatchObject({ tone: 'ok', state: 'On in Default' });
    expect(review(on, on)).toMatchObject({ tone: 'ok', state: 'On in Default and Research' });
    expect(review(on, paused)).toMatchObject({
      tone: 'attention',
      state: 'Paused in Research',
      text: 'On in Default',
    });
    // An organisation that may not use AI reviews nothing, whatever its admins switched on.
    expect(review({ ...on, enabled: false }, null)).toMatchObject({
      tone: 'off',
      state: 'Off everywhere',
    });
    // Nor does any without a provider.
    expect(review(on, null, { provider: null })).toMatchObject({ state: 'Off everywhere' });
    // One the settings do not hold has it off.
    expect(review({ reviewStatus: { enabled: false, consentCurrent: false } }, null).state).toBe(
      'Off everywhere',
    );
  });

  it('counts what the settings hold while the organizations could not be read', () => {
    const on = { reviewStatus: { enabled: true, consentCurrent: true } };
    const paused = { reviewStatus: { enabled: true, consentCurrent: false } };
    const settings = configured({
      organizations: {
        [ORG_ID]: stored(on),
        [RESEARCH]: stored(on),
        '0190a6c2-0000-7000-8000-000000000003': stored(paused),
        '0190a6c2-0000-7000-8000-000000000004': stored({ ...on, enabled: false }),
      },
    });
    expect(lineOf(settings, 'organizations', null)).toMatchObject({
      tone: 'ok',
      state: '3 organizations may use AI',
      sub: null,
      action: { id: 'manage' },
    });
    expect(lineOf(settings, 'review', null)).toMatchObject({
      tone: 'attention',
      state: 'Paused in 1 organization',
      text: 'On in 2 organizations',
    });
    expect(lineOf(configured({ organizations: {} }), 'organizations', null)).toMatchObject({
      tone: 'off',
      state: 'None may use AI',
    });
  });

  it('says the limits, the cap, and the prices set', () => {
    const capped = lineOf(
      configured({
        budgets: { ...CONFIGURED.budgets, reviewTokensPerOrganizationPerDay: 750_000 },
      }),
      'limits',
    );
    expect([capped.tone, capped.state, capped.text]).toEqual([
      'ok',
      'Set',
      'Assistant: 1,000,000 tokens a day per organization · AI review: capped at 750,000 tokens a day per organization',
    ]);
    const prices = { inputUsdPerMTok: 1, outputUsdPerMTok: 2, cachedInputUsdPerMTok: null };
    expect(
      lineOf(configured({ pricing: { ...prices, strong: null, fast: null } }), 'prices'),
    ).toMatchObject({
      tone: 'ok',
      state: 'Set for 1 model',
      sub: null,
      action: null,
    });
    expect(
      lineOf(configured({ pricing: { ...prices, strong: prices, fast: prices } }), 'prices').state,
    ).toBe('Set for 3 models');
    expect(lineOf(configured(), 'prices')).toMatchObject({
      tone: 'off',
      state: 'Not set',
      sub: 'Costs are not counted, and cost limits count nothing.',
      action: { id: 'prices', label: 'Enter prices' },
    });
    // Before a provider is saved, neither: there is nothing to limit or price yet.
    expect(lines(EMPTY as unknown as LlmSettings).map((l) => l.key)).toEqual([
      'provider',
      'organizations',
      'review',
    ]);
  });
});

describe('AiSettingsPage: its actions', () => {
  it('tests the provider again from its status, and reads the settings again for the status', async () => {
    const server = setup(configured());
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen2.5-coder',
        latencyMs: 12,
        toolCalling: 'supported',
        problem: null,
      }),
    });
    const { fixture, root } = await render();
    expect(server.requestsTo('GET', '/api/v0/system/llm')).toHaveLength(1);
    await click(fixture, button(statusLine(root, 'provider'), 'Test again'));
    expect(server.requestsTo('POST', '/api/v0/system/llm/test')).toHaveLength(1);
    expect(server.requestsTo('GET', '/api/v0/system/llm')).toHaveLength(2);
  });

  it('hides the status’s Test again while the provider has unsaved edits, as the section hides its own', async () => {
    setup(configured());
    const { fixture, root } = await render();
    expect(button(statusLine(root, 'provider'), 'Test again')).toBeDefined();
    await fill(fixture, root, 'ai-model', 'qwen3-coder');
    expect(root.querySelector('#ai-test-again')).toBeNull();
    expect(button(statusLine(root, 'provider'), 'Test again')).toBeUndefined();
    // The rest of the line stays.
    expect(text(statusLine(root, 'provider').querySelector('.badge'))).toBe('Connected');
    await fill(fixture, root, 'ai-model', 'qwen2.5-coder');
    expect(button(statusLine(root, 'provider'), 'Test again')).toBeDefined();
  });

  it('leads from the status to the organizations and to the prices', async () => {
    catchScrolls();
    setup(configured());
    const { fixture, root } = await render();
    const manage = button(statusLine(root, 'organizations'), 'Manage');
    // The button names its object.
    expect(manage?.getAttribute('aria-label')).toBe('Manage organizations');
    await click(fixture, manage);
    expect(document.activeElement).toBe(root.querySelector('#ai-orgs-heading'));
    await click(fixture, button(statusLine(root, 'prices'), 'Enter prices'));
    expect(document.activeElement).toBe(field(root, 'ai-prices'));
  });

  it('asks nothing before a model change where AI review is off everywhere: an organisation that may not use AI reviews nothing', async () => {
    const settings = configured({
      organizations: {
        [ORG_ID]: stored({
          enabled: false,
          reviewStatus: { enabled: true, consentCurrent: true },
        }),
      },
    });
    const server = setup(settings);
    storeBodies(server, settings);
    server.on('GET', '/api/v0/organizations', { body: page([DEFAULT_ORG]) });
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen3-coder',
        latencyMs: 12,
        toolCalling: 'supported',
        problem: null,
      }),
    });
    const { fixture, root } = await render();
    expect(text(statusLine(root, 'review'))).toBe('AI review Off everywhere');
    await fill(fixture, root, 'ai-model', 'qwen3-coder');
    await click(fixture, button(root.querySelector('section#provider')!, 'Save and test'));
    expect(root.querySelector<HTMLDialogElement>('#ai-pause-dialog')?.open).toBe(false);
    expect(puts(server)).toHaveLength(1);
    expect(puts(server)[0]?.provider).toMatchObject({ model: 'qwen3-coder' });
  });

  it('gives the provider every organisation, so its question names one listed on a later page', async () => {
    const first = organizationsFixture(100);
    const late: Organization = { ...RESEARCH_ORG, name: 'Late Org' };
    const server = setup(
      configured({
        organizations: {
          [RESEARCH]: stored({ reviewStatus: { enabled: true, consentCurrent: true } }),
        },
      }),
    );
    server.on('GET', '/api/v0/organizations', (request) =>
      request.query.get('cursor') === 'next'
        ? { body: page([late]) }
        : { body: page(first, 'next') },
    );
    const { fixture, root } = await render();
    await fill(fixture, root, 'ai-model', 'qwen3-coder');
    await click(fixture, button(root.querySelector('section#provider')!, 'Save and test'));
    expect(text(root.querySelector('#ai-pause-dialog h2'))).toBe('Pause AI review in Late Org?');
    expect(puts(server)).toEqual([]);
    expect(text(statusLine(root, 'organizations').querySelector('.badge'))).toBe(
      '1 of 101 may use AI',
    );
  });
});

describe('AiSettingsPage: saving', () => {
  it('sends the other sections as stored, and keeps their drafts (Review Focus 2)', async () => {
    const server = setup(CONFIGURED);
    storeBodies(server, CONFIGURED as LlmSettings);
    const { fixture, root } = await render();
    const explain = field(root, 'ai-budget-explain');
    await fill(fixture, root, 'ai-budget-explain', '300');
    await addPath(fixture, root, 'legacy/**');
    await click(fixture, button(root.querySelector('section#data')!, 'Save data and privacy'));
    expect(puts(server)[0]).toMatchObject({
      budgets: { explainPerDay: 200 },
      excludePaths: ['legacy/**'],
    });
    expect(footOf(root, 'limits')).toBe('1 unsaved change');
    expect(explain.value).toBe('300');
    await click(fixture, button(root.querySelector('section#limits')!, 'Save limits'));
    expect(puts(server)[1]).toMatchObject({
      budgets: { explainPerDay: 300 },
      excludePaths: ['legacy/**'],
    });
    expect(footOf(root, 'limits')).toMatch(/^Saved at /);
  });

  it('sends one save at a time, each built on the answer to the one before', async () => {
    const server = setup(CONFIGURED);
    const release = storeBodies(server, CONFIGURED as LlmSettings, { hold: true });
    const { fixture, root } = await render();
    await fill(fixture, root, 'ai-budget-explain', '300');
    await addPath(fixture, root, 'legacy/**');
    // Both saves start before the first is answered.
    button(root.querySelector('section#limits')!, 'Save limits')!.click();
    button(root.querySelector('section#data')!, 'Save data and privacy')!.click();
    await settle(fixture);
    expect(puts(server)).toHaveLength(1);
    expect(footOf(root, 'data')).toBe('Saving…');
    release();
    await settle(fixture);
    expect(puts(server)).toHaveLength(2);
    expect(puts(server)[1]).toMatchObject({
      budgets: { explainPerDay: 300 },
      excludePaths: ['legacy/**'],
    });
    expect(footOf(root, 'limits')).toMatch(/^Saved at /);
    expect(footOf(root, 'data')).toMatch(/^Saved at /);
  });

  it('sends a later save after one that failed', async () => {
    const server = setup(CONFIGURED);
    storeBodies(server, CONFIGURED as LlmSettings, { failFirst: true });
    const { fixture, root } = await render();
    await fill(fixture, root, 'ai-budget-explain', '300');
    await addPath(fixture, root, 'legacy/**');
    await click(fixture, button(root.querySelector('section#limits')!, 'Save limits'));
    expect(puts(server)).toHaveLength(1);
    expect(root.querySelector('section#limits .foot-status.bad')).not.toBeNull();
    await click(fixture, button(root.querySelector('section#data')!, 'Save data and privacy'));
    expect(puts(server)).toHaveLength(2);
    // Built on what is stored: the limits that failed are not in it.
    expect(puts(server)[1]).toMatchObject({
      budgets: { explainPerDay: 200 },
      excludePaths: ['legacy/**'],
    });
    expect(footOf(root, 'data')).toMatch(/^Saved at /);
    expect(field(root, 'ai-budget-explain').value).toBe('300');
  });

  it('sends a key typed with the provider’s save only, never with a later save', async () => {
    const server = setup(configured({ lastTest: null }));
    storeBodies(server, configured({ lastTest: null }));
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen2.5-coder',
        latencyMs: 12,
        toolCalling: 'supported',
        problem: null,
      }),
    });
    const { fixture, root } = await render();
    await click(fixture, button(root.querySelector('section#provider')!, 'Replace the key'));
    await fill(fixture, root, 'ai-key', KEY);
    await click(fixture, button(root.querySelector('section#provider')!, 'Save and test'));
    expect(puts(server)[0]?.provider).toHaveProperty('apiKey', KEY);
    await fill(fixture, root, 'ai-budget-fix', '30');
    await click(fixture, button(root.querySelector('section#limits')!, 'Save limits'));
    expect(puts(server)).toHaveLength(2);
    expect(JSON.stringify(puts(server)[1])).not.toContain(KEY);
    expect(puts(server)[1]?.provider).not.toHaveProperty('apiKey');
    // Nothing on the page holds it, attributes included.
    expect(new XMLSerializer().serializeToString(root)).not.toContain(KEY);
    expect(root.querySelector<HTMLInputElement>('#ai-key')?.value ?? '').toBe('');
  });

  it('saves an organisation’s entry with the other organisations as stored', async () => {
    const server = setup(CONFIGURED);
    storeBodies(server, CONFIGURED as LlmSettings);
    const { fixture, root } = await render();
    await click(fixture, button(root.querySelector('section#organizations')!, 'Edit'));
    await click(fixture, field(root, `org-${ORG_ID}-fix`));
    await click(fixture, button(root.querySelector('tr.editor')!, 'Save Default'));
    expect(puts(server)[0]?.organizations).toEqual({
      [ORG_ID]: {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [],
      },
    });
  });
});

describe('AiSettingsPage: leaving', () => {
  afterEach(() => localStorage.clear());

  it('asks before leaving with unsaved changes in any section', async () => {
    setup(CONFIGURED);
    const { fixture, root, page: aiPage } = await render();
    expect(aiPage.canLeave()).toBe(true);
    await fill(fixture, root, 'ai-budget-explain', '300');
    await addPath(fixture, root, 'legacy/**');
    const unload = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);

    const leave = root.querySelector<HTMLDialogElement>('q-leave-confirm dialog')!;
    let answer = aiPage.canLeave() as Promise<boolean>;
    await settle(fixture);
    expect(leave.open).toBe(true);
    expect(text(leave.querySelector('#leave-text'))).toBe(
      'Your changes to Limits and Data and privacy are not saved yet.',
    );
    await click(fixture, button(leave, 'Stay'));
    await expect(answer).resolves.toBe(false);
    answer = aiPage.canLeave() as Promise<boolean>;
    await settle(fixture);
    await click(fixture, button(leave, 'Leave without saving'));
    await expect(answer).resolves.toBe(true);
  });

  it('asks before leaving a path typed and not added', async () => {
    setup(CONFIGURED);
    const { fixture, root, page: aiPage } = await render();
    await fill(fixture, root, 'ai-exclude-add', 'legacy/**');
    const unload = new Event('beforeunload', { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);

    const leave = root.querySelector<HTMLDialogElement>('q-leave-confirm dialog')!;
    const answer = aiPage.canLeave() as Promise<boolean>;
    await settle(fixture);
    expect(leave.open).toBe(true);
    expect(text(leave.querySelector('#leave-text'))).toBe(
      'Your changes to Data and privacy are not saved yet.',
    );
    await click(fixture, button(leave, 'Stay'));
    await expect(answer).resolves.toBe(false);
    expect(field(root, 'ai-exclude-add').value).toBe('legacy/**');
  });

  it('lets the header switch the organisation without asking, and keeps the drafts: nothing on it depends on the organisation', async () => {
    const server = setup(CONFIGURED);
    server.on('GET', '/api/v0/organizations', { body: page([DEFAULT_ORG, RESEARCH_ORG]) });
    const { fixture, root } = await render();
    const org = TestBed.inject(OrgContext);
    expect(org.currentId()).toBe(ORG_ID);
    await fill(fixture, root, 'ai-budget-explain', '300');
    const ask = vi.spyOn(LeaveConfirm.prototype, 'ask');
    onTestFinished(() => ask.mockRestore());
    const leave = root.querySelector<HTMLDialogElement>('q-leave-confirm dialog')!;

    // As the header's select does.
    expect(await org.switchTo(RESEARCH)).toBe(true);
    await settle(fixture);
    expect(ask).not.toHaveBeenCalled();
    expect(leave.open).toBe(false);
    expect(org.currentId()).toBe(RESEARCH);
    expect(field(root, 'ai-budget-explain').value).toBe('300');
    expect(footOf(root, 'limits')).toBe('1 unsaved change');
  });

  it('has the route ask it before the router leaves, under its own title', () => {
    const route = settingsRoutes.find((r) => r.path === 'ai')!;
    expect(route.title).toBe('AI provider');
    expect(route.canDeactivate).toEqual([unsavedChangesGuard]);
  });

  it('asks once when Open leaves unsaved changes; Stay changes nothing', async () => {
    const server = setup(
      CONFIGURED,
      ['llm.auto-fix'],
      [{ path: 'settings', children: settingsRoutes }],
    );
    server.on('GET', '/api/v0/organizations', { body: page([DEFAULT_ORG, RESEARCH_ORG]) });
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/settings/ai', AiSettingsPage);
    await settle(harness.fixture);
    const root = harness.routeNativeElement!;
    const org = TestBed.inject(OrgContext);
    const router = TestBed.inject(Router);
    expect(org.currentId()).toBe(ORG_ID);
    await fill(harness.fixture, root, 'ai-budget-explain', '300');
    const ask = vi.spyOn(LeaveConfirm.prototype, 'ask');
    onTestFinished(() => ask.mockRestore());
    const leave = root.querySelector<HTMLDialogElement>('q-leave-confirm dialog')!;
    const openResearch = () =>
      [...root.querySelectorAll<HTMLButtonElement>('section#organizations tbody tr')]
        .find((tr) => text(tr.querySelector('th'))?.startsWith('Research'))!
        .querySelector<HTMLButtonElement>('button[aria-label="Open Research\'s AI page"]')!;

    openResearch().click();
    await renderWhileNavigating();
    expect(leave.open).toBe(true);
    await click(harness.fixture, button(leave, 'Stay'));
    await renderWhileNavigating();
    expect(ask).toHaveBeenCalledTimes(1);
    expect(org.currentId()).toBe(ORG_ID);
    expect(router.url).toBe('/settings/ai');
    expect(field(root, 'ai-budget-explain').value).toBe('300');

    openResearch().click();
    await renderWhileNavigating();
    expect(leave.open).toBe(true);
    button(leave, 'Leave without saving')!.click();
    await renderWhileNavigating();
    await harness.fixture.whenStable();
    // One question for the switch and the navigation together.
    expect(ask).toHaveBeenCalledTimes(2);
    expect(org.currentId()).toBe(RESEARCH);
    expect(router.url).toBe('/settings/ai-review');
  });

  it('switches at once when nothing is unsaved', async () => {
    const server = setup(
      CONFIGURED,
      ['llm.auto-fix'],
      [{ path: 'settings', children: settingsRoutes }],
    );
    server.on('GET', '/api/v0/organizations', { body: page([DEFAULT_ORG, RESEARCH_ORG]) });
    const harness = await RouterTestingHarness.create();
    await harness.navigateByUrl('/settings/ai', AiSettingsPage);
    await settle(harness.fixture);
    const root = harness.routeNativeElement!;
    const ask = vi.spyOn(LeaveConfirm.prototype, 'ask');
    onTestFinished(() => ask.mockRestore());
    root.querySelector<HTMLButtonElement>('button[aria-label="Open Research\'s AI page"]')!.click();
    await renderWhileNavigating();
    await harness.fixture.whenStable();
    expect(ask).not.toHaveBeenCalled();
    expect(TestBed.inject(OrgContext).currentId()).toBe(RESEARCH);
    expect(TestBed.inject(Router).url).toBe('/settings/ai-review');
  });
});
