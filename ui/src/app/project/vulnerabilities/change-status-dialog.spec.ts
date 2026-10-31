import { TestBed } from '@angular/core/testing';
import {
  FakeServer,
  FakeVulnerabilities,
  problem,
  provideFakeServer,
  settle,
  vulnerabilityCard,
  type VulnerabilityCard,
} from '../../../testing/fake-server';
import { ChangeStatusDialog, type DialogTarget } from './change-status-dialog';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000a1';
const MAIN = '0190a6c2-0000-7000-8000-0000000000d1';
const PUT = `/api/v0/projects/${PROJECT}/vulnerability-decisions`;
const TARGET: DialogTarget = { kind: 'branch', id: MAIN, name: 'main' };

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();

describe('ChangeStatusDialog', () => {
  let server: FakeServer;
  let fake: FakeVulnerabilities;

  function setup(): void {
    server = new FakeServer();
    TestBed.configureTestingModule({
      imports: [ChangeStatusDialog],
      providers: [provideFakeServer(server)],
    });
    fake = FakeVulnerabilities.install(server, PROJECT);
  }

  beforeEach(setup);

  async function open(item: VulnerabilityCard, target: DialogTarget | null = null) {
    const fixture = TestBed.createComponent(ChangeStatusDialog);
    fixture.componentRef.setInput('projectId', PROJECT);
    fixture.componentRef.setInput('target', target);
    const saved = vi.fn();
    fixture.componentInstance.saved.subscribe(saved);
    fixture.componentInstance.open(item);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const field = <T extends HTMLElement>(id: string) => root.querySelector<T>(`#${id}`);
    const save = () => [...root.querySelectorAll('button')].find((b) => text(b) === 'Save')!;
    const choose = async (id: string, value: string) => {
      const el = field<HTMLSelectElement>(id)!;
      el.value = value;
      el.dispatchEvent(new Event('change'));
      await settle(fixture);
    };
    const type = async (value: string) => {
      const el = field<HTMLTextAreaElement>('vuln-comment')!;
      el.value = value;
      el.dispatchEvent(new Event('input'));
      await settle(fixture);
    };
    return { fixture, root, field, save, choose, type, saved };
  }

  it('keeps Save disabled until Not affected has a reason and a comment', async () => {
    const d = await open(vulnerabilityCard());
    expect(d.save().disabled).toBe(false);
    await d.choose('vuln-status', 'false_positive');
    expect(d.save().disabled).toBe(true);
    await d.type('Only in tests');
    expect(d.save().disabled).toBe(true);
    await d.choose('vuln-reason', 'component_not_present');
    expect(d.save().disabled).toBe(false);
  });

  it('shows the reason only for Not affected, with the five texts', async () => {
    const d = await open(vulnerabilityCard());
    expect(d.field('vuln-reason')).toBeNull();
    await d.choose('vuln-status', 'false_positive');
    const options = [...d.field<HTMLSelectElement>('vuln-reason')!.options].map((o) => text(o));
    expect(options).toEqual([
      '',
      'The package is not in the build',
      'The vulnerable code is not in the build',
      'The vulnerable code is never called',
      'An attacker cannot control the input',
      'Another control already protects it',
    ]);
    await d.choose('vuln-status', 'wont_fix');
    expect(d.field('vuln-reason')).toBeNull();
    expect(d.save().disabled).toBe(true);
    await d.type('Accepted risk');
    expect(d.save().disabled).toBe(false);
  });

  it('sends the project decision and closes with the saved event', async () => {
    const d = await open(vulnerabilityCard());
    await d.choose('vuln-status', 'false_positive');
    await d.choose('vuln-reason', 'vulnerable_code_not_present');
    await d.type('  Not shipped  ');
    d.save().click();
    await settle(d.fixture);
    expect(server.requestsTo('PUT', PUT)[0]?.body).toEqual({
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2026-0001',
      scope: { kind: 'project' },
      status: 'false_positive',
      reason: 'vulnerable_code_not_present',
      comment: 'Not shipped',
    });
    expect(d.saved).toHaveBeenCalledOnce();
    expect(d.root.querySelector('dialog')?.hasAttribute('open')).toBe(false);
    expect(fake.decisions).toHaveLength(1);
  });

  it('sends no reason for Affected, won’t fix', async () => {
    const d = await open(vulnerabilityCard());
    await d.choose('vuln-status', 'wont_fix');
    await d.type('Accepted');
    d.save().click();
    await settle(d.fixture);
    const body = server.requestsTo('PUT', PUT)[0]?.body as Record<string, unknown>;
    expect(body).toMatchObject({ status: 'wont_fix', comment: 'Accepted' });
    expect(body).not.toHaveProperty('reason');
  });

  it('offers Only <target> in the one-target view and not across targets', async () => {
    const across = await open(vulnerabilityCard());
    expect(across.root.querySelectorAll('input[type="radio"]')).toHaveLength(0);
    expect(text(across.root)).toContain('All branches and versions of this project');
    TestBed.resetTestingModule();
    setup();
    const one = await open(vulnerabilityCard(), TARGET);
    const radios = [...one.root.querySelectorAll('label.choice')].map((l) => text(l));
    expect(radios).toEqual(['All branches and versions of this project', 'Only main']);
    expect(one.root.querySelector<HTMLInputElement>('input[type="radio"]')?.checked).toBe(true);
  });

  it('sends the target scope when Only <target> is chosen', async () => {
    const d = await open(vulnerabilityCard(), TARGET);
    await d.choose('vuln-status', 'wont_fix');
    await d.type('Accepted');
    d.root.querySelectorAll<HTMLInputElement>('input[type="radio"]')[1]?.click();
    await settle(d.fixture);
    d.save().click();
    await settle(d.fixture);
    const body = server.requestsTo('PUT', PUT)[0]?.body as Record<string, unknown>;
    expect(body['scope']).toEqual({ kind: 'branch', id: MAIN });
    expect(body).not.toHaveProperty('replaceOverrideOf');
  });

  it('preselects Only <target> for an override and sends replaceOverrideOf for All', async () => {
    const item = vulnerabilityCard({
      status: 'wont_fix',
      decision: {
        id: '0190a6c2-0000-7000-8000-0000000000f1',
        scope: 'branch',
        status: 'wont_fix',
        reason: null,
        comment: 'Accepted here',
        decidedAt: '2026-10-25T10:00:00.000Z',
        decidedBy: null,
      },
    });
    const d = await open(item, TARGET);
    const radios = d.root.querySelectorAll<HTMLInputElement>('input[type="radio"]');
    expect(radios[1]?.checked).toBe(true);
    expect(d.field<HTMLTextAreaElement>('vuln-comment')?.value).toBe('Accepted here');
    radios[0]?.click();
    await settle(d.fixture);
    d.save().click();
    await settle(d.fixture);
    expect(server.requestsTo('PUT', PUT)[0]?.body).toMatchObject({
      scope: { kind: 'project' },
      replaceOverrideOf: { kind: 'branch', id: MAIN },
    });
  });

  it('maps a 422 REASON_REQUIRED to the Reason field', async () => {
    server.on('PUT', PUT, {
      status: 422,
      body: problem(422, 'REASON_REQUIRED', [{ path: 'body.reason', message: 'Required' }]),
    });
    const d = await open(vulnerabilityCard());
    await d.choose('vuln-status', 'false_positive');
    await d.choose('vuln-reason', 'component_not_present');
    await d.type('x');
    d.save().click();
    await settle(d.fixture);
    const error = d.root.querySelector('#vuln-reason-error');
    expect(error?.getAttribute('role')).toBe('alert');
    expect(d.field('vuln-reason')?.getAttribute('aria-describedby')).toBe('vuln-reason-error');
    expect(d.field('vuln-reason')?.getAttribute('aria-invalid')).toBe('true');
    expect(d.saved).not.toHaveBeenCalled();
  });

  it('shows another failure as an alert and keeps the dialog open', async () => {
    server.on('PUT', PUT, { status: 429, body: problem(429, 'RATE_LIMITED') });
    const d = await open(vulnerabilityCard());
    await d.choose('vuln-status', 'wont_fix');
    await d.type('x');
    d.save().click();
    await settle(d.fixture);
    expect(d.root.querySelector('.alert-error')?.getAttribute('role')).toBe('alert');
    expect(d.saved).not.toHaveBeenCalled();
  });
});
