import type { Provider } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
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
import { inScope, REREAD_AFTER_REDELIVERY, type Webhook, WebhookList } from './webhook-list';
import { WebhooksPage } from './webhooks.page';

const PAYMENTS = '0190a6c2-0000-7000-8000-0000000000a1';
const BILLING = '0190a6c2-0000-7000-8000-0000000000a2';
const PROJECTS = [
  { id: PAYMENTS, name: 'Payments' },
  { id: BILLING, name: 'Billing' },
];

function webhook(id: string, url: string, overrides: Partial<Webhook> = {}): Webhook {
  return {
    id,
    organizationId: ORG_ID,
    projectId: null,
    url,
    events: ['analysis.completed'],
    active: true,
    createdAt: '',
    updatedAt: '',
    ...overrides,
  };
}

function setup(extra: Provider[] = []): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server), ...extra],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}

function render(inputs: { projectId?: string | null; projects?: typeof PROJECTS } = {}) {
  const fixture = TestBed.createComponent(WebhookList);
  fixture.componentRef.setInput('organizationId', ORG_ID);
  fixture.componentRef.setInput('canManage', true);
  fixture.componentRef.setInput('projectId', inputs.projectId ?? null);
  fixture.componentRef.setInput('projects', inputs.projects ?? PROJECTS);
  return fixture;
}

function tags(root: HTMLElement, section: number): string[] {
  const panel = root.querySelectorAll('section')[section]!;
  return [...panel.querySelectorAll('.webhook-scope')].map((t) => t.textContent!.trim());
}

function fillAndSubmit(root: HTMLElement, url: string): void {
  const field = root.querySelector<HTMLInputElement>('#webhook-url')!;
  field.value = url;
  field.dispatchEvent(new Event('input'));
  root.querySelector('dialog#create-dialog form')!.dispatchEvent(new Event('submit'));
}

describe('inScope', () => {
  it('keeps everything in organisation scope and one project webhooks in project scope', () => {
    const all = webhook('a', 'https://a.example.com/');
    const mine = webhook('b', 'https://b.example.com/', { projectId: PAYMENTS });
    expect(inScope(all, null)).toBe(true);
    expect(inScope(mine, null)).toBe(true);
    expect(inScope(all, PAYMENTS)).toBe(false);
    expect(inScope(mine, PAYMENTS)).toBe(true);
    expect(inScope(mine, BILLING)).toBe(false);
  });
});

describe('WebhookList: scope', () => {
  it('tags each webhook with its scope and links a project to its settings', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([
        webhook('w1', 'https://a.example.com/'),
        webhook('w2', 'https://b.example.com/', { projectId: PAYMENTS }),
        webhook('w3', 'https://c.example.com/', {
          projectId: '0190a6c2-0000-7000-8000-0000000000ff',
        }),
      ]),
    });
    const fixture = render();
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(tags(root, 0)).toEqual(['All projects']);
    expect(tags(root, 1)).toEqual(['Project: Payments']);
    const link = root
      .querySelectorAll('section')[1]!
      .querySelector<HTMLAnchorElement>('.webhook-scope a')!;
    expect(link.getAttribute('href')).toBe(`/projects/${PAYMENTS}/settings`);
    expect(tags(root, 2)).toEqual(['Project: (deleted)']);
    expect(root.querySelectorAll('section')[2]!.querySelector('.webhook-scope a')).toBeNull();
  });

  it('offers All projects first, then the projects by name, and sends the chosen one', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', { body: page([]) });
    server.on('POST', '/api/v0/webhooks', {
      status: 201,
      body: { ...webhook('w9', 'https://ci.example.com/hook'), secret: 'whsec_x' },
    });
    const fixture = render();
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const create = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
    const select = root.querySelector<HTMLSelectElement>('#webhook-scope')!;
    expect([...select.options].map((o) => o.textContent!.trim())).toEqual([
      'All projects',
      'Billing',
      'Payments',
    ]);

    select.value = PAYMENTS;
    select.dispatchEvent(new Event('change'));
    fillAndSubmit(root, 'https://ci.example.com/hook');
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/webhooks')[0]?.body).toEqual({
      organizationId: ORG_ID,
      url: 'https://ci.example.com/hook',
      events: ['analysis.completed', 'gate.status_changed'],
      projectId: PAYMENTS,
    });
    // Done, then the next one for all projects: no projectId key at all.
    [...create.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Done')!.click();
    await settle(fixture);
    fixture.componentInstance.openCreate();
    await settle(fixture);
    expect(root.querySelector<HTMLSelectElement>('#webhook-scope')!.value).toBe('');
    fillAndSubmit(root, 'https://other.example.com/hook');
    await settle(fixture);
    const second = server.requestsTo('POST', '/api/v0/webhooks')[1]!.body as Record<
      string,
      unknown
    >;
    expect('projectId' in second).toBe(false);
  });

  it('lists only the project webhooks, reading every page, with the scope fixed', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', (request) =>
      request.query.get('cursor') === 'c2'
        ? { body: page([webhook('w3', 'https://c.example.com/', { projectId: PAYMENTS })]) }
        : {
            body: {
              items: [
                webhook('w1', 'https://a.example.com/'),
                webhook('w2', 'https://b.example.com/', { projectId: BILLING }),
              ],
              nextCursor: 'c2',
            },
          },
    );
    server.on('POST', '/api/v0/webhooks', {
      status: 201,
      body: {
        ...webhook('w9', 'https://ci.example.com/hook', { projectId: PAYMENTS }),
        secret: 's',
      },
    });
    const fixture = render({ projectId: PAYMENTS });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const gets = server.requestsTo('GET', '/api/v0/webhooks');
    expect(gets).toHaveLength(2);
    expect(gets[1]!.query.get('cursor')).toBe('c2');
    const urls = [...root.querySelectorAll('section .webhook-url')].map((e) => e.textContent);
    expect(urls).toEqual(['https://c.example.com/']);
    expect(root.querySelector('#webhook-scope')).toBeNull();

    fillAndSubmit(root, 'https://ci.example.com/hook');
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/webhooks')[0]?.body).toMatchObject({
      projectId: PAYMENTS,
    });
  });

  it('says so when the project has no webhook', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([webhook('w1', 'https://a.example.com/')]),
    });
    const fixture = render({ projectId: PAYMENTS });
    await settle(fixture);
    expect((fixture.nativeElement as HTMLElement).textContent).toContain(
      'No webhooks for this project yet.',
    );
  });
});

describe('WebhooksPage: projects of the scope', () => {
  it('reads every page of the organization projects for the tags and the select', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([webhook('w1', 'https://b.example.com/', { projectId: PAYMENTS })]),
    });
    const project = (id: string, name: string) => ({ id, key: name.toLowerCase(), name });
    server.on('GET', '/api/v0/projects', (request) =>
      request.query.get('cursor') === 'p2'
        ? { body: page([project(PAYMENTS, 'Payments')]) }
        : { body: { items: [project(BILLING, 'Billing')], nextCursor: 'p2' } },
    );
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const gets = server.requestsTo('GET', '/api/v0/projects');
    expect(gets).toHaveLength(2);
    expect(gets[0]!.query.get('organizationId')).toBe(ORG_ID);
    expect(gets[0]!.query.get('limit')).toBe('100');
    expect(gets[1]!.query.get('cursor')).toBe('p2');
    expect(tags(root, 0)).toEqual(['Project: Payments']);
    expect(root.querySelectorAll('#webhook-scope option')).toHaveLength(3);
  });
});

describe('WebhookList: reading every page of a project', () => {
  it('does not hang when a refresh is still running as the last page comes', async () => {
    const server = setup();
    let firstCalls = 0;
    let pageTwoCalls = 0;
    let releasePageTwo: () => void = () => undefined;
    let releaseRefresh: () => void = () => undefined;
    const one = webhook('w1', 'https://a.example.com/', { projectId: BILLING });
    const two = webhook('w2', 'https://b.example.com/', { projectId: PAYMENTS });
    server.on('GET', '/api/v0/webhooks', (request) => {
      if (request.query.get('cursor') === 'c2') {
        pageTwoCalls++;
        const reply = { body: page([two]) };
        if (pageTwoCalls > 1) return reply;
        return new Promise((resolve) => (releasePageTwo = () => resolve(reply)));
      }
      firstCalls++;
      const reply = { body: { items: [one], nextCursor: 'c2' } };
      // The refresh after the creation (the second cursor-less read) is held.
      if (firstCalls !== 2) return reply;
      return new Promise((resolve) => (releaseRefresh = () => resolve(reply)));
    });
    server.on('POST', '/api/v0/webhooks', {
      status: 201,
      body: {
        ...webhook('w9', 'https://ci.example.com/hook', { projectId: PAYMENTS }),
        secret: 's',
      },
    });
    const fixture = render({ projectId: PAYMENTS });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    // Nothing of this project is on the first page: the list is not complete, so it says nothing.
    expect(root.querySelectorAll('section')).toHaveLength(0);
    expect(root.textContent).not.toContain('No webhooks for this project yet.');
    expect(root.textContent).not.toContain('Load more');
    fillAndSubmit(root, 'https://ci.example.com/hook');
    await settle(fixture);
    expect(firstCalls).toBe(2);
    // The last page answers while the refresh is still running: the loop must wait, not spin.
    releasePageTwo();
    await settle(fixture);
    expect(root.textContent).not.toContain('No webhooks for this project yet.');
    releaseRefresh();
    await settle(fixture);
    const urls = [...root.querySelectorAll('section .webhook-url')].map((e) => e.textContent);
    expect(urls).toEqual(['https://b.example.com/']);
    expect(root.textContent).not.toContain('Load more');
  }, 5000);

  it('reads on to the last page again after a change leaves a next page', async () => {
    const server = setup();
    let created = false;
    server.on('GET', '/api/v0/webhooks', (request) => {
      const mine = (id: string) =>
        webhook(id, `https://${id}.example.com/`, { projectId: PAYMENTS });
      if (request.query.get('cursor') === 'c2') return { body: page([mine('w2')]) };
      return { body: created ? { items: [mine('w1')], nextCursor: 'c2' } : page([mine('w1')]) };
    });
    server.on('POST', '/api/v0/webhooks', () => {
      created = true;
      return {
        status: 201,
        body: {
          ...webhook('w9', 'https://ci.example.com/hook', { projectId: PAYMENTS }),
          secret: 's',
        },
      };
    });
    const fixture = render({ projectId: PAYMENTS });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelectorAll('section')).toHaveLength(1);
    fillAndSubmit(root, 'https://ci.example.com/hook');
    await settle(fixture);
    const urls = [...root.querySelectorAll('section .webhook-url')].map((e) => e.textContent);
    expect(urls).toEqual(['https://w1.example.com/', 'https://w2.example.com/']);
  });
});

describe('WebhooksPage: the projects are read', () => {
  it('shows a neutral tag until the projects are in, then the name or (deleted)', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([
        webhook('w1', 'https://a.example.com/', { projectId: PAYMENTS }),
        webhook('w2', 'https://b.example.com/', { projectId: BILLING }),
      ]),
    });
    let release: () => void = () => undefined;
    server.on('GET', '/api/v0/projects', () => {
      return new Promise((resolve) => {
        release = () =>
          resolve({
            body: page([{ id: PAYMENTS, key: 'payments', name: 'Payments' }]),
          });
      });
    });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(tags(root, 0)).toEqual(['Project: …']);
    expect(root.textContent).not.toContain('(deleted)');
    release();
    await settle(fixture);
    expect(tags(root, 0)).toEqual(['Project: Payments']);
    expect(tags(root, 1)).toEqual(['Project: (deleted)']);
  });

  it('shows a bare Project tag and an alert when the projects cannot be read', async () => {
    const server = setup();
    server.on('GET', '/api/v0/webhooks', {
      body: page([webhook('w1', 'https://a.example.com/', { projectId: PAYMENTS })]),
    });
    server.on('GET', '/api/v0/projects', { status: 500, body: problem(500, 'INTERNAL') });
    const fixture = TestBed.createComponent(WebhooksPage);
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    expect(tags(root, 0)).toEqual(['Project']);
    expect(root.querySelector('p.alert-error[role="alert"]')).not.toBeNull();
    expect(root.textContent).not.toContain('(deleted)');
  });
});

describe('WebhookList: send a delivery again, rotate the secret', () => {
  const DELIVERY = {
    id: 'd1',
    event: 'analysis.completed',
    status: 'failed',
    attempts: 3,
    responseCode: 500,
    responseExcerpt: null,
    nextAttemptAt: null,
    createdAt: '2026-10-01T10:00:00.000Z',
  };
  const AGAIN = { ...DELIVERY, id: 'd2', status: 'pending', attempts: 0, responseCode: null };

  /** The re-read after a redelivery is scheduled through a stub: the spec fires it by hand. */
  function setupAgain(canManage = true) {
    const scheduled: { run: () => void; cancelled: boolean }[] = [];
    const server = setup([
      {
        provide: REREAD_AFTER_REDELIVERY,
        useValue: (run: () => void) => {
          const entry = { run, cancelled: false };
          scheduled.push(entry);
          return () => (entry.cancelled = true);
        },
      },
    ]);
    server.on('GET', '/api/v0/webhooks', {
      body: page([webhook('w1', 'https://a.example.com/')]),
    });
    let deliveries = [DELIVERY];
    server.on('GET', '/api/v0/webhooks/w1/deliveries', () => ({ body: page(deliveries) }));
    const fixture = render();
    fixture.componentRef.setInput('canManage', canManage);
    return {
      server,
      fixture,
      scheduled,
      setDeliveries: (d: (typeof DELIVERY)[]) => (deliveries = d),
    };
  }

  function sendAgain(root: HTMLElement): HTMLButtonElement | undefined {
    return [...root.querySelectorAll<HTMLButtonElement>('.deliveries button')].find(
      (b) => b.textContent?.trim() === 'Send again',
    );
  }

  function rowButton(root: HTMLElement, text: string): HTMLButtonElement {
    return [...root.querySelectorAll<HTMLButtonElement>('section .row-actions button')].find(
      (b) => b.textContent?.trim() === text,
    )!;
  }

  function dialogButton(dialog: HTMLElement, text: string): HTMLButtonElement {
    return [...dialog.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
  }

  it('offers Send again on each delivery to managers only', async () => {
    const { fixture } = setupAgain(false);
    await settle(fixture);
    expect(sendAgain(fixture.nativeElement)).toBeUndefined();
    expect(fixture.nativeElement.querySelector('dialog#rotate-secret')).toBeNull();
  });

  it('posts the redelivery, shows the queued delivery on top, and reads again later', async () => {
    const { server, fixture, scheduled, setDeliveries } = setupAgain();
    server.on('POST', '/api/v0/webhooks/w1/deliveries/d1/redeliver', { status: 202, body: AGAIN });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    sendAgain(root)!.click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/webhooks/w1/deliveries/d1/redeliver')).toHaveLength(
      1,
    );
    const rows = [...root.querySelectorAll('.deliveries tbody tr')];
    expect(rows).toHaveLength(2);
    expect(rows[0]!.textContent).toContain('Pending');
    expect(server.requestsTo('GET', '/api/v0/webhooks/w1/deliveries')).toHaveLength(1);
    expect(scheduled).toHaveLength(1);
    setDeliveries([{ ...AGAIN, status: 'succeeded', responseCode: 200 }, DELIVERY]);
    scheduled[0]!.run();
    await settle(fixture);
    expect(server.requestsTo('GET', '/api/v0/webhooks/w1/deliveries')).toHaveLength(2);
    expect(root.querySelector('.deliveries tbody tr')!.textContent).toContain('HTTP 200');
  });

  it.each([
    [404, 'NOT_FOUND', 'This delivery is no longer kept.'],
    [409, 'CONFLICT', 'The webhook is switched off: switch it on to send again.'],
    [429, 'RATE_LIMITED', 'Too many redeliveries; try again in a minute.'],
    [500, 'INTERNAL', 'The request failed (HTTP 500, INTERNAL).'],
  ])('shows a %s in the delivery row', async (status, code, text) => {
    const { server, fixture, scheduled } = setupAgain();
    server.on('POST', '/api/v0/webhooks/w1/deliveries/d1/redeliver', {
      status,
      body: problem(status, code),
    });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    sendAgain(root)!.click();
    await settle(fixture);
    expect(root.querySelector('.deliveries tbody tr')!.textContent).toContain(text);
    expect(root.querySelectorAll('.deliveries tbody tr')).toHaveLength(1);
    expect(scheduled).toHaveLength(0);
  });

  it.each(['destroy', 'organisation'] as const)(
    'cancels the re-read when the list is left by %s',
    async (how) => {
      const { server, fixture, scheduled } = setupAgain();
      server.on('POST', '/api/v0/webhooks/w1/deliveries/d1/redeliver', {
        status: 202,
        body: AGAIN,
      });
      await settle(fixture);
      sendAgain(fixture.nativeElement)!.click();
      await settle(fixture);
      expect(scheduled).toHaveLength(1);
      expect(scheduled[0]!.cancelled).toBe(false);
      if (how === 'destroy') {
        fixture.destroy();
      } else {
        fixture.componentRef.setInput('organizationId', '0190a6c2-0000-7000-8000-0000000000bb');
        await settle(fixture);
      }
      expect(scheduled[0]!.cancelled).toBe(true);
    },
  );

  it('rotates the secret in its dialog, shows it once, and keeps it through Escape', async () => {
    const { server, fixture } = setupAgain();
    server.on('POST', '/api/v0/webhooks/w1/regenerate-secret', {
      body: { ...webhook('w1', 'https://a.example.com/'), secret: 'whsec_new' },
    });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const dialog = root.querySelector<HTMLDialogElement>('dialog#rotate-secret')!;
    rowButton(root, 'Rotate secret').click();
    await settle(fixture);
    expect(dialog.open).toBe(true);
    expect(dialog.textContent).toContain(
      'The old secret stops signing at once. Update the receiver with the new one.',
    );
    expect(dialog.querySelector('q-secret-once')).toBeNull();
    dialogButton(dialog, 'Rotate secret').click();
    await settle(fixture);
    expect(server.requestsTo('POST', '/api/v0/webhooks/w1/regenerate-secret')).toHaveLength(1);
    expect(dialog.querySelector<HTMLInputElement>('q-secret-once input')!.value).toBe('whsec_new');
    const cancel = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(cancel);
    expect(cancel.defaultPrevented).toBe(true);
    dialogButton(dialog, 'Done').click();
    await settle(fixture);
    expect(dialog.querySelector('q-secret-once')).toBeNull();
    expect(dialog.open).toBe(false);
    expect(root.textContent).not.toContain('whsec_new');
  });

  it('shows a refused rotation in the dialog', async () => {
    const { server, fixture } = setupAgain();
    server.on('POST', '/api/v0/webhooks/w1/regenerate-secret', {
      status: 409,
      body: problem(409, 'CONFLICT'),
    });
    await settle(fixture);
    const root = fixture.nativeElement as HTMLElement;
    const dialog = root.querySelector<HTMLDialogElement>('dialog#rotate-secret')!;
    rowButton(root, 'Rotate secret').click();
    await settle(fixture);
    dialogButton(dialog, 'Rotate secret').click();
    await settle(fixture);
    expect(dialog.querySelector('[role="alert"]')!.textContent).toContain(
      'Someone else changed this at the same time.',
    );
    expect(dialog.querySelector('q-secret-once')).toBeNull();
  });
});
