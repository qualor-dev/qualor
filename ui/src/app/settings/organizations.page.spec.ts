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
import type { Organization } from '../api/types';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { OrganizationsPage } from './organizations.page';

const ACME = '0190a6c2-0000-7000-8000-0000000000ac';
const LABS = '0190a6c2-0000-7000-8000-0000000000fb';

function org(id: string, key: string, name: string): Organization {
  return { id, key, name, deleting: false, createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '' };
}

function setup(options: { admin?: boolean } = {}): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/organizations', {
    body: page([org(ORG_ID, 'default', 'Default'), org(ACME, 'acme', 'Acme')]),
  });
  server.on('GET', '/api/v0/auth/me', { body: me({ admin: options.admin ?? true }) });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: options.admin ?? true }));
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(OrganizationsPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

function row(root: HTMLElement, id: string): HTMLElement {
  return root.querySelector<HTMLElement>(`tr[data-key="${id}"]`)!;
}

function button(root: ParentNode, text: string): HTMLButtonElement {
  return [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;
}

function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

function field(root: HTMLElement, selector: string): HTMLInputElement {
  return root.querySelector<HTMLInputElement>(selector)!;
}

async function openNew(root: HTMLElement, fixture: { whenStable(): Promise<unknown> }) {
  button(root, 'New organization').click();
  await settle(fixture);
  const dialog = root.querySelector<HTMLDialogElement>('dialog#create-dialog')!;
  expect(dialog.open).toBe(true);
  return dialog;
}

async function submit(dialog: HTMLDialogElement, fixture: { whenStable(): Promise<unknown> }) {
  dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
  await settle(fixture);
}

describe('OrganizationsPage (Settings → Organizations)', () => {
  it('lists the organizations with their keys and when each was created, the current one marked', async () => {
    setup();
    const { root } = await render();
    expect(root.querySelector('h2')?.textContent?.trim()).toBe('Organizations');
    const current = row(root, ORG_ID);
    expect(current.querySelector('th')?.textContent).toContain('Default');
    expect(current.querySelector('code')?.textContent?.trim()).toBe('default');
    expect(current.textContent).toContain('Sep 1, 2026');
    expect(current.textContent).toContain('Current');
    expect(row(root, ACME).textContent).not.toContain('Current');
    expect(button(row(root, ACME), 'Switch to')?.getAttribute('aria-label')).toBe('Switch to Acme');
  });

  it('switches to an organization from its row, as the header does', async () => {
    setup();
    const { fixture, root } = await render();
    button(row(root, ACME), 'Switch to').click();
    await settle(fixture);
    expect(TestBed.inject(OrgContext).currentId()).toBe(ACME);
    expect(row(root, ACME).textContent).toContain('Current');
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Acme is the current organization now.',
    );
  });

  it('creates one in the New organization dialog: the key follows the name until it is edited', async () => {
    const server = setup();
    const labs = org(LABS, 'labs', 'Qualor Labs');
    let created = false;
    server.on('POST', '/api/v0/organizations', () => {
      created = true;
      return { status: 201, body: labs };
    });
    // The server lists it from then on (the list may be read again with the session).
    server.on('GET', '/api/v0/organizations', () => ({
      body: page([
        org(ORG_ID, 'default', 'Default'),
        org(ACME, 'acme', 'Acme'),
        ...(created ? [labs] : []),
      ]),
    }));
    const { fixture, root } = await render();
    const dialog = await openNew(root, fixture);
    type(root, '#org-name', 'Qualor Labs');
    await settle(fixture);
    expect(field(root, '#org-key').value).toBe('qualor-labs');
    type(root, '#org-key', 'labs');
    type(root, '#org-name', 'Qualor Labs ');
    await settle(fixture);
    // Edited by hand, the key no longer follows the name.
    expect(field(root, '#org-key').value).toBe('labs');
    await submit(dialog, fixture);
    expect(server.requestsTo('POST', '/api/v0/organizations').map((r) => r.body)).toEqual([
      { key: 'labs', name: 'Qualor Labs' },
    ]);
    expect(dialog.open).toBe(false);
    expect(row(root, LABS).textContent).toContain('Qualor Labs');
    // The header's switcher lists it too, and the session knows its new admin.
    expect(
      TestBed.inject(OrgContext)
        .orgs()
        .map((o) => o.key),
    ).toEqual(['default', 'acme', 'labs']);
    expect(server.requestsTo('GET', '/api/v0/auth/me')).toHaveLength(1);
    expect(root.querySelector('[role="status"]')?.textContent).toContain(
      'Qualor Labs created. You are its admin.',
    );
  });

  it('offers an empty form each time the dialog opens', async () => {
    setup();
    const { fixture, root } = await render();
    const dialog = await openNew(root, fixture);
    type(root, '#org-name', 'Draft');
    button(dialog, 'Cancel').click();
    await settle(fixture);
    await openNew(root, fixture);
    expect(field(root, '#org-name').value).toBe('');
    expect(field(root, '#org-key').value).toBe('');
  });

  it('asks for a name and a key the server takes, on their fields, without sending', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const dialog = await openNew(root, fixture);
    type(root, '#org-key', 'Not A Key');
    await submit(dialog, fixture);
    expect(server.requestsTo('POST', '/api/v0/organizations')).toEqual([]);
    expect(dialog.open).toBe(true);
    expect(root.querySelector('#org-name-error')?.textContent?.trim()).toBe(
      'Enter a name for the organization.',
    );
    expect(root.querySelector('#org-key-error')?.textContent?.trim()).toBe(
      'Use 2 to 64 lowercase letters, digits and hyphens, starting with a letter or a digit.',
    );
    expect(field(root, '#org-key').getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(field(root, '#org-name'));
  });

  it('says on the key field when the key is taken, and keeps the dialog open', async () => {
    const server = setup();
    server.on('POST', '/api/v0/organizations', {
      status: 409,
      body: problem(409, 'ORG_KEY_TAKEN'),
    });
    const { fixture, root } = await render();
    const dialog = await openNew(root, fixture);
    type(root, '#org-name', 'Acme');
    await submit(dialog, fixture);
    expect(dialog.open).toBe(true);
    expect(root.querySelector('#org-key-error')?.textContent?.trim()).toBe(
      'An organization with this key already exists.',
    );
    expect(document.activeElement).toBe(field(root, '#org-key'));
  });

  it('tells someone who is not an instance admin who manages organizations', async () => {
    setup({ admin: false });
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators manage organizations.');
    expect(root.querySelector('table')).toBeNull();
    expect(button(root, 'New organization')).toBeUndefined();
  });
});

describe('OrganizationsPage: New organization after Escape (final review)', () => {
  it('opens the dialog again on a refusal that came after it was closed', async () => {
    const server = setup();
    let answer = (): void => undefined;
    server.on(
      'POST',
      '/api/v0/organizations',
      () =>
        new Promise((resolve) => {
          answer = () => resolve({ status: 409, body: problem(409, 'ORG_KEY_TAKEN') });
        }),
    );
    const { fixture, root } = await render();
    const dialog = await openNew(root, fixture);
    type(root, '#org-name', 'Acme');
    await submit(dialog, fixture);
    dialog.removeAttribute('open');
    dialog.dispatchEvent(new Event('close'));
    await settle(fixture);
    answer();
    await settle(fixture);
    expect(dialog.open).toBe(true);
    expect(root.querySelector('#org-key-error')?.textContent?.trim()).toBe(
      'An organization with this key already exists.',
    );
  });
});

describe('OrganizationsPage: delete an organization (0.16, issue #37)', () => {
  const DELETE = `/api/v0/organizations/${ACME}`;
  let timers = false;

  afterEach(() => {
    localStorage.removeItem('qualor.organizationId');
    if (timers) vi.useRealTimers();
    timers = false;
  });

  /** The server with two organizations and two projects in Acme. */
  function setupDelete(): { server: FakeServer; orgs: Organization[] } {
    const server = setup();
    const orgs = [org(ORG_ID, 'default', 'Default'), org(ACME, 'acme', 'Acme')];
    server.on('GET', '/api/v0/organizations', () => ({ body: page(orgs) }));
    server.on('GET', '/api/v0/projects', (r) => ({
      body: r.query.get('organizationId') === ACME ? page([{ id: 'p1' }, { id: 'p2' }]) : page([]),
    }));
    server.on('DELETE', DELETE, () => {
      orgs[1] = { ...orgs[1]!, deleting: true };
      return { status: 202, body: orgs[1] };
    });
    return { server, orgs };
  }

  async function openDelete(
    root: HTMLElement,
    fixture: { whenStable(): Promise<unknown> },
    id = ACME,
  ) {
    button(row(root, id), 'Delete').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#delete-dialog')!;
    expect(dialog.open).toBe(true);
    return dialog;
  }

  it('gives every row a Delete button in its actions, beside Switch to or Current', async () => {
    setupDelete();
    const { root } = await render();
    for (const id of [ORG_ID, ACME]) {
      const actions = row(root, id).querySelector('.row-actions')!;
      expect(button(actions, 'Delete')).toBeTruthy();
    }
    expect(button(row(root, ACME), 'Delete').getAttribute('aria-label')).toBe('Delete Acme');
  });

  it('names the organization and its projects, and asks for its key before it can be sent', async () => {
    const { server } = setupDelete();
    const { fixture, root } = await render();
    const dialog = await openDelete(root, fixture);
    expect(dialog.textContent).toContain('Acme');
    expect(dialog.textContent).toContain('2 projects');
    const submitButton = button(dialog, 'Delete organization');
    expect(submitButton.getAttribute('aria-disabled')).toBe('true');
    type(root, '#delete-org-key', 'Acme');
    await settle(fixture);
    expect(submitButton.getAttribute('aria-disabled')).toBe('true');
    await submit(dialog, fixture);
    expect(server.requestsTo('DELETE', DELETE)).toEqual([]);
    type(root, '#delete-org-key', 'acme');
    await settle(fixture);
    expect(submitButton.getAttribute('aria-disabled')).toBeNull();
  });

  it('sends the key, announces it, and shows the row as Deleting… with Delete and Switch to off', async () => {
    const { server } = setupDelete();
    const { fixture, root } = await render();
    const dialog = await openDelete(root, fixture);
    type(root, '#delete-org-key', 'acme');
    await settle(fixture);
    await submit(dialog, fixture);
    const sent = server.requestsTo('DELETE', DELETE);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.query.get('confirm')).toBe('acme');
    expect(dialog.open).toBe(false);
    expect(root.querySelector('[role="status"]')?.textContent).toContain('Acme is being deleted.');
    const deleting = row(root, ACME);
    expect(deleting.textContent).toContain('Deleting…');
    expect(button(deleting, 'Delete').disabled).toBe(true);
    expect(button(deleting, 'Switch to').disabled).toBe(true);
  });

  it('says so when it is the last organization, and when a delete of it is already running', async () => {
    const { server } = setupDelete();
    server.on('DELETE', DELETE, { status: 409, body: problem(409, 'LAST_ORGANIZATION') });
    const { fixture, root } = await render();
    const dialog = await openDelete(root, fixture);
    type(root, '#delete-org-key', 'acme');
    await settle(fixture);
    await submit(dialog, fixture);
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector('[role="alert"]')?.textContent?.trim()).toBe(
      'The last organization cannot be deleted.',
    );
    server.on('DELETE', DELETE, { status: 409, body: problem(409, 'ORGANIZATION_DELETING') });
    await submit(dialog, fixture);
    expect(dialog.querySelector('[role="alert"]')?.textContent?.trim()).toBe(
      'A delete of this organization is already running.',
    );
  });

  describe('while one is deleting', () => {
    beforeEach(() => {
      // Only the timers: the fake fetch and Angular's scheduling still run.
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
      timers = true;
    });

    async function flush(fixture: { detectChanges(): void }): Promise<void> {
      for (let i = 0; i < 12; i++) {
        await vi.advanceTimersByTimeAsync(0);
        fixture.detectChanges();
      }
    }

    it('reads the list again every 3 s and stops after 40 reloads', async () => {
      const { server, orgs } = setupDelete();
      orgs[1] = { ...orgs[1]!, deleting: true };
      const fixture = TestBed.createComponent(OrganizationsPage);
      await flush(fixture);
      const reads = () => server.requestsTo('GET', '/api/v0/organizations').length;
      expect(reads()).toBe(1);
      await vi.advanceTimersByTimeAsync(2_999);
      expect(reads()).toBe(1);
      await vi.advanceTimersByTimeAsync(1);
      await flush(fixture);
      expect(reads()).toBe(2);
      for (let i = 0; i < 45; i++) {
        await vi.advanceTimersByTimeAsync(3_000);
        await flush(fixture);
      }
      expect(reads()).toBe(41);
      fixture.destroy();
    });

    it('does not read again when nothing is deleting', async () => {
      const { server } = setupDelete();
      const fixture = TestBed.createComponent(OrganizationsPage);
      await flush(fixture);
      await vi.advanceTimersByTimeAsync(10_000);
      expect(server.requestsTo('GET', '/api/v0/organizations')).toHaveLength(1);
      fixture.destroy();
    });
  });

  it('moves the current organization to another one once it is gone from the list', async () => {
    const { orgs } = setupDelete();
    const { fixture, root } = await render();
    const context = TestBed.inject(OrgContext);
    await context.switchTo(ACME);
    expect(context.currentId()).toBe(ACME);
    orgs.splice(1, 1);
    context.organizations.reload();
    await settle(fixture);
    expect(context.currentId()).toBe(ORG_ID);
    expect(row(root, ORG_ID).textContent).toContain('Current');
  });

  it('shows no organization, without throwing, when none is left', async () => {
    const { orgs } = setupDelete();
    const { fixture, root } = await render();
    orgs.splice(0, orgs.length);
    TestBed.inject(OrgContext).organizations.reload();
    await settle(fixture);
    expect(TestBed.inject(OrgContext).current()).toBeNull();
    expect(root.querySelectorAll('tbody tr')).toHaveLength(0);
    expect(root.textContent).toContain('There is no organization to show.');
  });
});
