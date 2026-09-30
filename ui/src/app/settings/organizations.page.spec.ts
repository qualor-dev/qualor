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
  return { id, key, name, createdAt: '2026-09-01T00:00:00.000Z', updatedAt: '' };
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
