import { TestBed } from '@angular/core/testing';
import {
  FakeServer,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import type { ProjectDto } from '../current-project';
import { ProjectTokensPanel } from './project-tokens-panel';

const PROJECT = '0190a6c2-0000-7000-8000-0000000000f1';
const LIST = `/api/v0/projects/${PROJECT}/tokens`;

function project(): ProjectDto {
  return {
    id: PROJECT,
    organizationId: ORG_ID,
    key: 'acme/payments',
    name: 'Payments',
    mainBranchName: 'main',
    qualityGateId: null,
    newCodeDefinition: null,
    scmConnectionId: null,
    scmProjectRef: null,
    createdAt: '',
    updatedAt: '',
    permissions: ['project.read', 'project.tokens.manage'],
  } as ProjectDto;
}

function token(id: string, name: string, over: Record<string, unknown> = {}) {
  return {
    id,
    name,
    prefix: `qlr_${id}`,
    scopes: ['analysis:write'],
    expiresAt: null,
    lastUsedAt: null,
    createdAt: '2026-09-01T10:00:00.000Z',
    ...over,
  };
}

function setup(items = [token('t1', 'ci'), token('t2', 'nightly')]): FakeServer {
  let rows = items;
  const server = new FakeServer();
  server.on('GET', LIST, () => ({ body: page(rows) }));
  server.on('DELETE', `${LIST}/t1`, () => {
    rows = rows.filter((t) => t.id !== 't1');
    return { status: 204 };
  });
  server.on('POST', LIST, (req) => {
    const name = (req.body as { name: string }).name;
    rows = [...rows, token('t9', name)];
    return { status: 201, body: { ...token('t9', name), token: 'qlr_secret-value' } };
  });
  TestBed.configureTestingModule({ providers: [provideFakeServer(server)] });
  return server;
}

async function render() {
  const fixture = TestBed.createComponent(ProjectTokensPanel);
  fixture.componentRef.setInput('project', project());
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}

const button = (root: ParentNode, text: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text)!;

function type(root: ParentNode, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event('input'));
}

describe('ProjectTokensPanel (spec §3.4)', () => {
  it('renders its section, heading, New token button and the rows', async () => {
    setup([
      token('t1', 'ci', {
        expiresAt: '2027-01-01T00:00:00.000Z',
        lastUsedAt: '2026-09-20T08:00:00.000Z',
      }),
      token('t2', 'nightly'),
    ]);
    const { root } = await render();
    const section = root.querySelector('section.card.panel')!;
    expect(section.id).toBe('tokens');
    const head = section.querySelector('.panel-head')!;
    expect(head.querySelector('h2')?.textContent?.trim()).toBe('Analysis tokens');
    expect(head.querySelector('h2')?.getAttribute('tabindex')).toBe('-1');
    expect(button(head, 'New token').classList.contains('btn')).toBe(true);
    expect(button(head, 'New token').classList.contains('btn-primary')).toBe(false);
    expect(button(head, 'New token').querySelector('q-icon')).not.toBeNull();
    expect(root.querySelectorAll('tbody tr[data-key]')).toHaveLength(2);
    const first = root.querySelector('tr[data-key="t1"]')!;
    expect(first.textContent).toContain('ci');
    expect(first.querySelector('code')?.textContent).toContain('qlr_t1…');
    expect(first.textContent).toContain('2027');
    expect(first.textContent).not.toContain('Never');
    const second = root.querySelector('tr[data-key="t2"]')!;
    expect(second.textContent).toContain('Never');
    expect(second.textContent).toContain('Never used');
  });

  it('keeps the loaded list when the project is read again', async () => {
    const server = setup();
    const { fixture, root } = await render();
    expect(server.requestsTo('GET', LIST)).toHaveLength(1);
    fixture.componentRef.setInput('project', project());
    await settle(fixture);
    expect(server.requestsTo('GET', LIST)).toHaveLength(1);
    expect(root.querySelectorAll('tbody tr[data-key]')).toHaveLength(2);
  });

  it('asks for at most 50 tokens', async () => {
    const server = setup();
    await render();
    expect(server.requestsTo('GET', LIST)[0]!.query.get('limit')).toBe('50');
  });

  it('creates a token: default 90 days, secret shown once, Done drops it and refreshes', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    expect(dialog.open).toBe(false);
    button(root, 'New token').click();
    await settle(fixture);
    expect(dialog.open).toBe(true);
    const select = dialog.querySelector<HTMLSelectElement>('#project-token-expiry')!;
    expect([...select.options].map((o) => o.value)).toEqual(['30', '90', '365', '']);
    expect(select.value).toBe('90');
    type(dialog, '#project-token-name', 'release');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', LIST)[0]!.body).toEqual({
      name: 'release',
      expiresInDays: 90,
    });
    expect(dialog.open).toBe(true);
    expect(dialog.querySelector<HTMLInputElement>('#secret-once')?.value).toBe('qlr_secret-value');
    expect(dialog.querySelector('#project-token-name')).toBeNull();
    expect(root.querySelector('tr[data-key="t9"]')).not.toBeNull();
    button(dialog, 'Done').click();
    await settle(fixture);
    expect(dialog.open).toBe(false);
    expect(root.querySelector('#secret-once')).toBeNull();
    expect(root.textContent).not.toContain('qlr_secret-value');
    expect(
      [...root.querySelectorAll<HTMLInputElement>('input')].some(
        (i) => i.value === 'qlr_secret-value',
      ),
    ).toBe(false);
    // Opened again: the empty form.
    button(root, 'New token').click();
    await settle(fixture);
    expect(dialog.querySelector('#secret-once')).toBeNull();
    expect(dialog.querySelector<HTMLInputElement>('#project-token-name')?.value).toBe('');
  });

  it('sends no expiresInDays for Never', async () => {
    const server = setup();
    const { fixture, root } = await render();
    button(root, 'New token').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    type(dialog, '#project-token-name', 'forever');
    const select = dialog.querySelector<HTMLSelectElement>('#project-token-expiry')!;
    select.value = '';
    select.dispatchEvent(new Event('change'));
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(server.requestsTo('POST', LIST)[0]!.body).toEqual({ name: 'forever' });
  });

  it('keeps the dialog open on Escape while the secret shows; Escape closes the form', async () => {
    setup();
    const { fixture, root } = await render();
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    button(root, 'New token').click();
    await settle(fixture);
    const onForm = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(onForm);
    expect(onForm.defaultPrevented).toBe(false);
    type(dialog, '#project-token-name', 'release');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const onSecret = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(onSecret);
    expect(onSecret.defaultPrevented).toBe(true);
    expect(dialog.querySelector<HTMLInputElement>('#secret-once')?.value).toBe('qlr_secret-value');
  });

  it('forgets the secret when the dialog closes in any other way', async () => {
    setup();
    const { fixture, root } = await render();
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    button(root, 'New token').click();
    await settle(fixture);
    type(dialog, '#project-token-name', 'release');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    dialog.removeAttribute('open');
    dialog.dispatchEvent(new Event('close'));
    await settle(fixture);
    expect(root.querySelector('#secret-once')).toBeNull();
  });

  it('drops the secret when the component is destroyed', async () => {
    setup();
    const { fixture, root } = await render();
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    button(root, 'New token').click();
    await settle(fixture);
    type(dialog, '#project-token-name', 'release');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    const panel = fixture.componentInstance as unknown as { created(): string | null };
    expect(panel.created()).toBe('qlr_secret-value');
    fixture.destroy();
    expect(panel.created()).toBeNull();
  });

  it('refuses an empty name on the field and sends nothing', async () => {
    const server = setup();
    const { fixture, root } = await render();
    button(root, 'New token').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    type(dialog, '#project-token-name', '   ');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(dialog.querySelector('.field-error')?.textContent?.trim()).toBe('Enter a name.');
    expect(server.requestsTo('POST', LIST)).toHaveLength(0);
  });

  it('shows a duplicate name (409) on the field', async () => {
    const server = setup();
    server.on('POST', LIST, { status: 409, body: problem(409, 'CONFLICT') });
    const { fixture, root } = await render();
    button(root, 'New token').click();
    await settle(fixture);
    const dialog = root.querySelector<HTMLDialogElement>('dialog#project-token-dialog')!;
    type(dialog, '#project-token-name', 'ci');
    dialog.querySelector('form')!.dispatchEvent(new Event('submit'));
    await settle(fixture);
    expect(dialog.querySelector('#project-token-name-error')).not.toBeNull();
    expect(dialog.querySelector('#project-token-name')?.getAttribute('aria-invalid')).toBe('true');
    expect(dialog.querySelector('#secret-once')).toBeNull();
  });

  it('asks before revoking, then deletes and moves focus to the next row', async () => {
    const server = setup();
    const { fixture, root } = await render();
    document.body.appendChild(root);
    const ask = root.querySelector<HTMLDialogElement>('dialog#project-token-revoke')!;
    const revoke = root.querySelector<HTMLButtonElement>('tr[data-key="t1"] button')!;
    revoke.focus();
    revoke.click();
    await settle(fixture);
    expect(ask.open).toBe(true);
    expect(ask.textContent).toContain('Revoke the token ci? CI jobs that use it stop working.');
    button(ask, 'Cancel').click();
    await settle(fixture);
    expect(ask.open).toBe(false);
    expect(server.requestsTo('DELETE', `${LIST}/t1`)).toHaveLength(0);
    revoke.click();
    await settle(fixture);
    button(ask, 'Revoke').click();
    await settle(fixture);
    expect(server.requestsTo('DELETE', `${LIST}/t1`)).toHaveLength(1);
    expect(root.querySelector('tr[data-key="t1"]')).toBeNull();
    expect(document.activeElement).toBe(root.querySelector('tr[data-key="t2"] button'));
    root.remove();
  });

  it('moves focus to the heading when the last row is revoked', async () => {
    setup([token('t1', 'ci')]);
    const { fixture, root } = await render();
    document.body.appendChild(root);
    root.querySelector<HTMLButtonElement>('tr[data-key="t1"] button')!.click();
    await settle(fixture);
    button(root.querySelector('dialog#project-token-revoke')!, 'Revoke').click();
    await settle(fixture);
    expect(root.querySelector('tr[data-key]')).toBeNull();
    expect(document.activeElement).toBe(root.querySelector('h2'));
    root.remove();
  });
});
