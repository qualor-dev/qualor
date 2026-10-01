import { TestBed } from '@angular/core/testing';
import { Title } from '@angular/platform-browser';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { RouterTestingHarness } from '@angular/router/testing';
import { FakeServer, me, provideFakeServer, settle } from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { DocsPage } from './docs.page';

describe('DocsPage: the built-in user guide', () => {
  let harness: RouterTestingHarness;

  beforeEach(async () => {
    const server = new FakeServer();
    server.on('GET', '/api/v0/system/info', {
      body: { version: '1.2.3', edition: 'community', features: [], extensions: [] },
    });
    TestBed.configureTestingModule({
      providers: [
        provideRouter(
          [
            { path: 'docs', component: DocsPage },
            { path: 'docs/:page', component: DocsPage },
          ],
          withComponentInputBinding(),
        ),
        provideFakeServer(server),
      ],
    });
    TestBed.inject(SessionStore).set(me());
    harness = await RouterTestingHarness.create();
  });

  async function open(url: string): Promise<HTMLElement> {
    await harness.navigateByUrl(url);
    await settle(harness.fixture);
    harness.detectChanges();
    return harness.routeNativeElement as HTMLElement;
  }

  it('lists the pages in the README order and shows the overview at /docs', async () => {
    const root = await open('/docs');
    const nav = [...root.querySelectorAll('.docs-nav a')].map((a) => a.textContent?.trim());
    expect(nav.slice(0, 3)).toEqual(['Overview', 'Quick start', 'Install the server']);
    expect(nav).toContain('Webhooks and REST API');
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Qualor documentation');
    expect(root.querySelector('.docs-nav a.active')?.getAttribute('aria-current')).toBe('page');
    // The guide is the one of this server's release.
    expect(root.querySelector('.docs-version')?.textContent).toContain('Qualor 1.2.3');
  });

  it('renders a page with its sections, app links, copy buttons and the next page', async () => {
    const root = await open('/docs/quick-start');
    expect(root.querySelector('h1')?.textContent?.trim()).toBe('Quick start');
    expect(TestBed.inject(Title).getTitle()).toBe('Quick start · Documentation · Qualor');
    const sections = [...root.querySelectorAll('.docs-toc a')];
    expect(sections.length).toBeGreaterThan(1);
    const first = root.querySelector('q-doc-content h2');
    expect(sections[0]?.getAttribute('href')).toBe(`/docs/quick-start#${first?.id}`);
    // A link to another guide page stays in the app.
    expect(root.querySelector('q-doc-content a[href^="/docs/install-server"]')).not.toBeNull();
    expect(root.querySelector('.code-box pre code')?.textContent).not.toBe('');
    expect(root.querySelector('.code-box button')?.textContent?.trim()).toBe('Copy');
    expect(root.querySelector('.pager-prev')?.textContent).toContain('Overview');
    expect(root.querySelector('.pager-next')?.textContent).toContain('Install the server');
  });

  it('labels the prompt blocks of the AI prompts page "Copy prompt" and copies the text', async () => {
    const writes: string[] = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: (text: string) => (writes.push(text), Promise.resolve()) },
    });
    const root = await open('/docs/ai-prompts');
    const prompt = root.querySelector<HTMLElement>('.code-box.is-prompt');
    const button = prompt?.querySelector('button');
    expect(button?.textContent?.trim()).toBe('Copy prompt');
    button?.click();
    await settle(harness.fixture);
    harness.detectChanges();
    expect(writes).toEqual([prompt?.querySelector('code')?.textContent?.replace(/\n$/, '')]);
    expect(button?.textContent?.trim()).toBe('Copied');
  });

  it('says so for a page the guide does not have', async () => {
    const root = await open('/docs/no-such-page');
    expect(root.textContent).toContain('The guide has no such page.');
    expect(root.querySelector('a[href="/docs"]')).not.toBeNull();
  });
});
