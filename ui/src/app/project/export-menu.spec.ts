import { TestBed } from '@angular/core/testing';
import { settle } from '../../testing/fake-server';
import { ExportMenu, type ExportKind, type ExportOption } from './export-menu';

const MAIN: ExportOption = { value: 'branch:b1', kind: 'branch', name: 'main' };
const RELEASE: ExportOption = { value: 'version:v1', kind: 'version', name: '2.1.0' };

const text = (el: Element | null | undefined) => el?.textContent.replace(/\s+/g, ' ').trim();

describe('ExportMenu', () => {
  async function render(
    options: readonly ExportOption[],
    more: { kind?: ExportKind; selectable?: boolean; preferred?: string | null } = {},
  ): Promise<HTMLElement> {
    TestBed.configureTestingModule({ imports: [ExportMenu] });
    const fixture = TestBed.createComponent(ExportMenu);
    fixture.componentRef.setInput('kind', more.kind ?? 'sbom');
    fixture.componentRef.setInput('menuId', 'test-export');
    fixture.componentRef.setInput('projectKey', 'acme/x');
    fixture.componentRef.setInput('options', options);
    if (more.selectable !== undefined) fixture.componentRef.setInput('selectable', more.selectable);
    if (more.preferred !== undefined) fixture.componentRef.setInput('preferred', more.preferred);
    await settle(fixture);
    return fixture.nativeElement as HTMLElement;
  }

  const links = (root: HTMLElement) =>
    [...root.querySelectorAll('#test-export a')].map((a) => [
      text(a),
      a.getAttribute('href'),
      a.hasAttribute('download'),
    ]);

  it('names the button and points it at its own panel', async () => {
    const root = await render([MAIN]);
    const button = root.querySelector('button');
    expect(text(button)).toBe('Export SBOM');
    expect(button?.getAttribute('popovertarget')).toBe('test-export');
    expect(root.querySelector('#test-export')?.getAttribute('aria-label')).toBe('Export SBOM');
  });

  it('without a Target select, links the formats of its one option', async () => {
    const root = await render([RELEASE], { selectable: false });
    expect(root.querySelector('select')).toBeNull();
    expect(text(root.querySelector('#test-export'))).not.toContain('Target');
    expect(links(root)).toEqual([
      [
        'CycloneDX 1.6 (JSON)',
        '/api/v0/projects/sbom?projectKey=acme%2Fx&version=2.1.0&format=cyclonedx',
        true,
      ],
      [
        'SPDX 2.3 (JSON)',
        '/api/v0/projects/sbom?projectKey=acme%2Fx&version=2.1.0&format=spdx',
        true,
      ],
    ]);
  });

  it('with the Target select, starts on the preferred option', async () => {
    const root = await render([MAIN, RELEASE], { kind: 'vex', preferred: RELEASE.value });
    expect(root.querySelector('select')?.value).toBe(RELEASE.value);
    expect(links(root).map((l) => l[1])).toEqual([
      '/api/v0/projects/vex?projectKey=acme%2Fx&version=2.1.0&format=cyclonedx',
      '/api/v0/projects/vex?projectKey=acme%2Fx&version=2.1.0&format=openvex',
    ]);
  });

  describe('with a popover', () => {
    const proto = HTMLElement.prototype as unknown as Record<string, unknown>;
    const original = { matches: proto['matches'], hidePopover: proto['hidePopover'] };
    let hide: ReturnType<typeof vi.fn>;
    beforeEach(() => {
      hide = vi.fn();
      proto['hidePopover'] = hide;
      proto['matches'] = function (this: Element, selector: string) {
        return selector === ':popover-open'
          ? true
          : (original.matches as (s: string) => boolean).call(this, selector);
      };
    });
    afterEach(() => {
      proto['matches'] = original.matches;
      if (original.hidePopover) proto['hidePopover'] = original.hidePopover;
      else delete proto['hidePopover'];
    });

    it('closes an open panel when the window scrolls or resizes', async () => {
      const root = await render([MAIN], { selectable: false });
      const panel = root.querySelector('#test-export');
      for (const type of ['scroll', 'resize']) {
        hide.mockClear();
        window.dispatchEvent(new Event(type));
        expect(hide, type).toHaveBeenCalledTimes(1);
        expect(hide.mock.contexts[0], type).toBe(panel);
      }
    });

    it('closes the panel when a download link is clicked', async () => {
      const root = await render([MAIN], { selectable: false });
      const link = root.querySelector<HTMLAnchorElement>('#test-export a');
      if (!link) throw new Error('no link');
      link.addEventListener('click', (e) => e.preventDefault());
      link.click();
      expect(hide).toHaveBeenCalledTimes(1);
    });
  });
});
