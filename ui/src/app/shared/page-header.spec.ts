import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { PageHeader } from './page-header';

describe('PageHeader', () => {
  async function render(crumbs: { label: string; link: string }[], compact = false) {
    TestBed.configureTestingModule({ imports: [PageHeader], providers: [provideRouter([])] });
    const fixture = TestBed.createComponent(PageHeader);
    fixture.componentRef.setInput('crumbs', crumbs);
    fixture.componentRef.setInput('compact', compact);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  it('shows breadcrumbs as text links on the ink band', async () => {
    const root = await render([{ label: '<b>Projects</b>', link: '/projects' }]);
    const crumbs = root.querySelector('nav[aria-label="Breadcrumb"]');
    expect(crumbs?.querySelector('a')?.getAttribute('href')).toBe('/projects');
    expect(crumbs?.textContent?.trim()).toBe('<b>Projects</b>');
    expect(root.querySelector('b')).toBeNull();
    expect(root.classList).toContain('page-band');
  });

  it('has no breadcrumb navigation without crumbs, and marks the compact band', async () => {
    const root = await render([], true);
    expect(root.querySelector('nav')).toBeNull();
    expect(root.classList).toContain('compact');
  });
});
