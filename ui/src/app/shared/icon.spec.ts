import { TestBed } from '@angular/core/testing';
import { ICONS, type IconName } from './icons';
import { Icon } from './icon';

describe('Icon', () => {
  it('draws every icon of the set, hidden from assistive technology', async () => {
    TestBed.configureTestingModule({ imports: [Icon] });
    for (const name of Object.keys(ICONS) as IconName[]) {
      const fixture = TestBed.createComponent(Icon);
      fixture.componentRef.setInput('name', name);
      await fixture.whenStable();
      const svg = (fixture.nativeElement as HTMLElement).querySelector('svg');
      expect(svg?.getAttribute('aria-hidden')).toBe('true');
      expect(svg?.querySelectorAll('path, circle').length).toBeGreaterThan(0);
    }
  });
});
