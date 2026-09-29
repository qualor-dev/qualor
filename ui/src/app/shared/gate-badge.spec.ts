import { TestBed } from '@angular/core/testing';
import { GateBadge } from './gate-badge';

describe('GateBadge', () => {
  it('shows the status as an icon and a word', async () => {
    TestBed.configureTestingModule({ imports: [GateBadge] });
    const cases = [
      ['failed', 'Failed'],
      ['passed', 'Passed'],
      [null, 'Not analyzed'],
    ] as const;
    for (const [status, word] of cases) {
      const fixture = TestBed.createComponent(GateBadge);
      fixture.componentRef.setInput('status', status);
      await fixture.whenStable();
      const root = fixture.nativeElement as HTMLElement;
      expect(root.textContent?.trim()).toBe(word);
      expect(root.querySelector('q-icon svg')).not.toBeNull();
    }
  });
});
