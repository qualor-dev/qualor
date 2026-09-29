import { TestBed } from '@angular/core/testing';
import { Rating } from './rating';

describe('Rating', () => {
  async function render(value: number | null, label = '') {
    TestBed.configureTestingModule({ imports: [Rating] });
    const fixture = TestBed.createComponent(Rating);
    fixture.componentRef.setInput('value', value);
    fixture.componentRef.setInput('label', label);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  it('shows the letter in a circle, with its label', async () => {
    const root = await render(5, 'Security');
    expect(root.querySelector('.rating-letter')?.textContent?.trim()).toBe('E');
    expect(root.querySelector('.rating-letter')?.getAttribute('data-rating')).toBe('E');
    expect(root.querySelector('.rating-label')?.textContent?.trim()).toBe('Security');
  });

  it('shows a dash for no rating', async () => {
    const root = await render(null);
    expect(root.querySelector('.rating-letter')?.textContent?.trim()).toBe('–');
    expect(root.querySelector('.rating-letter')?.hasAttribute('data-rating')).toBe(false);
  });
});
