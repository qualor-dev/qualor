import { TestBed } from '@angular/core/testing';
import { Meter } from './meter';

describe('Meter', () => {
  async function render(value: number, max: number | null, unit: 'count' | 'usd' = 'count') {
    TestBed.configureTestingModule({ imports: [Meter] });
    const fixture = TestBed.createComponent(Meter);
    fixture.componentRef.setInput('label', 'Explanations');
    fixture.componentRef.setInput('value', value);
    fixture.componentRef.setInput('max', max);
    fixture.componentRef.setInput('unit', unit);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }
  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

  it('shows the use against the budget in numbers, as a track a screen reader reads too', async () => {
    const root = await render(12, 200);
    expect(text(root.querySelector('.meter-label'))).toBe('Explanations');
    expect(text(root.querySelector('.meter-value'))).toBe('12 of 200');
    const track = root.querySelector('[role="meter"]')!;
    expect(track.getAttribute('aria-label')).toBe('Explanations');
    expect(track.getAttribute('aria-valuenow')).toBe('12');
    expect(track.getAttribute('aria-valuemin')).toBe('0');
    expect(track.getAttribute('aria-valuemax')).toBe('200');
    expect(track.getAttribute('aria-valuetext')).toBe('12 of 200');
    expect(root.querySelector<HTMLElement>('.meter-fill')?.style.width).toBe('6%');
    expect(root.querySelector('.meter-note')).toBeNull();
  });

  it('says in words that the budget is reached, and never draws past the end', async () => {
    const root = await render(250, 200);
    expect(text(root.querySelector('.meter-value'))).toBe('250 of 200');
    expect(root.querySelector('.meter')?.classList).toContain('reached');
    expect(text(root.querySelector('.meter-note'))).toBe('Budget reached for today');
    expect(root.querySelector<HTMLElement>('.meter-fill')?.style.width).toBe('100%');
    expect(root.querySelector('[role="meter"]')?.getAttribute('aria-valuetext')).toBe(
      '250 of 200, budget reached for today',
    );
  });

  it('says that a budget of 0 allows none', async () => {
    const root = await render(0, 0);
    expect(text(root.querySelector('.meter-value'))).toBe('0 of 0');
    expect(text(root.querySelector('.meter-note'))).toBe('None allowed: the budget is 0');
  });

  it('says when no budget is set, and draws no track', async () => {
    const root = await render(3.5, null, 'usd');
    expect(text(root.querySelector('.meter-value'))).toBe('$3.50');
    expect(text(root.querySelector('.meter-note'))).toBe('No budget set');
    expect(root.querySelector('[role="meter"]')).toBeNull();
  });

  it('groups large numbers and shows dollars with cents', async () => {
    const tokens = await render(1_234_567, 1_000_000);
    expect(text(tokens.querySelector('.meter-value'))).toBe('1,234,567 of 1,000,000');
    TestBed.resetTestingModule();
    const cost = await render(1.2, 5, 'usd');
    expect(text(cost.querySelector('.meter-value'))).toBe('$1.20 of $5.00');
  });
});
