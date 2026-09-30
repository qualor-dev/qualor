import { TestBed } from '@angular/core/testing';
import { Sparkline, sparkline } from './sparkline';

describe('sparkline', () => {
  it('spreads the values over the width and marks the last one', () => {
    const s = sparkline([10, 20, 15], 104, 34, 2);
    expect(s.points).toBe('2,32 52,2 102,17');
    expect(s.last).toEqual({ x: 102, y: 17 });
  });

  it('keeps gaps in place, draws a flat series in the middle, and nothing for no values', () => {
    expect(sparkline([5, null, 5], 104, 34, 2).points).toBe('2,17 102,17');
    expect(sparkline([null, null], 104, 34)).toEqual({ points: '', last: null });
  });
});

describe('Sparkline', () => {
  it('is decoration: hidden from assistive technology', async () => {
    TestBed.configureTestingModule({ imports: [Sparkline] });
    const fixture = TestBed.createComponent(Sparkline);
    fixture.componentRef.setInput('values', [3, 2, 1]);
    await fixture.whenStable();
    const svg = (fixture.nativeElement as HTMLElement).querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
    expect(svg?.querySelector('polyline')?.getAttribute('points')).toBeTruthy();
  });
});
