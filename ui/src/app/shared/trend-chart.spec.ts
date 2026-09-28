import { TestBed } from '@angular/core/testing';
import { TrendChart } from './trend-chart';

describe('TrendChart', () => {
  async function render(points: { date: string; value: number | null }[], metric = 'coverage') {
    TestBed.configureTestingModule({ imports: [TrendChart] });
    const fixture = TestBed.createComponent(TrendChart);
    fixture.componentRef.setInput('metric', metric);
    fixture.componentRef.setInput('points', points);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }

  it('draws the series and describes it for screen readers', async () => {
    const root = await render([
      { date: '2026-09-01T09:00:00.000Z', value: 60.8 },
      { date: '2026-09-08T09:00:00.000Z', value: null },
      { date: '2026-09-15T09:00:00.000Z', value: 65.7 },
    ]);
    const svg = root.querySelector('svg[role="img"]');
    expect(svg?.getAttribute('aria-label')).toBe(
      'Coverage went from 60.8 % on Sep 1, 2026 to 65.7 % on Sep 15, 2026',
    );
    expect(root.querySelector('polyline')?.getAttribute('points')).toBe('4.0,60.0 236.0,4.0');
    expect([...root.querySelectorAll('tbody td.num')].map((td) => td.textContent?.trim())).toEqual([
      '60.8 %',
      '–',
      '65.7 %',
    ]);
  });

  it('says so when there is nothing to draw', async () => {
    const root = await render([]);
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toBe('Coverage: no values yet');
    expect(root.querySelector('polyline')).toBeNull();
  });

  it('keeps the latest 1 000 points (the API maximum) of a longer history', async () => {
    const points = Array.from({ length: 5000 }, (_, i) => ({
      date: new Date(Date.UTC(2026, 0, 1) + i * 60_000).toISOString(),
      value: i,
    }));
    const root = await render(points, 'ncloc');
    expect(root.querySelector('polyline')?.getAttribute('points')?.split(' ')).toHaveLength(1000);
    expect(root.querySelectorAll('tbody tr')).toHaveLength(1000);
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toBe(
      'Lines of code went from 4,000 on Jan 3, 2026 to 4,999 on Jan 4, 2026',
    );
  });

  it('keeps markup in an unknown metric name as text', async () => {
    const root = await render([{ date: '2026-09-01T09:00:00.000Z', value: 1 }], '<b>x</b>');
    expect(root.querySelector('figcaption')?.textContent).toBe('<b>x</b>');
    expect(root.querySelector('b')).toBeNull();
  });
});
