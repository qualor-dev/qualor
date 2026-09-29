import { TestBed } from '@angular/core/testing';
import { LineChart, type ChartSeries } from './line-chart';

const series = (
  key: string,
  values: (number | null)[],
  tone = 'accent',
  label = key,
): ChartSeries => ({
  key,
  label,
  tone,
  points: values.map((value, i) => ({
    date: new Date(Date.UTC(2026, 8, 1 + 7 * i, 9)).toISOString(),
    value,
  })),
});

describe('LineChart', () => {
  async function render(s: ChartSeries[], metric = 'coverage', stacked = false) {
    TestBed.configureTestingModule({ imports: [LineChart] });
    const fixture = TestBed.createComponent(LineChart);
    fixture.componentRef.setInput('series', s);
    fixture.componentRef.setInput('metric', metric);
    fixture.componentRef.setInput('stacked', stacked);
    await fixture.whenStable();
    return { fixture, root: fixture.nativeElement as HTMLElement };
  }
  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();

  it('draws one series with its area, describes it, and lists its values in a table', async () => {
    const { root } = await render([series('coverage', [60.8, null, 65.7])]);
    const svg = root.querySelector('svg[role="img"]');
    expect(svg?.getAttribute('aria-label')).toBe(
      'Coverage went from 60.8 % on Sep 1, 2026 to 65.7 % on Sep 15, 2026',
    );
    expect(root.querySelector('polyline.line')?.getAttribute('points')?.split(' ')).toHaveLength(2);
    expect(root.querySelector('polygon.area')).not.toBeNull();
    expect([...root.querySelectorAll('tbody td.num')].map((td) => text(td))).toEqual([
      '60.8 %',
      '–',
      '65.7 %',
    ]);
    expect([...root.querySelectorAll('text.axis')].map((t) => text(t))).toContain('80 %');
  });

  it('says so when there is nothing to draw', async () => {
    const { root } = await render([series('coverage', [])]);
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toBe('Coverage: no values yet');
    expect(root.querySelector('polyline')).toBeNull();
  });

  it('stacks severities, describes their totals and shows a legend', async () => {
    const { root } = await render(
      [series('blocker', [1, 1], 'blocker', 'Blocker'), series('high', [2, null], 'high', 'High')],
      'issues',
      true,
    );
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toBe(
      'Issues went from 3 on Sep 1, 2026 to 1 on Sep 8, 2026',
    );
    expect(root.querySelectorAll('polygon.band')).toHaveLength(2);
    expect([...root.querySelectorAll('.chart-legend li')].map((li) => text(li))).toEqual([
      'Blocker',
      'High',
    ]);
  });

  it('moves a crosshair with the keyboard and shows every series in the tooltip', async () => {
    const { fixture, root } = await render(
      [series('blocker', [1, 4], 'blocker', 'Blocker'), series('high', [2, 5], 'high', 'High')],
      'issues',
      true,
    );
    const svg = root.querySelector<SVGSVGElement>('svg')!;
    svg.dispatchEvent(new FocusEvent('focus'));
    await fixture.whenStable();
    expect(text(root.querySelector('.chart-tip'))).toContain('9');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Home' }));
    await fixture.whenStable();
    expect(text(root.querySelector('.chart-tip'))).toBe('Sep 1, 2026 3 Blocker 1 High 2');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await fixture.whenStable();
    expect(root.querySelector('.chart-tip')).toBeNull();
  });

  it('draws a single stacked analysis as one stacked column, so a new project is never empty', async () => {
    const { root } = await render(
      [
        series('blocker', [2], 'blocker', 'Blocker'),
        series('high', [0], 'high', 'High'),
        series('medium', [1], 'medium', 'Medium'),
      ],
      'issues',
      true,
    );
    const segments = [...root.querySelectorAll('rect.band-col')];
    expect(segments.map((r) => r.getAttribute('class'))).toEqual([
      'band-col tone-blocker',
      'band-col tone-medium',
    ]);
    expect(Number(segments[0]?.getAttribute('height'))).toBeGreaterThan(
      Number(segments[1]?.getAttribute('height')),
    );
  });

  it('marks a single stacked analysis without issues on the baseline, so a clean project is never empty', async () => {
    const { root } = await render(
      [series('blocker', [0], 'blocker', 'Blocker'), series('high', [0], 'high', 'High')],
      'issues',
      true,
    );
    const base = root.querySelector('line.grid.base')?.getAttribute('y1');
    expect(base).toBeTruthy();
    expect(root.querySelector('circle.marker')?.getAttribute('cy')).toBe(base);
  });

  it('marks a stacked history that ends at zero on the baseline, at its end', async () => {
    const { root } = await render(
      [
        series('blocker', [2, 1, 0], 'blocker', 'Blocker'),
        series('high', [1, 0, 0], 'high', 'High'),
      ],
      'issues',
      true,
    );
    const marker = root.querySelector('circle.marker');
    expect(marker?.getAttribute('cy')).toBe(
      root.querySelector('line.grid.base')?.getAttribute('y1'),
    );
    expect(Number(marker?.getAttribute('cx'))).toBeGreaterThan(300);
  });

  it('sets the y ticks in proportional figures, which keep "5,000" and "7.5 %" tight', async () => {
    // In the brand face, tabular figures also space the separators: "5 , 000" (spec §3.2).
    const { root } = await render([series('ncloc', [900, 5000])], 'ncloc');
    const tick = root.querySelector('text.axis-y');
    expect(tick?.textContent?.trim()).toBe('0');
    expect(getComputedStyle(tick!).fontVariantNumeric).not.toContain('tabular-nums');
  });

  it('marks a single analysis of one series', async () => {
    const { root } = await render([series('coverage', [42])]);
    expect(root.querySelectorAll('circle.marker')).toHaveLength(1);
  });

  it('draws an all-equal series as a flat line', async () => {
    const { root } = await render([series('ncloc', [654, 654, 654])], 'ncloc');
    const ys = root
      .querySelector('polyline.line')
      ?.getAttribute('points')
      ?.split(' ')
      .map((p) => p.split(',')[1]);
    expect(ys).toHaveLength(3);
    expect(new Set(ys).size).toBe(1);
  });

  it('keeps the latest 1 000 points (the API maximum) of a longer history', async () => {
    const long: ChartSeries = {
      key: 'ncloc',
      label: 'Lines of code',
      tone: 'accent',
      points: Array.from({ length: 5000 }, (_, i) => ({
        date: new Date(Date.UTC(2026, 0, 1) + i * 60_000).toISOString(),
        value: i,
      })),
    };
    const { root } = await render([long], 'ncloc');
    expect(root.querySelector('polyline.line')?.getAttribute('points')?.split(' ')).toHaveLength(
      1000,
    );
    expect(root.querySelectorAll('tbody tr')).toHaveLength(1000);
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toBe(
      'Lines of code went from 4,000 on Jan 3, 2026 to 4,999 on Jan 4, 2026',
    );
  });

  it('keeps markup in labels and an unknown metric as text', async () => {
    const { root } = await render(
      [series('x', [1, 2], 'blocker', '<b>x</b>'), series('y', [1, 1])],
      '<i>m</i>',
      true,
    );
    expect(root.querySelector('.chart-legend')?.textContent).toContain('<b>x</b>');
    expect(root.querySelector('svg')?.getAttribute('aria-label')).toContain('<i>m</i>');
    expect(root.querySelector('b, i')).toBeNull();
  });
});
