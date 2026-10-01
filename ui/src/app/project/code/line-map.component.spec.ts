import { TestBed } from '@angular/core/testing';
import type { LineMap } from './line-map';
import { LineMapComponent } from './line-map.component';

/** 212 lines: 160 covered, 40 uncovered, 3 partly covered; 19 new; one block; 2 issues. */
const MAP: LineMap = {
  lines: 212,
  coverage: {
    runs: [
      { from: 1, to: 80, value: 'covered' },
      { from: 81, to: 83, value: 'partial' },
      { from: 84, to: 163, value: 'covered' },
      { from: 164, to: 203, value: 'uncovered' },
    ],
  },
  newCode: [{ from: 1, to: 19 }],
  duplication: [{ from: 100, to: 110 }],
  issues: [
    { line: 7, severity: 'high', id: 'i1' },
    { line: 150, severity: 'blocker', id: 'i2' },
  ],
};

const EMPTY: LineMap = {
  lines: 0,
  coverage: { runs: [] },
  newCode: [],
  duplication: [],
  issues: [],
};

describe('LineMapComponent (spec §4.3)', () => {
  async function render(map: LineMap, highlight: number | null = null) {
    TestBed.configureTestingModule({ imports: [LineMapComponent] });
    const fixture = TestBed.createComponent(LineMapComponent);
    fixture.componentRef.setInput('map', map);
    fixture.componentRef.setInput('highlight', highlight);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    return { fixture, root, svg: root.querySelector<SVGSVGElement>('svg[role="img"]')! };
  }
  const text = (el: Element | null | undefined) => el?.textContent?.replace(/\s+/g, ' ').trim();
  const num = (el: Element | null | undefined, name: string) => Number(el?.getAttribute(name));

  it('draws one rect per run and per issue marker, never one per line', async () => {
    const { svg } = await render(MAP);
    expect(svg.querySelectorAll('rect')).toHaveLength(4 + 1 + 1 + 2);
    expect(svg.querySelectorAll('rect.run')).toHaveLength(6);
    expect(svg.querySelectorAll('rect.marker')).toHaveLength(2);
    expect(svg.getAttribute('viewBox')).toBe('0 0 4 212');
    expect(svg.getAttribute('preserveAspectRatio')).toBe('none');
    const partial = svg.querySelector('rect.cov-partial');
    expect([num(partial, 'x'), num(partial, 'y'), num(partial, 'height')]).toEqual([
      expect.closeTo(0.15),
      80,
      3,
    ]);
    // Lanes left to right: coverage, new code, duplication, issues.
    expect(Math.floor(num(svg.querySelector('rect.new'), 'x'))).toBe(1);
    expect(Math.floor(num(svg.querySelector('rect.dup'), 'x'))).toBe(2);
    const marker = svg.querySelector('rect.marker');
    expect(Math.floor(num(marker, 'x'))).toBe(3);
    expect(num(marker, 'y')).toBe(6);
    expect(marker?.classList).toContain('tone-high');
  });

  it('draws a 50 000-line file with a single run as one rect', async () => {
    const { svg } = await render({
      ...EMPTY,
      lines: 50_000,
      coverage: { runs: [{ from: 1, to: 50_000, value: 'covered' }] },
    });
    expect(svg.querySelectorAll('rect')).toHaveLength(1);
    expect(svg.getAttribute('viewBox')).toBe('0 0 4 50000');
  });

  it('sums the map up in its aria-label', async () => {
    const { svg } = await render(MAP);
    expect(svg.getAttribute('tabindex')).toBe('0');
    expect(svg.getAttribute('aria-label')).toBe(
      '212 lines: 160 covered, 40 uncovered, 3 partly covered; 19 new; 2 issues',
    );
  });

  it('says when there is no coverage, and in the singular for one line and one issue', async () => {
    const { svg } = await render({
      ...EMPTY,
      lines: 1,
      issues: [{ line: 1, severity: 'low', id: 'x' }],
    });
    expect(svg.getAttribute('aria-label')).toBe('1 line: no coverage data; 0 new; 1 issue');
  });

  it('renders an empty file without marks', async () => {
    const { svg } = await render(EMPTY);
    expect(svg.querySelectorAll('rect')).toHaveLength(0);
    expect(svg.getAttribute('aria-label')).toBe('0 lines: no coverage data; 0 new; 0 issues');
  });

  it('highlights the line asked for', async () => {
    const { svg } = await render(MAP, 7);
    const hl = svg.querySelectorAll('rect.hl');
    expect(hl).toHaveLength(1);
    expect([num(hl[0], 'x'), num(hl[0], 'y'), num(hl[0], 'width'), num(hl[0], 'height')]).toEqual([
      0, 6, 4, 1,
    ]);
  });

  it('ignores a highlight outside the file', async () => {
    const { svg } = await render(MAP, 999);
    expect(svg.querySelector('rect.hl')).toBeNull();
  });

  it('walks the lines from the keyboard and says what is on each in a polite live region', async () => {
    const { fixture, root, svg } = await render(MAP, 6);
    const tip = root.querySelector('[aria-live="polite"]')!;
    expect(text(tip)).toBe('');
    svg.dispatchEvent(new FocusEvent('focus'));
    await fixture.whenStable();
    expect(text(tip)).toBe('Line 6: Covered, New code');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    await fixture.whenStable();
    expect(text(tip)).toBe('Line 7: Covered, New code, 1 issue');
    for (let i = 0; i < 7; i++) svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    await fixture.whenStable();
    expect(text(tip)).toBe('Line 1: Covered, New code');
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'End' }));
    await fixture.whenStable();
    expect(text(tip)).toBe('Line 212: Not coverable');
    expect(svg.querySelector('line.cursor')).not.toBeNull();
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    await fixture.whenStable();
    expect(text(tip)).toBe('');
    expect(svg.querySelector('line.cursor')).toBeNull();
  });

  it('opens an issue from a click on its marker, or Enter on its line', async () => {
    const { fixture, svg } = await render(MAP, 7);
    const opened: string[] = [];
    fixture.componentInstance.openIssue.subscribe((id) => opened.push(id));
    svg
      .querySelectorAll<SVGRectElement>('rect.marker')[1]!
      .dispatchEvent(new MouseEvent('click', { bubbles: true }));
    svg.dispatchEvent(new FocusEvent('focus'));
    svg.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter' }));
    expect(opened).toEqual(['i2', 'i1']);
  });

  it('lays the lanes out across on a phone', async () => {
    const original = window.matchMedia;
    window.matchMedia = ((query: string) =>
      ({
        matches: true,
        media: query,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
      }) as unknown as MediaQueryList) as typeof window.matchMedia;
    try {
      const { root, svg } = await render(MAP);
      expect(root.querySelector('.line-map')?.classList).toContain('horizontal');
      expect(svg.getAttribute('viewBox')).toBe('0 0 212 4');
      const partial = svg.querySelector('rect.cov-partial');
      expect([num(partial, 'x'), num(partial, 'width')]).toEqual([80, 3]);
      expect(Math.floor(num(svg.querySelector('rect.marker'), 'y'))).toBe(3);
    } finally {
      window.matchMedia = original;
    }
  });
});
