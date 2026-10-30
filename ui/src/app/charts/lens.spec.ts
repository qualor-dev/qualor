import { TestBed } from '@angular/core/testing';
import { Lens } from './lens';
import { lensGeometry } from './lens-geometry';

describe('lensGeometry', () => {
  // Every dot touches the circle; the lens clips what reaches past its ring.
  const inside = (g: ReturnType<typeof lensGeometry>) =>
    g.dots.every((d) => Math.hypot(d.x - g.c, d.y - g.c) - d.r < g.r + 0.01);

  it('draws nothing for no value or 0 %', () => {
    for (const value of [null, 0, Number.NaN]) {
      const g = lensGeometry(value, 76);
      expect(g.dots).toEqual([]);
      expect(g.level).toBeNull();
    }
  });

  it('fills the lower half at 50 %, with the level line through the centre', () => {
    const g = lensGeometry(50, 96);
    expect(g.level?.y).toBe(48);
    expect(g.dots.length).toBeGreaterThan(40);
    expect(g.dots.every((d) => d.y >= 48)).toBe(true);
    expect(inside(g)).toBe(true);
  });

  it('fills the whole circle at 100 %, without a level line, and clamps above', () => {
    const full = lensGeometry(100, 96);
    expect(full.level).toBeNull();
    expect(lensGeometry(250, 96).dots).toEqual(full.dots);
    expect(inside(full)).toBe(true);
  });

  it('lays the dots in straight columns, one under another, centred on the circle', () => {
    // The maintainer, 2026-09-29: no half-step shift on alternate rows.
    const g = lensGeometry(100, 96);
    const columns = [...new Set(g.dots.map((d) => d.x))].sort((a, b) => a - b);
    const rows = [...new Set(g.dots.map((d) => d.y))].sort((a, b) => a - b);
    expect(columns[1]! - columns[0]!).toBeCloseTo(rows[1]! - rows[0]!, 1);
    expect(columns[0]! + columns[columns.length - 1]!).toBeCloseTo(2 * g.c, 1);
  });

  it('fills the circle up to its ring, with no empty corners', () => {
    // The maintainer, 2026-09-29: the dots reach the ring all round, like a print cut by it.
    const g = lensGeometry(100, 96);
    const step = 96 / 17;
    for (let deg = 0; deg < 360; deg += 3) {
      const a = (deg * Math.PI) / 180;
      const [px, py] = [g.c + g.r * Math.cos(a), g.c + g.r * Math.sin(a)];
      const gap = Math.min(...g.dots.map((d) => Math.hypot(d.x - px, d.y - py) - d.r));
      // Between neighbouring dots a halftone keeps gaps; a missing dot leaves more than this.
      expect(gap).toBeLessThan(step * 0.6);
    }
  });

  it('grows the dots with depth, like the screen prints', () => {
    const g = lensGeometry(80, 96);
    const top = g.dots.reduce((a, d) => (d.y < a.y ? d : a));
    const bottom = g.dots.reduce((a, d) => (d.y > a.y ? d : a));
    expect(bottom.r).toBeGreaterThan(top.r);
  });
});

describe('Lens', () => {
  it('renders the ring, the dots and the level, hidden from assistive technology', async () => {
    TestBed.configureTestingModule({ imports: [Lens] });
    const fixture = TestBed.createComponent(Lens);
    fixture.componentRef.setInput('value', 65.7);
    fixture.componentRef.setInput('size', 76);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    const svg = root.querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
    expect(svg?.getAttribute('width')).toBe('76');
    expect(root.querySelectorAll('.lens-dots circle').length).toBeGreaterThan(20);
    expect(root.querySelector('.lens-level')).not.toBeNull();
    // The dots are cut by the ring's outer edge, so none shows outside it.
    expect(getComputedStyle(svg!).clipPath).toBe('circle(calc(50% - 0.375px))');
  });

  it('draws a mark in the middle for the gate emblem', async () => {
    TestBed.configureTestingModule({ imports: [Lens] });
    const fixture = TestBed.createComponent(Lens);
    fixture.componentRef.setInput('value', 0);
    fixture.componentRef.setInput('size', 34);
    fixture.componentRef.setInput('tone', 'bad');
    fixture.componentRef.setInput('mark', 'cross');
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.classList).toContain('lens-bad');
    expect(root.querySelector('.lens-mark')?.getAttribute('d')).toMatch(/^M/);
  });

  it('prints only the rows above the old level, bottom-up, and raises the level line', async () => {
    // The setup checklist's reveal (onboarding notes, Motion): from 20 % to 40 %.
    TestBed.configureTestingModule({ imports: [Lens] });
    const fixture = TestBed.createComponent(Lens);
    fixture.componentRef.setInput('value', 40);
    fixture.componentRef.setInput('size', 72);
    fixture.componentRef.setInput('from', 20);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    const before = lensGeometry(20, 72);
    const dots = [...root.querySelectorAll<SVGCircleElement>('.lens-dots circle')];
    const fresh = dots.filter((d) => d.classList.contains('new'));
    expect(fresh.length).toBeGreaterThan(0);
    // The new dots are those above the old level; the old ones are drawn still.
    const top = before.levelY + before.step * 0.2;
    const cy = (d: SVGCircleElement) => Number(d.getAttribute('cy'));
    expect(fresh.every((d) => cy(d) < top)).toBe(true);
    expect(dots.filter((d) => !fresh.includes(d)).every((d) => cy(d) >= top)).toBe(true);
    // Row by row from the bottom, 45 ms apart.
    const delay = (d: SVGCircleElement) => parseInt(d.style.animationDelay, 10);
    const lowest = fresh.reduce((a, d) => (cy(d) > cy(a) ? d : a));
    const highest = fresh.reduce((a, d) => (cy(d) < cy(a) ? d : a));
    expect(delay(lowest)).toBe(0);
    expect(delay(highest)).toBeGreaterThan(0);
    expect(delay(highest) % 45).toBe(0);
    const level = root.querySelector<SVGLineElement>('.lens-level')!;
    expect(level.classList).toContain('rising');
    expect(parseFloat(level.style.getPropertyValue('--dy'))).toBeGreaterThan(0);
  });

  it('prints nothing without a previous value', async () => {
    TestBed.configureTestingModule({ imports: [Lens] });
    const fixture = TestBed.createComponent(Lens);
    fixture.componentRef.setInput('value', 40);
    fixture.componentRef.setInput('size', 72);
    await fixture.whenStable();
    const root = fixture.nativeElement as HTMLElement;
    expect(root.querySelectorAll('.lens-dots .new')).toHaveLength(0);
    expect(root.querySelector('.lens-level')?.classList).not.toContain('rising');
  });
});
