import { TestBed } from '@angular/core/testing';
import { Lens } from './lens';
import { lensGeometry } from './lens-geometry';

describe('lensGeometry', () => {
  const inside = (g: ReturnType<typeof lensGeometry>) =>
    g.dots.every((d) => Math.hypot(d.x - g.c, d.y - g.c) <= g.r);

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
});
