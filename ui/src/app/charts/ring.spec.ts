import { TestBed } from '@angular/core/testing';
import { RingMeter, type RingStatus } from './ring';
import {
  growArc,
  meterValue,
  REVEAL_SWEEP_MS,
  revealDelays,
  ringGeometry,
  type RingGeometry,
} from './ring-geometry';

/** The ring's centre at a size, on the mark's final geometry (centre 32, 31 on its 64 grid). */
const centre = (size: number) => ({ x: (32 * size) / 64, y: (31 * size) / 64 });
/** The angle of a point seen from the centre, in degrees from 0 to 360, clockwise (y down). */
const angleOf = (size: number, x: number, y: number) => {
  const c = centre(size);
  return ((Math.atan2(y - c.y, x - c.x) * 180) / Math.PI + 360) % 360;
};
const litCount = (value: number | null, size: number) =>
  ringGeometry(value, size).dots.filter((d) => d.lit).length;
/** The dots per circle, from the inside out. */
const circles = (g: RingGeometry) => {
  const c = centre(g.size);
  const byRadius = new Map<number, number>();
  for (const d of g.dots) {
    const rho = Math.round(Math.hypot(d.x - c.x, d.y - c.y));
    byRadius.set(rho, (byRadius.get(rho) ?? 0) + 1);
  }
  return [...byRadius.entries()].sort((a, b) => a[0] - b[0]).map(([, n]) => n);
};
/** The two corners where a solid fill ends: the points around its `L` segment. */
const partEnd = (part: string) => {
  const m = /(-?[\d.]+) (-?[\d.]+)L(-?[\d.]+) (-?[\d.]+)A/.exec(part);
  if (!m) throw new Error(`no end in ${part}`);
  const [ox, oy, ix, iy] = m.slice(1).map(Number) as [number, number, number, number];
  return { outer: { x: ox, y: oy }, inner: { x: ix, y: iy } };
};

describe('ringGeometry', () => {
  it('lays the dots on two circles at 96 px and on one from 64 to 76 px', () => {
    // The approved board (style C, iteration 3): 15 + 20 dots at 96 px; 14 to 16 small ones below.
    expect(circles(ringGeometry(50, 96))).toEqual([15, 20]);
    expect(circles(ringGeometry(50, 76))).toEqual([16]);
    expect(circles(ringGeometry(50, 72))).toEqual([15]);
    expect(circles(ringGeometry(50, 64))).toEqual([14]);
    // Two circles fill the band's width; one keeps the smallest dots. Unlit ones are 0.85 of lit.
    expect([ringGeometry(50, 96).litR, ringGeometry(50, 96).unlitR]).toEqual([3, 2.55]);
    expect([ringGeometry(50, 72).litR, ringGeometry(50, 72).unlitR]).toEqual([2.59, 2.2]);
  });

  it('keeps every dot inside the band and clear of the status dot', () => {
    for (const size of [96, 76, 72, 64]) {
      const g = ringGeometry(100, size);
      const c = centre(size);
      const s = size / 64;
      for (const d of g.dots) {
        const rho = Math.hypot(d.x - c.x, d.y - c.y);
        expect(rho - g.litR).toBeGreaterThanOrEqual(12 * s - 0.01);
        expect(rho + g.litR).toBeLessThanOrEqual(22 * s + 0.01);
        // At least the mark's gap (3 on its grid) between a dot and the status dot.
        const clear = Math.hypot(d.x - g.dot.x, d.y - g.dot.y) - g.litR - g.dot.r;
        expect(clear).toBeGreaterThanOrEqual(3 * s);
      }
    }
  });

  it('runs each circle clockwise from just after the dot to just before it', () => {
    const g = ringGeometry(100, 96);
    for (const rho of [21.75, 29.25]) {
      const c = centre(96);
      const ring = g.dots.filter((d) => Math.abs(Math.hypot(d.x - c.x, d.y - c.y) - rho) < 0.1);
      // Unwrapped from the dot's direction (50°): every next dot further on.
      const angles = ring.map((d) => (angleOf(96, d.x, d.y) - 50 + 360) % 360);
      expect(angles).toEqual([...angles].sort((a, b) => a - b));
      expect(ring.map((d) => d.t)).toEqual(ring.map((_, i) => i / (ring.length - 1)));
      expect(angles[0]).toBeGreaterThan(30);
      expect(angles[angles.length - 1]).toBeLessThan(330);
    }
  });

  it('lights the dots from just after the dot, the first from any value above 0', () => {
    expect([null, 0, 1, 37, 50, 66, 100].map((v) => litCount(v, 96))).toEqual([
      0, 0, 2, 14, 18, 23, 35,
    ]);
    expect([null, 0, 1, 50, 100].map((v) => litCount(v, 72))).toEqual([0, 0, 1, 8, 15]);
    expect(litCount(66, 76)).toBe(10);
    expect(litCount(66, 64)).toBe(9);
    expect(litCount(0.2, 64)).toBe(1);
    // The lit ones lead each circle: no gap before an unlit dot.
    const g = ringGeometry(50, 72);
    expect(g.dots.map((d) => d.lit)).toEqual(g.dots.map((_, i) => i < 8));
  });

  it('clamps values and reads NaN and the infinities as no data', () => {
    expect(ringGeometry(250, 96).dots).toEqual(ringGeometry(100, 96).dots);
    expect(ringGeometry(-5, 96).dots).toEqual(ringGeometry(0, 96).dots);
    expect(ringGeometry(Number.NaN, 96).dots).toEqual(ringGeometry(null, 96).dots);
    expect([Number.NaN, Infinity, -Infinity, undefined].map(meterValue)).toEqual([
      null,
      null,
      null,
      null,
    ]);
  });

  it('draws dots from 64 px and a solid ring below, unless a style is given', () => {
    expect(ringGeometry(50, 64).style).toBe('dotted');
    expect(ringGeometry(50, 63).style).toBe('solid');
    expect(ringGeometry(50, 34).style).toBe('solid');
    expect(ringGeometry(50, 96, 'solid').style).toBe('solid');
    expect(ringGeometry(50, 34, 'dotted').style).toBe('dotted');
    expect(ringGeometry(50, 96, 'solid').dots).toEqual([]);
  });

  it("draws the solid ring as the brand's mark, at its optical size below 33 px", () => {
    // marketing/brand/mark.mjs, parts(FINAL), on its 64 grid.
    expect(ringGeometry(50, 64, 'solid').ring).toBe(
      'M36.51 52.53A22 22 0 1 1 52.42 39.18A10.6 10.6 0 0 0 42.04 37.56' +
        'A12 12 0 1 0 36.72 42.03A10.6 10.6 0 0 0 36.51 52.53Z',
    );
    expect(ringGeometry(50, 64, 'solid').dot).toEqual({ x: 45.82, y: 47.47, r: 7.6 });
    // preset(26): the dot 7.4 and the gap 3.6 on the 64 grid; at 34 px the final geometry.
    expect(ringGeometry(100, 26).dot.r).toBe(3.01);
    expect(ringGeometry(100, 34).dot.r).toBe(4.04);
    // Dots always sit on the final geometry.
    expect(ringGeometry(50, 26, 'dotted').dot.r).toBe(3.09);
  });

  it('fills the solid ring from just after the dot: track at 0 and no data, whole at 100 %', () => {
    for (const value of [null, 0]) {
      const g = ringGeometry(value, 34);
      expect([g.part, g.full]).toEqual([null, false]);
    }
    expect([ringGeometry(100, 34).part, ringGeometry(100, 34).full]).toEqual([null, true]);
    // Half fills to the point opposite the dot (50° + 180°).
    const half = partEnd(ringGeometry(50, 64, 'solid').part!);
    expect(angleOf(64, half.outer.x, half.outer.y)).toBeCloseTo(230, 0);
    expect(angleOf(64, half.inner.x, half.inner.y)).toBeCloseTo(230, 0);
    // 1 % still shows a sliver: 4° past the bite's edge at the band's middle (29.07° from the dot).
    const sliver = partEnd(ringGeometry(1, 64, 'solid').part!);
    expect(angleOf(64, sliver.outer.x, sliver.outer.y)).toBeCloseTo(83.07, 0);
    // The part starts where the ring does, at the bite.
    expect(ringGeometry(1, 64, 'solid').part).toMatch(/^M36\.51 52\.53A22 22 0 0 1 /);
  });

  it('draws a hollow dot with an outline of 0.3 of the step, at least 1 px, inside its edge', () => {
    expect([96, 76, 64, 34, 26].map((size) => ringGeometry(null, size).hollow)).toEqual([
      1.5, 1.19, 1, 1, 1,
    ]);
    // The outline's outer edge on the dot's: r 11.4 less half of 1.5 at 96 px.
    expect(ringGeometry(null, 96).hollowR).toBe(10.65);
    expect(ringGeometry(100, 34).hollowR).toBe(3.54);
  });

  it('rings a running dot 1.25 px clear of it and glows to 1.8 of its radius', () => {
    // A 1.5 px ring on r + 2: its inner edge 1.25 px from the dot (4.04 at 34 px).
    expect([ringGeometry(100, 34).auraR, ringGeometry(100, 34).glowR]).toEqual([6.04, 7.27]);
    expect([ringGeometry(100, 26).auraR, ringGeometry(100, 26).glowR]).toEqual([5.01, 5.41]);
  });
});

describe('the reveal', () => {
  it('delays the dots that light now in order clockwise, within the sweep', () => {
    // A checklist step done: from 40 % to 60 % at 72 px, three dots of fifteen.
    const g = ringGeometry(60, 72);
    const delays = revealDelays(g.dots, 40);
    expect(delays.filter((d) => d !== null)).toEqual([0, REVEAL_SWEEP_MS / 2, REVEAL_SWEEP_MS]);
    // The dots lit before and the unlit ones get none.
    expect(delays.slice(0, 6)).toEqual(Array(6).fill(null));
    expect(delays.slice(9)).toEqual(Array(6).fill(null));
  });

  it('starts at the first dot from 0, and spreads two circles by their place along the arc', () => {
    const one = revealDelays(ringGeometry(20, 72).dots, 0);
    expect(one.filter((d) => d !== null)).toEqual([0, 140, 280]);
    const g = ringGeometry(50, 96);
    const delays = revealDelays(g.dots, 0);
    const timed = g.dots
      .map((d, i) => ({ t: d.t, delay: delays[i] }))
      .filter((d) => d.delay !== null && d.delay !== undefined);
    expect(timed).toHaveLength(18);
    const byPlace = [...timed].sort((a, b) => a.t - b.t).map((d) => d.delay);
    expect(byPlace).toEqual([...byPlace].sort((a, b) => a! - b!));
    expect(Math.max(...timed.map((d) => d.delay!))).toBe(REVEAL_SWEEP_MS);
  });

  it('grows the solid fill from where the old value ended', () => {
    const fresh = growArc(34, 0, 20);
    expect(fresh.start).toBe(1);
    const step = growArc(34, 40, 60);
    expect(step.start).toBeGreaterThan(0.25);
    expect(step.start).toBeLessThan(0.35);
    expect(step.width).toBe(7.31);
    // From the dot's direction along the band's middle (17 on the grid), clockwise.
    expect(step.d).toMatch(/^M\d+\.?\d* \d+\.?\d*A9\.03 9\.03 0 1 1 /);
    // To 100 %: on to the bite's middle, so it ends as the whole ring.
    const end = /A[\d.]+ [\d.]+ 0 1 1 ([\d.]+) ([\d.]+)$/.exec(growArc(34, 80, 100).d)!;
    expect(angleOf(34, Number(end[1]), Number(end[2]))).toBeCloseTo(49, 0);
  });
});

describe('RingMeter', () => {
  async function render(inputs: Record<string, unknown>) {
    const fixture = TestBed.createComponent(RingMeter);
    for (const [name, value] of Object.entries(inputs)) fixture.componentRef.setInput(name, value);
    await fixture.whenStable();
    return fixture.nativeElement as HTMLElement;
  }
  const dot = (root: HTMLElement) => root.querySelector<SVGCircleElement>('.ring-dot')!;
  /** Every CSS rule the page holds, nested ones included. */
  const rules = () => {
    const all: CSSRule[] = [];
    const walk = (list: CSSRuleList) => {
      for (const rule of Array.from(list)) {
        all.push(rule);
        if ('cssRules' in rule) walk((rule as CSSGroupingRule).cssRules);
      }
    };
    for (const sheet of Array.from(document.styleSheets)) walk(sheet.cssRules);
    return all;
  };

  beforeEach(() => TestBed.configureTestingModule({ imports: [RingMeter] }));

  it('draws the dotted ring at 96 px with the flat brand dot, hidden from assistive technology', async () => {
    const root = await render({ value: 65.7, size: 96 });
    const svg = root.querySelector('svg');
    expect(svg?.getAttribute('aria-hidden')).toBe('true');
    expect(svg?.getAttribute('focusable')).toBe('false');
    expect(svg?.getAttribute('width')).toBe('96');
    expect(svg?.getAttribute('viewBox')).toBe('0 0 96 96');
    expect(root.querySelectorAll('.ring-fill circle')).toHaveLength(23);
    expect(root.querySelectorAll('.ring-track circle')).toHaveLength(12);
    expect(root.querySelector('.ring-fill circle')?.getAttribute('r')).toBe('3');
    expect(root.querySelector('.ring-track circle')?.getAttribute('r')).toBe('2.55');
    expect(dot(root).classList).toContain('brand');
    expect(dot(root).getAttribute('r')).toBe('11.4');
    expect(dot(root).getAttribute('stroke-width')).toBeNull();
    expect(root.querySelector('.ring-aura, .ring-glow, path')).toBeNull();
  });

  it('draws no data as the whole ring in track with a hollow brand dot, never as 100 %', async () => {
    const root = await render({ value: null, size: 96 });
    expect(root.querySelectorAll('.ring-fill circle')).toHaveLength(0);
    expect(root.querySelectorAll('.ring-track circle')).toHaveLength(35);
    expect(dot(root).classList).toContain('empty');
    // The outline's outer edge is the dot's edge: r 11.4 less half of 1.5.
    expect(dot(root).getAttribute('r')).toBe('10.65');
    expect(dot(root).getAttribute('stroke-width')).toBe('1.5');
  });

  it('draws a solid ring below 64 px: the track whole, the filled part over it', async () => {
    const root = await render({ value: 40, size: 34 });
    const paths = [...root.querySelectorAll('path')];
    expect(paths.map((p) => p.getAttribute('class'))).toEqual(['ring-track', 'ring-fill']);
    expect(paths[0]?.getAttribute('d')).toBe(ringGeometry(40, 34).ring);
    expect(paths[1]?.getAttribute('d')).toBe(ringGeometry(40, 34).part);
    expect(root.querySelectorAll('circle')).toHaveLength(1);
  });

  it('draws the gate emblem: the whole ring, the status in its dot, hollow for none', async () => {
    const cases: [RingStatus, string | null][] = [
      ['passed', null],
      ['failed', null],
      ['error', null],
      ['none', '1'],
    ];
    for (const [status, outline] of cases) {
      const root = await render({ value: 100, size: 34, status });
      expect(root.querySelector('path')?.getAttribute('class')).toBe('ring-fill');
      expect(root.querySelectorAll('path')).toHaveLength(1);
      expect(dot(root).getAttribute('class')).toBe(`ring-dot ${status}`);
      expect(dot(root).getAttribute('stroke-width')).toBe(outline);
      expect(root.querySelector('.ring-aura')).toBeNull();
    }
  });

  it('pulses a running dot, with a glow that only dark surfaces show', async () => {
    const root = await render({ value: 100, size: 34, status: 'running' });
    expect(dot(root).getAttribute('class')).toBe('ring-dot running');
    // A 1.5 px ring 2 px out from the dot's edge (4.04).
    const aura = root.querySelector('.ring-aura');
    expect(aura?.getAttribute('r')).toBe('6.04');
    const glow = root.querySelector('.ring-glow');
    expect(glow?.getAttribute('r')).toBe('7.27');
    const id = /^url\(#(.+)\)$/.exec(glow?.getAttribute('fill') ?? '')?.[1];
    expect(root.querySelector(`[id="${id}"]`)?.localName).toBe('radialGradient');
    // The glow, the ring, the pulse, then the dot on top.
    expect(
      [...root.querySelectorAll('svg > circle, svg > path')].map((e) => e.classList[0]),
    ).toEqual(['ring-glow', 'ring-fill', 'ring-aura', 'ring-dot']);

    // CSS keyframes, 1.8 s and on forever; still at full strength under reduced motion.
    const css = rules();
    const pulse = css.find((r) => /\.ring-aura\b/.test(r.cssText) && /animation:/.test(r.cssText));
    expect(pulse?.cssText).toMatch(/animation: \S*pulse 1\.8s ease-out infinite/);
    const keyframes = css.find((r) => /^@keyframes \S*pulse/.test(r.cssText));
    expect(keyframes?.cssText.replace(/\s+/g, ' ')).toMatch(
      /(from|0%) \{ transform: scale\(1\); opacity: 1; \} (to|100%) \{ transform: scale\(2\); opacity: 0; \}/,
    );
    const reduced = css.find((r) => /^@media \(prefers-reduced-motion: reduce\)/.test(r.cssText));
    expect(reduced?.cssText).toMatch(/\.ring-aura[^{]*\{ ?animation: none;? ?\}/);
    // The glow follows --ring-glow: 0 on light surfaces, 1 in the dark scheme.
    const dark = css.find((r) => /^@media \(prefers-color-scheme: dark\)/.test(r.cssText));
    expect(dark?.cssText).toContain('--ring-glow: 1');
  });

  it('gives every ring its own ids', async () => {
    const one = await render({ value: 100, size: 34, status: 'running' });
    const two = await render({ value: 100, size: 34, status: 'running' });
    const idOf = (root: HTMLElement) => root.querySelector('defs > [id]')?.id;
    expect(idOf(one)).toBeTruthy();
    expect(idOf(one)).not.toBe(idOf(two));
    expect(one.querySelector('.ring-glow')?.getAttribute('fill')).toBe(`url(#${idOf(one)})`);
    expect(two.querySelector('.ring-glow')?.getAttribute('fill')).toBe(`url(#${idOf(two)})`);
  });

  it('lights the new dots of the reveal clockwise, after one another', async () => {
    // The setup checklist's reveal when a step is done: from 40 % to 60 %.
    const root = await render({ value: 60, size: 72, from: 40 });
    const lit = [...root.querySelectorAll<SVGCircleElement>('.ring-fill circle')];
    expect(lit).toHaveLength(9);
    const fresh = lit.filter((c) => c.classList.contains('new'));
    expect(fresh).toEqual(lit.slice(6));
    expect(fresh.map((c) => parseInt(c.style.animationDelay, 10))).toEqual([0, 140, 280]);
    expect(lit.slice(0, 6).every((c) => c.style.animationDelay === '')).toBe(true);
  });

  it('grows the solid fill on from its old end, clipped by the ring', async () => {
    const root = await render({ value: 100, size: 34, from: 80, status: 'passed' });
    // The whole ring is track while the fill grows over it.
    const [base, grow] = [...root.querySelectorAll<SVGPathElement>('svg > path')];
    expect(base?.getAttribute('class')).toBe('ring-track');
    expect(grow?.getAttribute('class')).toBe('grow');
    expect(grow?.getAttribute('pathLength')).toBe('1');
    expect(parseFloat(grow!.style.getPropertyValue('--start'))).toBeGreaterThan(0);
    const id = /^url\(#(.+)\)$/.exec(grow?.getAttribute('clip-path') ?? '')?.[1];
    const clip = root.querySelector(`[id="${id}"]`);
    expect(clip?.localName).toBe('clipPath');
    expect(clip?.querySelector('path')?.getAttribute('d')).toBe(base?.getAttribute('d'));

    // The reveal over (no `from`), the ring is drawn whole and still.
    const still = await render({ value: 100, size: 34, status: 'passed' });
    expect([...still.querySelectorAll('path')].map((p) => p.getAttribute('class'))).toEqual([
      'ring-fill',
    ]);
  });

  it('plays no reveal without a lower earlier value, and none under reduced motion', async () => {
    for (const inputs of [
      { value: 60, size: 72 },
      { value: 60, size: 72, from: 60 },
      { value: 40, size: 72, from: 60 },
      { value: null, size: 72, from: 20 },
      { value: 60, size: 34, from: 80 },
    ]) {
      const root = await render(inputs);
      expect(root.querySelectorAll('.new, .grow')).toHaveLength(0);
    }
    const reduced = rules().find((r) =>
      /^@media \(prefers-reduced-motion: reduce\)/.test(r.cssText),
    );
    expect(reduced?.cssText).toMatch(/\.new[^{]*\{ ?animation: none;? ?\}/);
    expect(reduced?.cssText).toMatch(/\.grow[^{]*\{ ?animation: none;? ?\}/);
  });
});
