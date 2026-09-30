export interface LensDot {
  x: number;
  y: number;
  r: number;
}

export interface LensGeometry {
  size: number;
  /** The centre, on both axes. */
  c: number;
  /** The ring's radius (its stroke sits inside the box). */
  r: number;
  dots: LensDot[];
  /** The level line across the circle; none when empty or full. */
  level: { x1: number; x2: number; y: number } | null;
}

const round2 = (n: number) => Math.round(n * 100) / 100;

/**
 * The lens (spec §6.1): the brand's halftone circle as a meter. A grid of dots in straight columns
 * (one under another, centred on the circle) fills it from the bottom up to `value` percent; dots
 * grow with depth like the screen prints. Every dot that touches the circle is drawn, and the lens
 * clips them at its ring (lens.css), so the fill reaches the ring all round, with no empty corners.
 */
export function lensGeometry(value: number | null, size: number): LensGeometry {
  const c = size / 2;
  const r = c - 1;
  const pct = value === null || !Number.isFinite(value) ? 0 : Math.min(100, Math.max(0, value));
  const levelY = c + r - (2 * r * pct) / 100;
  const step = Math.max(3.2, size / 17);
  const dots: LensDot[] = [];
  if (pct > 0) {
    for (let y = step / 2; y < size; y += step) {
      if (y < levelY + step * 0.2) continue;
      const depth = Math.min(1, (y - levelY) / (2 * r * 0.75));
      const dotR = step * (0.2 + 0.3 * depth);
      for (let x = step / 2; x < size; x += step) {
        if (Math.hypot(x - c, y - c) - dotR >= r) continue;
        dots.push({ x: round2(x), y: round2(y), r: round2(dotR) });
      }
    }
  }
  const half = Math.sqrt(Math.max(0, r * r - (levelY - c) ** 2));
  const level =
    pct > 0 && pct < 100 ? { x1: round2(c - half), x2: round2(c + half), y: round2(levelY) } : null;
  return { size, c, r, dots, level };
}
