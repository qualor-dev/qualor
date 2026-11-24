/**
 * The ring meter's geometry (style C): the Qualor mark, a ring that reads as Q with a status dot
 * set into its lower right, drawn as the product's meter. Lengths are px of a size x size box;
 * angles are degrees clockwise from the positive x axis (y points down).
 */

/** The mark on its 64 grid, as qualor.dev's `marketing/brand/mark.mjs` draws it. */
export interface MarkGeometry {
  /** The ring's centre. */
  c: readonly [number, number];
  /** The ring's outer radius. */
  a: number;
  /** The ring's width. */
  band: number;
  /** The dot's direction from the centre. */
  angle: number;
  /** The dot's radius. */
  dot: number;
  /** The clear gap between the dot and the ring. */
  gap: number;
  /** The dot centre's distance from the ring's outer edge (negative: inside it). */
  out: number;
}

export const FINAL: MarkGeometry = {
  c: [32, 31],
  a: 22,
  band: 10,
  angle: 50,
  dot: 7.6,
  gap: 3,
  out: -0.5,
};

/** The mark's optical sizes: at 32 px and below, then 20 px and below, a wider gap and a smaller dot. */
export function preset(size: number): MarkGeometry {
  if (size <= 20) return { ...FINAL, band: 11, dot: 7.2, gap: 4.6 };
  if (size <= 32) return { ...FINAL, band: 10.4, dot: 7.4, gap: 3.6 };
  return FINAL;
}

export type RingStyle = 'dotted' | 'solid';

export interface Circle {
  x: number;
  y: number;
  r: number;
}

/** A dot of the dotted ring. */
export interface RingDot {
  x: number;
  y: number;
  /** Its place along its circle: 0 just after the bite, 1 just before it. */
  t: number;
  lit: boolean;
}

export interface RingGeometry {
  size: number;
  style: RingStyle;
  /** The status dot. */
  dot: Circle;
  /** A hollow dot's outline: 0.3 of the meter's step (5/96 of the size), at least 1 px. */
  hollow: number;
  /** A hollow dot's radius: its outline's outer edge is the dot's edge. */
  hollowR: number;
  /** The running dot's pulse: a 1.5 px ring, 1.25 px clear of the dot. */
  auraR: number;
  /** The running dot's glow (dark surfaces only). */
  glowR: number;
  /** Dotted: every dot, circle by circle from the inside, each circle clockwise from the bite. */
  dots: RingDot[];
  litR: number;
  unlitR: number;
  /** Solid: the mark's ring, one closed contour cut through around the dot. */
  ring: string;
  /** Solid: the filled part, from the bite to the value's end; null when empty or full. */
  part: string | null;
  /** Solid: the whole ring is filled. */
  full: boolean;
}

/** The smallest lit dot at 1x, in px: the unlit dots (0.85 of it) keep 2.2 px. */
export const MIN_DOT_R = 2.2 / 0.85;
/** An unlit dot's size, as a share of a lit one. */
const UNLIT = 0.85;
/** The dots' pitch, in lit radii, along the circles and across them. */
const PITCH = 2.5;
/** The least fill a value above 0 shows on the solid ring, in degrees. */
const MIN_SWEEP = 4;

const round2 = (n: number) => Math.round(n * 100) / 100;
const rad = (deg: number) => (deg * Math.PI) / 180;

/** The mark in a size x size box, in px. */
interface Box {
  cx: number;
  cy: number;
  /** The ring's outer radius. */
  R: number;
  /** The ring's inner radius. */
  r: number;
  dot: Circle;
  /** The radius of the cut around the dot: the dot and its gap. */
  bite: number;
  angle: number;
}

function markBox(size: number, geo: MarkGeometry): Box {
  const s = size / 64;
  const cx = geo.c[0] * s;
  const cy = geo.c[1] * s;
  const d = (geo.a + geo.out) * s;
  return {
    cx,
    cy,
    R: geo.a * s,
    r: (geo.a - geo.band) * s,
    dot: {
      x: cx + d * Math.cos(rad(geo.angle)),
      y: cy + d * Math.sin(rad(geo.angle)),
      r: geo.dot * s,
    },
    bite: (geo.dot + geo.gap) * s,
    angle: geo.angle,
  };
}

/** Half the angle that a circle of radius `e` around the dot covers at radius `rho`, seen from the centre. */
function halfAngle(b: Box, rho: number, e: number): number {
  const d = Math.hypot(b.dot.x - b.cx, b.dot.y - b.cy);
  const cos = (rho * rho + d * d - e * e) / (2 * rho * d);
  if (cos >= 1) return 0;
  if (cos <= -1) return 180;
  return (Math.acos(cos) * 180) / Math.PI;
}

/** The point at radius `rho` and angle `deg`, as path coordinates. */
function at(b: Box, rho: number, deg: number): string {
  return `${round2(b.cx + rho * Math.cos(rad(deg)))} ${round2(b.cy + rho * Math.sin(rad(deg)))}`;
}

/** The mark's ring: four arcs, one closed contour (the cut around the dot goes through it). */
function ringPath(b: Box): string {
  const ao = halfAngle(b, b.R, b.bite);
  const ai = halfAngle(b, b.r, b.bite);
  const [R, r, e] = [round2(b.R), round2(b.r), round2(b.bite)];
  return (
    `M${at(b, b.R, b.angle + ao)}A${R} ${R} 0 1 1 ${at(b, b.R, b.angle - ao)}` +
    `A${e} ${e} 0 0 0 ${at(b, b.r, b.angle - ai)}` +
    `A${r} ${r} 0 1 0 ${at(b, b.r, b.angle + ai)}` +
    `A${e} ${e} 0 0 0 ${at(b, b.R, b.angle + ao)}Z`
  );
}

/** The ring from the bite clockwise to `end`: the solid meter's filled part. */
function partPath(b: Box, end: number): string {
  const ao = halfAngle(b, b.R, b.bite);
  const ai = halfAngle(b, b.r, b.bite);
  const [R, r, e] = [round2(b.R), round2(b.r), round2(b.bite)];
  const large = (start: number) => (end - start > 180 ? 1 : 0);
  return (
    `M${at(b, b.R, b.angle + ao)}A${R} ${R} 0 ${large(b.angle + ao)} 1 ${at(b, b.R, end)}` +
    `L${at(b, b.r, end)}A${r} ${r} 0 ${large(b.angle + ai)} 0 ${at(b, b.r, b.angle + ai)}` +
    `A${e} ${e} 0 0 0 ${at(b, b.R, b.angle + ao)}Z`
  );
}

/**
 * Where the solid fill of `value` percent ends: clockwise from just after the bite (measured at the
 * band's middle) over the rest of the ring. A value above 0 shows at least a 4-degree sliver.
 */
function fillEnd(b: Box, value: number): number {
  const half = halfAngle(b, (b.R + b.r) / 2, b.bite);
  const span = 360 - 2 * half;
  return b.angle + half + span * Math.max(value / 100, MIN_SWEEP / span);
}

/**
 * The dotted ring's layout: as many concentric circles of dots as fit in the band with every dot
 * at least MIN_DOT_R and a pitch of 2.5 radii, both along the circles and across them: 2 circles
 * at 96 px, 1 from 64 to 76 px. Two or more circles fill the band's width; a single one keeps the
 * smallest dots, 14 to 16 of them (nine band-wide beads would read as a loading spinner). No dot
 * centre comes closer to the status dot than the bite and 0.6 of the pitch.
 */
function dottedLayout(b: Box): { litR: number; dots: Omit<RingDot, 'lit'>[] } {
  const band = b.R - b.r;
  const n = Math.max(1, Math.floor(band / (PITCH * MIN_DOT_R)));
  const across = band / n;
  const litR = n > 1 ? across / PITCH : MIN_DOT_R;
  const along = PITCH * litR;
  const clear = b.bite + 0.6 * along;
  const dots: Omit<RingDot, 'lit'>[] = [];
  for (let k = 0; k < n; k++) {
    const rho = b.r + across * (k + 0.5);
    const half = halfAngle(b, rho, clear);
    const sweep = 360 - 2 * half;
    const count = Math.max(2, Math.round((rho * rad(sweep)) / along) + 1);
    for (let i = 0; i < count; i++) {
      const t = i / (count - 1);
      const a = rad(b.angle + half + sweep * t);
      dots.push({
        x: round2(b.cx + rho * Math.cos(a)),
        y: round2(b.cy + rho * Math.sin(a)),
        t,
      });
    }
  }
  return { litR, dots };
}

/** The style a size gets by default: dots from 64 px, a solid ring below. */
export function defaultStyle(size: number): RingStyle {
  return size >= 64 ? 'dotted' : 'solid';
}

/** A value as the meter reads it: 0 to 100, or null for no data (NaN and the infinities too). */
export function meterValue(value: number | null | undefined): number | null {
  if (value === null || value === undefined || !Number.isFinite(value)) return null;
  return Math.min(100, Math.max(0, value));
}

/** Whether the dot at `t` is lit at `value` percent: the first one lights from any value above 0. */
export function isLit(t: number, value: number | null): boolean {
  return value !== null && value > 0 && t <= value / 100 + 1e-9;
}

/**
 * The ring meter: `value` (0 to 100, null for no data) fills the ring clockwise from just after
 * the bite, and the rest is track. Dotted: lit dots, and unlit ones at 0.85 of their size in the
 * track colour, on the mark's final geometry. Solid: the mark's ring in track with the filled part
 * over it, on the mark's optical size for the box.
 */
export function ringGeometry(
  value: number | null,
  size: number,
  style: RingStyle | null = null,
): RingGeometry {
  const v = meterValue(value);
  const chosen = style ?? defaultStyle(size);
  const b = markBox(size, chosen === 'dotted' ? FINAL : preset(size));
  const hollow = Math.max(1, 0.3 * (5 / 96) * size);
  const shared = {
    size,
    style: chosen,
    dot: { x: round2(b.dot.x), y: round2(b.dot.y), r: round2(b.dot.r) },
    hollow: round2(hollow),
    hollowR: round2(b.dot.r - hollow / 2),
    auraR: round2(b.dot.r + 2),
    glowR: round2(b.dot.r * 1.8),
  };
  if (chosen === 'dotted') {
    const layout = dottedLayout(b);
    return {
      ...shared,
      dots: layout.dots.map((d) => ({ ...d, lit: isLit(d.t, v) })),
      litR: round2(layout.litR),
      unlitR: round2(UNLIT * layout.litR),
      ring: '',
      part: null,
      full: false,
    };
  }
  return {
    ...shared,
    dots: [],
    litR: 0,
    unlitR: 0,
    ring: ringPath(b),
    part: v !== null && v > 0 && v < 100 ? partPath(b, fillEnd(b, v)) : null,
    full: v !== null && v >= 100,
  };
}

/** The dotted reveal's sweep: the last new dot starts this long after the first, in ms. */
export const REVEAL_SWEEP_MS = 280;

/**
 * The dotted reveal (the setup checklist, when a step gets done): the delay of each dot that is lit
 * now and was not at `from` percent, by its place along the arc, so that they light in order
 * clockwise within REVEAL_SWEEP_MS; null for every other dot.
 */
export function revealDelays(dots: readonly RingDot[], from: number): (number | null)[] {
  const fresh = (d: RingDot) => d.lit && !isLit(d.t, from);
  const places = dots.filter(fresh).map((d) => d.t);
  if (places.length === 0) return dots.map(() => null);
  const first = Math.min(...places);
  const range = Math.max(...places) - first;
  return dots.map((d) => {
    if (!fresh(d)) return null;
    return range > 0 ? Math.round((REVEAL_SWEEP_MS * (d.t - first)) / range) : 0;
  });
}

/** The solid reveal's arc: the fill grows along it, and the ring's own outline clips it. */
export interface GrowArc {
  /** Along the band's middle, clockwise from the dot's direction to the value's end. */
  d: string;
  /** Wider than the band, so the clip draws the edges. */
  width: number;
  /** The dash offset it grows from (path length 1): what `from` filled shows at once. */
  start: number;
}

/** The solid reveal from `from` to `value` percent (from below value). */
export function growArc(size: number, from: number, value: number): GrowArc {
  const b = markBox(size, preset(size));
  const rho = (b.R + b.r) / 2;
  // At 100 % the whole ring fills: on past the value's end, up to the bite's middle.
  const end = value >= 100 ? b.angle + 359 : fillEnd(b, value);
  const shown = from > 0 ? (fillEnd(b, from) - b.angle) / (end - b.angle) : 0;
  const large = end - b.angle > 180 ? 1 : 0;
  return {
    d: `M${at(b, rho, b.angle)}A${round2(rho)} ${round2(rho)} 0 ${large} 1 ${at(b, rho, end)}`,
    width: round2(b.R - b.r + 2),
    start: Math.round((1 - Math.min(1, shown)) * 1000) / 1000,
  };
}
