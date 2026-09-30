import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The colour tokens keep their contrast in both schemes (spec §3, UI redesign step 11): text
 * 4.5:1 on every surface it sits on, marks and the borders of form fields 3:1 (WCAG 1.4.3, 1.4.11).
 * The dark scheme overrides the light tokens in `@media (prefers-color-scheme: dark)`; a token it
 * leaves alone keeps its light value.
 */
const styles = readFileSync(new URL('../../ui/src/styles.css', import.meta.url), 'utf8');

/** The body of the first `{ … }` block that follows `start`. */
function block(start: string): string {
  const at = styles.indexOf(start);
  if (at < 0) throw new Error(`no ${start} in styles.css`);
  const open = styles.indexOf('{', at);
  let depth = 0;
  for (let i = open; i < styles.length; i++) {
    if (styles[i] === '{') depth += 1;
    if (styles[i] === '}' && --depth === 0) return styles.slice(open + 1, i);
  }
  throw new Error(`unclosed ${start}`);
}

function colours(text: string): Record<string, string> {
  return Object.fromEntries(
    [...text.matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})\b/gi)].map((m) => [m[1]!, m[2]!.toLowerCase()]),
  );
}

const light = colours(block(':root {'));
const schemes = {
  light,
  dark: { ...light, ...colours(block('@media (prefers-color-scheme: dark) {')) },
};

/** WCAG 2 contrast ratio of two #rrggbb colours. */
function contrast(a: string, b: string): number {
  const luminance = (hex: string) => {
    const [r, g, bl] = [1, 3, 5].map((i) => {
      const c = parseInt(hex.slice(i, i + 2), 16) / 255;
      return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
    });
    return 0.2126 * r! + 0.7152 * g! + 0.0722 * bl!;
  };
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

/** Text: [foreground, backgrounds]; `#fff` is the primary button's label. */
const TEXT: [string, string[]][] = [
  ['text', ['bg', 'surface', 'surface-2', 'neutral-soft']],
  ['text-2', ['bg', 'surface', 'surface-2']],
  ['text-muted', ['bg', 'surface', 'surface-2', 'neutral-soft']],
  ['accent', ['bg', 'surface', 'surface-2', 'accent-soft']],
  ['accent-text', ['accent']],
  ['ok', ['surface', 'ok-soft']],
  ['bad', ['surface', 'bad-soft']],
  ['warn', ['surface', 'warn-soft']],
  ['#ffffff', ['primary', 'primary-hover']],
  ['ink-text', ['ink', 'ink-2']],
  ['ink-muted', ['ink', 'ink-2']],
];

/**
 * Marks and field borders: the chart accent and the pending mark, the fills of states, the focus
 * ring, the border of an input, and the severities a chart draws without words beside each mark.
 * Low and Info are the ramp's quiet end: their marks always stand beside their names and counts.
 */
const MARKS: [string, string[]][] = [
  ['chart-accent', ['surface', 'chart-track']],
  ['chart-spark', ['surface']],
  ['ok', ['surface', 'chart-track']],
  ['bad', ['surface', 'chart-track']],
  ['warn', ['surface', 'chart-track']],
  ['focus', ['bg', 'surface']],
  ['control-border', ['bg', 'surface', 'surface-2']],
  ['sev-blocker', ['surface']],
  ['sev-high', ['surface']],
  ['sev-medium', ['surface']],
  ['rating-a', ['surface']],
  ['rating-b', ['surface']],
  ['rating-c', ['surface']],
  ['rating-d', ['surface']],
  ['rating-e', ['surface']],
];

function value(scheme: Record<string, string>, name: string): string {
  const colour = name.startsWith('#') ? name : scheme[name];
  if (!colour) throw new Error(`no --${name} colour in styles.css`);
  return colour;
}

for (const [name, scheme] of Object.entries(schemes)) {
  describe(`the ${name} scheme`, () => {
    for (const [fg, bgs] of TEXT) {
      for (const bg of bgs) {
        it(`text ${fg} on ${bg} reads at 4.5:1`, () => {
          expect(contrast(value(scheme, fg), value(scheme, bg))).toBeGreaterThanOrEqual(4.5);
        });
      }
    }
    for (const [fg, bgs] of MARKS) {
      for (const bg of bgs) {
        it(`mark ${fg} on ${bg} stands out at 3:1`, () => {
          expect(contrast(value(scheme, fg), value(scheme, bg))).toBeGreaterThanOrEqual(3);
        });
      }
    }
  });
}

describe('the form fields', () => {
  it('draw their border in --control-border', () => {
    const fields = block('\ninput,\nselect,\ntextarea {');
    expect(fields).toMatch(/border:\s*1px solid var\(--control-border\)/);
  });
});

describe('the severity badges', () => {
  // The dot takes the ramp the charts draw severities in (facets, distribution, legend).
  for (const severity of ['blocker', 'high', 'medium', 'low', 'info']) {
    it(`draw the ${severity} dot in --sev-${severity}`, () => {
      // Every rule for the dot (a shared rule gives its shape, its own one its colour).
      const rules = styles
        .split(`\n.badge-${severity}::before {`)
        .slice(1)
        .map((rest) => rest.slice(0, rest.indexOf('}')).replace(/\s+/g, ' '));
      expect(rules).toContainEqual(expect.stringContaining(`background: var(--sev-${severity});`));
    });
  }
});

describe('the pages outside the shell', () => {
  it('mark the edge of their ink panel on dark, where the page is nearly the same colour', () => {
    // The ink panel against the dark page is 1.07:1 (step 10 review).
    expect(contrast(schemes.dark['ink']!, schemes.dark['bg']!)).toBeLessThan(1.5);
    const dark = styles
      .split('@media (prefers-color-scheme: dark)')
      .slice(1)
      .map((rest) => rest.replace(/\s+/g, ' '));
    expect(
      dark.some((rule) =>
        /^[^@]*\.auth-art \{ box-shadow: inset -1px 0 0 var\(--hairline\)/.test(rule),
      ),
    ).toBe(true);
  });
});
