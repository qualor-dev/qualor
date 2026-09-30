import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The rating letters (q-rating) are 17px text on a 12% tint of their own colour (rating.css): they
 * must reach WCAG AA for normal text, 4.5:1, in both schemes (UI redesign spec §2). The tint is
 * `color-mix(in srgb, <colour> 12%, var(--surface))`, mixed here the same way.
 */
const styles = readFileSync(new URL('../../ui/src/styles.css', import.meta.url), 'utf8');
const ratingCss = readFileSync(
  new URL('../../ui/src/app/charts/rating.css', import.meta.url),
  'utf8',
);

const light = styles.slice(0, styles.indexOf('@media (prefers-color-scheme: dark)'));
const dark = styles.slice(styles.indexOf('@media (prefers-color-scheme: dark)'));

function token(block: string, name: string): string {
  const found = new RegExp(`--${name}:\\s*(#[0-9a-f]{6});`, 'i').exec(block);
  if (!found?.[1]) throw new Error(`no --${name} in the block`);
  return found[1];
}

const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
const mix = (fg: string, bg: string, share: number) => {
  const [f, b] = [rgb(fg), rgb(bg)];
  return f.map((c, i) => Math.round(c * share + (b[i] ?? 0) * (1 - share)));
};
const luminance = ([r, g, b]: number[]) =>
  [r, g, b]
    .map((c) => (c ?? 0) / 255)
    .map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4))
    .reduce((sum, c, i) => sum + c * [0.2126, 0.7152, 0.0722][i]!, 0);
const contrast = (a: number[], b: number[]) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x! + 0.05) / (y! + 0.05);
};

describe('rating letters', () => {
  for (const [scheme, block] of [
    ['light', light],
    ['dark', dark],
  ] as const) {
    it(`reach 4.5:1 on their tint in the ${scheme} scheme`, () => {
      const surface = token(block, 'surface');
      for (const letter of ['a', 'b', 'c', 'd', 'e']) {
        const colour = token(block, `rating-${letter}`);
        const ratio = contrast(rgb(colour), mix(colour, surface, 0.12));
        expect(ratio, `rating ${letter.toUpperCase()} ${colour}`).toBeGreaterThanOrEqual(4.5);
      }
    });

    it(`show "no rating" in a text colour that reaches 4.5:1 in the ${scheme} scheme`, () => {
      const rule =
        /\.rating-letter:not\(\[data-rating\]\)\s*\{[^}]*color:\s*var\(--([\w-]+)\)/.exec(
          ratingCss,
        );
      expect(rule?.[1], 'a colour rule for the no-rating dash').toBeDefined();
      const surface = token(block, 'surface');
      const tint = mix(token(block, 'border-strong'), surface, 0.12);
      expect(contrast(rgb(token(block, rule![1]!)), tint)).toBeGreaterThanOrEqual(4.5);
    });
  }
});
