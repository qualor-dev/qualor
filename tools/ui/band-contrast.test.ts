import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

/**
 * The header band is ink in both schemes. A tag on it takes one of the band's own colours: the
 * page's muted text is about 2.5:1 on ink in the light scheme (UI redesign, step 6 review).
 */
const styles = readFileSync(new URL('../../ui/src/styles.css', import.meta.url), 'utf8');

function rule(selector: string): string {
  const at = styles.indexOf(`\n${selector} {`);
  if (at < 0) throw new Error(`no ${selector} rule in styles.css`);
  return styles.slice(at, styles.indexOf('}', at));
}

/** A colour token's light-scheme value (the first definition, in `:root`). */
function token(name: string): string {
  const value = new RegExp(`--${name}:\\s*(#[0-9a-f]{6})`, 'i').exec(styles)?.[1];
  if (!value) throw new Error(`no --${name} colour in styles.css`);
  return value;
}

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

describe('tags on the header band', () => {
  it('a Built-in tag reads at 4.5:1 or more on the ink band', () => {
    const color = /\bcolor:\s*var\(--([\w-]+)\)/.exec(rule('.page-band .badge-tag'))?.[1];
    expect(color).toBeDefined();
    expect(contrast(token(color!), token('ink'))).toBeGreaterThanOrEqual(4.5);
  });
});
