/**
 * The markup checks of the live Jira check (live.live.test.ts), kept apart so a unit test can prove
 * them. They read element tags only, never text or attribute values: an encoded advisory href
 * (`%7Bcolor:red%7D`) or a panel's `border-color` is correct output, a `<font>` is not.
 */
const TAG = /<\/?([a-z][a-z0-9]*)\b([^>]*)>/gi;
const STYLE = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i;
/** A `color:` declaration of its own, not the tail of `border-color` or `background-color`. */
const COLOUR_DECLARATION = /(?:^|[;\s])color\s*:/i;

const ELEMENTS: [string, ReadonlySet<string>][] = [
  ['an image', new Set(['img'])],
  ['bold or italic', new Set(['b', 'strong', 'em', 'i'])],
  ['a coloured text (font)', new Set(['font'])],
  ['a script', new Set(['script'])],
];

/** What the rendered HTML must not contain (names), judged by element, empty when it is clean. */
export function forbiddenMarkup(html: string): string[] {
  const found = new Set<string>();
  for (const [, tag, attributes] of html.matchAll(TAG)) {
    const name = (tag ?? '').toLowerCase();
    for (const [what, names] of ELEMENTS) if (names.has(name)) found.add(what);
    const style = STYLE.exec(attributes ?? '');
    if (COLOUR_DECLARATION.test(style?.[1] ?? style?.[2] ?? ''))
      found.add('a coloured text (style)');
  }
  return [...found];
}
