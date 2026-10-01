import { Lexer, type Token, type Tokens } from 'marked';

/**
 * The user guide (`docs/guide/*.md`) as data the templates render: Markdown is lexed with marked
 * and narrowed to the few kinds of node the guide uses. No HTML is ever produced or inserted
 * (`ui/tools/templates.test.ts`): text is interpolated, so raw HTML in a page shows as text.
 */

/** Where a link goes: a guide page in this app (a route), or anywhere else (a plain href). */
export type DocLink =
  | { kind: 'page'; route: string[]; fragment: string | null }
  | { kind: 'external'; href: string };

export type DocInline =
  | { kind: 'text'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'br' }
  | { kind: 'strong' | 'em' | 'del'; children: DocInline[] }
  | { kind: 'link'; link: DocLink; children: DocInline[] };

export interface DocListItem {
  blocks: DocBlock[];
}

export type DocAlign = 'left' | 'center' | 'right' | null;

export type DocBlock =
  | { kind: 'heading'; depth: number; id: string; children: DocInline[] }
  | { kind: 'paragraph'; children: DocInline[] }
  /** The text of a tight list item: inline content without a paragraph around it. */
  | { kind: 'plain'; children: DocInline[] }
  | { kind: 'code'; lang: string; text: string }
  | { kind: 'list'; ordered: boolean; start: number; items: DocListItem[] }
  | { kind: 'blockquote'; blocks: DocBlock[] }
  | { kind: 'table'; align: DocAlign[]; header: DocInline[][]; rows: DocInline[][][] }
  | { kind: 'hr' };

export interface DocHeading {
  depth: number;
  id: string;
  text: string;
}

export interface DocPage {
  /** The page's `# Title`, or the page name when it has none. */
  title: string;
  /** Everything after the title. */
  blocks: DocBlock[];
  /** Every heading below the title, in order, with its anchor. */
  headings: DocHeading[];
}

/** Repository files the guide links to are shown on GitHub, as on qualor.dev. */
export const REPOSITORY = 'https://github.com/qualor-dev/qualor';
const GUIDE_DIR = 'docs/guide';

/** `a/b/../c/./d` → `a/c/d`; a path that climbs above the root keeps its leading `..`. */
export function normalizePath(path: string): string {
  const out: string[] = [];
  for (const part of path.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..' && out.length > 0 && out.at(-1) !== '..') out.pop();
    else out.push(part);
  }
  return out.join('/');
}

/**
 * A guide link in the app: `./gitlab.md#tokens` is the route `/docs/gitlab` at `#tokens`, `#x` the
 * current page at `#x`, `../../deploy/README.md` the file on GitHub; a URL with a scheme stays as is.
 */
export function docLink(href: string, page: string): DocLink {
  if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('/')) return { kind: 'external', href };
  const hash = href.indexOf('#');
  const path = hash === -1 ? href : href.slice(0, hash);
  const fragment = hash === -1 ? null : decodeURIComponent(href.slice(hash + 1));
  if (path === '') return { kind: 'page', route: pageRoute(page), fragment };
  const target = normalizePath(`${GUIDE_DIR}/${path}`);
  const guidePage = new RegExp(`^${GUIDE_DIR}/([\\w.-]+)\\.md$`).exec(target)?.[1];
  if (guidePage !== undefined) return { kind: 'page', route: pageRoute(guidePage), fragment };
  if (target.startsWith('..')) return { kind: 'external', href };
  const kind = path.endsWith('/') ? 'tree' : 'blob';
  const anchor = fragment === null ? '' : '#' + fragment;
  return { kind: 'external', href: `${REPOSITORY}/${kind}/main/${target}${anchor}` };
}

/** The route of a guide page: README is the docs home. */
export function pageRoute(page: string): string[] {
  return page === 'README' ? ['/docs'] : ['/docs', page];
}

/**
 * GitHub's heading anchors (github-slugger), which the guide's `#anchor` links are written
 * against: lower case, punctuation dropped, spaces to dashes, repeats numbered `-1`, `-2`.
 */
export function slugger(): (text: string) => string {
  const seen = new Map<string, number>();
  return (text) => {
    const base = text
      .toLowerCase()
      .replace(/[^\p{L}\p{M}\p{N}\p{Pc} -]/gu, '')
      .replace(/ /g, '-');
    const count = seen.get(base);
    seen.set(base, (count ?? -1) + 1);
    return count === undefined ? base : `${base}-${count + 1}`;
  };
}

/** The text of inline nodes, as a heading's anchor and the table of contents read it. */
export function plainText(nodes: readonly DocInline[]): string {
  return nodes.map(inlineText).join('');
}

function inlineText(n: DocInline): string {
  if (n.kind === 'text' || n.kind === 'code') return n.text;
  if (n.kind === 'br') return ' ';
  return plainText(n.children);
}

/** marked decodes entities in `text` but keeps them in `raw`; inline text tokens carry both. */
function inlines(tokens: readonly Token[] | undefined, page: string): DocInline[] {
  const out: DocInline[] = [];
  for (const t of tokens ?? []) {
    switch (t.type) {
      case 'text':
      case 'escape': {
        const text = t as Tokens.Text | Tokens.Escape;
        if ('tokens' in text && text.tokens !== undefined && text.tokens.length > 0) {
          out.push(...inlines(text.tokens, page));
        } else {
          out.push({ kind: 'text', text: text.text });
        }
        break;
      }
      case 'codespan':
        out.push({ kind: 'code', text: (t as Tokens.Codespan).text });
        break;
      case 'br':
        out.push({ kind: 'br' });
        break;
      case 'strong':
      case 'em':
      case 'del':
        out.push({ kind: t.type, children: inlines((t as Tokens.Strong).tokens, page) });
        break;
      case 'link': {
        const link = t as Tokens.Link;
        out.push({ kind: 'link', link: docLink(link.href, page), children: inlines(link.tokens, page) });
        break;
      }
      case 'image': {
        // The guide has no images; one would show as its description.
        out.push({ kind: 'text', text: (t as Tokens.Image).text });
        break;
      }
      default:
        // Inline HTML and anything else: its source, as text.
        out.push({ kind: 'text', text: t.raw });
    }
  }
  return out;
}

function blocks(tokens: readonly Token[], page: string, slug: (text: string) => string): DocBlock[] {
  const out: DocBlock[] = [];
  for (const t of tokens) {
    switch (t.type) {
      case 'heading': {
        const h = t as Tokens.Heading;
        const children = inlines(h.tokens, page);
        out.push({ kind: 'heading', depth: h.depth, id: slug(plainText(children)), children });
        break;
      }
      case 'paragraph':
        out.push({ kind: 'paragraph', children: inlines((t as Tokens.Paragraph).tokens, page) });
        break;
      case 'text': {
        const text = t as Tokens.Text;
        out.push({
          kind: 'plain',
          children:
            text.tokens === undefined ? [{ kind: 'text', text: text.text }] : inlines(text.tokens, page),
        });
        break;
      }
      case 'code': {
        const code = t as Tokens.Code;
        out.push({ kind: 'code', lang: (code.lang ?? '').trim().split(/\s/)[0] ?? '', text: code.text });
        break;
      }
      case 'list': {
        const list = t as Tokens.List;
        out.push({
          kind: 'list',
          ordered: list.ordered,
          start: typeof list.start === 'number' ? list.start : 1,
          items: list.items.map((item) => ({ blocks: blocks(item.tokens, page, slug) })),
        });
        break;
      }
      case 'blockquote':
        out.push({
          kind: 'blockquote',
          blocks: blocks((t as Tokens.Blockquote).tokens, page, slug),
        });
        break;
      case 'table': {
        const table = t as Tokens.Table;
        out.push({
          kind: 'table',
          align: table.align,
          header: table.header.map((cell) => inlines(cell.tokens, page)),
          rows: table.rows.map((row) => row.map((cell) => inlines(cell.tokens, page))),
        });
        break;
      }
      case 'hr':
        out.push({ kind: 'hr' });
        break;
      case 'html':
        out.push({ kind: 'paragraph', children: [{ kind: 'text', text: t.raw.trim() }] });
        break;
      default:
        // `space` and link definitions (marked has resolved them) carry nothing to show.
        break;
    }
  }
  return out;
}

function collectHeadings(nodes: readonly DocBlock[], into: DocHeading[]): DocHeading[] {
  for (const b of nodes) {
    if (b.kind === 'heading') into.push({ depth: b.depth, id: b.id, text: plainText(b.children) });
    else if (b.kind === 'blockquote') collectHeadings(b.blocks, into);
  }
  return into;
}

/** One guide page (`page` is its file name without `.md`) as data. */
export function parseDocPage(markdown: string, page: string): DocPage {
  const slug = slugger();
  const all = blocks(Lexer.lex(markdown.replace(/\r\n/g, '\n'), { gfm: true }), page, slug);
  const first = all[0];
  const titled = first?.kind === 'heading' && first.depth === 1;
  const body = titled ? all.slice(1) : all;
  return {
    title: titled ? plainText(first.children) : page,
    blocks: body,
    headings: collectHeadings(body, []),
  };
}
