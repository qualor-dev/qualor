import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  AST,
  ASTWithSource,
  BindingPipe,
  LiteralPrimitive,
  parseTemplate,
  TemplateLiteralElement,
  TmplAstBoundAttribute,
  TmplAstBoundText,
  TmplAstElement,
  TmplAstText,
  TmplAstTextAttribute,
} from '@angular/compiler';
import { describe, expect, it } from 'vitest';

/**
 * Brief §7 and plan 1F rulings Y3/Y5, checked on every `pnpm test`:
 * - every user-facing string in a template is marked for i18n with a stable `@@id`;
 * - no template binds `innerHTML`/`outerHTML`, and no code bypasses Angular's sanitizer or writes
 *   HTML itself, so server strings (issue messages, rule descriptions) are only ever text.
 */
const SRC = fileURLToPath(new URL('../src', import.meta.url));
/** Attributes a person reads or hears. */
const USER_FACING_ATTRIBUTES = new Set([
  'title',
  'placeholder',
  'alt',
  'label',
  'aria-label',
  'aria-description',
  'aria-placeholder',
  'aria-roledescription',
  'aria-valuetext',
]);
const LETTER = /\p{L}/u;
/** `<input type="submit|button|reset">` shows its `value` as the button's label. */
const BUTTON_INPUT_TYPES = new Set(['submit', 'button', 'reset']);
const FORBIDDEN_CODE: [RegExp, string][] = [
  [/bypassSecurityTrust/, 'bypasses the sanitizer'],
  [/\b(inner|outer)HTML\b/, 'touches innerHTML/outerHTML'],
  [/\bsetProperty\([^)]*['"`](inner|outer)HTML['"`]/, 'sets HTML through the renderer'],
  [/\bcreateContextualFragment\b|\bDOMParser\b/, 'parses HTML'],
  [/insertAdjacentHTML|document\.write/, 'writes HTML'],
  [
    /\btemplate\s*:\s*[`'"]/,
    'uses an inline template (use templateUrl, so the i18n check sees it)',
  ],
];

const display = (file: string) => relative(SRC, file).split(sep).join('/');

function files(dir: string, suffix: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return files(path, suffix);
    return entry.name.endsWith(suffix) ? [path] : [];
  });
}

interface I18nMeta {
  constructor: { name: string };
  customId?: string;
}

function isMessage(meta: unknown): meta is I18nMeta {
  return (meta as I18nMeta | undefined)?.constructor.name === 'Message';
}

/** What in one `.ts` source bypasses the sanitizer, touches or parses HTML, or inlines a template. */
export function codeProblems(source: string): string[] {
  return FORBIDDEN_CODE.filter(([pattern]) => pattern.test(source)).map(([, why]) => why);
}

/**
 * String literals with letters in an expression: text the template shows without i18n. Pipe
 * arguments (`label: 'severity'`) are parameters, not text, so they are skipped.
 */
function literalTexts(expression: unknown): string[] {
  const found: string[] = [];
  const seen = new Set<unknown>();
  const walk = (node: unknown): void => {
    if (node === null || typeof node !== 'object' || seen.has(node)) return;
    seen.add(node);
    if (node instanceof ASTWithSource) return walk(node.ast);
    if (node instanceof LiteralPrimitive) {
      if (typeof node.value === 'string' && LETTER.test(node.value)) found.push(node.value);
      return;
    }
    if (node instanceof TemplateLiteralElement) {
      if (LETTER.test(node.text)) found.push(node.text);
      return;
    }
    if (node instanceof BindingPipe) return walk(node.exp);
    for (const [key, value] of Object.entries(node)) {
      if (/span$/i.test(key)) continue;
      for (const child of Array.isArray(value) ? value : [value]) {
        if (child instanceof AST || child instanceof ASTWithSource) walk(child);
        else if (child instanceof TemplateLiteralElement) walk(child);
      }
    }
  };
  walk(expression);
  return found;
}

/** Problems in one template, as `line:column message`. */
export function templateProblems(source: string, url: string): string[] {
  const parsed = parseTemplate(source, url, { preserveWhitespaces: false });
  const problems = (parsed.errors ?? []).map((e) => e.toString());
  const seen = new Set<unknown>();
  const at = (node: { sourceSpan: { start: { line: number; col: number } } }) =>
    `${node.sourceSpan.start.line + 1}:${node.sourceSpan.start.col + 1}`;

  const visit = (node: unknown, inI18n: boolean): void => {
    if (node === null || typeof node !== 'object' || seen.has(node)) return;
    seen.add(node);
    const record = node as Record<string, unknown> & {
      i18n?: unknown;
      name?: string;
      sourceSpan: { start: { line: number; col: number } };
    };
    const message = isMessage(record.i18n) ? record.i18n : undefined;
    if (message && !message.customId) problems.push(`${at(record)} i18n without an @@id`);
    const translated = inI18n || message !== undefined;
    if (node instanceof TmplAstText && LETTER.test(node.value) && !translated) {
      problems.push(`${at(record)} untranslated text "${node.value.trim()}"`);
    }
    if (node instanceof TmplAstBoundText && !translated) {
      const strings = (node.value as unknown as { ast: { strings?: string[] } }).ast.strings ?? [];
      if (strings.some((s) => LETTER.test(s))) {
        problems.push(`${at(record)} untranslated text around an interpolation`);
      }
    }
    if (
      node instanceof TmplAstTextAttribute &&
      USER_FACING_ATTRIBUTES.has(node.name) &&
      LETTER.test(node.value) &&
      message === undefined
    ) {
      problems.push(`${at(record)} untranslated attribute ${node.name}="${node.value}"`);
    }
    if (node instanceof TmplAstBoundText) {
      for (const text of literalTexts(node.value)) {
        problems.push(`${at(record)} string literal "${text}" in an interpolation`);
      }
    }
    if (node instanceof TmplAstBoundAttribute && USER_FACING_ATTRIBUTES.has(node.name)) {
      for (const text of literalTexts(node.value)) {
        problems.push(`${at(record)} string literal "${text}" bound to ${node.name}`);
      }
    }
    if (node instanceof TmplAstElement && node.name === 'input') {
      const type = node.attributes.find((a) => a.name === 'type')?.value.toLowerCase();
      if (type !== undefined && BUTTON_INPUT_TYPES.has(type)) {
        for (const attribute of node.attributes) {
          if (attribute.name === 'value' && LETTER.test(attribute.value) && !attribute.i18n) {
            problems.push(`${at(attribute)} untranslated attribute value="${attribute.value}"`);
          }
        }
        for (const input of node.inputs) {
          if (input.name !== 'value') continue;
          for (const text of literalTexts(input.value)) {
            problems.push(`${at(input)} string literal "${text}" bound to value`);
          }
        }
      }
    }
    if (typeof record.name === 'string' && /^(innerHTML|outerHTML)$/i.test(record.name)) {
      problems.push(`${at(record)} binds ${record.name}`);
    }
    for (const [key, value] of Object.entries(record)) {
      if (key === 'i18n' || key.endsWith('Span')) continue;
      const children = Array.isArray(value) ? value : [value];
      for (const child of children) {
        if (child !== null && typeof child === 'object' && 'sourceSpan' in child) {
          visit(child, translated);
        }
      }
    }
  };
  for (const node of parsed.nodes) visit(node, false);
  return problems;
}

describe('UI templates and code (brief §7, plan 1F rulings Y3/Y5)', () => {
  it('reports untranslated text, attributes without i18n, missing ids and innerHTML', () => {
    const problems = templateProblems(
      `<h1 i18n="@@ok.title">Fine {{ name }}</h1>
       <p>Plain text</p>
       <p>{{ count }} issues</p>
       <p>{{ a }} · {{ b }} 42%</p>
       <input placeholder="Search" />
       <input placeholder="Search" i18n-placeholder="@@ok.search" />
       <span i18n>No id</span>
       @if (x) { <b i18n="@@ok.yes">Yes</b> } @else { No }
       <div [innerHTML]="html"></div>`,
      'sample.html',
    );
    expect(problems).toEqual([
      '2:11 untranslated text "Plain text"',
      '3:11 untranslated text around an interpolation',
      '5:15 untranslated attribute placeholder="Search"',
      '7:8 i18n without an @@id',
      '8:55 untranslated text "No"',
      '9:13 binds innerHTML',
    ]);
  });

  it('reports string literals with letters in interpolations and user-facing bindings', () => {
    const problems = templateProblems(
      `<p>{{ 'Hello' }}</p>
       <p>{{ v | label: 'severity' }} {{ v | label: kind }}</p>
       <p>{{ ok ? 'Yes' : count }}</p>
       <b [title]="'Hello'"></b>
       <b [attr.aria-label]="'Close'"></b>
       <b [attr.aria-describedby]="x ? 'some-id' : null"></b>
       <a [routerLink]="'/projects'"></a>
       <i aria-placeholder="Type here"></i>
       <input type="submit" value="Save" />
       <input type="submit" value="Save" i18n-value="@@ok.save" />
       <input type="text" value="Prefilled" />
       <input type="button" [value]="'Go'" />
       <p>{{ \`Hi \${name}\` }}</p>
       <p i18n="@@ok.p">Count {{ 'items' }}</p>
       <p>{{ 42 }} {{ '·' }}</p>`,
      'sample.html',
    );
    expect(problems).toEqual([
      '1:4 string literal "Hello" in an interpolation',
      '3:11 string literal "Yes" in an interpolation',
      '4:11 string literal "Hello" bound to title',
      '5:11 string literal "Close" bound to aria-label',
      '8:11 untranslated attribute aria-placeholder="Type here"',
      '9:29 untranslated attribute value="Save"',
      '12:29 string literal "Go" bound to value',
      '13:11 string literal "Hi " in an interpolation',
      '14:25 string literal "items" in an interpolation',
    ]);
  });

  it('finds no problem in any template of ui/src', () => {
    const problems = files(SRC, '.html')
      .filter((file) => !file.endsWith('index.html'))
      .flatMap((file) =>
        templateProblems(readFileSync(file, 'utf8'), file).map((p) => `${display(file)}:${p}`),
      );
    expect(problems).toEqual([]);
  });

  it('reports code that touches or parses HTML, bypasses the sanitizer or inlines a template', () => {
    const bad: [string, string[]][] = [
      ['el.innerHTML = s;', ['touches innerHTML/outerHTML']],
      ['const html = el.innerHTML;', ['touches innerHTML/outerHTML']],
      ["el['outerHTML'] = s;", ['touches innerHTML/outerHTML']],
      [
        "renderer.setProperty(el, 'innerHTML', s);",
        ['touches innerHTML/outerHTML', 'sets HTML through the renderer'],
      ],
      ['range.createContextualFragment(s);', ['parses HTML']],
      ["new DOMParser().parseFromString(s, 'text/html');", ['parses HTML']],
      ["el.insertAdjacentHTML('beforeend', s);", ['writes HTML']],
      ['document.write(s);', ['writes HTML']],
      ['sanitizer.bypassSecurityTrustHtml(s);', ['bypasses the sanitizer']],
      [
        "@Component({ template: '<p></p>' })",
        ['uses an inline template (use templateUrl, so the i18n check sees it)'],
      ],
    ];
    for (const [source, expected] of bad) expect(codeProblems(source), source).toEqual(expected);
    expect(
      codeProblems("el.textContent = s; const innerHtmlish = 1; templateUrl: './x.html'"),
    ).toEqual([]);
  });

  it('finds no sanitizer bypass, HTML writing or inline template in ui/src', () => {
    const problems = files(SRC, '.ts').flatMap((file) =>
      codeProblems(readFileSync(file, 'utf8')).map((why) => `${display(file)} ${why}`),
    );
    expect(problems).toEqual([]);
  });
});
