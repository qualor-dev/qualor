import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { Language, Parser, type Tree } from 'web-tree-sitter';
import { VENDORED_GRAMMARS } from './vendored';

export const GRAMMARS = [
  'typescript',
  'tsx',
  'javascript',
  'java',
  'csharp',
  'python',
  'html',
  'css',
  'kotlin',
  'swift',
  'php',
] as const;
export type GrammarId = (typeof GRAMMARS)[number];
export type WasmAsset = 'core' | GrammarId;

type VendoredGrammar = keyof typeof VENDORED_GRAMMARS;

/**
 * Package-relative WASM files (ruling C1: exact versions pinned in cli/package.json). The
 * vendored grammars (plan 8F, vendored.ts) are files in cli/grammars/ instead.
 */
const PACKAGE_FILES: Readonly<Record<Exclude<WasmAsset, VendoredGrammar>, string>> = {
  core: 'web-tree-sitter/web-tree-sitter.wasm',
  typescript: 'tree-sitter-typescript/tree-sitter-typescript.wasm',
  tsx: 'tree-sitter-typescript/tree-sitter-tsx.wasm',
  javascript: 'tree-sitter-javascript/tree-sitter-javascript.wasm',
  java: 'tree-sitter-java/tree-sitter-java.wasm',
  csharp: 'tree-sitter-c-sharp/tree-sitter-c_sharp.wasm',
  python: 'tree-sitter-python/tree-sitter-python.wasm',
  html: 'tree-sitter-html/tree-sitter-html.wasm',
  css: 'tree-sitter-css/tree-sitter-css.wasm',
  kotlin: '@tree-sitter-grammars/tree-sitter-kotlin/tree-sitter-kotlin.wasm',
  php: 'tree-sitter-php/tree-sitter-php.wasm',
};

export const DEFAULT_PARSE_TIMEOUT_MS = 10_000;

let embedded: Readonly<Record<WasmAsset, string>> | null = null;

/** Called by entry.bun.ts with the `$bunfs` paths of the embedded files (null resets). */
export function registerEmbeddedAssets(paths: Record<WasmAsset, string> | null): void {
  embedded = paths === null ? null : { ...paths };
}

export function wasmPath(asset: WasmAsset): string {
  const fromBinary = embedded?.[asset];
  if (fromBinary !== undefined) return fromBinary;
  if (Object.hasOwn(VENDORED_GRAMMARS, asset)) {
    const { file } = VENDORED_GRAMMARS[asset as VendoredGrammar];
    return fileURLToPath(new URL(`../../grammars/${file}`, import.meta.url));
  }
  return createRequire(import.meta.url).resolve(
    PACKAGE_FILES[asset as Exclude<WasmAsset, VendoredGrammar>],
  );
}

export interface Parsers {
  /** Parses `text`; null when it took longer than `timeoutMs`. The caller must `delete()` the tree. */
  parse(grammar: GrammarId, text: string, timeoutMs?: number): Tree | null;
  abiVersion(grammar: GrammarId): number;
  delete(): void;
}

let runtime: Promise<void> | undefined;
let languages: Promise<ReadonlyMap<GrammarId, Language>> | undefined;

async function loadLanguages(): Promise<ReadonlyMap<GrammarId, Language>> {
  runtime ??= Parser.init({ wasmBinary: readFileSync(wasmPath('core')) });
  await runtime;
  const map = new Map<GrammarId, Language>();
  for (const grammar of GRAMMARS) {
    map.set(grammar, await Language.load(readFileSync(wasmPath(grammar))));
  }
  return map;
}

/** Loads the grammars from the embedded or packaged WASM files; never touches the network. */
export async function loadParsers(): Promise<Parsers> {
  languages ??= loadLanguages();
  const loaded = await languages;
  const parser = new Parser();
  let current: GrammarId | null = null;
  return {
    parse(grammar, text, timeoutMs = DEFAULT_PARSE_TIMEOUT_MS) {
      const language = loaded.get(grammar);
      if (language === undefined) throw new Error(`unknown grammar ${grammar}`);
      if (current !== grammar) {
        parser.setLanguage(language);
        current = grammar;
      }
      const deadline = performance.now() + timeoutMs;
      const tree = parser.parse(text, null, {
        progressCallback: () => performance.now() > deadline,
      });
      if (tree === null) parser.reset();
      return tree;
    },
    abiVersion(grammar) {
      return loaded.get(grammar)?.abiVersion ?? 0;
    },
    delete() {
      parser.delete();
    },
  };
}
