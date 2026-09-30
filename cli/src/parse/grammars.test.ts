import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { testParsers } from '../../test/parsers';
import { GRAMMARS, registerEmbeddedAssets, wasmPath } from './grammars';

const SAMPLES = {
  typescript: 'export function f(a: number): number { return a && 1; }\n',
  tsx: 'export const C = () => <div className="x">{1}</div>;\n',
  javascript: 'const C = () => <b />;\nfunction* g() { yield 1; }\n',
  java: 'class A { int m(int x) { return x > 0 ? 1 : 0; } }\n',
  csharp: 'class A { int M(int x) => x > 0 ? 1 : 0; }\n',
  python: 'def f(x):\n    return 1 if x else 0\n',
  html: '<!DOCTYPE html>\n<p class="a">x</p>\n<script>let a = 1;</script>\n',
  css: '.a > b:hover { color: #fff; margin: calc(1px + 2em); }\n',
} as const;

afterEach(() => registerEmbeddedAssets(null));

describe('loadParsers', () => {
  it('parses every grammar without errors and reports a compatible ABI', async () => {
    const parsers = await testParsers();
    for (const grammar of GRAMMARS) {
      const tree = parsers.parse(grammar, SAMPLES[grammar]);
      expect(tree, grammar).not.toBeNull();
      expect(tree!.rootNode.hasError, grammar).toBe(false);
      tree!.delete();
      expect(parsers.abiVersion(grammar)).toBeGreaterThanOrEqual(13);
      expect(parsers.abiVersion(grammar)).toBeLessThanOrEqual(15);
    }
  });

  it('cancels a parse that exceeds its time budget and keeps working afterwards', async () => {
    const parsers = await testParsers();
    const big = `const a = [${'1,'.repeat(400_000)}];\n`;
    expect(parsers.parse('typescript', big, 0)).toBeNull();
    const tree = parsers.parse('typescript', 'let x = 1;\n');
    expect(tree?.rootNode.type).toBe('program');
    tree?.delete();
  });

  it('parses CRLF and BOM text with the same rows as LF text', async () => {
    const parsers = await testParsers();
    const tree = parsers.parse('typescript', '﻿let x = 1;\r\nlet y = 2;\r\n');
    expect(tree!.rootNode.hasError).toBe(false);
    expect(tree!.rootNode.child(1)!.startPosition.row).toBe(1);
    tree!.delete();
  });
});

describe('wasmPath', () => {
  it('resolves the packaged files and prefers registered embedded paths', () => {
    expect(wasmPath('java')).toMatch(/tree-sitter-java\.wasm$/);
    expect(wasmPath('csharp')).toMatch(/tree-sitter-c_sharp\.wasm$/);
    expect(wasmPath('python')).toMatch(/tree-sitter-python\.wasm$/);
    const require = createRequire(import.meta.url);
    const java = require.resolve('tree-sitter-java/tree-sitter-java.wasm');
    registerEmbeddedAssets({
      core: 'core.wasm',
      typescript: 'ts.wasm',
      tsx: 'tsx.wasm',
      javascript: 'js.wasm',
      java,
      csharp: 'cs.wasm',
      python: 'py.wasm',
      html: 'html.wasm',
      css: 'css.wasm',
    });
    expect(wasmPath('core')).toBe('core.wasm');
    expect(wasmPath('python')).toBe('py.wasm');
    expect(wasmPath('java')).toBe(java);
  });
});
