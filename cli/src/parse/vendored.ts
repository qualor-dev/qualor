/**
 * Grammars no npm package ships as WASM (plan 8F): the upstream release's own WASM file, committed
 * in cli/grammars/ and checked against its SHA-256 by vendored.test.ts. A bump downloads the new
 * release asset over the old file, updates this entry, re-runs the metrics tests, and replaces
 * deploy/scanner/licenses/TREE-SITTER-SWIFT-LICENSE.txt with the tag's LICENSE.
 */
export const VENDORED_GRAMMARS = {
  swift: {
    name: 'tree-sitter-swift',
    version: '0.7.3',
    file: 'tree-sitter-swift.wasm',
    url: 'https://github.com/alex-pinkus/tree-sitter-swift/releases/download/0.7.3/tree-sitter-swift.wasm',
    sha256: '0258a7ef17303a8079ffe0748b3583d59656b5c3e8653fca7b6451b3e6689eb2',
    licence: 'MIT',
  },
} as const;
