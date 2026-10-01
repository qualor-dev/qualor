// Entry point of the compiled binary (`bun build --compile`, ruling C2). The imports below make
// bun embed the WASM files; at run time they are paths inside the binary's `$bunfs`.
import coreWasm from 'web-tree-sitter/web-tree-sitter.wasm' with { type: 'file' };
import kotlinWasm from '@tree-sitter-grammars/tree-sitter-kotlin/tree-sitter-kotlin.wasm' with { type: 'file' };
import csharpWasm from 'tree-sitter-c-sharp/tree-sitter-c_sharp.wasm' with { type: 'file' };
import cssWasm from 'tree-sitter-css/tree-sitter-css.wasm' with { type: 'file' };
import htmlWasm from 'tree-sitter-html/tree-sitter-html.wasm' with { type: 'file' };
import javaWasm from 'tree-sitter-java/tree-sitter-java.wasm' with { type: 'file' };
import javascriptWasm from 'tree-sitter-javascript/tree-sitter-javascript.wasm' with { type: 'file' };
import pythonWasm from 'tree-sitter-python/tree-sitter-python.wasm' with { type: 'file' };
import rubyWasm from 'tree-sitter-ruby/tree-sitter-ruby.wasm' with { type: 'file' };
import tsxWasm from 'tree-sitter-typescript/tree-sitter-tsx.wasm' with { type: 'file' };
import typescriptWasm from 'tree-sitter-typescript/tree-sitter-typescript.wasm' with { type: 'file' };
import swiftWasm from '../grammars/tree-sitter-swift.wasm' with { type: 'file' };
import { processIO } from './io';
import { main } from './main';
import { registerEmbeddedAssets } from './parse/grammars';

registerEmbeddedAssets({
  core: coreWasm,
  typescript: typescriptWasm,
  tsx: tsxWasm,
  javascript: javascriptWasm,
  java: javaWasm,
  csharp: csharpWasm,
  python: pythonWasm,
  html: htmlWasm,
  css: cssWasm,
  kotlin: kotlinWasm,
  swift: swiftWasm,
  ruby: rubyWasm,
});
process.exitCode = await main(process.argv.slice(2), processIO());
