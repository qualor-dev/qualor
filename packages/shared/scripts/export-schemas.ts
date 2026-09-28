import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generatedSchemas } from '../src/schemas';

const outDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../schema');
mkdirSync(outDir, { recursive: true });
for (const [name, content] of Object.entries(generatedSchemas())) {
  writeFileSync(path.join(outDir, name), content);
  console.log(`wrote schema/${name}`);
}
