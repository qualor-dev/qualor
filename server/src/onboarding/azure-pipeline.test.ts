import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';
import { azurePipeline } from './ci-templates';

/** The generated pipeline file must not drift from the examples in integrations/azure-devops. */
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const example = (name: string) =>
  readFileSync(path.join(ROOT, 'integrations', 'azure-devops', name), 'utf8');

interface Pipeline {
  trigger: unknown;
  pool: unknown;
  variables: Record<string, string>;
  steps: unknown[];
}

const CASES = [
  { csharp: false, file: 'qualor-docker.yml', image: 'qualor/scanner:0.16.1' },
  { csharp: true, file: 'qualor-dotnet-docker.yml', image: 'qualor/scanner-dotnet:0.16.1' },
] as const;

describe.each(CASES)('azurePipeline (csharp: $csharp)', ({ csharp, file, image }) => {
  const exampleText = example(file);
  const exampleDoc = parse(exampleText) as Pipeline;

  it.each([
    { label: 'hosted', pool: { vmImage: 'ubuntu-latest' } as const },
    { label: 'named', pool: { name: 'Self hosted: Linux' } as const },
  ])('$label pool: steps, trigger and checkout equal the example', ({ pool }) => {
    const text = azurePipeline({ projectKey: 'acme/app-2', version: '0.16.1', pool, csharp });
    const docs = parseAllDocuments(text);
    expect(docs).toHaveLength(1);
    expect(docs[0]?.errors).toEqual([]);
    expect(docs[0]?.warnings).toEqual([]);
    const doc = parse(text) as Pipeline;
    expect(doc.steps).toEqual(exampleDoc.steps);
    expect(doc.trigger).toEqual(exampleDoc.trigger);
    expect(doc.pool).toEqual(pool);
    expect(doc.variables).toEqual({
      QUALOR_SCANNER_IMAGE: image,
      QUALOR_PROJECT_KEY: 'acme/app-2',
    });
    // The step text, comments included, is the example's from `steps:` on.
    const from = (t: string) => t.slice(t.indexOf('\nsteps:\n'));
    expect(from(text)).toBe(from(exampleText));
  });

  it('writes no QUALOR_URL and no token, and says who made the pipeline', () => {
    const text = azurePipeline({
      projectKey: 'k',
      version: '0.16.1',
      pool: { vmImage: 'ubuntu-latest' },
      csharp,
    });
    expect(text).toMatch(/created by Qualor/);
    expect(text).toMatch(/Build validation/);
    const code = text
      .split('\n')
      .filter((l) => !l.trimStart().startsWith('#'))
      .join('\n');
    expect(code).not.toMatch(/QUALOR_URL:/);
    expect(text.match(/\$\(QUALOR_TOKEN\)/g)).toHaveLength(1);
  });

  it('quotes a hostile key and pool name as scalars', () => {
    const text = azurePipeline({
      projectKey: "a: b #c' - x",
      version: '0.16.1',
      pool: { name: "x vmImage: evil # '" },
      csharp,
    });
    const doc = parse(text) as Pipeline;
    expect(doc.variables.QUALOR_PROJECT_KEY).toBe("a: b #c' - x");
    expect(doc.pool).toEqual({ name: "x vmImage: evil # '" });
  });
});
