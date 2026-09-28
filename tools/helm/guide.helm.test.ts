import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { helmTemplate } from './render';

const guide = readFileSync('docs/guide/install-server.md', 'utf8');
const section = guide.slice(
  guide.indexOf('## Kubernetes (Helm)'),
  guide.indexOf('## External PostgreSQL'),
);
const yamlBlocks = [...section.matchAll(/```yaml\n([\s\S]*?)```/g)].map(
  (m) => parse(m[1] ?? '') as Record<string, unknown>,
);

describe('the guide’s Helm values render (AGENTS.md rule 9)', () => {
  it('has the values.yaml, external-database, private-CA, extraEnv and NetworkPolicy examples', () => {
    expect(yamlBlocks).toHaveLength(5);
  });

  it.each([0, 1, 2, 3, 4])('example %i renders with the guide’s Secret', (i) => {
    const r = helmTemplate([], { secrets: { existingSecret: 'qualor-secrets' }, ...yamlBlocks[i] });
    expect(r.ok, r.ok ? '' : r.error).toBe(true);
  });
});
