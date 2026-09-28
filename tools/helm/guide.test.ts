import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CHART_REPOSITORY } from '../release/publish';
import { BACKUP_COMMAND, restoreOverrides } from './smoke';

const guide = readFileSync('docs/guide/install-server.md', 'utf8');
const section = guide.slice(
  guide.indexOf('## Kubernetes (Helm)'),
  guide.indexOf('## External PostgreSQL'),
);

describe('install-server.md, Kubernetes (AGENTS.md rule 9)', () => {
  it('installs from the chart repository the release publishes to', () => {
    expect(section).toContain(`helm install qualor ${CHART_REPOSITORY}/qualor --version`);
  });

  it('shows the backup and restore commands the smoke test ran', () => {
    expect(section).toContain(BACKUP_COMMAND);
    expect(section).toContain(`--overrides='${restoreOverrides('qualor/server:0.1.0')}'`);
  });
});
