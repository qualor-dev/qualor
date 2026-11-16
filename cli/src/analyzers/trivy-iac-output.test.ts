import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import type { SarifLog, SarifResult } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { recorded } from '../../test/analyzers';
import { FIXTURES_DIR } from '../../test/fixtures';
import { trivyIacJsonToSarif } from './trivy-iac-output';

const FIXTURE = path.join(FIXTURES_DIR, 'iac-basic');
const NOT_MAPPED = ' (line not mapped from the rendered chart)';

function filesOf(dir: string, prefix = ''): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    const rel = prefix === '' ? name : `${prefix}/${name}`;
    return statSync(full).isDirectory() ? filesOf(full, rel) : [rel];
  });
}

const fixtureLines = (repoPath: string): readonly string[] | null => {
  try {
    return readFileSync(path.join(FIXTURE, repoPath), 'utf8').split('\n');
  } catch {
    return null;
  }
};

const run = (log: SarifLog) => {
  const first = log.runs[0];
  if (first === undefined) throw new Error('no run');
  return first;
};
const resultsOf = (log: SarifLog): SarifResult[] => run(log).results ?? [];
const uriOf = (r: SarifResult) => r.locations?.[0]?.physicalLocation?.artifactLocation?.uri;
const regionOf = (r: SarifResult | undefined) => r?.locations?.[0]?.physicalLocation?.region;

interface Entry {
  Target: string;
  ID: string;
  Type?: string;
  StartLine?: number;
  EndLine?: number;
  Lines?: { Number: number; Content: string; IsCause: boolean }[];
  Status?: string;
  Message?: string;
  Description?: string;
  Resolution?: string;
  PrimaryURL?: string;
  Provider?: string;
  Service?: string;
  Resource?: string;
  Severity?: string;
}

/** A Trivy report with one result per target, built from short entries. */
function report(entries: Entry[]) {
  const targets = [...new Set(entries.map((e) => e.Target))];
  return {
    SchemaVersion: 2,
    Results: targets.map((Target) => ({
      Target,
      Class: 'config',
      Type: entries.find((e) => e.Target === Target)?.Type ?? 'terraform',
      Misconfigurations: entries
        .filter((e) => e.Target === Target)
        .map((e) => ({
          ID: e.ID,
          Title: `Title ${e.ID}`,
          Description: e.Description ?? 'Desc',
          Message: e.Message ?? `Message ${e.ID}`,
          Resolution: e.Resolution ?? 'Fix it',
          Severity: e.Severity ?? 'HIGH',
          ...(e.PrimaryURL !== undefined && { PrimaryURL: e.PrimaryURL }),
          Status: e.Status ?? 'FAIL',
          CauseMetadata: {
            ...(e.Resource !== undefined && { Resource: e.Resource }),
            Provider: e.Provider ?? 'AWS',
            Service: e.Service ?? 's3',
            ...(e.StartLine !== undefined && { StartLine: e.StartLine }),
            ...(e.EndLine !== undefined && { EndLine: e.EndLine }),
            Code: { Lines: e.Lines ?? [] },
          },
        })),
    })),
  };
}

const none = () => null;

describe('trivyIacJsonToSarif: recorded fixture', () => {
  const log = trivyIacJsonToSarif(recorded('trivy-iac/iac-basic.json'), fixtureLines);
  const results = resultsOf(log);
  const files = new Set(filesOf(FIXTURE));

  it('is one Trivy run with results', () => {
    expect(log.runs).toHaveLength(1);
    expect(run(log).tool.driver.name).toBe('Trivy');
    expect(results.length).toBeGreaterThan(40);
  });

  it('puts every result on a fixture file', () => {
    for (const r of results) expect(files.has(uriOf(r) ?? '')).toBe(true);
  });

  it('has no KCV id and no rule without a result', () => {
    expect(results.some((r) => r.ruleId?.startsWith('KCV-'))).toBe(false);
    const used = new Set(results.map((r) => r.ruleId));
    const rules = run(log).tool.driver.rules ?? [];
    expect(rules.map((r) => r.id).sort()).toEqual([...used].sort());
  });

  it('names the Terraform bucket by its resource address', () => {
    const bucket = results.find((r) => r.ruleId === 'AWS-0086' && uriOf(r) === 'terraform/main.tf');
    expect(bucket?.properties).toMatchObject({
      iacType: 'terraform',
      iacResource: 'aws_s3_bucket.logs',
    });
  });

  it('gives the Dockerfile DS-0002 result no region', () => {
    const user = results.find((r) => r.ruleId === 'DS-0002');
    expect(user === undefined ? undefined : uriOf(user)).toBe('docker/Dockerfile');
    expect(regionOf(user)).toBeUndefined();
  });

  it('gives nothing for the Terraform aggregate', () => {
    const raw = recorded('trivy-iac/iac-basic.json') as {
      Results: { Target: string; Type: string; Misconfigurations?: unknown[] }[];
    };
    const aggregate = raw.Results.find(
      (r) => r.Type === 'terraform' && r.Misconfigurations === undefined,
    );
    expect(aggregate).toBeDefined();
    expect(results.some((r) => uriOf(r) === aggregate?.Target)).toBe(false);
  });

  it('has nothing from a module with a registry or git source', () => {
    for (const r of results) expect(uriOf(r)).not.toMatch(/terraform-aws-modules|example\/mod/);
  });

  it('maps a verbatim Helm cause line and leaves a rendered value unmapped', () => {
    const helm = results.filter((r) => uriOf(r) === 'helm/app/templates/deployment.yaml');
    const main = helm.find((r) => r.ruleId === 'KSV-0001' && r.message?.text?.includes("'main'"));
    // The template has `- name: main` on line 16; Helm rendered it on line 17.
    expect(regionOf(main)).toMatchObject({ startLine: 16, endLine: 17 });
    const dbg = helm.find((r) => r.ruleId === 'KSV-0017');
    expect(regionOf(dbg)).toBeUndefined();
    expect(dbg?.message?.text?.endsWith(NOT_MAPPED)).toBe(true);
  });
});

describe('trivyIacJsonToSarif: rule metadata', () => {
  const rule = (entry: Omit<Entry, 'Target' | 'ID'>) =>
    run(trivyIacJsonToSarif(report([{ Target: 'a.tf', ID: 'AWS-0086', ...entry }]), none)).tool
      .driver.rules?.[0];

  it('joins the description and the resolution', () => {
    expect(rule({})?.id).toBe('AWS-0086');
    expect(rule({})?.name).toBe('Title AWS-0086');
    expect(rule({})?.shortDescription?.text).toBe('Desc\n\nHow to fix: Fix it');
  });

  it('cuts a long description to 4000 characters', () => {
    expect(rule({ Description: 'x'.repeat(5000) })?.shortDescription?.text).toHaveLength(4000);
  });

  it('keeps only an https help link', () => {
    expect(rule({ PrimaryURL: 'http://avd.example/x' })?.helpUri).toBeUndefined();
    expect(rule({ PrimaryURL: 'https://avd.example/x' })?.helpUri).toBe('https://avd.example/x');
  });

  it('tags a rule with iac, its provider and its service unless general', () => {
    const log = trivyIacJsonToSarif(
      report([
        {
          Target: 'k.yaml',
          Type: 'kubernetes',
          ID: 'KSV-0001',
          Provider: 'Kubernetes',
          Service: 'general',
        },
        { Target: 'a.tf', ID: 'AWS-0086', Provider: 'AWS', Service: 's3' },
      ]),
      none,
    );
    const tags = (id: string) =>
      run(log).tool.driver.rules?.find((r) => r.id === id)?.properties?.['tags'];
    expect(tags('KSV-0001')).toEqual(['iac', 'kubernetes']);
    expect(tags('AWS-0086')).toEqual(['iac', 'aws', 's3']);
  });

  it('carries severity, type and resource on a result, and a region from StartLine', () => {
    const log = trivyIacJsonToSarif(
      report([
        {
          Target: 'a.tf',
          ID: 'AWS-0086',
          Severity: 'CRITICAL',
          Resource: 'aws_s3_bucket.b',
          StartLine: 3,
          EndLine: 6,
        },
      ]),
      none,
    );
    const [r] = resultsOf(log);
    expect(r?.properties).toEqual({
      trivySeverity: 'CRITICAL',
      iacType: 'terraform',
      iacResource: 'aws_s3_bucket.b',
    });
    expect(regionOf(r)).toEqual({ startLine: 3, endLine: 6 });
  });
});

describe('trivyIacJsonToSarif: drops', () => {
  it('drops KCV ids, archive targets, PASS entries and exact duplicates', () => {
    const entry = { Target: 'a.tf', ID: 'AWS-0001', StartLine: 1, EndLine: 2 };
    const log = trivyIacJsonToSarif(
      report([
        entry,
        entry,
        { Target: 'a.tf', ID: 'KCV-0001', StartLine: 1 },
        { Target: 'chart.tgz:templates/x.yaml', Type: 'helm', ID: 'KSV-0001', StartLine: 1 },
        { Target: 'a.tf', ID: 'AWS-0002', Status: 'PASS', StartLine: 1 },
      ]),
      none,
    );
    expect(resultsOf(log).map((r) => r.ruleId)).toEqual(['AWS-0001']);
  });

  it('keeps two buckets with the same id', () => {
    const log = trivyIacJsonToSarif(
      report([
        { Target: 'a.tf', ID: 'AWS-0086', Resource: 'aws_s3_bucket.a', StartLine: 1, EndLine: 3 },
        { Target: 'a.tf', ID: 'AWS-0086', Resource: 'aws_s3_bucket.b', StartLine: 5, EndLine: 7 },
      ]),
      none,
    );
    expect(resultsOf(log)).toHaveLength(2);
    expect(run(log).tool.driver.rules).toHaveLength(1);
  });
});

describe('trivyIacJsonToSarif: helm mapping', () => {
  const helm = (entry: Partial<Entry>) =>
    report([
      {
        Target: 'helm/templates/x.yaml',
        Type: 'helm',
        ID: 'KSV-0001',
        Provider: 'Kubernetes',
        Service: 'general',
        ...entry,
      },
    ]);
  const lines = (n: number, set: Record<number, string>) =>
    Array.from({ length: n }, (_, i) => set[i + 1] ?? `# ${i + 1}`);

  it('shifts the range by the offset of the matching template line', () => {
    const file = lines(40, { 11: '        - name: c' });
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 12,
        EndLine: 15,
        Lines: [{ Number: 12, Content: '        - name: c', IsCause: true }],
      }),
      () => file,
    );
    expect(regionOf(resultsOf(log)[0])).toEqual({ startLine: 11, endLine: 14 });
  });

  it('picks the equal template line nearest to the rendered start', () => {
    const file = lines(40, { 5: '  - name: c', 30: '  - name: c' });
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 29,
        EndLine: 31,
        Lines: [{ Number: 29, Content: '  - name: c', IsCause: true }],
      }),
      () => file,
    );
    expect(regionOf(resultsOf(log)[0])).toEqual({ startLine: 30, endLine: 32 });
  });

  it('takes the lower line on a tie', () => {
    const file = lines(40, { 8: 'x: 1', 12: 'x: 1' });
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 11,
        EndLine: 11,
        Lines: [{ Number: 11, Content: 'x: 1', IsCause: true }],
      }),
      () => file,
    );
    expect(regionOf(resultsOf(log)[0])?.startLine).toBe(8);
  });

  it('has no region and a note when every cause line is a rendered value', () => {
    const file = lines(20, { 6: '          privileged: {{ .Values.priv }}' });
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 7,
        EndLine: 7,
        Message: 'privileged',
        Lines: [{ Number: 7, Content: '          privileged: true', IsCause: true }],
      }),
      () => file,
    );
    const [r] = resultsOf(log);
    expect(regionOf(r)).toBeUndefined();
    expect(r?.message?.text).toBe(`privileged${NOT_MAPPED}`);
  });

  it('clamps a mapped end to the file length', () => {
    const file = lines(11, { 11: '- name: c' });
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 12,
        EndLine: 30,
        Lines: [{ Number: 12, Content: '- name: c', IsCause: true }],
      }),
      () => file,
    );
    expect(regionOf(resultsOf(log)[0])).toEqual({ startLine: 11, endLine: 11 });
  });

  it('has no region and a note when the template cannot be read', () => {
    const log = trivyIacJsonToSarif(
      helm({
        StartLine: 12,
        EndLine: 13,
        Message: 'm',
        Lines: [{ Number: 12, Content: '- name: c', IsCause: true }],
      }),
      none,
    );
    const [r] = resultsOf(log);
    expect(regionOf(r)).toBeUndefined();
    expect(r?.message?.text).toBe(`m${NOT_MAPPED}`);
  });
});

describe('trivyIacJsonToSarif: tolerates', () => {
  it('gives an empty run for an empty object and for null results', () => {
    for (const input of [{}, { Results: null }]) {
      const log = trivyIacJsonToSarif(input, none);
      expect(log.runs).toHaveLength(1);
      expect(resultsOf(log)).toEqual([]);
    }
  });

  it('gives a result without region when CauseMetadata is missing', () => {
    const log = trivyIacJsonToSarif(
      {
        Results: [
          {
            Target: 'a.tf',
            Class: 'config',
            Type: 'terraform',
            Misconfigurations: [{ ID: 'AWS-0001', Status: 'FAIL', Severity: 'LOW', Message: 'm' }],
          },
        ],
      },
      none,
    );
    const [r] = resultsOf(log);
    expect(regionOf(r)).toBeUndefined();
    expect(r?.properties).toEqual({ trivySeverity: 'LOW', iacType: 'terraform' });
  });

  it('throws on input that is not an object, as the dependency converter does', () => {
    expect(() => trivyIacJsonToSarif('nope', none)).toThrow();
    expect(() => trivyIacJsonToSarif(null, none)).toThrow();
  });
});
