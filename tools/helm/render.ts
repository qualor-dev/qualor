import { createHash } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { parseAllDocuments } from 'yaml';
import { REPO_ROOT, type RunResult } from '../deploy/stack';
import { runTool } from '../release/toolbox';

export const CHART_DIR = 'deploy/helm/qualor';
const WORK = '.tmp/helm-test';

export interface EnvVar {
  name: string;
  value?: string;
  valueFrom?: { secretKeyRef?: { name: string; key: string } };
}
export interface Probe {
  httpGet?: { path: string; port: string | number };
  tcpSocket?: { port: string | number };
  exec?: { command: string[] };
  periodSeconds?: number;
  failureThreshold?: number;
}
export interface Container {
  name: string;
  image: string;
  imagePullPolicy?: string;
  command?: string[];
  env?: EnvVar[];
  securityContext?: Record<string, unknown>;
  args?: string[];
  resources?: { requests?: Record<string, string>; limits?: Record<string, string> };
  volumeMounts?: { name: string; mountPath: string; readOnly?: boolean }[];
  startupProbe?: Probe;
  readinessProbe?: Probe;
  livenessProbe?: Probe;
}
export interface Volume {
  name: string;
  emptyDir?: { sizeLimit?: string };
  secret?: { secretName: string; items?: { key: string; path: string }[] };
  persistentVolumeClaim?: { claimName: string };
}
export interface PodSpec {
  securityContext?: Record<string, unknown>;
  automountServiceAccountToken?: boolean;
  enableServiceLinks?: boolean;
  initContainers?: Container[];
  terminationGracePeriodSeconds?: number;
  containers: Container[];
  volumes?: Volume[];
}
export interface K8sObject {
  apiVersion: string;
  kind: string;
  metadata: {
    name: string;
    annotations?: Record<string, string>;
    labels?: Record<string, string>;
  };
  spec?: Record<string, unknown> & {
    replicas?: number;
    serviceName?: string;
    template?: {
      metadata?: { annotations?: Record<string, string>; labels?: Record<string, string> };
      spec: PodSpec;
    };
    volumeClaimTemplates?: {
      metadata: { name: string };
      spec: { resources: { requests: { storage: string } } };
    }[];
    persistentVolumeClaimRetentionPolicy?: Record<string, string>;
    containers?: Container[];
  };
  data?: Record<string, string>;
}
export type RenderResult = { ok: true; objects: K8sObject[] } | { ok: false; error: string };

/** `-f` arguments: ci/ values files, then the inline overrides (written under .tmp/). */
function valuesArgs(valuesFiles: string[], overrides: Record<string, unknown>): string[] {
  const args: string[] = [];
  for (const f of valuesFiles) args.push('-f', `/work/${CHART_DIR}/${f}`);
  if (Object.keys(overrides).length > 0) {
    const text = JSON.stringify(overrides);
    const name = createHash('sha256').update(text).digest('hex').slice(0, 16);
    const file = `${WORK}/${name}.json`;
    mkdirSync(path.join(REPO_ROOT, WORK), { recursive: true });
    writeFileSync(path.join(REPO_ROOT, file), text);
    args.push('-f', `/work/${file}`);
  }
  return args;
}

/**
 * `helm template <release>` (default `qualor`) with ci/ values files and inline overrides.
 * `flags` are more Helm flags (the tests pass `--skip-schema-validation` to reach the template's
 * own refusals).
 */
export function helmTemplate(
  valuesFiles: string[],
  overrides: Record<string, unknown> = {},
  flags: readonly string[] = [],
  release = 'qualor',
): RenderResult {
  const args = ['template', release, `/work/${CHART_DIR}`, '--namespace', 'qualor', ...flags];
  args.push(...valuesArgs(valuesFiles, overrides));
  const r = runTool('helm', args);
  if (r.code !== 0) return { ok: false, error: r.stderr };
  const objects = parseAllDocuments(r.stdout)
    .map((d) => d.toJSON() as K8sObject | null)
    .filter((o): o is K8sObject => o !== null);
  return { ok: true, objects };
}

/**
 * NOTES.txt as `helm install` prints it, from a client-side dry run (`helm template` never renders
 * the notes). No cluster is contacted: the toolbox has no network.
 */
export function helmNotes(valuesFiles: string[], overrides: Record<string, unknown> = {}): string {
  const args = ['install', 'qualor', `/work/${CHART_DIR}`, '--namespace', 'qualor'];
  args.push('--dry-run=client', ...valuesArgs(valuesFiles, overrides));
  const r = runTool('helm', args);
  if (r.code !== 0) throw new Error(`helm install --dry-run=client: ${r.stderr}`);
  const marker = '\nNOTES:\n';
  const at = r.stdout.indexOf(marker);
  if (at < 0) throw new Error('helm install --dry-run=client printed no NOTES');
  return r.stdout.slice(at + marker.length);
}

export function helmLint(valuesFile: string): RunResult {
  return runTool('helm', [
    'lint',
    '--strict',
    `/work/${CHART_DIR}`,
    '-f',
    `/work/${CHART_DIR}/${valuesFile}`,
  ]);
}

/** Every pod spec: of the workloads' templates, and of bare Pods (the test hook). */
export function podSpecs(objects: K8sObject[]): { owner: string; spec: PodSpec }[] {
  return objects.flatMap((o) => {
    if (o.spec?.template?.spec) {
      return [{ owner: `${o.kind}/${o.metadata.name}`, spec: o.spec.template.spec }];
    }
    if (o.kind === 'Pod' && o.spec?.containers) {
      return [{ owner: `Pod/${o.metadata.name}`, spec: o.spec as unknown as PodSpec }];
    }
    return [];
  });
}
