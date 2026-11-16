import { createReadStream, createWriteStream, statSync } from 'node:fs';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { createGzip } from 'node:zlib';
import type { UploadSbomFlags } from '../args';
import { loadSettings, requireServer, type ConfigFlags } from '../config/settings';
import { CliError, EXIT, type ExitCode } from '../errors';
import type { CliIO } from '../io';
import type { Logger } from '../log';
import { withPrivateGzipFile } from '../scan/report';
import { serverEndpoint } from '../server/endpoint';
import { clean } from '../server/http';
import { uploadSbom, type SbomUploadAnswer } from '../server/sbom-upload';

/** The SBOM file, which must be a readable regular file (exit 2 otherwise). */
function sbomFile(io: CliIO, name: string): string {
  const file = path.resolve(io.cwd, name);
  try {
    if (!statSync(file).isFile()) throw new Error('not a regular file');
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    throw new CliError(EXIT.USAGE, `cannot read the SBOM file ${name}: ${why}`);
  }
  return file;
}

/** Streams `src` through gzip into `dest` (mode 0600) and returns the compressed size. */
async function gzipTo(src: string, dest: string): Promise<number> {
  try {
    await pipeline(createReadStream(src), createGzip(), createWriteStream(dest, { mode: 0o600 }));
    return statSync(dest).size;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    const why = err instanceof Error ? err.message : String(err);
    throw new CliError(
      code === 'ENOENT' || code === 'EACCES' || code === 'EISDIR' ? EXIT.USAGE : EXIT.SERVER,
      `cannot compress the SBOM file ${src}: ${why}`,
    );
  }
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** What the server stored. Text that comes from the uploaded file is cleaned of control characters. */
function render(status: 200 | 201, a: SbomUploadAnswer): string {
  const lines = [
    `${status === 201 ? 'created' : 'replaced'} version ${clean(a.version.label)}: ${clean(a.format)}` +
      (a.subject === null ? '' : ` of ${clean(a.subject)}`),
    `  ${plural(a.packages, 'package', 'packages')} (${a.osPackages} operating-system)` +
      (a.distribution === null
        ? ''
        : `, distribution ${clean(a.distribution.family)} ${clean(a.distribution.version)}`),
  ];
  const skipped = [
    a.skipped.noPurl > 0 && `${a.skipped.noPurl} without a package URL`,
    a.skipped.unsupportedType > 0 && `${a.skipped.unsupportedType} of an unsupported type`,
    a.skipped.duplicate > 0 && plural(a.skipped.duplicate, 'duplicate', 'duplicates'),
  ].filter((s): s is string => s !== false);
  if (skipped.length > 0) lines.push(`  skipped: ${skipped.join(', ')}`);
  for (const w of a.warnings) lines.push(`  warning ${clean(w.code)}: ${clean(w.message)}`);
  lines.push(
    !a.monitoring.enabled
      ? '  vulnerability monitoring is off'
      : a.monitoring.recheckQueued
        ? '  a vulnerability re-check is queued'
        : '  vulnerability monitoring is on; no re-check was needed',
  );
  return `${lines.join('\n')}\n`;
}

/**
 * `qualor upload-sbom FILE` (0.16 SBOM, spec §6.10): uploads an image's SBOM (Trivy or Syft) to
 * `PUT /api/v0/projects/sbom`. Settings, token, TLS and the retry of a busy server are `qualor
 * scan`'s. The file is streamed through gzip into a private temporary file, never held in memory.
 * Exit 0 on success, 2 for a usage error (the server URL only in qualor.yml included), 5 for
 * 401/403, 4 for any other refusal or an unreachable server.
 */
export async function runUploadSbom(
  flags: UploadSbomFlags,
  io: CliIO,
  log: Logger,
  deps: { wait?: (ms: number) => Promise<unknown>; tempRoot?: string } = {},
): Promise<ExitCode> {
  const source = sbomFile(io, flags.file);
  const configFlags: ConfigFlags = {
    sarif: [],
    coverage: [],
    wait: true,
    ...(flags.config !== undefined && { config: flags.config }),
    ...(flags.projectKey !== undefined && { projectKey: flags.projectKey }),
    ...(flags.tokenFile !== undefined && { tokenFile: flags.tokenFile }),
    ...(flags.serverUrl !== undefined && { serverUrl: flags.serverUrl }),
    ...(flags.caFile !== undefined && { caFile: flags.caFile }),
  };
  const settings = loadSettings({ cwd: io.cwd, env: io.env, flags: configFlags, log });
  const projectKey = settings.config.project.key;
  if (projectKey === undefined || projectKey === '') {
    throw new CliError(
      EXIT.USAGE,
      'a project key is required: pass --project-key, set QUALOR_PROJECT_KEY or project.key in qualor.yml',
    );
  }
  requireServer(settings);
  const endpoint = serverEndpoint(settings, { upload: true, log, env: io.env });
  if (endpoint === null) throw new Error('internal error: requireServer passed without a server');

  const { status, answer } = await withPrivateGzipFile(
    'sbom.json.gz',
    (dest) => gzipTo(source, dest),
    ({ file, size }) => {
      log.info(`uploading the SBOM (${size} bytes gzipped)`);
      return uploadSbom(
        endpoint,
        { projectKey, ...(flags.version !== undefined && { version: flags.version }), file, size },
        { log, ...(deps.wait !== undefined && { wait: deps.wait }) },
      );
    },
    { what: 'SBOM', ...(deps.tempRoot !== undefined && { tempRoot: deps.tempRoot }) },
  );
  io.stdout(render(status, answer));
  return EXIT.OK;
}
