import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv } from 'ajv';

/**
 * The vendored copy of GitLab's SAST report schema (MIT, © GitLab B.V.; `LICENSE.md` next to it),
 * byte for byte as tag v15.1.4 of gitlab-org/security-products/security-report-schemas has it at
 * `dist/sast-report-format.json`, and of its Dependency Scanning schema
 * (`dist/dependency-scanning-report-format.json`, plan 2B). The tests pin both files by SHA-256
 * (cli/src/scan/gitlab-reports.test.ts); the tag's commit is {@link SCHEMA_SOURCE_COMMIT}.
 */
export const SCHEMA_DIR = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  'schemas',
  'gitlab',
);
export const SCHEMA_FILE = path.join(SCHEMA_DIR, 'sast-report-format-15.1.4.json');
export const DEPENDENCY_SCANNING_SCHEMA_FILE = path.join(
  SCHEMA_DIR,
  'dependency-scanning-report-format-15.1.4.json',
);
/** Where the three files come from: the tag, its commit, and the raw URLs of that commit. */
export const SCHEMA_SOURCE_TAG = 'v15.1.4';
export const SCHEMA_SOURCE_COMMIT = '2338bb3425aac1af974bb2b12649ecfecdfa7358';
export const SCHEMA_SOURCE_URLS = [
  `https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/${SCHEMA_SOURCE_COMMIT}/dist/sast-report-format.json`,
  `https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/${SCHEMA_SOURCE_COMMIT}/LICENSE.md`,
  `https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/${SCHEMA_SOURCE_COMMIT}/dist/dependency-scanning-report-format.json`,
];

/** The vendored schema compiled (draft-07, every error reported). */
export function sastValidator() {
  const schema = JSON.parse(readFileSync(SCHEMA_FILE, 'utf8')) as object;
  return new Ajv({ allErrors: true, strict: false }).compile(schema);
}

/** The vendored Dependency Scanning schema compiled (draft-07, every error reported). */
export function dependencyScanningValidator() {
  const schema = JSON.parse(readFileSync(DEPENDENCY_SCANNING_SCHEMA_FILE, 'utf8')) as object;
  return new Ajv({ allErrors: true, strict: false }).compile(schema);
}

/**
 * GitLab's documented Code Quality fields (docs.gitlab.com, "Code Quality report format"): a JSON
 * array of Code Climate issues, each with `description`, `check_name`, `fingerprint`, `severity`
 * (one of five) and `location.path` with `location.lines.begin`. GitLab publishes no schema file
 * for it; this one states exactly those documented requirements, plus the shape Qualor writes
 * (a 32-hex fingerprint, nothing else).
 */
export const CODE_QUALITY_SCHEMA = {
  type: 'array',
  items: {
    type: 'object',
    additionalProperties: false,
    required: ['description', 'check_name', 'fingerprint', 'severity', 'location'],
    properties: {
      description: { type: 'string' },
      check_name: { type: 'string', minLength: 1 },
      fingerprint: { type: 'string', pattern: '^[0-9a-f]{32}$' },
      severity: { enum: ['info', 'minor', 'major', 'critical', 'blocker'] },
      location: {
        type: 'object',
        additionalProperties: false,
        required: ['path', 'lines'],
        properties: {
          path: { type: 'string', minLength: 1 },
          lines: {
            type: 'object',
            additionalProperties: false,
            required: ['begin'],
            properties: { begin: { type: 'integer', minimum: 1 } },
          },
        },
      },
    },
  },
} as const;

/** {@link CODE_QUALITY_SCHEMA} compiled. */
export function codeQualityValidator() {
  return new Ajv({ allErrors: true, strict: true }).compile(CODE_QUALITY_SCHEMA);
}
