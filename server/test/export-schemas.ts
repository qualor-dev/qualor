import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import Ajv, { type ErrorObject, type ValidateFunction } from 'ajv';
import Ajv2020 from 'ajv/dist/2020';

export type ExportSchema = 'cyclonedx' | 'spdx' | 'openvex';

const DIR = join(__dirname, 'export-schemas');
const read = (file: string): object => JSON.parse(readFileSync(join(DIR, file), 'utf8')) as object;

// The formats package is not a dependency, so the formats the schemas use are accepted as written.
const FORMATS = ['date-time', 'uri', 'iri-reference', 'idn-email', 'email', 'iri', 'uri-reference'];

const cache = new Map<ExportSchema, ValidateFunction>();

function compile(schema: ExportSchema): ValidateFunction {
  if (schema === 'openvex') {
    const ajv = new Ajv2020({ strict: false, allErrors: true });
    for (const f of FORMATS) ajv.addFormat(f, true);
    return ajv.compile(read('openvex_json_schema.json'));
  }
  const ajv = new Ajv({ strict: false, allErrors: true });
  for (const f of FORMATS) ajv.addFormat(f, true);
  if (schema === 'cyclonedx') {
    ajv.addSchema(read('spdx.schema.json'));
    ajv.addSchema(read('jsf-0.82.schema.json'));
    return ajv.compile(read('bom-1.6.schema.json'));
  }
  return ajv.compile(read('spdx-schema.json'));
}

/** The ajv errors of a document against its official schema; empty when it is valid. */
export function validateAgainst(schema: ExportSchema, document: object): string[] {
  let validate = cache.get(schema);
  if (validate === undefined) {
    validate = compile(schema);
    cache.set(schema, validate);
  }
  if (validate(document)) return [];
  return (validate.errors ?? []).map(
    (e: ErrorObject) => `${e.instancePath || '/'} ${e.message ?? 'invalid'}`,
  );
}
