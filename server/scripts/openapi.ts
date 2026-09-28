import { writeFile } from 'node:fs/promises';
import { OPENAPI_PATH, openApiDocument, serializeOpenApi } from '../src/http/openapi-doc';

await writeFile(OPENAPI_PATH, serializeOpenApi(await openApiDocument()));
process.stdout.write(`wrote ${OPENAPI_PATH}\n`);
