// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { writeFile } from 'node:fs/promises';
import { serializeOpenApi } from '../../server/src/http/openapi-doc';
import { ENTERPRISE_OPENAPI_PATH, enterpriseOpenApiDocument } from './openapi-doc';

await writeFile(ENTERPRISE_OPENAPI_PATH, serializeOpenApi(await enterpriseOpenApiDocument()));
process.stdout.write('wrote enterprise/openapi.json\n');
