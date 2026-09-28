// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { buildEnterprise } from './bundle';

await buildEnterprise();
process.stdout.write('built enterprise/dist/plugin.js\n');
