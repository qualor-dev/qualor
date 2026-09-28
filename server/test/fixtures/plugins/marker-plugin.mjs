// enterprise.md §12: a plugin that records being imported. The boot tests point
// QUALOR_PLUGIN_PATHS at it without a valid licence and check that the marker never appears.
import { writeFileSync } from 'node:fs';

writeFileSync(process.env.QUALOR_TEST_PLUGIN_MARKER ?? 'marker-plugin-imported', 'imported');

export default { name: 'marker', apiVersion: 1, features: ['fixture.marker'], register() {} };
