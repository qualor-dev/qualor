import { buildPluginFileCheck, buildServer } from './bundle';

// The release build (the image runs `pnpm --filter @qualor/server build`): never test licence
// keys, so the bundle defines __QUALOR_TEST_LICENSE_KEYS__ as undefined (enterprise.md §14.2).
await buildServer();
process.stdout.write('built server/dist/main.js\n');
// The plugin file check of the loader, as a command (enterprise.md §10.1.1).
await buildPluginFileCheck();
process.stdout.write('built server/dist/check-plugin-file.js\n');
