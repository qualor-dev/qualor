/**
 * `node dist/check-plugin-file.js <path>` (enterprise.md §10.1.1): runs the loader's own plugin
 * file check, prints its result as JSON, and exits 0 when the file would be accepted, 1 when not.
 * It never imports the plugin. The image smoke test runs it on /app/enterprise/plugin.js; an
 * operator can run it to see why a plugin was refused.
 */
import { checkPluginFile } from './plugins/plugin-file';

const [path, ...rest] = process.argv.slice(2);
if (path === undefined || rest.length > 0) {
  process.stderr.write('usage: node check-plugin-file.js <absolute path of a plugin module>\n');
  process.exit(2);
}
const result = await checkPluginFile(path);
process.stdout.write(`${JSON.stringify(result)}\n`);
process.exit(result.ok ? 0 : 1);
