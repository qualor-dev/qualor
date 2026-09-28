import { processIO } from './io';
import { main } from './main';

process.exitCode = await main(process.argv.slice(2), processIO());
