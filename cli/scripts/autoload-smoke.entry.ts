// Entry point of the autoload smoke binary (`pnpm --filter @qualor/cli smoke:autoload`): prints
// what it sees of QUALOR_TEST_X, which only a `.env` in its working directory can set.
console.log(JSON.stringify(process.env['QUALOR_TEST_X'] ?? null));
