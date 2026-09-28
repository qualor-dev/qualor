import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { decodeLicenseText, MAX_LICENSE_FILE_BYTES } from '../../server/src/license/source';
import {
  inspectKey,
  keygen,
  PASSPHRASE_VARIABLE,
  refuseMissingPrerequisites,
  refuseRetiredFeatures,
  signKey,
} from './license-tool';

const USAGE = `usage:
  pnpm license:keygen --kid <kid> --out <dir outside any repository>
  pnpm license:sign --key <private.pem> --kid <kid> --customer <name> --expires <date>
                    [--features a,b] [--issued <date>] [--id <uuid>]
  Business:   --features sso,audit-log,llm.fix-quota
  Enterprise: --features sso,sso.multi,audit-log,audit-log.stream,llm.fix-quota,scim
  pnpm license:inspect <key | ->
Dates are YYYY-MM-DD (00:00 UTC) or YYYY-MM-DDTHH:MM:SSZ.
The private key's passphrase comes from ${PASSPHRASE_VARIABLE}, never from an argument.`;

/** `-` reads standard input, bounded and decoded as the server reads QUALOR_LICENSE_FILE. */
function readStdin(): string {
  const content = readFileSync(0);
  if (content.length > MAX_LICENSE_FILE_BYTES) {
    throw new Error('the key on standard input is larger than 16 KiB');
  }
  return decodeLicenseText(content, 'standard input');
}

function main(): void {
  const [command, ...rest] = process.argv.slice(2);
  let parsed;
  try {
    parsed = parseArgs({
      args: rest,
      allowPositionals: command === 'inspect',
      strict: true,
      options: {
        kid: { type: 'string' },
        out: { type: 'string' },
        key: { type: 'string' },
        customer: { type: 'string' },
        expires: { type: 'string' },
        issued: { type: 'string' },
        organizations: { type: 'string' },
        features: { type: 'string' },
        id: { type: 'string' },
      },
    });
  } catch {
    // Not the parser's message: it would echo an argument, which may be a secret.
    throw new Error(`invalid arguments\n${USAGE}`);
  }
  const { values, positionals } = parsed;
  const passphrase = process.env[PASSPHRASE_VARIABLE];
  const need = (name: keyof typeof values): string => {
    const v = values[name];
    if (typeof v !== 'string' || v === '') throw new Error(`--${name} is required\n${USAGE}`);
    return v;
  };
  if (command === 'keygen') {
    const { privateKeyPath, line, warnings } = keygen({
      kid: need('kid'),
      outDir: need('out'),
      passphrase,
    });
    for (const warning of warnings) process.stderr.write(`warning: ${warning}\n`);
    process.stdout.write(
      `wrote ${privateKeyPath} (keep it offline, with a backup)\n` +
        `add to PRODUCTION_KEYS in server/src/license/public-keys.ts:\n${line}\n`,
    );
  } else if (command === 'sign') {
    // enterprise.md §3.1, §15: keys no longer carry an organisation limit. Refused before any
    // key file is read, so a leftover --organizations never silently signs a key without it.
    if (values.organizations !== undefined) {
      throw new Error(
        `--organizations is no longer used: licence keys carry no organisation limit (enterprise.md §3.1)\n${USAGE}`,
      );
    }
    const features = (values.features ?? '')
      .split(',')
      .map((f) => f.trim())
      .filter((f) => f !== '');
    // enterprise.md §1.4, §3.1, §15: refused before any key file is read, beside --organizations.
    refuseRetiredFeatures(features);
    // enterprise.md §7.1, §15: refused the same way, before any key file is read.
    refuseMissingPrerequisites(features);
    const key = signKey({
      keyFile: need('key'),
      passphrase,
      kid: need('kid'),
      customer: need('customer'),
      expires: need('expires'),
      features,
      ...(values.issued ? { issued: values.issued } : {}),
      ...(values.id ? { id: values.id } : {}),
      onWarning: (message) => void process.stderr.write(`warning: ${message}\n`),
    });
    process.stdout.write(`${key}\n`);
  } else if (command === 'inspect') {
    const arg = positionals[0];
    if (!arg || positionals.length > 1) throw new Error(USAGE);
    process.stdout.write(`${inspectKey(arg === '-' ? readStdin() : arg)}\n`);
  } else {
    throw new Error(USAGE);
  }
}

try {
  main();
} catch (err) {
  process.stderr.write(`${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
}
