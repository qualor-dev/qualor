import { describe, expect, it } from 'vitest';
import { REDACTED } from '../sarif/normalize';
import { sampleInput } from '../../test/llm';
import { buildPrompt } from './prompts';
import { REDACT_MAX_CHARS, redactInput, redactText, SECRET_PATTERNS } from './redact';

const j = (...parts: string[]) => parts.join('');
const AWS = j('AK', 'IA', 'Z'.repeat(16));
const GH = j('gh', 'p_', 'a1B2'.repeat(9));
const GL = j('gl', 'pat-', 'x9Y8'.repeat(5));
const OPENAI = j('s', 'k-', 'proj-', 'Q'.repeat(10), 'r'.repeat(20));
const JWT = j('ey', 'J', 'h'.repeat(12), '.', 'ey', 'J', 'p'.repeat(12), '.', 's'.repeat(16));
const QLR = j('ql', 'r_pat_', 'A1'.repeat(16));

describe('redactText (llm.md §5.2)', () => {
  it.each([
    ['aws', `key = ${AWS}`],
    ['github', `token: ${GH}`],
    ['gitlab', `x ${GL} y`],
    ['openai', `OPENAI_KEY=${OPENAI}`],
    ['jwt', `Authorization: Bearer ${JWT}`],
    ['qualor', `QUALOR_TOKEN=${QLR}`],
  ])('replaces a %s secret', (_name, text) => {
    const out = redactText(text);
    expect(out.count).toBe(1);
    expect(out.text).toContain(REDACTED);
    for (const s of [AWS, GH, GL, OPENAI, JWT, QLR]) expect(out.text).not.toContain(s);
  });

  it('replaces only the password of a URL and the value of a secret assignment', () => {
    const pass = j('hunter', '2hunter2');
    expect(redactText(`postgres://app:${pass}@db:5432/x`).text).toBe(
      `postgres://app:${REDACTED}@db:5432/x`,
    );
    expect(redactText(`const dbPassword = "${pass}";`).text).toBe(
      `const dbPassword = "${REDACTED}";`,
    );
    expect(redactText(`api_key: '${pass}'`).text).toBe(`api_key: '${REDACTED}'`);
  });

  it('leaves ordinary code, short literals and existing markers alone', () => {
    for (const text of [
      'if (a == 1) {}',
      'const token = "short";',
      `const password = "${REDACTED}";`,
      'const skills = ["sk-learn"];',
    ]) {
      expect(redactText(text)).toEqual({ text, count: 0 });
    }
  });
});

describe('redactInput', () => {
  it('redacts every string, a private key block to its END line, and counts', () => {
    const begin = j('-----BEGIN RSA ', 'PRIVATE KEY-----');
    const end = j('-----END RSA ', 'PRIVATE KEY-----');
    const { input, redactions } = redactInput(
      sampleInput({
        message: `leaked ${GH}`,
        rule: { key: 'x:y', name: 'n', description: `see ${AWS}`, cwe: [] },
        snippet: {
          startLine: 1,
          lines: ['const k = `', begin, 'MIIEow', 'AbCd', end, '`;', 'ok();'],
        },
      }),
    );
    expect(input.message).toBe(`leaked ${REDACTED}`);
    expect(input.rule.description).toBe(`see ${REDACTED}`);
    expect(input.snippet?.lines).toEqual([
      'const k = `',
      REDACTED,
      REDACTED,
      REDACTED,
      REDACTED,
      '`;',
      'ok();',
    ]);
    expect(redactions).toBe(6);
  });

  it('redacts a private key block that runs past the snippet end', () => {
    const begin = j('-----BEGIN ', 'PRIVATE KEY-----');
    const { input } = redactInput(
      sampleInput({ snippet: { startLine: 3, lines: ['a', begin, 'MIIE', 'Zz'] } }),
    );
    expect(input.snippet?.lines).toEqual(['a', REDACTED, REDACTED, REDACTED]);
  });
});

// Hardening beyond the brief: multi-line keys, secrets split over lines, truncation, bounded work.

const BEGIN = (kind = 'RSA ') => j('-----BEGIN ', kind, 'PRIVATE', ' KEY-----');
const END = (kind = 'RSA ') => j('-----END ', kind, 'PRIVATE', ' KEY-----');
/** A line of fake key body: base64 letters and digits, never a real key. */
const body = (seed: string) => j(seed, 'Qm9ndXMga2V5IGJvZHkgZm9yIHRlc3RzIG9ubHkgMTIzNDU2Nzg5MA');

/** Neither the secret nor any 12-character piece of it is left. */
function expectGone(text: string, secret: string): void {
  expect(text).not.toContain(secret);
  for (let i = 0; i + 12 <= secret.length; i += 4)
    expect(text).not.toContain(secret.slice(i, i + 12));
}

describe('redactText: multi-line private keys', () => {
  it.each(['RSA ', 'EC ', 'OPENSSH ', 'ENCRYPTED ', 'DSA ', ''])(
    'redacts a %sprivate key block inside one string, line by line',
    (kind) => {
      const key = [BEGIN(kind), body('MIIEo1'), body('AbCd2'), 'Zz9=', END(kind)].join('\n');
      const out = redactText(`here it is:\n${key}\ndone`);
      expect(out.text.split('\n')).toEqual([
        'here it is:',
        REDACTED,
        REDACTED,
        REDACTED,
        REDACTED,
        REDACTED,
        'done',
      ]);
      expect(out.count).toBe(5);
    },
  );

  it('redacts a PGP private key block', () => {
    const block = [
      j('-----BEGIN PGP ', 'PRIVATE', ' KEY BLOCK-----'),
      '',
      body('lQOYBF'),
      j('-----END PGP ', 'PRIVATE', ' KEY BLOCK-----'),
    ];
    const out = redactText(block.join('\n'));
    expect(out.text.split('\n')).toEqual([REDACTED, REDACTED, REDACTED, REDACTED]);
  });

  it('redacts a key block written on one line with escaped line breaks', () => {
    const out = redactText(`const k = "${BEGIN()}\\n${body('MIIEo1')}\\n${END()}";`);
    expect(out.text).toBe(REDACTED);
  });

  it('redacts a key block whose BEGIN line is above the snippet', () => {
    const lines = [body('xYz1a'), body('Qw2e'), 'Zz9=', END(), '`;', 'ok();'];
    const { input } = redactInput(sampleInput({ snippet: { startLine: 10, lines } }));
    expect(input.snippet?.lines).toEqual([REDACTED, REDACTED, REDACTED, REDACTED, '`;', 'ok();']);
  });

  it('redacts a snippet that lies wholly inside a key body', () => {
    const lines = [
      `  "${body('Ab1')}" +`,
      `  "${body('Cd2')}" +`,
      `  "${body('Ef3')}\\n" +`,
      '  "Gh4=="',
    ];
    const { input } = redactInput(sampleInput({ snippet: { startLine: 20, lines } }));
    expect(input.snippet?.lines).toEqual([REDACTED, REDACTED, REDACTED, REDACTED]);
  });

  it('redacts a base64 DER key on one line without its PEM lines', () => {
    const der = j('MII', 'EvQIBADANBgkqhkiG9w0BAQEFAASC', 'BKcwggSjAgEAAoIBAQC7', 'x'.repeat(40));
    expectGone(redactText(`const keyDer = '${der}';`).text, der);
  });

  it('keeps ordinary code around a key block and after its END line', () => {
    const lines = ['const a = 1;', BEGIN(), body('Q1'), END(), 'const b = 2;'];
    const { input } = redactInput(sampleInput({ snippet: { startLine: 1, lines } }));
    expect(input.snippet?.lines).toEqual([
      'const a = 1;',
      REDACTED,
      REDACTED,
      REDACTED,
      'const b = 2;',
    ]);
  });
});

describe('redactText: secrets split over two lines', () => {
  it.each([
    ['string concatenation', (a: string, b: string) => [`const t = "${a}" +`, `  "${b}";`]],
    ['a leading +', (a: string, b: string) => [`const t = "${a}"`, `  + "${b}";`]],
    ['implicit concatenation', (a: string, b: string) => [`t = ("${a}"`, `     "${b}")`]],
    ['a shell line continuation', (a: string, b: string) => [`export TOKEN=${a}\\`, b]],
    ['a wrapped template literal', (a: string, b: string) => ['const t = `' + a, `${b}\`;`]],
  ])('redacts a GitHub token split by %s', (_name, split) => {
    const [a, b] = [GH.slice(0, 18), GH.slice(18)];
    const { input } = redactInput(
      sampleInput({ snippet: { startLine: 1, lines: [...split(a, b), 'ok();'] } }),
    );
    const text = (input.snippet?.lines ?? []).join('\n');
    expectGone(text, GH);
    expect(text).not.toContain(a);
    expect(text).not.toContain(b);
    expect(input.snippet?.lines.at(-1)).toBe('ok();');
  });

  it('redacts an AWS key id and a JWT split inside one multi-line message', () => {
    const message = `id "${AWS.slice(0, 10)}" +\n"${AWS.slice(10)}" and "${JWT.slice(0, 20)}" +\n"${JWT.slice(20)}"`;
    const out = redactText(message);
    expectGone(out.text, AWS);
    expectGone(out.text, JWT);
    expect(out.text).not.toContain(AWS.slice(10));
    expect(out.text).not.toContain(JWT.slice(20));
  });

  it('redacts a secret assignment whose value is on the next line', () => {
    const pass = j('hunter', '2hunter2', 'xyz');
    const lines = ['const dbPassword =', `  "${pass}";`, 'ok();'];
    const { input } = redactInput(sampleInput({ snippet: { startLine: 1, lines } }));
    expect(input.snippet?.lines.join('\n')).not.toContain(pass);
    expect(input.snippet?.lines.at(-1)).toBe('ok();');
  });

  it('does not join ordinary lines into a secret', () => {
    const lines = ['const a = "sk";', '"-learn";', 'const token = getToken();', 'return token;'];
    expect(
      redactInput(sampleInput({ snippet: { startLine: 1, lines } })).input.snippet?.lines,
    ).toEqual(lines);
  });
});

describe('redactText: truncated and unterminated values', () => {
  it('redacts a token cut by the CLI truncation mark', () => {
    const out = redactText(`${'x'.repeat(20)} ${GH.slice(0, 14)}…`);
    expect(out.text).not.toContain(GH.slice(0, 14));
    expect(out.count).toBe(1);
  });

  it('redacts an assignment whose closing quote is cut off', () => {
    const pass = j('hunter', '2hunter2', 'abcdef');
    expect(redactText(`const password = "${pass}…`).text).toBe(`const password = "${REDACTED}`);
    expect(redactText(`password: '${pass}`).text).toBe(`password: '${REDACTED}`);
  });

  it('redacts the password of a URL cut before its host', () => {
    const pass = j('hunter', '2hunter2');
    expect(redactText(`postgres://app:${pass}…`).text).not.toContain(pass);
  });

  it('redacts a Redis URL with a password and no user', () => {
    const pass = j('hunter', '2hunter2');
    expect(redactText(`redis://:${pass}@cache:6379`).text).toBe(`redis://:${REDACTED}@cache:6379`);
  });
});

describe('redactText: bounded work (no ReDoS)', () => {
  it('uses no unbounded quantifier in any pattern', () => {
    for (const { id, pattern } of SECRET_PATTERNS) {
      const outsideClasses = pattern.source.replace(/\\./g, '').replace(/\[[^\]]*\]/g, '');
      expect(outsideClasses, id).not.toMatch(/[*+]|\{\d+,\}/);
    }
  });

  it.each([
    ['URL schemes', `${'a.'.repeat(30_000)}://`],
    ['URL users', `x://${'u'.repeat(60_000)}`],
    ['URL passwords', `x://u:${'p:'.repeat(30_000)}`],
    ['assignment names', 'password'.repeat(8_000)],
    ['assignment values', `token = "${'v'.repeat(60_000)}`],
    ['assignment separators', `secret${' '.repeat(60_000)}=`],
    ['JWT parts', `eyJ${'a'.repeat(30_000)}.eyJ${'b'.repeat(30_000)}`],
    ['token prefixes', 'ghp_'.repeat(15_000)],
    ['truncated prefixes', `${'sk-'.repeat(20_000)}x`],
    ['key headers', j('-----BEGIN ', ' '.repeat(60_000))],
    ['base64 lines', `${'A1b2'.repeat(16)}\n`.repeat(900)],
    ['split lines', `"${'sk-'.repeat(20)}" +\n`.repeat(900)],
    ['short lines', 'a\n'.repeat(30_000)],
    // The review's probes (fix 3a) and the unquoted and glued forms.
    ['JWT headers', 'eyJ-'.repeat(16_000)],
    ['JWT parts in a chain', `eyJ${'a'.repeat(10)}.`.repeat(4_000)],
    ['URL schemes with passwords', `a://:${'p'.repeat(1_000)} `.repeat(60)],
    ['short quoted assignments', `password='${'v'.repeat(7)}'`.repeat(3_000)],
    ['AWS prefixes', 'AKIA'.repeat(16_000)],
    ['DER prefixes', `MII${'A'.repeat(59)}-`.repeat(1_000)],
    ['split AWS prefixes', '"AKIA" +\n'.repeat(7_000)],
    ['split OpenAI prefixes', `"${'sk-'.repeat(10_000)}" +\n"${'sk-'.repeat(10_000)}"`],
    ['split JWT headers', `"${'eyJ-'.repeat(8_000)}" +\n"${'eyJ-'.repeat(8_000)}"`],
    ['key END lines', j('-----END ', 'PRIVATE', ' KEY-----\n').repeat(2_000)],
    [
      'base64 lines that almost match',
      `${' '.repeat(64)}${'A'.repeat(255)}${' '.repeat(128)}!\n`.repeat(128),
    ],
    ['glued lines that almost match', `"${'a1B2'.repeat(20)}"${' '.repeat(80)}x\n`.repeat(390)],
    ['unquoted values before a call', `password=${'a'.repeat(4_090)}(\n`.repeat(15)],
    ['line values before a call', `password: ${'a'.repeat(4_090)}(\n`.repeat(15)],
    ['names before a colon', `${'password'.repeat(8)}: ${'a'.repeat(4_000)}(\n`.repeat(15)],
    ['unclosed XML values', `<password>${'a'.repeat(4_090)}\n`.repeat(15)],
    ['one-line glue', `"a" + `.repeat(10_000)],
    ['glued windows', `"${'a1'.repeat(10)}" +\n`.repeat(2_500)],
    // The final review's patterns (M3).
    ['mysql options', `mysql ${' -x'.repeat(21_000)}`],
    ['mysql -p options', `mysql ${' -p'.repeat(21_000)}`],
    ['app settings', `<add key="password" value="${'v'.repeat(60_000)}`],
    ['app setting keys', `<add key="${'k'.repeat(60_000)}`],
    ['short names', `key=${'A1b!'.repeat(15_000)}(`],
  ])('stays fast on adversarial %s', (_name, text) => {
    expect(text.length).toBeLessThanOrEqual(REDACT_MAX_CHARS);
    const started = performance.now();
    redactText(text);
    // Catastrophic backtracking takes far longer; the margin covers a slow CI runner with coverage.
    expect(performance.now() - started).toBeLessThan(2_500);
  });

  it('redacts a text over the size cap as a whole', () => {
    expect(redactText(`${GH} ${'x'.repeat(REDACT_MAX_CHARS)}`)).toEqual({
      text: REDACTED,
      count: 1,
    });
  });

  it('redacts snippet lines over the size cap as a whole', () => {
    const lines = [GH, 'x'.repeat(REDACT_MAX_CHARS)];
    const { input, redactions } = redactInput(sampleInput({ snippet: { startLine: 1, lines } }));
    expect(input.snippet?.lines).toEqual([REDACTED, REDACTED]);
    expect(redactions).toBe(2);
  });
});

describe('redactInput: nothing secret reaches the prompt', () => {
  it('leaves no secret, whole or in part, in the built prompt', () => {
    const pass = j('hunter', '2hunter2');
    const secrets = [AWS, GH, GL, OPENAI, JWT, QLR, pass, body('MIIEo1')];
    const { input } = redactInput(
      sampleInput({
        message: `tokens ${GH} and ${GL}\nand ${AWS}`,
        rule: {
          key: `x:${QLR}`,
          name: `n ${OPENAI}`,
          description: `${BEGIN()}\n${body('MIIEo1')}\n${END()}`,
          cwe: [],
        },
        path: `src/${JWT}.ts`,
        snippet: {
          startLine: 1,
          lines: [
            `const url = "https://u:${pass}@h/x";`,
            `const k = "${GH.slice(0, 20)}" +`,
            `  "${GH.slice(20)}";`,
          ],
        },
      }),
    );
    const prompt = buildPrompt('fix', input, '0123456789abcdef0123456789abcdef');
    for (const s of secrets) expectGone(`${prompt.system}\n${prompt.user}`, s);
  });
});

// Review 1-3 (fix 3a): unquoted secrets (L2), fewer false positives, more token shapes.

const PASS = j('Hunter', '2Secret', 'Value9');
const B64 = j('dGhpcy', '1pcy1hLWZha2Uta2V5', 'LWZvci10ZXN0cw==');

describe('redactText: unquoted secrets (llm.md §5.2)', () => {
  it.each([
    ['a .env line', `DB_PASSWORD=${PASS}`, `DB_PASSWORD=${REDACTED}`],
    ['a shell export', `export API_KEY=${PASS}`, `export API_KEY=${REDACTED}`],
    ['a YAML value', `  password: ${PASS}`, `  password: ${REDACTED}`],
    ['a YAML list item', `  - client_secret: ${PASS}`, `  - client_secret: ${REDACTED}`],
    ['a YAML value with spaces', 'password: my very secret phrase', `password: ${REDACTED}`],
    [
      'a Java property',
      `spring.datasource.password=${PASS}`,
      `spring.datasource.password=${REDACTED}`,
    ],
    ['a property with spaces', `db.password = ${PASS}`, `db.password = ${REDACTED}`],
    ['a Dockerfile ENV', `ENV DB_PASSWORD ${PASS}`, `ENV DB_PASSWORD ${REDACTED}`],
    ['a Dockerfile ENV with =', `ENV DB_PASSWORD=${PASS}`, `ENV DB_PASSWORD=${REDACTED}`],
    ['a Dockerfile ARG', `ARG GITHUB_TOKEN=${PASS}`, `ARG GITHUB_TOKEN=${REDACTED}`],
    [
      'an ADO.NET connection string',
      `"DefaultConnection": "Server=db;User Id=sa;Password=${PASS};"`,
      `"DefaultConnection": "Server=db;User Id=sa;Password=${REDACTED};"`,
    ],
    ['an ODBC Pwd', `Driver=x;Uid=sa;Pwd=${PASS};`, `Driver=x;Uid=sa;Pwd=${REDACTED};`],
    [
      'a JDBC query',
      `jdbc:postgresql://db/x?user=app&password=${PASS}`,
      `jdbc:postgresql://db/x?user=app&password=${REDACTED}`,
    ],
    [
      'an Azure storage key',
      `DefaultEndpointsProtocol=https;AccountName=x;AccountKey=${B64};EndpointSuffix=core`,
      `DefaultEndpointsProtocol=https;AccountName=x;AccountKey=${REDACTED};EndpointSuffix=core`,
    ],
    [
      'an Azure shared access key',
      `Endpoint=sb://x/;SharedAccessKeyName=root;SharedAccessKey=${B64}`,
      `Endpoint=sb://x/;SharedAccessKeyName=root;SharedAccessKey=${REDACTED}`,
    ],
    [
      'a Basic authorization header',
      `Authorization: Basic ${j('YWxhZGRpbjpv', 'cGVuc2VzYW1l')}`,
      `Authorization: Basic ${REDACTED}`,
    ],
    [
      'a Bearer authorization header',
      `Authorization: Bearer ${j('abcdef0123', '456789ABCDEF')}`,
      `Authorization: Bearer ${REDACTED}`,
    ],
    [
      'a quoted header',
      `headers: { "Authorization": "Bearer ${j('abcdef0123', '456789ABCDEF')}" }`,
      `headers: { "Authorization": "Bearer ${REDACTED}" }`,
    ],
    [
      'an AWS secret key',
      `aws_secret_access_key=${j('wJalrXUtnFEMI', '/K7MDENG/bPxRfiCYEXAMPLEKEY')}`,
      `aws_secret_access_key=${REDACTED}`,
    ],
    ['an XML element', `<password>${PASS}</password>`, `<password>${REDACTED}</password>`],
    [
      'an XML element with a prefix',
      `<db:ApiKey> ${PASS} </db:ApiKey>`,
      `<db:ApiKey> ${REDACTED} </db:ApiKey>`,
    ],
    ['a passphrase', `passphrase=${PASS}`, `passphrase=${REDACTED}`],
    // The final review (M3): .NET appSettings, the MySQL clients, the short names pass and key.
    [
      'a .NET app setting',
      `<add key="StripeApiKey" value="${PASS}" />`,
      `<add key="StripeApiKey" value="${REDACTED}" />`,
    ],
    [
      'a .NET app setting named Secret',
      `  <add key='Smtp.Password' value='${PASS}'/>`,
      `  <add key='Smtp.Password' value='${REDACTED}'/>`,
    ],
    [
      'a .NET app setting named Token',
      `<add key="GitHubToken" value="${GH.slice(0, 12)}" />`,
      `<add key="GitHubToken" value="${REDACTED}" />`,
    ],
    [
      'a mysql -p password',
      `mysql -h db -uroot -p${PASS} app < dump.sql`,
      `mysql -h db -uroot -p${REDACTED} app < dump.sql`,
    ],
    [
      'a quoted mysqldump -p password',
      `mysqldump -u app -p'${PASS}' app`,
      `mysqldump -u app -p'${REDACTED}' app`,
    ],
    [
      'a short mysql password',
      `mysql -uroot -p${j('ro', 'ot')} app`,
      `mysql -uroot -p${REDACTED} app`,
    ],
    ['a random pass', `pass: "${PASS}"`, `pass: "${REDACTED}"`],
    ['a random PASS in .env', `PASS=${PASS}`, `PASS=${REDACTED}`],
    ['a random key', `key = '${j('a1B2', 'c3D4', 'e5F6', 'g7H8')}'`, `key = '${REDACTED}'`],
    [
      'a hex key',
      `"key": "${j('0123456789', 'abcdef', '0123456789', 'abcdef')}"`,
      `"key": "${REDACTED}"`,
    ],
  ])('redacts %s', (_name, text, expected) => {
    expect(redactText(text).text).toBe(expected);
  });

  it.each([
    'password: ${DB_PASSWORD}',
    'DB_PASSWORD=$DB_PASS_FROM_VAULT',
    'token: {{ .Values.token }}',
    'password = getPassword();',
    'password: %(db_password)s',
    'secret: (none given here)',
    'password: short',
    'if (password === confirmPassword) {}',
    'if (password == null) return;',
    'const f = (token) => token.trim();',
    'tokens.map(token=>token.value);',
    'Authorization: Bearer ${token}',
    '  token: string;',
    '  apiKey: config.apiKey,',
    'this.password = password;',
    '  password: process.env.DB_PASSWORD',
    `password: ${REDACTED}`,
    '<password>${DB_PASSWORD}</password>',
    'Password=;',
  ])('leaves %s alone', (text) => {
    expect(redactText(text)).toEqual({ text, count: 0 });
  });
});

describe('redactText: fewer false positives', () => {
  it.each([
    'const tokenType = "refresh_token";',
    'const authorName = "Jane Q. Public";',
    'author: "Jane Doe <jane@example.com>"',
    'author: jane.doe@example.com',
    'const authUrl = "https://login.example.com/oauth";',
    'throw new Error("password must be at least 8 characters");',
    'const PASSWORD_HINT = "Use a long passphrase";',
    'secretName: "my-app-secret"',
    'const tokenizer = "whitespace";',
    'const apiKeyHeader = "X-Api-Key";',
    'const passwordLabel = "Your password";',
    'expect(screen.getByLabelText("Password")).toBeVisible();',
    'const skillSet = sk-learn-and-other-things-long;',
    'url: "https://user@example.com/path"',
    'const auth = { user: "admin", password: process.env.DB_PASS };',
    'see https://pkgs.example.com:8080/a/@scope/pkg',
    'const task = "disk-usage-monitoring-service-name";',
    // A quoted value of three or more plain words is prose, not a secret, for a weaker name.
    'authRequired: "Please sign in again",',
    'const accessKeyMessage = "Your access key has expired.";',
    // `credentials` of fetch() takes these values.
    "fetch(url, { credentials: 'same-origin' });",
    'const init = { credentials: "include" };',
    // The short names `pass` and `key` (M3): only a random-looking value is a secret.
    '<li key="user-settings-panel-item">',
    'key: "app.settings.title.long",',
    "const key = 'com.example.FooBarService2';",
    'items.map((item) => ({ key: item.identifier }));',
    'pass: true,',
    'key={`row-${index}-${column}`}',
    'bypass = "some.value.that.is.long";',
    'monkey: "Abcdefgh12345678!"',
    'const passport = "A1b2C3d4E5f6G7h8";',
    '<add key="LogLevel" value="Information" />',
    '<add key="ApiKeyHeader" value="X-Api-Key-Header-Name" />',
    'mysql -P3306 -h db app',
    'mysql -u root -p app',
    'mysql --defaults-extra-file=/etc/app/my.cnf app',
    'mysql -uroot -p$MYSQL_ROOT_PASSWORD app',
  ])('leaves %s alone', (text) => {
    expect(redactText(text)).toEqual({ text, count: 0 });
  });

  // Ruling (fix 3a): a passphrase is words; a strong name gets no prose exemption.
  it.each([
    ['password', 'passwordRequired: "Password is required",'],
    ['token', 'const tokenMessage = "Your session token has expired.";'],
    ['passphrase', `const passphrase = "${['correct', 'horse', 'battery', 'staple'].join(' ')}";`],
    ['secret', 'client_secret: "open the pod bay doors"'],
    ['pwd', 'PWD="my dog has fleas"'],
    ['passwd', "passwd = 'let me in please'"],
    ['api key', 'api_key: "this is my key"'],
    ['private key', 'privateKey = "three plain words"'],
    ['credential', 'const credential = "blue sky thinking";'],
  ])('redacts a multi-word quoted value assigned to a %s name', (_name, text) => {
    const out = redactText(text);
    expect(out.count).toBe(1);
    expect(out.text).toContain(REDACTED);
  });
});

describe('redactText: more token shapes and positions', () => {
  it.each([
    ['a GitLab CI build token', j('gl', 'cbt-', 'a1B2'.repeat(6))],
    ['a GitLab OAuth secret', j('gl', 'oas-', 'a1B2'.repeat(10))],
    ['a GitLab feed token', j('gl', 'ft-', 'a1B2'.repeat(6))],
    ['a GitLab runner registration token', j('GR134', '8941', 'a1B2c3D4e5'.repeat(2))],
    ['an npm token', j('np', 'm_', 'a1B2'.repeat(9))],
    ['a Hugging Face token', j('h', 'f_', 'aBcD'.repeat(9))],
    ['a SendGrid key', j('S', 'G.', 'aBcD'.repeat(5), 'ab.', 'aBcD'.repeat(10), 'x')],
    ['a Stripe webhook secret', j('wh', 'sec_', 'aBcD'.repeat(8))],
    [
      'a JWT without an eyJ payload',
      j('ey', 'JhbGciOiJIUzI1NiJ9.', 'abcDEFghiJKL123.', 'sig0'.repeat(8)),
    ],
  ])('redacts %s', (_name, secret) => {
    const out = redactText(`value ${secret} end`);
    expectGone(out.text, secret);
    expect(out.text).toBe(`value ${REDACTED} end`);
  });

  it.each([
    ['inside a word', (s: string) => `x${s}`],
    ['after an underscore', (s: string) => `TOKEN_${s}`],
    ['after letters', (s: string) => `xx${s}`],
  ])('redacts a token %s', (_name, wrap) => {
    for (const secret of [AWS, GH, GL, QLR, j('np', 'm_', 'a1B2'.repeat(9))]) {
      expectGone(redactText(wrap(secret)).text, secret);
    }
  });

  it('redacts an OpenAI key after an underscore or a sign, not inside a word', () => {
    const key = j('s', 'k-', 'proj-', 'Q1'.repeat(15));
    expectGone(redactText(`TOKEN_${key}`).text, key);
    expectGone(redactText(`key=${key}`).text, key);
    expect(redactText(`task-${'Q1'.repeat(15)}`).count).toBe(0);
  });

  it('redacts the body of a PuTTY key file', () => {
    const text = [
      'PuTTY-User-Key-File-3: ssh-rsa',
      'Encryption: none',
      'Public-Lines: 2',
      'AAAAB3NzaC1yc2E',
      'Private-Lines: 2',
      j('AAAAgQC7', 'AAAAgQC7'.repeat(7)),
      'AAAAQQDx',
      j('Private-MAC: ', 'ab12'.repeat(10)),
      'done',
    ].join('\n');
    const lines = redactText(text).text.split('\n');
    expect(lines.slice(0, 8)).toEqual(Array(8).fill(REDACTED));
    expect(lines[8]).toBe('done');
  });

  it('redacts a URL password holding a / or an @', () => {
    expect(redactText('mysql://app:Hun/ter2Secret@db/x').text).toBe(`mysql://app:${REDACTED}@db/x`);
    expect(redactText(`mysql://app:Hun@${PASS}@db/x`).text).toBe(`mysql://app:${REDACTED}@db/x`);
  });

  it('redacts a quoted value with escaped quotes', () => {
    const out = redactText(`password = "Hunter2\\"${PASS}";`);
    expect(out.text).toBe(`password = "${REDACTED}";`);
  });
});

describe('redactText: secrets glued from pieces', () => {
  it.each([
    ['same-line concatenation', `const t = "${GH.slice(0, 18)}" + "${GH.slice(18)}";`],
    [
      'a joined array',
      `const t = ["${GH.slice(0, 10)}", "${GH.slice(10, 25)}", "${GH.slice(25)}"].join('');`,
    ],
    ['Python implicit concatenation', `t = ("${GH.slice(0, 18)}" "${GH.slice(18)}")`],
    [
      'a three-line split',
      `const t = "${GH.slice(0, 14)}" +\n  "${GH.slice(14, 27)}" +\n  "${GH.slice(27)}";`,
    ],
    [
      'a four-line split',
      `t = "${GH.slice(0, 10)}" +\n "${GH.slice(10, 20)}" +\n "${GH.slice(20, 30)}" +\n "${GH.slice(30)}";`,
    ],
    ['a split array', `t = [\n "${GH.slice(0, 16)}",\n "${GH.slice(16)}",\n].join('');`],
  ])('redacts a token glued by %s', (_name, text) => {
    const out = redactText(`${text}\nok();`).text;
    for (const piece of [GH.slice(4, 14), GH.slice(14, 24), GH.slice(24, 36)]) {
      expect(out).not.toContain(piece);
    }
    expect(out.split('\n').at(-1)).toBe('ok();');
  });

  it('keeps ordinary concatenations', () => {
    for (const text of [
      'const a = "Hello, " + "world";',
      'const parts = ["src", "lib", "index.ts"].join("/");',
    ]) {
      expect(redactText(text)).toEqual({ text, count: 0 });
    }
  });
});
