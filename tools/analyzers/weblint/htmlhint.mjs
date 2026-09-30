// Qualor's HTMLHint pass (config.md §6, plan 8D): HTMLHint's core API with the rules the CLI
// resolved (the project's .htmlhintrc, or Qualor's set). Never HTMLHint's command line, which
// searches for .htmlhintrc up to the filesystem root and loads JavaScript rules (--rulesdir).
//   node htmlhint.mjs --root <dir> --out <file.sarif> --files <list.json> --rules <rules.json>
// Prints one JSON line {"files":N,"listed":N,"parseErrors":N}: files counts the files linted,
// listed the usable entries of the --files list (the same number: HTMLHint has no ignore file),
// parseErrors the files HTMLHint threw on (an in-file directive such as
// `<!-- htmlhint constructor:true -->` crashes it), which are skipped, never the whole pass
// (ruling D11).
// Exit 0 whenever the log is written, 2 on any error, a throw on every one of two or more listed
// files included.
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import htmlhint from 'htmlhint';
import { listedFiles, readJson, region, required, run, stderr, uriOf } from './files.mjs';

const { HTMLHint } = htmlhint;
const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = /\.html?$/i;

/**
 * One file's messages. `verify` writes a file's `<!-- htmlhint … -->` directive into the ruleset
 * object it gets (verified facts F10), so each file gets its own copy, and a frozen ruleset (the
 * CLI's default) is never handed over itself.
 */
export function lintHtml(text, rules) {
  return HTMLHint.verify(text, { ...rules });
}

/** HTMLHint reports some problems twice at one place (tag-no-obsolete on start and end tag). */
export function dedupe(messages) {
  const seen = new Set();
  return messages.filter((m) => {
    const key = `${m.rule?.id}\u0000${m.line}\u0000${m.message}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function main(args) {
  const root = path.resolve(required(args, '--root'));
  const out = path.resolve(required(args, '--out'));
  const rules = readJson(required(args, '--rules'));
  if (rules === null || typeof rules !== 'object' || Array.isArray(rules)) {
    throw new Error('--rules must name a JSON object');
  }
  const files = listedFiles(root, readJson(required(args, '--files')), SOURCE);
  const version = JSON.parse(
    readFileSync(path.join(here, 'node_modules/htmlhint/package.json'), 'utf8'),
  ).version;

  const used = new Map();
  const results = [];
  let parseErrors = 0;
  for (const file of files) {
    let messages;
    try {
      messages = dedupe(lintHtml(readFileSync(file, 'utf8'), rules));
    } catch (err) {
      parseErrors += 1;
      stderr(`htmlhint: ${uriOf(root, file)} not linted: ${err?.message ?? err}\n`);
      continue;
    }
    for (const m of messages) {
      if (!m.rule?.id) continue;
      used.set(m.rule.id, m.rule);
      results.push({
        ruleId: m.rule.id,
        level: m.type === 'error' ? 'error' : m.type === 'warning' ? 'warning' : 'note',
        message: { text: m.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: uriOf(root, file) },
              region: region(m.line, m.col),
            },
          },
        ],
      });
    }
  }
  // A single file that throws is counted like any parse error (final review, minor 7).
  if (files.length >= 2 && parseErrors === files.length) {
    throw new Error(`HTMLHint failed on every file (${parseErrors})`);
  }
  const sarifRules = [...used.values()]
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((r) => ({
      id: r.id,
      name: r.id,
      shortDescription: { text: r.description ?? r.id },
      helpUri: `https://htmlhint.com/rules/${r.id}`,
    }));
  writeFileSync(
    out,
    JSON.stringify({
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: {
              name: 'htmlhint',
              version,
              informationUri: 'https://htmlhint.com',
              rules: sarifRules,
            },
          },
          results,
        },
      ],
    }),
  );
  process.stdout.write(
    `${JSON.stringify({ files: files.length, listed: files.length, parseErrors })}\n`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run('htmlhint', main);
}
