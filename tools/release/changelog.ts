/** release.md §2: release notes are the version's section of CHANGELOG.md. */
export function changelogSection(md: string, heading: string): string | null {
  const lines = md.split(/\r?\n/);
  const start = lines.findIndex((l) => l === `## [${heading}]` || l.startsWith(`## [${heading}] `));
  if (start === -1) return null;
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('## ['));
  return (end === -1 ? rest : rest.slice(0, end)).join('\n').trim();
}

/** The heading line of a section, or null. */
function headingLine(md: string, heading: string): string | null {
  return (
    md.split(/\r?\n/).find((l) => l === `## [${heading}]` || l.startsWith(`## [${heading}] `)) ??
    null
  );
}

/** `YYYY-MM-DD` that is a real calendar date. */
function isDate(text: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!m) return false;
  const d = new Date(`${text}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().startsWith(text);
}

/**
 * The notes of `version`: its own section, whose heading must be `## [x.y.z] - YYYY-MM-DD`, or
 * (the dry run only) `## [Unreleased]`. An empty section is refused either way.
 */
export function releaseNotes(
  md: string,
  version: string,
  o: { allowUnreleased: boolean },
): { notes: string; fromUnreleased: boolean } {
  const own = changelogSection(md, version);
  if (own !== null) {
    const line = headingLine(md, version) ?? '';
    const date = line.slice(`## [${version}] - `.length);
    if (!line.startsWith(`## [${version}] - `) || !isDate(date)) {
      throw new Error(`CHANGELOG.md: "${line}" must read "## [${version}] - YYYY-MM-DD"`);
    }
    if (own === '') throw new Error(`CHANGELOG.md: the section of ${version} is empty`);
    return { notes: own, fromUnreleased: false };
  }
  const unreleased = o.allowUnreleased ? changelogSection(md, 'Unreleased') : null;
  if (unreleased === '') throw new Error('CHANGELOG.md: the Unreleased section is empty');
  if (unreleased !== null) return { notes: unreleased, fromUnreleased: true };
  throw new Error(`CHANGELOG.md has no "## [${version}] - YYYY-MM-DD" section`);
}
