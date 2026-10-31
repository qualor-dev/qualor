/** Where a project has vulnerabilities it has not shown yet (`ProjectDto.vulnerabilities.newIn`). */
export interface NewIn {
  main: boolean;
  branches: number;
  versions: number;
}

/**
 * The badge text for the targets with new vulnerabilities ("New vulnerabilities in main and 2
 * versions"), or null when nothing is new. The parts are joined with "and", main first.
 */
export function newMarkerText(newIn: NewIn): string | null {
  const parts: string[] = [];
  if (newIn.main) parts.push($localize`:@@vuln.new.main:main`);
  if (newIn.branches > 0) {
    parts.push(
      newIn.branches === 1
        ? $localize`:@@vuln.new.branch.one:1 branch`
        : $localize`:@@vuln.new.branch.many:${newIn.branches}:count: branches`,
    );
  }
  if (newIn.versions > 0) {
    parts.push(
      newIn.versions === 1
        ? $localize`:@@vuln.new.version.one:1 version`
        : $localize`:@@vuln.new.version.many:${newIn.versions}:count: versions`,
    );
  }
  if (parts.length === 0) return null;
  const where = parts.reduce(
    (all, part) => $localize`:@@vuln.new.and:${all}:all: and ${part}:part:`,
  );
  return $localize`:@@vuln.new.text:New vulnerabilities in ${where}:where:`;
}
