export interface ParsedVersion {
  numbers: [number, number, number, number];
  /** `"<major>.<minor>"` */
  line: string;
  prerelease: boolean;
}

const VERSION =
  /^[vV]?(\d{1,9})\.(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$/;

/** Parses a version label; a missing part is 0 and build metadata is ignored. */
export function parseVersionLabel(label: string): ParsedVersion | null {
  const m = VERSION.exec(label);
  if (!m) return null;
  const numbers: [number, number, number, number] = [
    Number(m[1]),
    Number(m[2]),
    Number(m[3] ?? 0),
    Number(m[4] ?? 0),
  ];
  return { numbers, line: `${numbers[0]}.${numbers[1]}`, prerelease: m[5] !== undefined };
}
