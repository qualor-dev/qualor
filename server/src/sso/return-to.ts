const HOME = '/';
const MAX_LENGTH = 2_048;
const PROBE_ORIGIN = 'https://qualor.invalid';
/** How many layers of percent-encoding are undone to look for a hidden `//`, `\` or control. */
const MAX_DECODES = 4;
const ENCODED = /%[0-9a-f]{2}/i;

/**
 * Only visible ASCII (0x21-0x7e): no C0/C1 control, DEL, space, line separator or other non-ASCII
 * character. A browser drops tabs and newlines (`/<TAB>/host` becomes `//host`), and a `Location`
 * header cannot carry non-Latin-1 text; the UI percent-encodes everything else.
 */
function visibleAscii(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

/** A C0 or C1 control, DEL, or a line or paragraph separator. */
function hasControl(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      return true;
    }
  }
  return false;
}

/**
 * Whether the path a URL parser makes of it starts with `//`: dot segments normalise away
 * (`/.//host`, `/a/..//host`, `/%2e//host` all become `//host`), which a later redirect or
 * re-parse could read as another host.
 */
function normalisesToDoubleSlash(value: string): boolean {
  try {
    return new URL(value, PROBE_ORIGIN).pathname.startsWith('//');
  } catch {
    return true;
  }
}

/**
 * A path of this origin: one leading `/`, never `//` or a backslash (browsers read it as `/`),
 * no control character, and no dot segment that normalises into `//`. A decoded form may hold
 * other non-ASCII text (`/caf%C3%A9`).
 */
function plainPath(value: string): boolean {
  return (
    value.startsWith('/') &&
    !value.startsWith('//') &&
    !value.includes(String.fromCharCode(92)) &&
    !hasControl(value) &&
    !normalisesToDoubleSlash(value)
  );
}

/**
 * sso-scim.md §7.3: a same-origin path (with query and fragment), else `/`. The UI's
 * `safeReturnUrl`, again on the server, and stricter: every percent-decoding of it (up to four
 * layers) must still be a plain path, so `/%2F%2Fhost`, `/%5Chost`, `/%09/host` and their
 * double-encoded forms are refused whatever later decodes them; malformed encoding is refused too.
 */
export function safeReturnTo(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.length > MAX_LENGTH) return HOME;
  if (!visibleAscii(raw) || !plainPath(raw)) return HOME;
  let current = raw;
  for (let i = 0; i < MAX_DECODES && ENCODED.test(current); i++) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(current);
    } catch {
      return HOME;
    }
    if (!plainPath(decoded)) return HOME;
    current = decoded;
  }
  // Still encoded after four layers: nobody legitimate nests that deep.
  if (ENCODED.test(current)) return HOME;
  return new URL(raw, PROBE_ORIGIN).origin === PROBE_ORIGIN ? raw : HOME;
}
