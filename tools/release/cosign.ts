/**
 * cosign argument lists (release.md §7). Offline: no transparency log and no signing config
 * (TUF), so every call runs with --network none or on the internal dry-run network (Task 2's
 * probe, tools/release/probe.ts, used exactly these flags). Real releases (release:publish) pass
 * offline: false only if the release chooses Rekor (publish.ts, REKOR_FOR_REAL_RELEASES).
 */
export const SIGN_OFFLINE = ['--tlog-upload=false', '--use-signing-config=false'] as const;
export const VERIFY_OFFLINE = ['--insecure-ignore-tlog=true'] as const;
export const PLAIN_HTTP = ['--allow-insecure-registry', '--allow-http-registry'] as const;

/**
 * Ruling R-REGOPTS: no defaults. Every call site says whether it uploads to Rekor and whether it
 * talks plain HTTP, so a real release can never inherit the dry run's plain-HTTP flags by omission.
 */
export interface RegistryOptions {
  /** true: no transparency log (Rekor) and no signing config; the only mode of the dry run. */
  offline: boolean;
  /** true: plain HTTP, for the dry-run registry only; release:publish always passes false. */
  plainHttp: boolean;
}

export function assertDigestRef(ref: string): void {
  if (!/@sha256:[0-9a-f]{64}$/.test(ref)) {
    throw new Error(`${ref}: sign and verify images by digest (repository@sha256:…)`);
  }
}

const signFlags = (o: RegistryOptions): string[] => [
  ...(o.offline ? SIGN_OFFLINE : []),
  ...(o.plainHttp ? PLAIN_HTTP : []),
];
const verifyFlags = (o: RegistryOptions): string[] => [
  ...(o.offline ? VERIFY_OFFLINE : []),
  ...(o.plainHttp ? PLAIN_HTTP : []),
];

/** A blob has no registry: only `offline` applies (the same Rekor switch as the images). */
export const signBlobArgs = (
  key: string,
  file: string,
  bundle: string,
  o: Pick<RegistryOptions, 'offline'>,
): string[] => [
  'sign-blob',
  '--yes',
  '--key',
  key,
  '--bundle',
  bundle,
  ...(o.offline ? SIGN_OFFLINE : []),
  file,
];
export const verifyBlobArgs = (pub: string, file: string, bundle: string): string[] => [
  'verify-blob',
  '--key',
  pub,
  '--bundle',
  bundle,
  ...VERIFY_OFFLINE,
  file,
];

export function signImageArgs(key: string, ref: string, o: RegistryOptions): string[] {
  assertDigestRef(ref);
  return ['sign', '--yes', '--key', key, ...signFlags(o), ref];
}
export function attestArgs(
  key: string,
  ref: string,
  predicate: string,
  o: RegistryOptions,
): string[] {
  assertDigestRef(ref);
  return [
    'attest',
    '--yes',
    '--key',
    key,
    '--type',
    'spdxjson',
    '--predicate',
    predicate,
    ...signFlags(o),
    ref,
  ];
}
export function verifyImageArgs(pub: string, ref: string, o: RegistryOptions): string[] {
  assertDigestRef(ref);
  return ['verify', '--key', pub, ...verifyFlags(o), ref];
}
export function verifyAttestationArgs(pub: string, ref: string, o: RegistryOptions): string[] {
  assertDigestRef(ref);
  return ['verify-attestation', '--key', pub, '--type', 'spdxjson', ...verifyFlags(o), ref];
}
