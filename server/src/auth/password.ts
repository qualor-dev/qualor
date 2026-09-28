import { hash, verify } from '@node-rs/argon2';

export const PASSWORD_MIN_LENGTH = 12;
/** Caps argon2 input so a huge "password" cannot be used to burn CPU. */
export const PASSWORD_MAX_LENGTH = 256;

// OWASP baseline for argon2id (the library's default algorithm): 19 MiB, 2 passes, 1 lane.
const OPTIONS = { memoryCost: 19_456, timeCost: 2, parallelism: 1 };

let dummyHash: Promise<string> | undefined;
let dummyHashReady = false;

function dummy(): Promise<string> {
  dummyHash ??= hashPassword('qualor-timing-equaliser').then((value) => {
    dummyHashReady = true;
    return value;
  });
  return dummyHash;
}

/**
 * Computes the dummy hash now (buildApp awaits this), so the first login for an unknown user does
 * not also pay for hashing it — which would make that one response measurably slower.
 */
export async function warmPasswordHashing(): Promise<void> {
  await dummy();
}

/** For tests: whether the dummy hash has been computed. */
export function dummyHashIsWarm(): boolean {
  return dummyHashReady;
}

export function hashPassword(password: string): Promise<string> {
  return hash(password, OPTIONS);
}

/**
 * Always performs one argon2 verification — against a dummy hash when the user has none or does
 * not exist — so the response time does not reveal whether a username exists.
 */
export async function verifyPassword(stored: string | null, password: string): Promise<boolean> {
  const target = stored ?? (await dummy());
  let ok: boolean;
  try {
    ok = await verify(target, password);
  } catch {
    ok = false;
  }
  return stored !== null && ok;
}
