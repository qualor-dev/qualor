import { InstallationTokenCache, MutationPacer } from './github/app-auth';
import type { ScmError } from './provider';

/** scm.md §4.2: consecutive failed jobs of a connection that open its circuit ... */
export const SCM_CIRCUIT_FAILURES = 5;
/** ... for this long. */
export const SCM_CIRCUIT_OPEN_MS = 10 * 60_000;
/** scm.md §4.2: decoration jobs of one organisation in flight at once, per process. */
export const MAX_DECORATIONS_PER_ORGANIZATION = 2;

/**
 * A failure that says the provider is down or limiting: the job is tried again later, and the
 * failure counts against the connection's circuit ({@link CircuitBreaker.reportError}).
 */
export const retryable = (error: ScmError): boolean =>
  error.kind === 'transient' || error.kind === 'rate_limited';

/**
 * A circuit breaker per connection, in the worker's memory (scm.md §4.2): after
 * {@link SCM_CIRCUIT_FAILURES} consecutive transient failures the circuit is open for
 * {@link SCM_CIRCUIT_OPEN_MS}. After that window it is half-open: exactly one job (the probe) goes
 * through, and every other job is refused as by an open circuit until the probe has an answer. A
 * failed probe opens the circuit again for a whole window (the count is still at the threshold);
 * a probe that GitLab answered closes it; a probe that ended without a request (its
 * organisation's slots were taken, say) hands the probe to the next job.
 */
export class CircuitBreaker {
  private readonly state = new Map<
    string,
    { failures: number; openUntil: number; probing: boolean }
  >();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly threshold = SCM_CIRCUIT_FAILURES,
    private readonly openMs = SCM_CIRCUIT_OPEN_MS,
  ) {}

  /** The time the circuit is open until, or null when it is closed or half-open. */
  openUntil(key: string): number | null {
    const entry = this.state.get(key);
    return entry && entry.openUntil > this.now() ? entry.openUntil : null;
  }

  /**
   * Whether a job may send requests now: the circuit is closed, or it is half-open and this job
   * becomes the probe. The caller then reports {@link success}, {@link failure} or
   * {@link release}.
   */
  tryPass(key: string): boolean {
    const entry = this.state.get(key);
    if (!entry || entry.failures < this.threshold) return true;
    if (entry.openUntil > this.now() || entry.probing) return false;
    entry.probing = true;
    return true;
  }

  /**
   * Whether {@link tryPass} would let a job through now: the circuit is closed, or it is half-open
   * with no probe in flight. It makes no job the probe: a job that has work of its own to do before
   * its requests asks it first, and passes the circuit when it sends them.
   */
  wouldPass(key: string): boolean {
    const entry = this.state.get(key);
    if (!entry || entry.failures < this.threshold) return true;
    return entry.openUntil <= this.now() && !entry.probing;
  }

  /** GitLab answered: the count starts again and the circuit is closed. */
  success(key: string): void {
    this.state.delete(key);
  }

  /** A transient failure (5xx, timeout, connection, 429). */
  failure(key: string): void {
    const entry = this.state.get(key) ?? { failures: 0, openUntil: 0, probing: false };
    entry.failures += 1;
    entry.probing = false;
    if (entry.failures >= this.threshold) entry.openUntil = this.now() + this.openMs;
    this.state.set(key, entry);
  }

  /** A job that passed ended without an answer either way: a probe goes to the next job. */
  release(key: string): void {
    const entry = this.state.get(key);
    if (entry) entry.probing = false;
  }

  /**
   * A job that passed ended with a request that failed, `error`: a transient failure or a rate
   * limit counts ({@link failure}); any other failure that came with an HTTP status was an answer,
   * so the provider is up and the count starts again ({@link success}); one that came before any
   * request, with no status, hands the probe on ({@link release}).
   */
  reportError(key: string, error: ScmError): void {
    if (retryable(error)) this.failure(key);
    else if (error.status !== null) this.success(key);
    else this.release(key);
  }

  /** Where the circuit stands, for the support bundle (4E-3b §1); it changes nothing. */
  inspect(key: string): {
    state: 'closed' | 'open' | 'half-open';
    failures: number;
    openedAt: Date | null;
  } {
    const entry = this.state.get(key);
    if (!entry || entry.failures < this.threshold) {
      return { state: 'closed', failures: entry?.failures ?? 0, openedAt: null };
    }
    return {
      state: entry.openUntil > this.now() ? 'open' : 'half-open',
      failures: entry.failures,
      openedAt: new Date(entry.openUntil - this.openMs),
    };
  }
}

/**
 * The last decoration outcome of each connection in this process, for the support bundle
 * (4E-3b §1): `ok` after GitLab or GitHub answered, `failing` with the error after a failure.
 */
export class ConnectionHealth {
  private readonly last = new Map<string, { ok: boolean; error: string | null; at: Date }>();

  constructor(private readonly now: () => number = Date.now) {}

  record(connectionId: string, error: string | null): void {
    this.last.set(connectionId, { ok: error === null, error, at: new Date(this.now()) });
  }

  get(connectionId: string): { ok: boolean; error: string | null; at: Date } | null {
    return this.last.get(connectionId) ?? null;
  }
}

/** At most `max` decorations per organisation in flight in this process (scm.md §4.2). */
export class OrganizationSlots {
  private readonly taken = new Map<string, number>();

  constructor(private readonly max = MAX_DECORATIONS_PER_ORGANIZATION) {}

  tryTake(organizationId: string): boolean {
    const n = this.taken.get(organizationId) ?? 0;
    if (n >= this.max) return false;
    this.taken.set(organizationId, n + 1);
    return true;
  }

  release(organizationId: string): void {
    const n = (this.taken.get(organizationId) ?? 1) - 1;
    if (n <= 0) this.taken.delete(organizationId);
    else this.taken.set(organizationId, n);
  }
}

/**
 * The key of an installation's slot: GitHub counts content-creating requests per installation, so
 * two decorations of one installation must not run together (its secondary rate limit).
 */
export function installationSlotKey(baseUrl: string, installationId: number): string {
  return `github:${baseUrl}|${installationId}`;
}

/** The per-process state of the decoration worker. */
export interface ScmRuntime {
  circuit: CircuitBreaker;
  /** 4E-3b §1: the last outcome per connection, read by the support bundle. */
  health: ConnectionHealth;
  slots: OrganizationSlots;
  /** One GitHub decoration in flight per installation (key: {@link installationSlotKey}). */
  installationSlots: OrganizationSlots;
  /** github.md §4: installation tokens, shared by every job of the process. */
  githubTokens: InstallationTokenCache;
  /** github.md §5.3: mutations of one installation at least a second apart, per process. */
  githubPacer: MutationPacer;
  /**
   * Azure DevOps design §7.1: Microsoft Entra tokens of service principal connections (key:
   * `entraCacheKey`), reused until shortly before they expire, never stored.
   */
  azureTokens: InstallationTokenCache;
}

export function createScmRuntime(now: () => number = Date.now): ScmRuntime {
  return {
    circuit: new CircuitBreaker(now),
    health: new ConnectionHealth(now),
    slots: new OrganizationSlots(),
    installationSlots: new OrganizationSlots(1),
    githubTokens: new InstallationTokenCache(now),
    githubPacer: new MutationPacer(now),
    azureTokens: new InstallationTokenCache(now),
  };
}
