import { describe, expect, it } from 'vitest';
import { ScmError } from './provider';
import {
  CircuitBreaker,
  ConnectionHealth,
  createScmRuntime,
  installationSlotKey,
  retryable,
} from './runtime';

describe('one GitHub decoration at a time per installation', () => {
  const key = installationSlotKey('https://api.github.com', 777);

  it('keys a slot by the base URL and the installation', () => {
    expect(key).toBe('github:https://api.github.com|777');
    expect(installationSlotKey('https://ghe.example/api/v3', 777)).not.toBe(key);
  });

  it('answers busy to a second decoration of the installation until the first ends', () => {
    const { installationSlots } = createScmRuntime();
    expect(installationSlots.tryTake(key)).toBe(true);
    expect(installationSlots.tryTake(key)).toBe(false);
    installationSlots.release(key);
    expect(installationSlots.tryTake(key)).toBe(true);
  });

  it('lets two installations decorate at once', () => {
    const { installationSlots } = createScmRuntime();
    expect(installationSlots.tryTake(key)).toBe(true);
    expect(installationSlots.tryTake(installationSlotKey('https://api.github.com', 888))).toBe(
      true,
    );
  });

  it('leaves the organisation slots as they were (a GitLab decoration takes only those)', () => {
    const { slots, installationSlots } = createScmRuntime();
    expect(installationSlots.tryTake(key)).toBe(true);
    expect(slots.tryTake('org')).toBe(true);
    expect(slots.tryTake('org')).toBe(true);
    expect(slots.tryTake('org')).toBe(false); // MAX_DECORATIONS_PER_ORGANIZATION, unchanged
  });
});

describe('the token caches of the runtime', () => {
  it('keeps Microsoft Entra tokens apart from GitHub installation tokens, on the same clock', () => {
    let now = 1_000_000;
    const { azureTokens, githubTokens } = createScmRuntime(() => now);
    expect(azureTokens).not.toBe(githubTokens);
    azureTokens.set('key', 'entra', now + 60 * 60_000);
    expect(azureTokens.get('key')).toBe('entra');
    expect(githubTokens.get('key')).toBeNull();
    now += 56 * 60_000; // within the reuse margin of the token's end: asked again
    expect(azureTokens.get('key')).toBeNull();
  });
});

describe('the circuit breaker of a connection (scm.md §4.2)', () => {
  it('opens after the threshold, then lets one probe through; the others wait for its answer', () => {
    let now = 0;
    const circuit = new CircuitBreaker(() => now, 2, 1_000);
    expect(circuit.tryPass('k')).toBe(true);
    circuit.failure('k');
    expect(circuit.tryPass('k')).toBe(true);
    circuit.failure('k');
    expect(circuit.openUntil('k')).toBe(1_000);
    expect(circuit.tryPass('k')).toBe(false);
    now = 1_001;
    expect(circuit.tryPass('k')).toBe(true); // the probe
    expect(circuit.tryPass('k')).toBe(false); // a second job waits for the probe's answer
    circuit.failure('k'); // the probe failed: open again for a whole window
    expect(circuit.openUntil('k')).toBe(2_001);
    expect(circuit.tryPass('k')).toBe(false);
    now = 2_002;
    expect(circuit.tryPass('k')).toBe(true);
    circuit.success('k'); // the probe succeeded: closed, every job goes through
    expect(circuit.openUntil('k')).toBeNull();
    expect(circuit.tryPass('k')).toBe(true);
    expect(circuit.tryPass('k')).toBe(true);
  });

  it('hands the probe to the next job when it ends without an answer from GitLab', () => {
    let now = 0;
    const circuit = new CircuitBreaker(() => now, 1, 1_000);
    circuit.failure('k');
    now = 1_001;
    expect(circuit.tryPass('k')).toBe(true);
    expect(circuit.tryPass('k')).toBe(false);
    circuit.release('k'); // the organisation's slots were taken, say: no request was made
    expect(circuit.tryPass('k')).toBe(true);
    expect(circuit.openUntil('k')).toBeNull(); // the window is over; the probe decides
  });

  it('tells whether a job would pass without making it the probe', () => {
    let now = 0;
    const circuit = new CircuitBreaker(() => now, 1, 1_000);
    expect(circuit.wouldPass('k')).toBe(true); // closed
    circuit.failure('k');
    expect(circuit.wouldPass('k')).toBe(false); // open
    now = 1_001;
    expect(circuit.wouldPass('k')).toBe(true); // half-open, no probe in flight
    expect(circuit.wouldPass('k')).toBe(true); // asking took nothing
    expect(circuit.tryPass('k')).toBe(true); // the probe
    expect(circuit.wouldPass('k')).toBe(false); // the others wait for its answer
    circuit.success('k');
    expect(circuit.wouldPass('k')).toBe(true);
  });

  it('keeps connections apart, and releasing a closed circuit changes nothing', () => {
    const circuit = new CircuitBreaker(() => 0, 1, 1_000);
    circuit.failure('a');
    expect(circuit.tryPass('a')).toBe(false);
    expect(circuit.tryPass('b')).toBe(true);
    circuit.release('b');
    expect(circuit.tryPass('b')).toBe(true);
  });
});

describe('what a failed job tells the circuit of its connection (scm.md §4.2)', () => {
  it('retries only what says the provider is down or limiting', () => {
    expect(retryable(new ScmError('transient', 'down'))).toBe(true);
    expect(retryable(new ScmError('rate_limited', 'slow', { status: 429 }))).toBe(true);
    for (const kind of ['auth', 'not_found', 'refused', 'bad_answer', 'budget'] as const) {
      expect(retryable(new ScmError(kind, 'no')), kind).toBe(false);
    }
  });

  it('counts a transient failure or a rate limit against the connection, with a status or without', () => {
    const circuit = new CircuitBreaker(() => 0, 2, 1_000);
    circuit.reportError('k', new ScmError('transient', 'down'));
    expect(circuit.inspect('k')).toMatchObject({ state: 'closed', failures: 1 });
    circuit.reportError('k', new ScmError('rate_limited', 'slow', { status: 429 }));
    expect(circuit.inspect('k')).toMatchObject({ state: 'open', failures: 2 });
  });

  it('takes any other failure that came with a status as an answer: the provider is up', () => {
    const circuit = new CircuitBreaker(() => 0, 2, 1_000);
    circuit.failure('k');
    circuit.reportError('k', new ScmError('auth', 'refused the token', { status: 401 }));
    expect(circuit.inspect('k')).toEqual({ state: 'closed', failures: 0, openedAt: null });
  });

  it('hands the probe on when the failure came before any request', () => {
    let now = 0;
    const circuit = new CircuitBreaker(() => now, 1, 1_000);
    circuit.failure('k');
    now = 1_001;
    expect(circuit.tryPass('k')).toBe(true); // the probe
    expect(circuit.tryPass('k')).toBe(false);
    circuit.reportError('k', new ScmError('refused', 'the address is not allowed'));
    expect(circuit.tryPass('k')).toBe(true); // the next job is the probe; nothing was counted
    expect(circuit.inspect('k').failures).toBe(1);
  });
});

describe('what the support bundle reads of a connection (4E-3b §1)', () => {
  it('inspects the circuit without changing it', () => {
    let now = 0;
    const circuit = new CircuitBreaker(() => now, 2, 1_000);
    expect(circuit.inspect('k')).toEqual({ state: 'closed', failures: 0, openedAt: null });
    circuit.failure('k');
    expect(circuit.inspect('k')).toEqual({ state: 'closed', failures: 1, openedAt: null });
    now = 50;
    circuit.failure('k');
    expect(circuit.inspect('k')).toEqual({ state: 'open', failures: 2, openedAt: new Date(50) });
    now = 1_051;
    expect(circuit.inspect('k')).toEqual({
      state: 'half-open',
      failures: 2,
      openedAt: new Date(50),
    });
    expect(circuit.tryPass('k')).toBe(true); // inspecting took no probe
  });

  it('keeps the last outcome of each connection', () => {
    const health = new ConnectionHealth(() => 7);
    expect(health.get('a')).toBeNull();
    health.record('a', 'GitLab answered 502');
    expect(health.get('a')).toEqual({ ok: false, error: 'GitLab answered 502', at: new Date(7) });
    health.record('a', null);
    expect(health.get('a')).toEqual({ ok: true, error: null, at: new Date(7) });
  });
});
