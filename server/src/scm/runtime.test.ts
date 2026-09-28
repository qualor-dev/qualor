import { describe, expect, it } from 'vitest';
import { CircuitBreaker } from './runtime';

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

  it('keeps connections apart, and releasing a closed circuit changes nothing', () => {
    const circuit = new CircuitBreaker(() => 0, 1, 1_000);
    circuit.failure('a');
    expect(circuit.tryPass('a')).toBe(false);
    expect(circuit.tryPass('b')).toBe(true);
    circuit.release('b');
    expect(circuit.tryPass('b')).toBe(true);
  });
});
