import type { TelemetryPayload } from './collect';

const DEFAULT_TIMEOUT_MS = 5_000;

/** telemetry.md: one POST, 5 s at most, no retry; the outcome is returned, never thrown. */
export async function sendTelemetry(
  url: string,
  payload: TelemetryPayload,
  options: { userAgent: string; timeoutMs?: number },
): Promise<{ ok: true } | { ok: false; reason: string }> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'user-agent': options.userAgent },
      body: JSON.stringify(payload),
      redirect: 'error',
      signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    });
    await response.body?.cancel();
    return response.ok ? { ok: true } : { ok: false, reason: `HTTP ${response.status}` };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.name : 'error' };
  }
}
