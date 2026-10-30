import { computed, effect, inject, Injectable, signal } from '@angular/core';
import { SessionStore } from '../auth/session';

/** A one-time token a run revealed, and whether the person copied it (Copy, or from its field). */
export interface RevealedToken {
  token: string;
  copied: boolean;
}

type RunTokens = ReadonlyMap<string, RevealedToken>;

/**
 * The one-time tokens repository-setup runs revealed, by run and repository ref, for as long as
 * the browser page lives: the server shows each token once, so a token must survive moving
 * between runs (**Try again**, back, a link) and leaving the page. Memory only: never storage,
 * never a log. They belong to the user who received them: another user signed in on the same page
 * sees none of them, and the first token that user receives replaces them. Signing out forgets
 * them all.
 */
@Injectable({ providedIn: 'root' })
export class SetupTokens {
  private readonly session = inject(SessionStore);
  private readonly kept = signal<{ owner: string | null; runs: ReadonlyMap<string, RunTokens> }>({
    owner: null,
    runs: new Map(),
  });
  private readonly user = computed(() => this.session.user()?.id ?? null);

  constructor() {
    // Signed out (null), not merely unknown while the session is asked again (undefined).
    effect(() => {
      if (this.session.me() === null) this.kept.set({ owner: null, runs: new Map() });
    });
  }

  /** A run's tokens by ref, for the signed-in user. */
  forRun(runId: string): RunTokens {
    const kept = this.kept();
    if (kept.owner === null || kept.owner !== this.user()) return EMPTY;
    return kept.runs.get(runId) ?? EMPTY;
  }

  /** Keeps tokens the server revealed; one already kept stays as it is (with its copied mark). */
  keep(runId: string, revealed: readonly { ref: string; token: string }[]): void {
    const owner = this.user();
    if (owner === null || revealed.length === 0) return;
    this.kept.update((kept) => {
      const runs = new Map(kept.owner === owner ? kept.runs : []);
      const tokens = new Map(runs.get(runId) ?? []);
      for (const { ref, token } of revealed) {
        if (!tokens.has(ref)) tokens.set(ref, { token, copied: false });
      }
      runs.set(runId, tokens);
      return { owner, runs };
    });
  }

  markCopied(runId: string, ref: string): void {
    const owner = this.user();
    this.kept.update((kept) => {
      const found = kept.runs.get(runId)?.get(ref);
      if (kept.owner !== owner || !found || found.copied) return kept;
      const runs = new Map(kept.runs);
      runs.set(runId, new Map(runs.get(runId)).set(ref, { ...found, copied: true }));
      return { owner: kept.owner, runs };
    });
  }
}

const EMPTY: RunTokens = new Map();
