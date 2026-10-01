import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  output,
  resource,
  signal,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { problemMessage } from '../../api/errors';
import type { ItemOf } from '../../api/types';
import { label } from '../../i18n/labels';
import { inputValue } from '../../shared/forms';
import type { ProjectDto } from '../current-project';

type Gate = ItemOf<'/api/v0/quality-gates'>;
type Language = ItemOf<'/api/v0/quality-profiles'>['language'];

interface ProfileOption {
  id: string;
  name: string;
}

interface ProfileRow {
  language: Language;
  /** The profile the project uses for it; null when the organisation has none for the language. */
  profileId: string | null;
  source: 'project' | 'default';
  options: ProfileOption[];
}

/** The catch-all language: listed last. */
const ANY = '*';
/** The server's page size cap. */
const PAGE = 100;

/**
 * Project → Settings → Quality gate and profiles (spec §3.2): the project's gate (a select of the
 * organisation's gates, saved with its own button) and, per language, the quality profile its
 * analyses use (saved as soon as the select changes). It tells the page with `saved` when the
 * project itself changed (the gate); a profile change does not touch the project.
 */
@Component({
  selector: 'q-gate-profiles-panel',
  imports: [RouterLink],
  templateUrl: './gate-profiles-panel.html',
  styleUrl: './gate-profiles-panel.css',
})
export class GateProfilesPanel {
  private readonly api = inject(Api);
  readonly project = input.required<ProjectDto>();
  readonly saved = output();

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);

  private readonly gates = resource({
    params: () => this.project().organizationId,
    loader: async ({ params: organizationId }): Promise<Gate[]> => {
      const all: Gate[] = [];
      let cursor: string | undefined;
      do {
        const result = await ok(
          this.api.client.GET('/api/v0/quality-gates', {
            params: { query: { organizationId, limit: PAGE, ...(cursor ? { cursor } : {}) } },
          }),
        );
        all.push(...result.items);
        cursor = result.nextCursor ?? undefined;
      } while (cursor);
      return all;
    },
  });
  protected readonly gateList = computed(() => (this.gates.hasValue() ? this.gates.value() : []));
  protected readonly gatesFailed = computed(() => this.gates.status() === 'error');
  private readonly defaultGateId = computed(
    () => this.gateList().find((g) => g.isDefault)?.id ?? null,
  );
  /** The gate the project uses now: its own, or else the organisation's default. */
  private readonly currentGateId = computed(
    () => this.project().qualityGateId ?? this.defaultGateId(),
  );
  protected readonly chosenGate = linkedSignal<string | null>(() => this.currentGateId());
  protected readonly gateDirty = computed(
    () => this.chosenGate() !== null && this.chosenGate() !== this.currentGateId(),
  );

  private readonly assignments = resource({
    params: () => ({ id: this.project().id, organizationId: this.project().organizationId }),
    loader: async ({ params }): Promise<ProfileRow[]> => {
      const assigned = await ok(
        this.api.client.GET('/api/v0/projects/{id}/quality-profiles', {
          params: { path: { id: params.id } },
        }),
      );
      const rows = await Promise.all(
        assigned.map(async (item): Promise<ProfileRow> => {
          const options: ProfileOption[] = [];
          let cursor: string | undefined;
          do {
            const result = await ok(
              this.api.client.GET('/api/v0/quality-profiles', {
                params: {
                  query: {
                    organizationId: params.organizationId,
                    language: item.language,
                    limit: PAGE,
                    ...(cursor ? { cursor } : {}),
                  },
                },
              }),
            );
            options.push(...result.items.map((p) => ({ id: p.id, name: p.name })));
            cursor = result.nextCursor ?? undefined;
          } while (cursor);
          return {
            language: item.language,
            profileId: item.profile?.id ?? null,
            source: item.source,
            options,
          };
        }),
      );
      return rows.sort((a, b) => Number(a.language === ANY) - Number(b.language === ANY));
    },
  });
  /** The rows, changed in place by a saved profile; started again whenever they are read again. */
  protected readonly rows = linkedSignal<ProfileRow[]>(() =>
    this.assignments.hasValue() ? this.assignments.value() : [],
  );
  protected readonly profilesFailed = computed(() => this.assignments.status() === 'error');
  protected readonly rowBusy = signal<Record<string, boolean>>({});
  protected readonly rowError = signal<Record<string, string>>({});

  protected gateName(gate: Gate): string {
    return gate.isDefault
      ? $localize`:@@gate.defaultOption:${gate.name}:name: (default)`
      : gate.name;
  }

  protected languageName(language: string): string {
    return language === ANY
      ? $localize`:@@gate.profiles.anyLanguage:Other languages`
      : label('language', language);
  }

  /** The options of a row, with its current profile kept when the list does not hold it. */
  protected optionsOf(row: ProfileRow): ProfileOption[] {
    return row.profileId !== null && !row.options.some((o) => o.id === row.profileId)
      ? [
          { id: row.profileId, name: $localize`:@@gate.profiles.current:Current profile` },
          ...row.options,
        ]
      : row.options;
  }

  protected chooseGate(event: Event): void {
    this.chosenGate.set(inputValue(event) || null);
    this.announcement.set(null);
    this.error.set(null);
  }

  protected async saveGate(): Promise<void> {
    const qualityGateId = this.chosenGate();
    if (this.busy() || !this.gateDirty() || qualityGateId === null) return;
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await ok(
        this.api.client.PATCH('/api/v0/projects/{id}', {
          params: { path: { id: this.project().id } },
          body: { qualityGateId },
        }),
      );
      this.announcement.set($localize`:@@gate.saved:Quality gate saved.`);
      this.saved.emit();
    } catch (err) {
      this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async chooseProfile(row: ProfileRow, event: Event): Promise<void> {
    const select = event.target as HTMLSelectElement;
    const profileId = select.value;
    const language = row.language;
    if (!profileId || profileId === row.profileId || this.rowBusy()[language]) {
      select.value = row.profileId ?? '';
      return;
    }
    this.rowBusy.update((b) => ({ ...b, [language]: true }));
    this.rowError.update(without(language));
    this.announcement.set(null);
    try {
      const result = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/quality-profiles/{language}', {
          params: { path: { id: this.project().id, language } },
          body: { profileId },
        }),
      );
      this.rows.update((rows) =>
        rows.map((r) =>
          r.language === language
            ? { ...r, profileId: result.profile?.id ?? profileId, source: result.source }
            : r,
        ),
      );
      this.announcement.set(
        $localize`:@@gate.profiles.saved:Profile for ${label('language', language)}:language: saved.`,
      );
    } catch (err) {
      select.value = row.profileId ?? '';
      const message = problemMessage(err);
      this.rowError.update((e) => ({ ...e, [language]: message }));
    } finally {
      this.rowBusy.update(without(language));
    }
  }
}

function without<T>(key: string): (record: Record<string, T>) => Record<string, T> {
  return (record) => Object.fromEntries(Object.entries(record).filter(([k]) => k !== key));
}
