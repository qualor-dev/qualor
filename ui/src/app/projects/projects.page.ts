import {
  Component,
  effect,
  type ElementRef,
  inject,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { inputValue } from '../shared/forms';
import { GateBadge } from '../shared/gate-badge';
import { KeysetList } from '../shared/keyset';
import { MeasurePipe } from '../shared/measure.pipe';

export type Project = ItemOf<'/api/v0/projects'>;
const PAGE_SIZE = 50;
/** The API's limit for `q`, key and name (openapi.json): longer text would only be refused. */
const MAX_TEXT = 255;

/**
 * The current organisation's projects (brief §2.3) with their gate and main-branch measures:
 * a search that lives in the URL, keyset pages, and project creation for organisation admins.
 */
@Component({
  selector: 'q-projects-page',
  imports: [DateTimePipe, GateBadge, MeasurePipe, RouterLink],
  templateUrl: './projects.page.html',
})
export class ProjectsPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  protected readonly org = inject(OrgContext);

  /** `?q=`: a case-insensitive search on key and name (router input binding). */
  readonly q = input<string>();

  protected readonly maxText = MAX_TEXT;
  /** The main-branch measures the table shows, in column order. */
  protected readonly columns = ['issues', 'coverage', 'duplicated_lines_density', 'ncloc'];
  protected readonly search = signal('');
  protected readonly list = new KeysetList<Project, { organizationId: string | null; q: string }>(
    async (params, cursor) =>
      ok(
        this.api.client.GET('/api/v0/projects', {
          params: {
            query: {
              limit: PAGE_SIZE,
              ...(params.organizationId ? { organizationId: params.organizationId } : {}),
              ...(params.q ? { q: params.q } : {}),
              ...(cursor ? { cursor } : {}),
            },
          },
        }),
      ),
  );

  protected readonly newKey = signal('');
  protected readonly newName = signal('');
  protected readonly creating = signal(false);
  protected readonly createError = signal<string | null>(null);
  protected readonly keyError = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  /** The last creation's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  private readonly keyField = viewChild<ElementRef<HTMLInputElement>>('keyField');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  protected readonly inputValue = inputValue;

  constructor() {
    effect(() => {
      const q = (this.q() ?? '').trim().slice(0, MAX_TEXT);
      this.search.set(q);
      if (this.org.organizations.isLoading()) return;
      const organizationId = this.org.currentId();
      // Only the search and the organisation start a new load, not what the request reads.
      untracked(() => void this.list.reset({ organizationId, q }));
    });
  }

  protected submitSearch(event: Event): void {
    event.preventDefault();
    const q = this.search().trim().slice(0, MAX_TEXT);
    void this.router.navigate([], { queryParams: { q: q || null }, replaceUrl: true });
  }

  protected setKey(event: Event): void {
    this.newKey.set(inputValue(event));
    this.keyError.set(null);
  }

  protected setName(event: Event): void {
    this.newName.set(inputValue(event));
    this.nameError.set(null);
  }

  /**
   * Creates a project and opens it. Blank fields are refused here; what the server refuses goes to
   * its field (`body.key`, `body.name`, 409 `PROJECT_KEY_TAKEN` on the key), and focus moves to
   * the first refused field. While the request runs the button stays focusable (`aria-disabled`).
   */
  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    if (!organizationId || !this.org.canChange('org.projects.create') || this.creating()) return;
    const key = this.newKey().trim();
    const name = this.newName().trim();
    this.keyError.set(key ? null : $localize`:@@projects.create.keyRequired:Enter a key.`);
    this.nameError.set(name ? null : $localize`:@@projects.create.nameRequired:Enter a name.`);
    if (!key || !name) {
      this.focusFirstInvalid();
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.announcement.set(null);
    try {
      const project = await ok(
        this.api.client.POST('/api/v0/projects', { body: { organizationId, key, name } }),
      );
      this.announcement.set($localize`:@@projects.created:Project ${project.name}:name: created.`);
      await this.router.navigate(['/projects', project.id]);
    } catch (err) {
      const fields = fieldErrors(err);
      if (err instanceof ApiError && err.code === 'PROJECT_KEY_TAKEN') {
        this.keyError.set(problemMessage(err));
      } else if (fields['body.key'] !== undefined) {
        this.keyError.set(
          $localize`:@@projects.create.badKey:Use letters, digits and . _ - / : for the key.`,
        );
      }
      if (fields['body.name'] !== undefined) {
        this.nameError.set(
          $localize`:@@projects.create.badName:Enter a name of at most 255 characters, without control characters.`,
        );
      }
      if (!this.keyError() && !this.nameError()) this.createError.set(problemMessage(err));
      this.focusFirstInvalid();
    } finally {
      this.creating.set(false);
    }
  }

  private focusFirstInvalid(): void {
    if (this.keyError()) this.keyField()?.nativeElement.focus();
    else if (this.nameError()) this.nameField()?.nativeElement.focus();
  }
}
