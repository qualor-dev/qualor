import { Component, computed, effect, inject, input, resource } from '@angular/core';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import {
  type ComplianceBranch,
  ComplianceReportsComponent,
  type ComplianceVersion,
} from '../compliance/compliance-reports.component';
import { SystemInfo } from '../shell/system-info';
import { CurrentProject } from './current-project';

/** The branches offered for a report: the first 500 (the API's largest page). */
const BRANCH_LIMIT = 500;
/** The versions offered: the first page (the API's largest). */
const VERSION_LIMIT = 100;

/**
 * A project's Compliance tab (4E-1 §4, feature `compliance-export`): its compliance reports, and
 * **Create report** of one of its branches or versions for a holder of
 * `project.compliance.create`. The tab is listed only while the feature is active; a direct address after a lapse says so instead of
 * asking the enterprise API.
 */
@Component({
  selector: 'q-project-compliance-page',
  imports: [ComplianceReportsComponent],
  templateUrl: './compliance.page.html',
})
export class ProjectCompliancePage {
  private readonly api = inject(Api);
  private readonly info = inject(SystemInfo);
  private readonly project = inject(CurrentProject);
  readonly projectId = input.required<string>();

  protected readonly licensed = computed(() => this.info.features().includes('compliance-export'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  /** A failed `GET /system/info`, shown instead of an empty page. */
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly scope = computed(() => ({ projectId: this.projectId() }));
  /** rbac-audit.md §17: the control shows once the project says the caller may use it. */
  protected readonly canCreate = computed(() =>
    this.project.canChange(this.projectId(), 'project.compliance.create'),
  );
  /** The project's branches (merge requests have no report), read only for those who create. */
  private readonly branchList = resource({
    params: () => (this.licensed() && this.canCreate() ? this.projectId() : undefined),
    loader: ({ params: id }) =>
      ok(
        this.api.client.GET('/api/v0/projects/{id}/branches', {
          params: { path: { id }, query: { kind: 'branch', limit: BRANCH_LIMIT } },
        }),
      ),
  });
  protected readonly branches = computed<ComplianceBranch[]>(() =>
    this.branchList.hasValue()
      ? this.branchList.value().items.map((b) => ({ id: b.id, name: b.name, isMain: b.isMain }))
      : [],
  );

  /** The project's versions, which a report can be made of (dependencies only). */
  private readonly versionList = resource({
    params: () => (this.licensed() && this.canCreate() ? this.projectId() : undefined),
    loader: ({ params: id }) =>
      ok(
        this.api.client.GET('/api/v0/projects/{id}/versions', {
          params: { path: { id }, query: { limit: VERSION_LIMIT } },
        }),
      ),
  });
  protected readonly versions = computed<ComplianceVersion[]>(() =>
    this.versionList.hasValue()
      ? this.versionList
          .value()
          .items.map((v) => ({ id: v.id, label: v.label, tracked: v.tracked }))
      : [],
  );

  constructor() {
    effect(() => this.project.use(this.projectId()));
  }
}
