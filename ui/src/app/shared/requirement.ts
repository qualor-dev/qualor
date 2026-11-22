import { Component, computed, inject, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { Icon } from './icon';
import type { ScmProvider } from './scm-provider';

/** Where a missing setting is changed: the settings page that holds it. */
export type RequirementPlace = 'ai-provider' | 'org-ai' | 'repositories' | ScmProvider;

/**
 * A place's page and its name as the navigation shows it. `opens` says whether the viewer can
 * open the page: instance admins the AI provider, organisation admins (by permission) the rest.
 * An organisation's page (`organization`) is the one of the organisation the header shows.
 */
interface Place {
  route: string;
  label: () => string;
  organization: boolean;
  opens: (session: SessionStore, org: OrgContext) => boolean;
}

/** Settings → Repositories, where each project's connection is chosen. */
const REPOSITORIES: Place = {
  route: '/settings/repositories',
  label: () => $localize`:@@requirement.repositories:Settings → Repositories`,
  organization: true,
  opens: (_, org) => org.can('org.scm.manage'),
};

const PLACES: Record<RequirementPlace, Place> = {
  'ai-provider': {
    route: '/settings/ai',
    label: () => $localize`:@@requirement.aiProvider:Settings → AI provider`,
    organization: false,
    opens: (session) => session.user()?.isInstanceAdmin === true,
  },
  'org-ai': {
    route: '/settings/ai-review',
    label: () => $localize`:@@requirement.orgAi:Settings → AI`,
    organization: true,
    opens: (_, org) => org.can('org.ai.manage'),
  },
  repositories: REPOSITORIES,
  gitlab: {
    route: '/settings/gitlab',
    label: () => $localize`:@@requirement.gitlab:Settings → GitLab`,
    organization: true,
    opens: (_, org) => org.can('org.scm.manage'),
  },
  github: {
    route: '/settings/github',
    label: () => $localize`:@@requirement.github:Settings → GitHub`,
    organization: true,
    opens: (_, org) => org.can('org.scm.manage'),
  },
  azure: REPOSITORIES, // azure-pending(2): Settings → Azure DevOps (Task 7)
};

/** A place as a viewer sees it: its page, its name, and whether it is a link for them. */
export interface PlaceView {
  route: string;
  label: string;
  link: boolean;
}

/**
 * A place for the viewer: a link when they can open its page, else its name only. A setting of a
 * named organisation (`organizationId`, a project's) is a link only while the header shows that
 * organisation: its pages are the header organisation's, so a link would open another one's.
 */
export function placeView(
  name: RequirementPlace,
  session: SessionStore,
  org: OrgContext,
  organizationId: string | null = null,
): PlaceView {
  const place = PLACES[name];
  const shown =
    !place.organization || organizationId === null || organizationId === org.currentId();
  return { route: place.route, label: place.label(), link: shown && place.opens(session, org) };
}

/**
 * `q-requirement` (spec §3.3, §7.5): why a control cannot work, in one sentence, directly above
 * the control it disables, which points at the note (`aria-describedby` = `noteId`). `text` names
 * what is missing and who changes it, and ends where the place goes: "Needs Suggest a fix for
 * Acme, which an instance admin turns on in" + " Settings → AI provider." The place is a link for
 * a viewer who can open it, else its name only; for a setting of another organisation than the
 * header's (`organizationId`), its name only. Without a place, `text` is the whole sentence.
 */
@Component({
  selector: 'q-requirement',
  imports: [Icon, RouterLink],
  templateUrl: './requirement.html',
  styleUrl: './requirement.css',
})
export class Requirement {
  private readonly session = inject(SessionStore);
  private readonly org = inject(OrgContext);

  readonly noteId = input.required<string>();
  readonly text = input.required<string>();
  readonly place = input<RequirementPlace | null>(null);
  /** The organisation the setting belongs to, when it is not simply the header's (a project's). */
  readonly organizationId = input<string | null>(null);

  protected readonly where = computed(() => {
    const name = this.place();
    return name === null ? null : placeView(name, this.session, this.org, this.organizationId());
  });
}
