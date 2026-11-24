import { Component, input } from '@angular/core';
import { Icon } from '../shared/icon';
import type { ItemState, Provider } from './repository-setup';

/**
 * `q-setup-badge`: a repository's state in a repository-setup run, as a badge with words and an
 * icon (never colour alone). The one in hand says what is being done: CI setup, or adding the
 * project when the run sets up no CI. An opened request is named in its provider's word: a merge
 * request on GitLab (and while the provider is not known), a pull request on GitHub and Azure DevOps.
 */
@Component({
  selector: 'q-setup-badge',
  imports: [Icon],
  templateUrl: './setup-badge.html',
})
export class SetupBadge {
  readonly state = input.required<ItemState>();
  /** Whether the run sets up CI: the working state says so. */
  readonly ciSetup = input(true);
  /** The run's provider, when known. */
  readonly provider = input<Provider | null>(null);
}
