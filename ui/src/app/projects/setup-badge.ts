import { Component, input } from '@angular/core';
import { Icon } from '../shared/icon';
import type { ItemState } from './repository-setup';

/**
 * `q-setup-badge`: a repository's state in a repository-setup run, as a badge with words and an
 * icon (never colour alone). The one in hand says what is being done: CI setup, or adding the
 * project when the run sets up no CI.
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
}
