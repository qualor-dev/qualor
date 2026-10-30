import { Component, input, output } from '@angular/core';
import { RouterLink } from '@angular/router';
import type { ResponseBody } from '../api/types';

export type Checklist = ResponseBody<'/api/v0/organizations/{id}/setup-checklist', 'get'>;
export type ChecklistStep = Checklist['steps'][number];
export type StepId = ChecklistStep['id'];

/** A step as the list draws it. */
export interface StepView {
  id: StepId;
  name: string;
  done: boolean;
  /** Not counted: the AI step when only the server admin can make it possible. */
  waiting: boolean;
  /** The first counted step not done yet. */
  next: boolean;
  /** Done since this browser last saw the checklist: its tick draws itself once. */
  justDone: boolean;
  /** Where the step is done; null once it is done, or while it waits for the server admin. */
  link: string | null;
  hint: ChecklistStep['hint'];
  /** "Done:", "To do:" or "Not counted:", for screen readers: the state is never colour only. */
  state: string;
}

/**
 * The setup checklist's steps (onboarding notes, Layout): a ring per step, filled in the lens's
 * blue with a check when done (green with the rest at "All set"), dashed while the step is not
 * counted. An open step is a link to where it is done, the whole row its target; done steps are
 * text. Step 1 also offers GitLab and step 2 the SonarQube import.
 */
@Component({
  selector: 'q-setup-steps',
  imports: [RouterLink],
  templateUrl: './setup-steps.html',
  styleUrl: './setup-steps.css',
  host: { '[class.all-set]': 'allSet()' },
})
export class SetupSteps {
  readonly steps = input.required<readonly StepView[]>();
  readonly allSet = input(false);
  /** A link in the list was followed. */
  readonly followed = output();
}
