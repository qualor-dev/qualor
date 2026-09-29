import { Component, input } from '@angular/core';

/**
 * The pages outside the shell (spec §7.9: sign in, change password, server unavailable): the ink
 * panel with the lens mark, the tagline and an illustration beside the page's card, which the page
 * projects. On a phone the panel is a band of ink above the card, its words on flat ink and the
 * illustration faded in at the right, so the words stay legible and the form is in the first
 * screen.
 */
@Component({
  selector: 'q-auth-layout',
  templateUrl: './auth-layout.html',
})
export class AuthLayout {
  /** The illustration: the lens over its scan lines, or the two servers of "unavailable". */
  readonly art = input<'signin' | 'offline'>('signin');
}
