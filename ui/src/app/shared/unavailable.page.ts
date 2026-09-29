import { Component, inject, input } from '@angular/core';
import { Router } from '@angular/router';
import { safeReturnUrl } from '../auth/guards';
import { AuthLayout } from './auth-layout';

/** The server could not say who is signed in (network error, 5xx): a retry, not a sign-in page. */
@Component({
  selector: 'q-unavailable-page',
  imports: [AuthLayout],
  templateUrl: './unavailable.page.html',
})
export class UnavailablePage {
  private readonly router = inject(Router);

  /** `?returnUrl=` (router input binding): the page the user was opening. */
  readonly returnUrl = input<string>();

  protected retry(): void {
    void this.router.navigateByUrl(safeReturnUrl(this.returnUrl()));
  }
}
