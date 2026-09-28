import { inject } from '@angular/core';
import { type CanActivateFn, Router, UrlTree } from '@angular/router';
import type { Me } from '../api/types';
import { AuthService } from './auth.service';

const HOME = '/projects';
const PROBE_ORIGIN = 'https://qualor.invalid';
/** A backslash (read as `/` by browsers) or a C0/DEL control character (tabs and newlines are dropped). */
// eslint-disable-next-line no-control-regex
const UNSAFE_CHARACTER = /[\\\u0000-\u001f\u007f]/;

/**
 * Only a path of this app (path, query, fragment): never `//host` or `/\host`, which a browser
 * reads as another host, nor anything with a backslash or a control character (`/\t/host`
 * becomes `//host` once the browser drops the tab). What is left must resolve to this origin.
 *
 * Only safe as the argument of `router.navigateByUrl()`, which stays inside the app. Never pass
 * the result to `location.href`, `window.open`, an `href` or a server redirect.
 */
export function safeReturnUrl(url: string | null | undefined): string {
  if (!url || !url.startsWith('/') || url.startsWith('//') || UNSAFE_CHARACTER.test(url)) {
    return HOME;
  }
  return new URL(url, PROBE_ORIGIN).origin === PROBE_ORIGIN ? url : HOME;
}

/**
 * The session, or the retry page when the server cannot say (network error, 5xx): an unreachable
 * server is not a signed-out user. Nothing is cached then, so "Try again" asks the server again.
 */
async function loadSession(url: string): Promise<Me | null | UrlTree> {
  const router = inject(Router);
  try {
    return await inject(AuthService).ensureLoaded();
  } catch {
    return router.createUrlTree(['/unavailable'], { queryParams: { returnUrl: url } });
  }
}

/** Signed in, and not required to change the password first (ruling R7). */
export const requireUser: CanActivateFn = async (_route, state) => {
  const router = inject(Router);
  const me = await loadSession(state.url);
  if (me instanceof UrlTree) return me;
  if (!me) return router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
  if (me.user.passwordChangeRequired) return router.createUrlTree(['/change-password']);
  return true;
};

/** Signed in, whatever the password state (the password change page). */
export const requireSession: CanActivateFn = async (_route, state) => {
  const router = inject(Router);
  const me = await loadSession(state.url);
  if (me instanceof UrlTree) return me;
  return me ? true : router.createUrlTree(['/login'], { queryParams: { returnUrl: state.url } });
};

/**
 * Signed out (the login page); a signed-in user goes to the projects. A failed single sign-on
 * link (sso-scim.md §7.7, §8.2) also ends at `/login?sso_error=<code>`, in a browser that is still
 * signed in: that user goes to Settings → Linked accounts, which shows the code's fixed message.
 */
export const requireGuest: CanActivateFn = async (route, state) => {
  const router = inject(Router);
  const me = await loadSession(state.url);
  if (me instanceof UrlTree) return me;
  if (!me) return true;
  const ssoError = route.queryParamMap.get('sso_error');
  return ssoError
    ? router.createUrlTree(['/settings/ee/linked-accounts'], {
        queryParams: { sso_error: ssoError },
      })
    : router.createUrlTree(['/projects']);
};
