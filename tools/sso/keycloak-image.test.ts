import { describe, expect, it } from 'vitest';
import { KEYCLOAK_IMAGE } from './keycloak-image';

describe('the Keycloak image of the SSO tests (sso-scim.md §19.4)', () => {
  it('is pinned by tag and digest', () => {
    expect(KEYCLOAK_IMAGE).toMatch(
      /^quay\.io\/keycloak\/keycloak:\d+\.\d+\.\d+@sha256:[0-9a-f]{64}$/,
    );
    expect(KEYCLOAK_IMAGE).toContain('26.7.4@sha256:82a77884');
  });
});
