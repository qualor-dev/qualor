/**
 * What `tools/deploy/screenshots.ts` seeds into the dockerized server (plan 1G), as the docker
 * screenshots read it from the JSON file named by QUALOR_DOCKER_SEED.
 */
export interface DockerSeed {
  qualor: { id: string; mergeRequestBranchId: string };
  fixtures: Record<'ts-basic' | 'java-basic' | 'mixed-secrets', { id: string; name: string }>;
}

export const DOCKER_STORAGE_STATE = '../.tmp/playwright/docker-admin.json';
