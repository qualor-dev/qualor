import type { FastifyInstance } from 'fastify';
import type { RouteDeps } from '../app';
import { issueChangeCharge } from '../issues/rate-limit';
import { aiRoutes } from './ai';
import { analysisRoutes } from './analyses';
import { authRoutes } from './auth';
import { branchRoutes } from './branches';
import { gateRoutes } from './gates';
import { githubWebhookRoutes } from './github-webhooks';
import { issueRoutes } from './issues';
import { issueStatusImportRoutes } from './issue-status-import';
import { licenseRoutes } from './license';
import { llmSettingsRoutes } from './llm-settings';
import { measureRoutes } from './measures';
import { newCodeRoutes } from './newcode';
import { organizationRoutes } from './organizations';
import { profileRoutes } from './profiles';
import { projectMemberRoutes } from './project-members';
import { projectRoutes } from './projects';
import { ruleRoutes } from './rules';
import { systemRoutes } from './system';
import { tokenRoutes } from './tokens';
import { userRoutes } from './users';
import { scmConnectionRoutes } from './scm-connections';
import { webhookRoutes } from './webhooks';

export async function registerRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  // Ruling G7: one bound per app on the issue changes of a user, shared by the routes that
  // change issues or act on them (llm.md §8.2).
  const chargeIssueChanges = issueChangeCharge();
  await app.register(systemRoutes, { deps });
  await app.register(authRoutes, { prefix: '/api/v0', deps });
  await app.register(userRoutes, { prefix: '/api/v0', deps });
  await app.register(tokenRoutes, { prefix: '/api/v0', deps });
  await app.register(organizationRoutes, { prefix: '/api/v0', deps });
  await app.register(projectRoutes, { prefix: '/api/v0', deps });
  await app.register(projectMemberRoutes, { prefix: '/api/v0', deps });
  await app.register(branchRoutes, { prefix: '/api/v0', deps });
  await app.register(analysisRoutes, { prefix: '/api/v0', deps });
  await app.register(newCodeRoutes, { prefix: '/api/v0', deps });
  await app.register(measureRoutes, { prefix: '/api/v0', deps });
  await app.register(gateRoutes, { prefix: '/api/v0', deps });
  await app.register(issueRoutes, { prefix: '/api/v0', deps, chargeIssueChanges });
  await app.register(issueStatusImportRoutes, { prefix: '/api/v0', deps });
  await app.register(ruleRoutes, { prefix: '/api/v0', deps });
  await app.register(profileRoutes, { prefix: '/api/v0', deps });
  await app.register(webhookRoutes, { prefix: '/api/v0', deps });
  await app.register(scmConnectionRoutes, { prefix: '/api/v0', deps });
  await app.register(llmSettingsRoutes, { prefix: '/api/v0', deps });
  await app.register(licenseRoutes, { prefix: '/api/v0', deps });
  await app.register(aiRoutes, { prefix: '/api/v0', deps, chargeIssueChanges });
  // Its own plugin: its raw-body JSON parser stays in its encapsulation context (github.md §9).
  await app.register(githubWebhookRoutes, { deps });
}
