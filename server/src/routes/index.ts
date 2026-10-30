import type { FastifyInstance } from 'fastify';
import type { RouteDeps } from '../app';
import { UploadSlots } from '../ingest/upload';
import { issueChangeCharge } from '../issues/rate-limit';
import { aiRoutes } from './ai';
import { analysisRoutes } from './analyses';
import { accountRoutes } from './account';
import { autoFixRoutes } from './auto-fix';
import { authRoutes } from './auth';
import { branchRoutes } from './branches';
import { dependencyRoutes } from './dependencies';
import { gateRoutes } from './gates';
import { githubWebhookRoutes } from './github-webhooks';
import { gitlabWebhookRoutes } from './gitlab-webhooks';
import { issueRoutes } from './issues';
import { issueStatusImportRoutes } from './issue-status-import';
import { licenseRoutes } from './license';
import { licensePolicyRoutes } from './license-policy';
import { llmSettingsRoutes } from './llm-settings';
import { mailSettingsRoutes } from './mail-settings';
import { mcpSettingsRoutes } from './mcp-settings';
import { oauthConsentRoutes } from './oauth';
import { measureRoutes } from './measures';
import { newCodeRoutes } from './newcode';
import { notificationRoutes, unsubscribeRoutes } from './notifications';
import { organizationRoutes } from './organizations';
import { profileRoutes } from './profiles';
import { projectMemberRoutes } from './project-members';
import { projectRoutes } from './projects';
import { reviewRoutes } from './review';
import { ruleRoutes } from './rules';
import { systemRoutes } from './system';
import { tokenRoutes } from './tokens';
import { userRoutes } from './users';
import { repositorySetupRoutes } from './repository-setup';
import { scmConnectionRoutes } from './scm-connections';
import { webhookRoutes } from './webhooks';

export async function registerRoutes(app: FastifyInstance, deps: RouteDeps): Promise<void> {
  // Ruling G7: one bound per app on the issue changes of a user, shared by the routes that
  // change issues or act on them (llm.md §8.2).
  const chargeIssueChanges = issueChangeCharge();
  // S11, 6I-2: one bound per app on the uploads read at once, the reports and the review
  // snapshots together (QUALOR_MAX_CONCURRENT_UPLOADS).
  const uploadSlots = new UploadSlots(deps.config.maxConcurrentUploads);
  await app.register(systemRoutes, { deps });
  await app.register(authRoutes, { prefix: '/api/v0', deps });
  await app.register(accountRoutes, { prefix: '/api/v0', deps });
  await app.register(userRoutes, { prefix: '/api/v0', deps });
  await app.register(tokenRoutes, { prefix: '/api/v0', deps });
  await app.register(notificationRoutes, { prefix: '/api/v0', deps });
  // Its own plugin: its body parsers (RFC 8058 forms, ignored) stay in its encapsulation context.
  await app.register(unsubscribeRoutes, { prefix: '/api/v0', deps });
  await app.register(organizationRoutes, { prefix: '/api/v0', deps });
  await app.register(projectRoutes, { prefix: '/api/v0', deps });
  await app.register(projectMemberRoutes, { prefix: '/api/v0', deps });
  await app.register(branchRoutes, { prefix: '/api/v0', deps });
  await app.register(analysisRoutes, { prefix: '/api/v0', deps, uploadSlots });
  await app.register(newCodeRoutes, { prefix: '/api/v0', deps });
  await app.register(measureRoutes, { prefix: '/api/v0', deps });
  await app.register(dependencyRoutes, { prefix: '/api/v0', deps });
  await app.register(gateRoutes, { prefix: '/api/v0', deps });
  await app.register(issueRoutes, { prefix: '/api/v0', deps, chargeIssueChanges });
  await app.register(issueStatusImportRoutes, { prefix: '/api/v0', deps });
  await app.register(ruleRoutes, { prefix: '/api/v0', deps });
  await app.register(profileRoutes, { prefix: '/api/v0', deps });
  await app.register(webhookRoutes, { prefix: '/api/v0', deps });
  await app.register(scmConnectionRoutes, { prefix: '/api/v0', deps });
  await app.register(repositorySetupRoutes, { prefix: '/api/v0', deps });
  await app.register(llmSettingsRoutes, { prefix: '/api/v0', deps });
  await app.register(mailSettingsRoutes, { prefix: '/api/v0', deps });
  await app.register(mcpSettingsRoutes, { prefix: '/api/v0', deps });
  await app.register(oauthConsentRoutes, { prefix: '/api/v0', deps });
  await app.register(licenseRoutes, { prefix: '/api/v0', deps });
  await app.register(aiRoutes, { prefix: '/api/v0', deps, chargeIssueChanges });
  await app.register(autoFixRoutes, { prefix: '/api/v0', deps });
  await app.register(reviewRoutes, { prefix: '/api/v0', deps, uploadSlots });
  await app.register(licensePolicyRoutes, { prefix: '/api/v0', deps });
  // Their own plugins: each one's raw-body JSON parser stays in its encapsulation context
  // (github.md §9).
  await app.register(githubWebhookRoutes, { deps });
  await app.register(gitlabWebhookRoutes, { deps });
}
