/**
 * The user guide built into the app: every `docs/guide/*.md` of the repository, bundled as text
 * (angular.json `loader`), one lazy chunk per page, so the server always shows the guide of its own
 * release. `ui/tools/docs.test.ts` checks that this list names every page of `docs/guide/`.
 */
const PAGES: Readonly<Record<string, () => Promise<{ default: string }>>> = {
  README: () => import('../../../../docs/guide/README.md'),
  'ai-assistant': () => import('../../../../docs/guide/ai-assistant.md'),
  'ai-prompts': () => import('../../../../docs/guide/ai-prompts.md'),
  cli: () => import('../../../../docs/guide/cli.md'),
  configuration: () => import('../../../../docs/guide/configuration.md'),
  // The guide's page about the enterprise edition (Markdown text), not the enterprise/ package.
  // eslint-disable-next-line no-restricted-syntax
  enterprise: () => import('../../../../docs/guide/enterprise.md'),
  github: () => import('../../../../docs/guide/github.md'),
  gitlab: () => import('../../../../docs/guide/gitlab.md'),
  'install-server': () => import('../../../../docs/guide/install-server.md'),
  'languages-and-analyzers': () => import('../../../../docs/guide/languages-and-analyzers.md'),
  'migrate-from-sonarqube': () => import('../../../../docs/guide/migrate-from-sonarqube.md'),
  'other-ci': () => import('../../../../docs/guide/other-ci.md'),
  'quality-gates': () => import('../../../../docs/guide/quality-gates.md'),
  'quick-start': () => import('../../../../docs/guide/quick-start.md'),
  'roles-and-audit': () => import('../../../../docs/guide/roles-and-audit.md'),
  'sso-and-scim': () => import('../../../../docs/guide/sso-and-scim.md'),
  telemetry: () => import('../../../../docs/guide/telemetry.md'),
  troubleshooting: () => import('../../../../docs/guide/troubleshooting.md'),
  'users-projects-tokens': () => import('../../../../docs/guide/users-projects-tokens.md'),
  'webhooks-and-api': () => import('../../../../docs/guide/webhooks-and-api.md'),
};

export interface GuideEntry {
  /** The file name without `.md`; README is the docs home. */
  page: string;
  /** The link text of the page in README's numbered list ("Overview" for README itself). */
  title: string;
}

/** The Markdown of a page, or null for a name the guide does not have. */
export async function loadGuidePage(page: string): Promise<string | null> {
  const load = Object.hasOwn(PAGES, page) ? PAGES[page] : undefined;
  return load === undefined ? null : (await load()).default;
}

/**
 * The navigation, as on qualor.dev: README first, then the pages of its numbered list in that
 * order, then any page the list does not name, by name.
 */
export function guideNavigation(readme: string, overview: string): GuideEntry[] {
  const entries: GuideEntry[] = [{ page: 'README', title: overview }];
  for (const m of readme.matchAll(/^\d+\.\s+\[([^\]]+)\]\(\.\/([\w.-]+)\.md\)/gm)) {
    const [, title = '', page = ''] = m;
    if (Object.hasOwn(PAGES, page) && !entries.some((e) => e.page === page)) {
      entries.push({ page, title: title.replace(/`/g, '') });
    }
  }
  for (const page of Object.keys(PAGES).sort()) {
    if (!entries.some((e) => e.page === page)) entries.push({ page, title: page });
  }
  return entries;
}
