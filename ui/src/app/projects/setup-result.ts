import { NgTemplateOutlet } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  type ElementRef,
  inject,
  Injector,
  input,
  output,
  signal,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { SecretOnce } from '../settings/secret-once';
import { Icon } from '../shared/icon';
import { safeHelpUri } from '../shared/links';
import { assertNever } from '../shared/scm-provider';
import {
  type Connection,
  errorText,
  itemState,
  mergeRequestNumber,
  pathParts,
  type Provider,
  type RunItem,
} from './repository-setup';
import { SetupBadge } from './setup-badge';

/** The files a snippet goes into. */
const WORKFLOW_FILE = '.github/workflows/qualor.yml';
const GITLAB_CI_FILE = '.gitlab-ci.yml';
const AZURE_PIPELINE_FILE = '.azure-pipelines/qualor.yml';
/** The name of the secret or CI/CD variable the token goes into: a name, not text to translate. */
const SECRET_NAME = 'QUALOR_TOKEN';

/**
 * The provider a snippet is for, told by its first line; null for any other text. It mirrors the
 * snippets of server/src/onboarding/ci-templates.ts: GitHub's workflow starts `name: qualor`,
 * GitLab's start `include:` or `qualor:`, Azure Pipelines' starts `# Qualor in Azure Pipelines`.
 */
export function providerOfSnippet(snippet: string): Provider | null {
  if (/^name: /.test(snippet)) return 'github';
  if (/^(include|qualor):/.test(snippet)) return 'gitlab';
  if (/^# Qualor in Azure Pipelines/.test(snippet)) return 'azure';
  return null;
}

/** The reason of a snippet whose provider is not known. */
const otherReason = (): string =>
  $localize`:@@addRepos.reason.other:Qualor did not change the repository.`;

/** Where the address goes without a public URL: in GitHub's file, a variable on GitLab. */
function noPublicUrlText(provider: Provider | null): string {
  if (provider === null) return otherReason();
  switch (provider) {
    case 'github':
      return $localize`:@@addRepos.reason.noPublicUrlGithub:Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI. Replace https://qualor.example.com in the file with this server's address.`;
    case 'gitlab':
      return $localize`:@@addRepos.reason.noPublicUrlGitlab:Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI. Set the CI/CD variable QUALOR_URL to this server's address.`;
    case 'azure':
      return $localize`:@@addRepos.reason.noPublicUrlAzure:Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI. Set the pipeline variable QUALOR_URL to this server's address.`;
    default:
      return assertNever(provider, 'provider');
  }
}

/** The token's texts while its provider is not known: none. */
const NO_SECRET_TEXT = { title: '', intro: '', where: '' };

/** What the token is called, and where it goes, for a provider (nothing while it is unknown). */
function secretText(provider: Provider | null): { title: string; intro: string; where: string } {
  if (provider === null) return NO_SECRET_TEXT;
  switch (provider) {
    case 'github':
      return {
        title: $localize`:@@addRepos.secret.github:Secret`,
        intro: $localize`:@@addRepos.secret.githubIntro:Add it to the repository's Actions secrets.`,
        where: $localize`:@@addRepos.secret.githubWhere:On GitHub: the repository's Settings, then Secrets and variables, Actions, New repository secret.`,
      };
    case 'gitlab':
      return {
        title: $localize`:@@addRepos.secret.gitlab:CI/CD variable`,
        intro: $localize`:@@addRepos.secret.gitlabIntro:Add it to the project's CI/CD variables, masked.`,
        where: $localize`:@@addRepos.secret.gitlabWhere:On GitLab: the project's Settings, then CI/CD, Variables, Add variable. Add QUALOR_URL with this server's address too.`,
      };
    case 'azure':
      return {
        title: $localize`:@@addRepos.secret.azure:Secret variable`,
        intro: $localize`:@@addRepos.secret.azureIntro:Add it to the pipeline's variables, as a secret.`,
        where: $localize`:@@addRepos.secret.azureWhere:On Azure DevOps: the pipeline, Edit, Variables, New variable, with Keep this value secret ticked. Add QUALOR_URL with this server's address too.`,
      };
    default:
      return assertNever(provider, 'provider');
  }
}

/**
 * `q-setup-result`: what a finished repository-setup run did for one repository, as an article
 * labelled by its path. A merge request links to the provider; a snippet shows why, the token
 * once (`q-secret-once`) with where it goes, and the file with **Copy**; without the token (it is
 * shown only once) it points to the project's token settings. A failure says why, in the page's
 * words, and **Try again** asks for a new run of this repository.
 */
@Component({
  selector: 'q-setup-result',
  imports: [Icon, NgTemplateOutlet, RouterLink, SecretOnce, SetupBadge],
  templateUrl: './setup-result.html',
  styleUrl: './setup-result.css',
})
export class SetupResult {
  readonly item = input.required<RunItem>();
  /** Its place in the run: the ids of its heading, token field and file. */
  readonly index = input.required<number>();
  /** The run's connection, when known: the provider's name and where the snippet goes. */
  readonly connection = input<Connection | null>(null);
  /** The token the run revealed for it, kept by the page; null once it is gone. */
  readonly token = input<string | null>(null);
  /** GitHub called it C#: the build command of the merge request wants a look. */
  readonly csharp = input(false);
  /** **Try again** is offered (the run's connection is known), and whether a retry is on its way. */
  readonly canRetry = input(false);
  readonly retrying = input(false);
  /**
   * Other repositories of the run hold one-time tokens the person has not copied: **Try again**
   * asks first, inline, whether to go on or stay and copy them.
   */
  readonly askBeforeRetry = input(false);
  readonly retry = output();
  /** The token was copied: with Copy, or from its field. */
  readonly tokenCopied = output();
  private readonly injector = inject(Injector);
  /** **Try again** waits for the person's answer to the question about uncopied tokens. */
  protected readonly asking = signal(false);
  private readonly question = viewChild<ElementRef<HTMLElement>>('question');
  private readonly retryButton = viewChild<ElementRef<HTMLElement>>('retryButton');

  protected readonly state = computed(() => itemState(this.item(), null));
  protected readonly parts = computed(() => pathParts(this.item().name));
  protected readonly link = computed(() => safeHelpUri(this.item().ciUrl));
  protected readonly number = computed(() => {
    const url = this.item().ciUrl;
    return url ? mergeRequestNumber(url) : null;
  });
  protected readonly error = computed(() => {
    const connection = this.connection();
    return errorText(this.item(), connection);
  });
  /**
   * The provider: the connection's, else told by the snippet (a GitHub workflow starts with its
   * name; GitLab's is an include or a job); null when neither says.
   */
  protected readonly provider = computed<Provider | null>(() => {
    const connection = this.connection();
    if (connection) return connection.provider;
    return providerOfSnippet(this.item().snippet ?? '');
  });
  protected readonly file = computed(() => {
    const provider = this.provider();
    if (provider === null) return '';
    switch (provider) {
      case 'github':
        return WORKFLOW_FILE;
      case 'gitlab':
        return GITLAB_CI_FILE;
      case 'azure':
        return AZURE_PIPELINE_FILE;
      default:
        return assertNever(provider, 'provider');
    }
  });
  /** Qualor made no token for it: a pipeline of someone else owns the file. */
  protected readonly noToken = computed(() => this.item().ciReason === 'foreign_pipeline');
  /** What Qualor made on Azure DevOps outside the pull request, as lines of text. */
  protected readonly azureLines = computed(() => azureLines(this.item().azure));
  protected readonly pipelineLink = computed(() =>
    safeHelpUri(this.item().azure?.pipelineUrl ?? null),
  );
  protected readonly copyState = signal<'idle' | 'copied' | 'failed'>('idle');
  protected readonly secretName = SECRET_NAME;

  /** Why the repository got a snippet rather than a merge request, in one sentence. */
  protected readonly reason = computed(() => {
    const item = this.item();
    if (item.ciOutcome === 'skipped') {
      return $localize`:@@addRepos.reason.skipped:This run did not set up CI. Add the job and the token to the repository to run the first analysis.`;
    }
    switch (item.ciReason) {
      case 'already_set_up':
        return $localize`:@@addRepos.reason.already:The repository already has a Qualor job or a QUALOR_TOKEN secret, so Qualor did not change it.`;
      case 'not_allowed':
        return $localize`:@@addRepos.reason.notAllowed:CI setup is off for this connection, so Qualor did not change the repository.`;
      case 'foreign_pipeline':
        return $localize`:@@addRepos.reason.foreignPipeline:A pipeline that Qualor did not create already uses .azure-pipelines/qualor.yml, so Qualor wrote nothing and made no token. Rename that pipeline's file or delete the pipeline, or copy the job below into a file of your own.`;
      case 'missing_permissions':
        return $localize`:@@addRepos.reason.permissions:The connection may not change this repository's CI files and secrets, so Qualor did not change it.`;
      case 'empty_repository':
        return $localize`:@@addRepos.reason.empty:The repository has no commits yet, so Qualor did not change it.`;
      case 'custom_ci_path':
        return $localize`:@@addRepos.reason.customPath:The project reads its CI configuration from another file than .gitlab-ci.yml, so Qualor did not change it.`;
      case 'yaml_unsupported':
        return $localize`:@@addRepos.reason.yaml:Qualor cannot change this .gitlab-ci.yml safely (anchors, several documents or invalid YAML), so it did not change it.`;
      // The address is in GitHub's workflow file; GitLab's job reads it from a CI/CD variable.
      case 'no_public_url':
        return noPublicUrlText(this.provider());
      default:
        return otherReason();
    }
  });

  protected readonly secretTitle = computed(() => secretText(this.provider()).title);
  protected readonly secretIntro = computed(() => secretText(this.provider()).intro);
  protected readonly secretWhere = computed(() => secretText(this.provider()).where);
  protected readonly tokenLabel = computed(
    () => $localize`:@@addRepos.secret.label:Token for ${this.item().name}:repository:`,
  );

  /** **Try again**: at once, or after asking while other tokens of the run are not copied. */
  protected tryAgain(): void {
    if (this.retrying()) return;
    if (!this.askBeforeRetry()) {
      this.retry.emit();
      return;
    }
    this.asking.set(true);
    afterNextRender(() => this.question()?.nativeElement.focus(), { injector: this.injector });
  }

  protected goOn(): void {
    this.asking.set(false);
    this.retry.emit();
  }

  /** Stay: the question goes, and focus is back on **Try again**. */
  protected stay(): void {
    this.asking.set(false);
    afterNextRender(() => this.retryButton()?.nativeElement.focus(), { injector: this.injector });
  }

  protected async copySnippet(): Promise<void> {
    try {
      await navigator.clipboard.writeText(this.item().snippet ?? '');
      this.copyState.set('copied');
    } catch {
      // No Clipboard API (an insecure context) or permission refused: the file stays selectable.
      this.copyState.set('failed');
    }
  }
}

/** The pool and policy lines of an Azure DevOps setup, each in the page's words. */
function azureLines(azure: RunItem['azure']): string[] {
  if (azure === null) return [];
  const lines: string[] = [];
  switch (azure.queue) {
    case 'authorized':
      lines.push(
        $localize`:@@addRepos.azure.queueAuthorized:Qualor authorised the pipeline to use its agent pool.`,
      );
      break;
    case 'open':
      lines.push($localize`:@@addRepos.azure.queueOpen:The agent pool is open to every pipeline.`);
      break;
    case 'manual':
      lines.push(
        $localize`:@@addRepos.azure.queueManual:Approve the pipeline for its agent pool: Azure DevOps asks for it before the first run, and Qualor's identity may not do it.`,
      );
      break;
    case null:
      break;
    default:
      return assertNever(azure.queue, 'queue');
  }
  switch (azure.policy) {
    case 'pending':
      lines.push(
        $localize`:@@addRepos.azure.policyPending:The pull request check starts after the first analysis of the main branch.`,
      );
      break;
    case 'on':
      lines.push($localize`:@@addRepos.azure.policyOn:The pull request check is on.`);
      break;
    case 'manual':
      lines.push(
        $localize`:@@addRepos.azure.policyManual:Add the Build validation policy to the main branch yourself: Qualor's identity may not edit policies.`,
      );
      break;
    case 'failed':
      lines.push(
        $localize`:@@addRepos.azure.policyFailed:Qualor could not add the pull request check. Add the Build validation policy to the main branch yourself.`,
      );
      break;
    case null:
      break;
    default:
      return assertNever(azure.policy, 'policy');
  }
  return lines;
}
