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
import {
  type Connection,
  errorText,
  itemState,
  mergeRequestNumber,
  pathParts,
  type Provider,
  providerName,
  type RunItem,
} from './repository-setup';
import { SetupBadge } from './setup-badge';

/** The files a snippet goes into. */
const WORKFLOW_FILE = '.github/workflows/qualor.yml';
const GITLAB_CI_FILE = '.gitlab-ci.yml';

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
    return errorText(this.item(), connection ? providerName(connection) : null);
  });
  /**
   * The provider: the connection's, else told by the snippet (a GitHub workflow starts with its
   * name; GitLab's is an include or a job).
   */
  protected readonly provider = computed<Provider>(() => {
    const connection = this.connection();
    if (connection) return connection.provider;
    return /^name: /.test(this.item().snippet ?? '') ? 'github' : 'gitlab';
  });
  protected readonly file = computed(() =>
    this.provider() === 'github' ? WORKFLOW_FILE : GITLAB_CI_FILE,
  );
  protected readonly copyState = signal<'idle' | 'copied' | 'failed'>('idle');

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
      case 'missing_permissions':
        return $localize`:@@addRepos.reason.permissions:The connection may not change this repository's CI files and secrets, so Qualor did not change it.`;
      case 'empty_repository':
        return $localize`:@@addRepos.reason.empty:The repository has no commits yet, so Qualor did not change it.`;
      case 'custom_ci_path':
        return $localize`:@@addRepos.reason.customPath:The project reads its CI configuration from another file than .gitlab-ci.yml, so Qualor did not change it.`;
      case 'yaml_unsupported':
        return $localize`:@@addRepos.reason.yaml:Qualor cannot change this .gitlab-ci.yml safely (anchors, several documents or invalid YAML), so it did not change it.`;
      case 'no_public_url':
        return $localize`:@@addRepos.reason.noPublicUrl:Qualor needs its public address (QUALOR_PUBLIC_URL) to set up CI. Replace https://qualor.example.com in the file with this server's address.`;
      default:
        return $localize`:@@addRepos.reason.other:Qualor did not change the repository.`;
    }
  });

  protected readonly secretTitle = computed(() =>
    this.provider() === 'github'
      ? $localize`:@@addRepos.secret.github:Secret`
      : $localize`:@@addRepos.secret.gitlab:CI/CD variable`,
  );
  protected readonly secretIntro = computed(() =>
    this.provider() === 'github'
      ? $localize`:@@addRepos.secret.githubIntro:Add it to the repository's Actions secrets.`
      : $localize`:@@addRepos.secret.gitlabIntro:Add it to the project's CI/CD variables, masked.`,
  );
  protected readonly secretWhere = computed(() =>
    this.provider() === 'github'
      ? $localize`:@@addRepos.secret.githubWhere:On GitHub: the repository's Settings, then Secrets and variables, Actions, New repository secret.`
      : $localize`:@@addRepos.secret.gitlabWhere:On GitLab: the project's Settings, then CI/CD, Variables, Add variable. Add QUALOR_URL with this server's address too.`,
  );
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
