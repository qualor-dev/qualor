import { assertNever } from '@qualor/shared';
import type { ReviewJobDeps } from './job';
import {
  queueAzureAnswers,
  queueGitHubAnswers,
  queueGitLabAnswers,
  queueScanAfterCircuit,
  replyWindow,
  type ReplyWindow,
} from './reply-queue';
import {
  azureScanSide,
  githubScanSide,
  gitlabScanSide,
  GONE,
  orGone,
  providerClientOf,
  type Listing,
  type ScanSide,
} from './reply-sides';
import { CLOSED, JobSteps, targetOf, WAITING, type Target } from './reply-steps';

/*
 * The `ai-reply` job's scan (6I-4): the job a webhook queues for a merge request (routes/
 * gitlab-webhooks.ts), so that a reply in one of Qualor's threads, or a command, is answered at
 * once rather than at the next decoration. The webhook names a merge request and nothing else: the
 * scan reads its notes through the API, with a client of its own and its own request budget, and
 * queues what it finds as a decoration queues the notes it read (reply-queue.ts: the same
 * detection, the same ledger, so a note found by both is answered once).
 *
 * It does nothing for a branch that is not a merge request's, or one whose project has no AI
 * review active (the same window as decoration's), and nothing more for a merge request that is
 * merged or closed, which is read first, as the answer job reads it, through no organisation slot.
 * The requests pass the connection's circuit as the answer job's do (reply-steps.ts): a circuit
 * that does not let them through queues the scan again for when it reopens, with no try spent. A
 * merge request the provider no longer has ends the scan at info level, with the branch and none of
 * the provider's words. Any other error fails the job into its second try; after that, a later scan
 * or decoration finds the same notes. Nothing a person wrote is read here or logged: the job
 * reads the notes and hands them to the queue, which keeps only the ids and the author's name.
 */

/** What a scan finds of a merge request: its notes, or why there are none to read. */
type Found = Listing | typeof CLOSED | typeof GONE;

class ScanFlow extends JobSteps {
  constructor(
    deps: ReviewJobDeps,
    private readonly branchId: string,
    /** Whether this is the job's last try (its attempts are spent with it). */
    private readonly lastTry: boolean,
  ) {
    super(deps);
  }

  async run(): Promise<void> {
    try {
      await this.scan();
    } catch (err) {
      this.logFailure('AI reply scan', { branchId: this.branchId }, err, this.lastTry);
      throw err;
    }
  }

  private async scan(): Promise<void> {
    const { db, logger } = this.deps;
    const { branchId } = this;
    const target = await targetOf(db, branchId);
    if (target === null || target.branch.kind !== 'merge_request') {
      logger.debug?.({ branchId }, 'AI reply scan left a branch that is no merge request alone');
      return;
    }
    const window = await replyWindow(db, target.project, branchId);
    if (window === null) {
      logger.debug?.({ branchId }, 'AI reply scan left a project without AI review alone');
      return;
    }
    const side = this.sideOf(target);
    if (side === null) {
      logger.warn({ branchId }, 'AI reply scan: the SCM connection of the project cannot be used');
      return;
    }
    const { connectionId } = side;
    const found = await this.passCircuit(
      connectionId,
      async (waitSeconds) => {
        if (await queueScanAfterCircuit(db, branchId, waitSeconds)) {
          logger.info(
            { branchId, connectionId, retryInSeconds: waitSeconds },
            'AI reply scan waits for the circuit of its SCM connection',
          );
        }
      },
      () => this.read(target, side, window),
    );
    if (found === WAITING) return;
    if (found === CLOSED) {
      logger.debug?.({ branchId }, 'AI reply scan left a merge request that is not open alone');
      return;
    }
    if (found === GONE) {
      logger.info({ branchId }, 'AI reply scan: the merge request is gone from its provider');
      return;
    }
    const ids = { projectId: target.project.id, branchId };
    let queued: number;
    switch (found.provider) {
      case 'gitlab':
        queued = await queueGitLabAnswers(db, ids, window, found.botId, found.discussions);
        break;
      case 'github':
        queued = await queueGitHubAnswers(db, ids, window, found.login, found);
        break;
      case 'azure':
        queued = await queueAzureAnswers(db, ids, window, found.identityId, found.threads);
        break;
      default:
        return assertNever(found, 'provider');
    }
    if (queued > 0) logger.info({ branchId, queued }, 'AI reply scan queued answers');
  }

  /**
   * What the go reads: the merge request's state first, read as the review job reads it (CLOSED
   * when it is merged or closed; a state that cannot be read lets the job go on), then its notes.
   * A merge request the provider says it has none of is GONE, which the circuit hears as an answer.
   */
  private async read(target: Target, side: ScanSide, window: ReplyWindow): Promise<Found> {
    if (await this.closed({ projectId: target.project.id }, target)) return CLOSED;
    return orGone(() => side.list(window));
  }

  /**
   * The notes' side on the provider the project is mapped to now; null when its client cannot be
   * made (a key that no longer decrypts, an address the rules no longer allow) or the ids are none
   * of the provider's.
   */
  private sideOf(target: Target): ScanSide | null {
    const { connection } = target;
    const found = providerClientOf(this.deps, target);
    if (connection === null || found === null) return null;
    switch (found.provider) {
      case 'github':
        return githubScanSide(connection.id, found.client, found.repo, found.number);
      case 'gitlab':
        return gitlabScanSide(connection.id, found.client, found.ref, found.iid);
      case 'azure':
        return azureScanSide(connection.id, found.client, found.repositoryId, found.prId);
      default:
        return assertNever(found, 'provider');
    }
  }
}

/**
 * Scans the merge request of a branch for the replies and commands nobody has queued yet, as the
 * job of a webhook's delivery: queues their answers. `lastTry` says that a failure is the job's
 * last.
 */
export function scanMergeRequest(
  deps: ReviewJobDeps,
  branchId: string,
  lastTry: boolean,
): Promise<void> {
  return new ScanFlow(deps, branchId, lastTry).run();
}
