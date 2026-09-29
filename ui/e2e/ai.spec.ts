import type { Page } from '@playwright/test';
import { expect, expectAccessible, test } from './fixtures';
import { MERGE_REQUEST, PAYMENTS } from './seed-data';

/**
 * The AI assistant (llm.md §18) against the fake LLM and the fake GitLab that
 * `server/scripts/e2e/serve.ts` runs on 127.0.0.1: nothing here reaches a real model or GitLab.
 * The seed points the provider at the fake, enables the default organisation with every feature
 * and maps Payments API to the fake GitLab, whose merge request !42 adds the flagged `==` line.
 */

/** The key the fake LLM expects (fake-llm.ts), assembled at run time for the Gitleaks check. */
const FAKE_LLM_KEY = ['fake', 'llm', 'key', '0123456789'].join('-');
/** The eqeqeq issue: the fake explains it, calls it a true positive and fixes its `==`. */
const EQEQEQ_MESSAGE = "Expected '===' and instead saw '=='.";
/** The issue serve.ts answers as a hostile model would, with a false-positive triage. */
const HOSTILE_ISSUE_MESSAGE = "Assignment to function parameter 'amount'.";
/**
 * An answer comes from a queued job (the worker, the fake model, then the panel's next poll): on a
 * loaded machine that outlasts the default 5 s, so the first check after each ask waits longer.
 */
const ANSWER = { timeout: 30_000 };

async function openIssue(page: Page, message: string, mergeRequest = false): Promise<void> {
  await page.goto('/projects');
  await page.getByRole('link', { name: PAYMENTS.name }).click();
  await page.getByRole('link', { name: 'All open issues' }).click();
  if (mergeRequest) {
    await page
      .getByLabel('Branch')
      .selectOption({ label: `!${MERGE_REQUEST.id} ${MERGE_REQUEST.source} → main` });
    await expect(page).toHaveURL(/branch=/);
  }
  await page.getByRole('link', { name: message, exact: true }).click();
  await expect(page).toHaveTitle('Issue · Qualor');
}

test.describe('AI assistant (llm.md §18)', () => {
  test('an instance admin sets the key, which never comes back, and Test reaches the provider', async ({
    page,
  }) => {
    const answers: Promise<string>[] = [];
    page.on('response', (response) => {
      if (new URL(response.url()).pathname.startsWith('/api/v0/system/llm')) {
        answers.push(response.text().catch(() => ''));
      }
    });
    await page.goto('/settings/ai');
    await expect(page).toHaveTitle(/AI assistant/);
    await expect(page.getByRole('heading', { name: 'AI assistant', level: 2 })).toBeVisible();
    await expect(page.getByText('On for 1 organisation', { exact: true })).toBeVisible();
    // The seed pointed it at the fake LLM on loopback, never at a real host.
    await expect(page.getByLabel('Base URL')).toHaveValue(/^http:\/\/127\.0\.0\.1:\d+\/v1$/);
    await expect(page.getByText('An API key is set')).toBeVisible();
    await expect(page.locator('#ai-key')).toHaveValue('');
    await expectAccessible(page);

    // The admin types the key again and saves: the field is emptied, the key never shown again.
    await page.locator('#ai-key').fill(FAKE_LLM_KEY);
    await page.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status')).toHaveText('The AI assistant settings were saved.');
    await expect(page.locator('#ai-key')).toHaveValue('');
    await page.reload();
    await expect(page.getByText('An API key is set')).toBeVisible();
    await expect(page.locator('#ai-key')).toHaveValue('');
    expect(await page.content()).not.toContain(FAKE_LLM_KEY);
    expect(page.url()).not.toContain(FAKE_LLM_KEY);
    const stored = await page.evaluate(() =>
      JSON.stringify([{ ...localStorage }, { ...sessionStorage }, document.cookie]),
    );
    expect(stored).not.toContain(FAKE_LLM_KEY);

    await page.getByRole('button', { name: 'Test' }).click();
    await expect(page.getByRole('status')).toContainText(
      /^Connected to fake-openai-model in \d+ ms\.$/,
    );
    await expectAccessible(page);
    // No answer of the settings API (the save's included) carried the key.
    const bodies = await Promise.all(answers);
    expect(bodies.length).toBeGreaterThanOrEqual(3);
    for (const body of bodies) expect(body).not.toContain(FAKE_LLM_KEY);
  });

  test('explain, triage and a fix preview, posted to the merge request after a confirmation', async ({
    page,
  }) => {
    await openIssue(page, EQEQEQ_MESSAGE, true);
    const panel = page.getByRole('region', { name: 'AI assistant' });
    // Nothing is sent before a click; the notice names the fake's host and the model.
    await expect(panel).toContainText('code around the issue');
    await expect(panel).toContainText(/127\.0\.0\.1:\d+ \(fake-model\)/);

    await panel.getByRole('button', { name: 'Explain' }).click();
    await expect(panel.getByText('Loose equality compares after type coercion.')).toBeVisible(
      ANSWER,
    );
    await expect(panel.getByText('AI-generated, may be wrong').first()).toBeVisible();

    await panel.getByRole('button', { name: 'Suggest triage' }).click();
    await expect(panel.getByText('Likely a true positive')).toBeVisible(ANSWER);
    await expect(panel.getByRole('button', { name: 'Mark as false positive…' })).toHaveCount(0);

    await panel.getByRole('button', { name: 'Suggest a fix' }).click();
    await expect(page.locator('#ai-fix-before')).toContainText(
      'if (order.currency == "EUR") {',
      ANSWER,
    );
    await expect(page.locator('#ai-fix-after')).toContainText('if (order.currency === "EUR") {');
    await expectAccessible(page);

    // Two steps: the first click only asks; Cancel posts nothing.
    await panel.getByRole('button', { name: 'Post to merge request' }).click();
    // The confirmation names the merge request of the issue's branch.
    await expect(panel).toContainText(
      `Post this suggestion as a comment on merge request !${MERGE_REQUEST.id}`,
    );
    await panel.getByRole('button', { name: 'Cancel' }).click();
    await expect(panel.getByRole('button', { name: 'Confirm: post as a suggestion' })).toHaveCount(
      0,
    );
    await panel.getByRole('button', { name: 'Post to merge request' }).click();
    await expectAccessible(page);
    await panel.getByRole('button', { name: 'Confirm: post as a suggestion' }).click();
    // The scm worker posts it to the fake GitLab; the panel follows the queued post.
    await expect(panel.getByText('Posted', { exact: true })).toBeVisible({ timeout: 30_000 });
    // The link to the posted comment, on the fake GitLab's merge request.
    await expect(panel.getByRole('link', { name: 'See it on the merge request' })).toHaveAttribute(
      'href',
      new RegExp(
        `^http://127\\.0\\.0\\.1:\\d+/${PAYMENTS.key}/-/merge_requests/${MERGE_REQUEST.id}#note_\\d+$`,
      ),
    );
    await expect(panel.getByRole('button', { name: 'Post to merge request' })).toHaveCount(0);
    await expect(panel.locator('.alert-error')).toHaveCount(0);
  });

  test('a hostile answer stays inert text; a false-positive triage is the person’s decision', async ({
    page,
  }) => {
    await openIssue(page, HOSTILE_ISSUE_MESSAGE);
    const panel = page.getByRole('region', { name: 'AI assistant' });
    await panel.getByRole('button', { name: 'Explain' }).click();
    // HTML, a link, Markdown and a fence of the model's: shown as the characters they are.
    await expect(panel).toContainText(
      'Hostile <img src=x onerror="alert(1)"> <a href="https://evil.example/">click me</a>',
      ANSWER,
    );
    await expect(panel).toContainText('See [the docs](https://evil.example/docs)');
    await expect(panel).toContainText('</p><script>alert(2)</script>');
    await expect(panel).toContainText('<b>Bold</b> <iframe src="https://evil.example/"></iframe>');
    await expect(panel).toContainText('**not bold**');
    await expect(panel.locator('a, img, iframe, script')).toHaveCount(0);
    await expect(panel.locator('.ai-text *')).toHaveCount(0);
    // The bidi override is gone before the text is stored (llm.md §9.4).
    expect(await panel.textContent()).not.toContain('\u202E');
    await expectAccessible(page);

    await panel.getByRole('button', { name: 'Suggest triage' }).click();
    await expect(panel.getByText('Likely a false positive')).toBeVisible(ANSWER);
    await expect(panel).toContainText('The parameter is a local copy <em>on purpose</em>.');
    await expect(panel.locator('a, img, iframe, script')).toHaveCount(0);
    await expect(panel.locator('.ai-text *')).toHaveCount(0);
    await expectAccessible(page);

    // The suggestion changes nothing: the person writes the comment and presses the button.
    await panel.getByRole('button', { name: 'Mark as false positive…' }).click();
    const comment = page.getByLabel('Comment');
    await expect(comment).toBeFocused();
    await expect(comment).toHaveValue('');
    await expect(page.getByText('Pressing False positive also records')).toBeVisible();
    await expect(page.getByRole('button', { name: 'False positive', exact: true })).toBeDisabled();
    await comment.fill('The copy is on purpose; checked by hand.');
    await page.getByRole('button', { name: 'False positive', exact: true }).click();
    const change = page.getByRole('region', { name: 'Change' });
    await expect(change.getByRole('status')).toHaveText('Status changed to False positive.');
    const history = page.getByRole('region', { name: 'History' });
    await expect(history).toContainText('Status: Open → False positive');
    await expect(history).toContainText('The copy is on purpose; checked by hand.');
    await expect(history).toContainText(/AI triage suggestion \S+ \(likely_false_positive, high/);
    await expect(history).toContainText("the decision is admin's");

    // Leave the shared e2e database as the seed made it.
    await page.getByRole('button', { name: 'Reopen' }).click();
    await expect(history).toContainText('Status: False positive → Open');
  });
});
