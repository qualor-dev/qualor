import { ApiError, problemMessage } from '../api/errors';
import type { ItemOf, ResponseBody } from '../api/types';

type MailSettings = ResponseBody<'/api/v0/system/mail', 'get'>;
export type Security = NonNullable<MailSettings['server']>['security'];
export type MailMessage = ItemOf<'/api/v0/system/mail/messages'>;

/** The form's fields a refusal can point at; each is the input `#email-<field>`. */
export const FIELDS = [
  'host',
  'port',
  'username',
  'password',
  'from-name',
  'from-address',
  'reply-to',
  'test-to',
] as const;
export type Field = (typeof FIELDS)[number];

/** A refusal of the email routes in the page's own words (plan 1F ruling Y3). */
export function mailProblemText(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'MAIL_NOT_CONFIGURED':
        return $localize`:@@email.problem.notConfigured:Save an SMTP server before sending a test message.`;
      case 'MAIL_SET_BY_ENVIRONMENT':
        return $localize`:@@email.problem.environment:The SMTP server is set by QUALOR_SMTP_URL, so it cannot be changed here.`;
      case 'MAIL_SEND_FAILED':
        return sendFailureText(err.problem?.reason ?? null);
    }
  }
  return problemMessage(err);
}

/** Why a test message was not sent, from the problem's `reason` (the server's MailErrorCode). */
export function sendFailureText(reason: string | null): string {
  switch (reason) {
    case 'connection':
      return $localize`:@@email.failure.connection:The SMTP server could not be reached, or the TLS connection to it failed.`;
    case 'auth':
      return $localize`:@@email.failure.auth:The SMTP server refused the user name or password.`;
    case 'rejected':
      return $localize`:@@email.failure.rejected:The SMTP server refused the message.`;
    case 'timeout':
      return $localize`:@@email.failure.timeout:The SMTP server did not answer in time.`;
    case 'config':
      return $localize`:@@email.failure.config:The stored SMTP password can no longer be read. Enter it again.`;
    default:
      return $localize`:@@email.failure.other:The message was not sent.`;
  }
}

export function securityHint(security: Security): string {
  switch (security) {
    case 'starttls':
      return $localize`:@@email.security.starttlsHint:Usually port 587. The connection switches to TLS; Qualor does not send if the server does not offer it.`;
    case 'tls':
      return $localize`:@@email.security.tlsHint:Usually port 465. TLS from the first byte.`;
    case 'none':
      return $localize`:@@email.security.noneHint:No encryption, usually port 25: only for a relay on your own network.`;
  }
}

export function fieldRefusal(field: Field): string {
  switch (field) {
    case 'host':
      return $localize`:@@email.refused.host:Enter a host name or an IP address.`;
    case 'port':
      return $localize`:@@email.refused.port:Enter a port from 1 to 65535.`;
    case 'username':
      return $localize`:@@email.refused.username:Enter the user name on one line, at most 256 characters.`;
    case 'password':
      return $localize`:@@email.refused.password:Enter the password on one line, at most 1024 characters.`;
    case 'from-name':
      return $localize`:@@email.refused.fromName:Enter the sender's name on one line, at most 100 characters.`;
    case 'from-address':
      return $localize`:@@email.refused.fromAddress:Enter the sender's email address.`;
    case 'reply-to':
      return $localize`:@@email.refused.replyTo:Enter an email address, or leave it empty.`;
    case 'test-to':
      return $localize`:@@email.refused.testTo:Enter the email address to send the test to.`;
  }
}

export function messageKindText(kind: string): string {
  switch (kind) {
    case 'test':
      return $localize`:@@email.kind.test:Test message`;
    case 'license.expiry':
      return $localize`:@@email.kind.license:Licence expiry`;
    case 'webhook.failed':
      return $localize`:@@email.kind.webhook:Failing webhook`;
    case 'account.password-reset':
      return $localize`:@@email.kind.passwordReset:Password reset`;
    case 'account.invitation':
      return $localize`:@@email.kind.invitation:Invitation`;
    case 'account.password-changed':
      return $localize`:@@email.kind.passwordChanged:Password changed`;
    case 'notify.gate-failed':
      return $localize`:@@email.kind.gateFailed:Quality gate failed`;
    case 'notify.gate-recovered':
      return $localize`:@@email.kind.gateRecovered:Quality gate passes again`;
    case 'notify.analysis-failed':
      return $localize`:@@email.kind.analysisFailed:Analysis failed`;
    case 'notify.vulnerabilities-digest':
      return $localize`:@@email.kind.vulnerabilitiesDigest:Vulnerability digest`;
    case 'notify.vulnerabilities-exploited':
      return $localize`:@@email.kind.vulnerabilitiesExploited:Exploited vulnerability`;
    default:
      return kind;
  }
}

export function messageStatusText(m: Pick<MailMessage, 'status' | 'attempts'>): string {
  if (m.status === 'sent') return $localize`:@@email.status.sent:Delivered`;
  if (m.status === 'failed') return $localize`:@@email.status.failed:Failed`;
  return m.attempts > 0
    ? $localize`:@@email.status.retrying:Retrying ${m.attempts}:attempts:/7`
    : $localize`:@@email.status.pending:Pending`;
}

export function messageStatusBadge(m: Pick<MailMessage, 'status' | 'attempts'>): string {
  if (m.status === 'sent') return 'badge badge-passed';
  if (m.status === 'failed') return 'badge badge-failed';
  return m.attempts > 0 ? 'badge badge-warn' : 'badge badge-none';
}
