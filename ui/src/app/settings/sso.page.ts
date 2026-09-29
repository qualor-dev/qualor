import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import {
  EeApi,
  type SamlMetadataPreview,
  type SsoConnection,
  type SsoConnectionInput,
  type SsoConnectionPatch,
  type SsoConnectionTest,
  type SsoMapping,
} from '../api/ee';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import { SessionStore } from '../auth/session';
import { label } from '../i18n/labels';
import { LabelPipe } from '../i18n/label.pipe';
import { OrgContext } from '../org/org-context';
import { SystemInfo } from '../shell/system-info';
import { DateTimePipe } from '../shared/date-time.pipe';
import { keepFocus } from '../shared/focus';
import { inputValue, isChecked } from '../shared/forms';
import { CopyValue } from './copy-value';
import {
  metadataProblemText,
  nameTakenText,
  ssoProblem,
  testProblemText,
} from './sso-settings-text';

type Protocol = SsoConnection['protocol'];
type GroupSource = SsoConnection['groupSource'];
type ClientAuth = NonNullable<SsoConnection['oidc']>['clientAuth'];
type NameIdFormat = NonNullable<SsoConnection['saml']>['nameIdFormat'];
type Role = SsoMapping['role'];

/** sso-scim.md §4.1: at most 10 connections, in every plan. */
const MAX_CONNECTIONS = 10;
/** §4.1: at most 5 required claims. */
const MAX_REQUIRED_CLAIMS = 5;
/** §9.2: at most 500 mappings per connection. */
const MAX_MAPPINGS = 500;
/** §9.2: a group value is 1–255 characters. */
const MAX_GROUP = 255;
/** The projects offered for a project mapping: one page, the most the API gives at once. */
const PROJECT_PAGE = 500;

const NAME_ID_FORMATS: readonly NameIdFormat[] = [
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
];
const ROLES: readonly Role[] = ['admin', 'project_admin', 'member', 'viewer'];

/** The form of one connection: text as typed, the protocol's fields side by side. */
interface Draft {
  protocol: Protocol;
  name: string;
  enabled: boolean;
  jit: boolean;
  linkByEmail: boolean;
  groupSource: GroupSource;
  /** `claim=value`, one a line (§4.1). */
  requiredClaims: string;
  claimUsername: string;
  claimEmail: string;
  claimDisplayName: string;
  claimGroups: string;
  issuer: string;
  clientId: string;
  /** Write-only: always empty unless the admin types a new one. */
  clientSecret: string;
  clientAuth: ClientAuth;
  /** Space-separated. */
  scopes: string;
  userinfo: boolean;
  idpEntityId: string;
  idpSsoUrl: string;
  /** One or more PEM blocks. */
  idpCertificates: string;
  metadataUrl: string;
  nameIdFormat: NameIdFormat;
  emailVerified: boolean;
  wantResponseSigned: boolean;
  /** Write-only: always empty unless the admin gives a new key. */
  spKey: string;
  spCertificate: string;
}

type TextField = {
  [K in keyof Draft]: Draft[K] extends string ? K : never;
}[keyof Draft];
type FlagField = { [K in keyof Draft]: Draft[K] extends boolean ? K : never }[keyof Draft];

/** A mapping row as the table shows it; new rows carry the keys the page chose them by. */
interface MappingRow {
  group: string;
  organizationId: string;
  organizationKey: string;
  projectId: string | null;
  projectKey: string | null;
  role: Role;
}

interface ProjectOption {
  id: string;
  key: string;
  name: string;
}

function blank(protocol: Protocol): Draft {
  // §4.2, §4.3: each protocol's defaults.
  const oidc = protocol === 'oidc';
  return {
    protocol,
    name: '',
    enabled: false,
    jit: true,
    linkByEmail: false,
    groupSource: 'none',
    requiredClaims: '',
    claimUsername: oidc ? 'preferred_username' : '',
    claimEmail: 'email',
    claimDisplayName: oidc ? 'name' : 'displayName',
    claimGroups: '',
    issuer: '',
    clientId: '',
    clientSecret: '',
    clientAuth: 'client_secret_basic',
    scopes: 'openid email profile',
    userinfo: false,
    idpEntityId: '',
    idpSsoUrl: '',
    idpCertificates: '',
    metadataUrl: '',
    nameIdFormat: NAME_ID_FORMATS[0] ?? 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    emailVerified: false,
    wantResponseSigned: false,
    spKey: '',
    spCertificate: '',
  };
}

/** The form of a stored connection. Secrets are never in the view, so never in the form. */
function draftOf(c: SsoConnection): Draft {
  const d = blank(c.protocol);
  return {
    ...d,
    name: c.name,
    enabled: c.enabled,
    jit: c.jit,
    linkByEmail: c.linkByEmail,
    groupSource: c.groupSource,
    requiredClaims: c.requiredClaims.map((r) => `${r.claim}=${r.value}`).join('\n'),
    claimUsername: c.claims.username ?? '',
    claimEmail: c.claims.email ?? '',
    claimDisplayName: c.claims.displayName ?? '',
    claimGroups: c.claims.groups ?? '',
    ...(c.oidc
      ? {
          issuer: c.oidc.issuer,
          clientId: c.oidc.clientId,
          clientAuth: c.oidc.clientAuth,
          scopes: c.oidc.scopes.join(' '),
          userinfo: c.oidc.userinfo,
        }
      : {}),
    ...(c.saml
      ? {
          idpEntityId: c.saml.idpEntityId,
          idpSsoUrl: c.saml.idpSsoUrl,
          idpCertificates: c.saml.idpCertificates.map((x) => x.pem.trim()).join('\n'),
          metadataUrl: c.saml.metadataUrl ?? '',
          nameIdFormat: c.saml.nameIdFormat,
          emailVerified: c.saml.emailVerified,
          wantResponseSigned: c.saml.wantResponseSigned,
          spCertificate: c.saml.spCertificate ?? '',
        }
      : {}),
  };
}

/** The PEM blocks of a text area, each with its BEGIN and END lines. */
function pemBlocks(text: string): string[] {
  return [...text.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map(
    (m) => `${m[0]}\n`,
  );
}

/** `claim=value` lines; a line without `=` is kept whole as the claim, for the server to refuse. */
function requiredClaimsOf(text: string): { claim: string; value: string }[] {
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '')
    .map((line) => {
      const at = line.indexOf('=');
      return at < 0
        ? { claim: line, value: '' }
        : { claim: line.slice(0, at).trim(), value: line.slice(at + 1).trim() };
    });
}

const orNull = (text: string): string | null => (text.trim() === '' ? null : text.trim());

/**
 * The 422 paths of the connection routes (§17.2, core's field paths) and the field each one marks.
 * A path matches its own entry or any path below it (`body.saml.idpCertificates.1`).
 */
const FIELD_OF_PATH: readonly (readonly [string, string])[] = [
  ['body.name', 'sso-name'],
  ['body.oidc.issuer', 'sso-issuer'],
  ['body.oidc.clientId', 'sso-client-id'],
  ['body.oidc.clientSecret', 'sso-client-secret'],
  ['body.oidc.scopes', 'sso-scopes'],
  ['body.saml.idpEntityId', 'sso-idp-entity-id'],
  ['body.saml.idpSsoUrl', 'sso-idp-sso-url'],
  ['body.saml.idpCertificates', 'sso-idp-certificates'],
  ['body.saml.metadataUrl', 'sso-metadata-url'],
  ['body.saml.spKey', 'sso-sp-key'],
  ['body.saml.spCertificate', 'sso-sp-certificate'],
  ['body.claims.username', 'sso-claim-username'],
  ['body.claims.email', 'sso-claim-email'],
  ['body.claims.displayName', 'sso-claim-display-name'],
  ['body.claims.groups', 'sso-claim-groups'],
  ['body.requiredClaims', 'sso-required-claims'],
];

/** The fixed text a marked field shows (the server's own message is never shown). */
function fieldText(id: string): string {
  switch (id) {
    case 'sso-name':
      return $localize`:@@sso.field.name:Give a name of 1 to 64 characters, without control characters. It is the text of the sign-in button.`;
    case 'sso-issuer':
      return $localize`:@@sso.field.issuer:Give the issuer URL exactly as the identity provider publishes it: https (http only for a host in QUALOR_SSO_INTERNAL_HOSTS), without a query, fragment or spaces.`;
    case 'sso-client-id':
      return $localize`:@@sso.field.clientId:Give the client id, 1 to 255 characters.`;
    case 'sso-client-secret':
      return $localize`:@@sso.field.clientSecret:Give the client secret. It is needed when the connection is added and again when the issuer changes.`;
    case 'sso-scopes':
      return $localize`:@@sso.field.scopes:List 1 to 20 scopes separated by spaces, including openid.`;
    case 'sso-idp-entity-id':
      return $localize`:@@sso.field.idpEntityId:Give the identity provider's entity id, 1 to 1 024 characters.`;
    case 'sso-idp-sso-url':
      return $localize`:@@sso.field.idpSsoUrl:Give the identity provider's SSO URL for the HTTP-Redirect binding: https (http only for a host in QUALOR_SSO_INTERNAL_HOSTS), without a fragment.`;
    case 'sso-idp-certificates':
      return $localize`:@@sso.field.idpCertificates:Paste 1 to 3 PEM certificates of the identity provider: RSA of at least 2048 bits, or EC P-256, P-384 or P-521.`;
    case 'sso-metadata-url':
      return $localize`:@@sso.field.metadataUrl:The metadata URL is not valid, or its document could not be read or was refused.`;
    case 'sso-sp-key':
      return $localize`:@@sso.field.spKey:Give an unencrypted PKCS#8 PEM RSA key of 2048 to 4096 bits, with its certificate.`;
    case 'sso-sp-certificate':
      return $localize`:@@sso.field.spCertificate:Give the PEM certificate of the service provider key.`;
    case 'sso-required-claims':
      return $localize`:@@sso.field.requiredClaims:Give at most 5 lines of the form claim=value.`;
    default:
      return $localize`:@@sso.field.claim:Give a claim or attribute name of 1 to 128 letters, digits and _ . : / -, or leave it empty.`;
  }
}

/**
 * Settings → Single sign-on (sso-scim.md §4, §9, §18; feature `sso`, instance admins): the
 * connections, and one connection's form per protocol with the values to copy into the identity
 * provider, **Test**, **Read metadata** (SAML: the change shown with the certificates' SHA-256
 * fingerprints before it is saved), the group mappings and **Delete**.
 *
 * Secrets are write-only (§4.2, §4.3): the view only says whether one is set (`clientSecretSet`,
 * `spKeySet`); the field starts empty behind **Change**, and a save without it keeps the stored
 * one. **Test** shows a fixed text per problem code, never the server's message. Every role, and
 * project mappings, are offered whenever the page is shown (§9.2: `sso` alone since 5B; only
 * `admin` is not a project role). Nothing is asked of the enterprise API while `sso` is
 * inactive or the caller is not an instance admin.
 *
 * Without `sso.multi` (§4.4, plan 5D) one connection signs people in at a time: a line says so,
 * a connection is created disabled while another is enabled, a disabled connection's **Enabled**
 * switch is disabled while another is enabled, and an enabled connection the server reports as
 * not in effect is marked. With `sso.multi` the page counts the connections against the 10.
 */
@Component({
  selector: 'q-sso-page',
  imports: [CopyValue, DateTimePipe, LabelPipe],
  templateUrl: './sso.page.html',
})
export class SsoPage {
  private readonly ee = inject(EeApi);
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly info = inject(SystemInfo);
  protected readonly org = inject(OrgContext);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);

  protected readonly licensed = computed(() => this.info.features().includes('sso'));
  private readonly scim = computed(() => this.info.features().includes('scim'));
  /** §4.4: several enabled connections, all in effect, need `sso.multi` (the Enterprise plan). */
  protected readonly multi = computed(() => this.info.features().includes('sso.multi'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  protected readonly allowed = computed(() => this.licensed() && this.instanceAdmin());

  protected readonly connections = signal<SsoConnection[] | null>(null);
  protected readonly canAdd = computed(() => (this.connections()?.length ?? 0) < MAX_CONNECTIONS);
  protected readonly maxConnections = MAX_CONNECTIONS;
  /** Some enabled connection is not in effect (§4.4): the page explains the badge once. */
  protected readonly anyNotInEffect = computed(
    () => this.connections()?.some((c) => c.enabled && !c.inEffect) ?? false,
  );
  protected readonly loadError = signal<string | null>(null);
  /** The connection being edited: its id, `new` for one not saved yet, or null for the list. */
  protected readonly editing = signal<string | null>(null);
  protected readonly current = computed(
    () => this.connections()?.find((c) => c.id === this.editing()) ?? null,
  );
  protected readonly draft = signal<Draft>(blank('oidc'));
  /**
   * §4.4: without `sso.multi`, a connection that is not enabled cannot be enabled while another
   * one is: its **Enabled** switch is off and disabled, and a new one is created disabled.
   */
  protected readonly enableBlocked = computed(() => {
    if (this.multi() || this.current()?.enabled === true) return false;
    const id = this.editing();
    return (this.connections() ?? []).some((c) => c.enabled && c.id !== id);
  });
  /** **Change** was pressed: the secret field is shown (empty). A new connection always shows it. */
  protected readonly changeSecret = signal(false);
  protected readonly changeSpKey = signal(false);
  protected readonly errors = signal<Readonly<Record<string, string>>>({});
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly test = signal<SsoConnectionTest | null>(null);
  protected readonly preview = signal<SamlMetadataPreview | null>(null);

  protected readonly mappings = signal<MappingRow[]>([]);
  protected readonly mappingsDirty = signal(false);
  protected readonly mappingsError = signal<string | null>(null);
  protected readonly newGroup = signal('');
  protected readonly newOrg = signal('');
  protected readonly newProject = signal('');
  protected readonly newRole = signal<Role>('member');
  protected readonly newMappingError = signal<string | null>(null);
  protected readonly projects = signal<ProjectOption[]>([]);

  protected readonly nameIdFormats = NAME_ID_FORMATS;
  protected readonly roles = ROLES;
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');

  constructor() {
    effect(() => {
      const allowed = this.allowed();
      untracked(() => {
        this.connections.set(null);
        this.editing.set(null);
        if (allowed) void this.load();
      });
    });
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      this.connections.set(await ok(this.ee.client.GET('/api/v0/ee/sso/connections')));
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  // ─── The form ─────────────────────────────────────────────────────────────────────────────

  protected add(protocol: Protocol): void {
    this.reset();
    this.draft.set(blank(protocol));
    this.editing.set('new');
    this.focus('sso-name');
  }

  protected async edit(connection: SsoConnection): Promise<void> {
    this.reset();
    this.draft.set(draftOf(connection));
    this.editing.set(connection.id);
    this.focus('sso-form-title');
    await this.loadMappings(connection.id);
  }

  protected close(): void {
    this.reset();
    this.editing.set(null);
    keepFocus(this.injector, this.document, () => this.heading().nativeElement);
  }

  private reset(): void {
    this.changeSecret.set(false);
    this.changeSpKey.set(false);
    this.errors.set({});
    this.error.set(null);
    this.announcement.set(null);
    this.test.set(null);
    this.preview.set(null);
    this.mappings.set([]);
    this.mappingsDirty.set(false);
    this.mappingsError.set(null);
    this.newMappingError.set(null);
  }

  protected setText(field: TextField, event: Event): void {
    const value = inputValue(event);
    this.draft.update((d) => ({ ...d, [field]: value }));
  }

  protected setFlag(field: FlagField, event: Event): void {
    const value = isChecked(event);
    this.draft.update((d) => ({ ...d, [field]: value }));
  }

  protected setGroupSource(event: Event): void {
    const value = inputValue(event) as GroupSource;
    this.draft.update((d) => ({ ...d, groupSource: value }));
  }

  protected setClientAuth(event: Event): void {
    const value = inputValue(event) as ClientAuth;
    this.draft.update((d) => ({ ...d, clientAuth: value }));
  }

  protected setNameIdFormat(event: Event): void {
    const value = inputValue(event) as NameIdFormat;
    this.draft.update((d) => ({ ...d, nameIdFormat: value }));
  }

  protected showSecretField(): void {
    this.changeSecret.set(true);
    this.focus('sso-client-secret');
  }

  protected showSpKeyField(): void {
    this.changeSpKey.set(true);
    this.focus('sso-sp-key');
  }

  protected editLabel(connection: SsoConnection): string {
    return $localize`:@@sso.editNamed:Edit ${connection.name}:name:`;
  }

  protected removeMappingLabel(group: string): string {
    return $localize`:@@sso.mapping.removeNamed:Remove the mapping of ${group}:group:`;
  }

  protected fieldError(id: string): string | null {
    return this.errors()[id] ?? null;
  }

  protected nameIdLabel(format: NameIdFormat): string {
    switch (format) {
      case 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress':
        return $localize`:@@sso.nameId.email:Email address`;
      case 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified':
        return $localize`:@@sso.nameId.unspecified:Unspecified`;
      default:
        return $localize`:@@sso.nameId.persistent:Persistent (recommended)`;
    }
  }

  /** The body of a new connection (§17.2 `POST`): every field the form holds. */
  private createBody(d: Draft): SsoConnectionInput {
    return {
      name: d.name.trim(),
      protocol: d.protocol,
      ...this.commonBody(d),
      ...(d.protocol === 'oidc'
        ? { oidc: { ...this.oidcBody(d), clientSecret: d.clientSecret } }
        : { saml: { ...this.samlBody(d), ...(d.spKey ? { spKey: d.spKey } : {}) } }),
    };
  }

  /** The body of a change (§17.2 `PATCH`): a secret only when a new one was typed. */
  private patchBody(d: Draft): SsoConnectionPatch {
    return {
      name: d.name.trim(),
      ...this.commonBody(d),
      ...(d.protocol === 'oidc'
        ? {
            oidc: {
              ...this.oidcBody(d),
              ...(this.changeSecret() && d.clientSecret ? { clientSecret: d.clientSecret } : {}),
            },
          }
        : {
            saml: {
              ...this.samlBody(d),
              ...(this.changeSpKey() && d.spKey ? { spKey: d.spKey } : {}),
            },
          }),
    };
  }

  private commonBody(d: Draft) {
    return {
      enabled: d.enabled && !this.enableBlocked(),
      jit: d.jit,
      linkByEmail: d.linkByEmail,
      groupSource: d.groupSource,
      requiredClaims: requiredClaimsOf(d.requiredClaims),
      claims: {
        username: orNull(d.claimUsername),
        email: orNull(d.claimEmail),
        displayName: orNull(d.claimDisplayName),
        groups: orNull(d.claimGroups),
      },
    };
  }

  private oidcBody(d: Draft) {
    return {
      issuer: d.issuer,
      clientId: d.clientId.trim(),
      clientAuth: d.clientAuth,
      scopes: d.scopes.split(/\s+/).filter((s) => s !== ''),
      userinfo: d.userinfo,
    };
  }

  private samlBody(d: Draft) {
    return {
      idpEntityId: d.idpEntityId.trim(),
      idpSsoUrl: d.idpSsoUrl,
      idpCertificates: pemBlocks(d.idpCertificates),
      metadataUrl: orNull(d.metadataUrl),
      nameIdFormat: d.nameIdFormat,
      emailVerified: d.emailVerified,
      wantResponseSigned: d.wantResponseSigned,
      spCertificate: orNull(d.spCertificate),
    };
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const d = this.draft();
    const id = this.editing();
    const local: Record<string, string> = {};
    if (d.name.trim() === '') local['sso-name'] = fieldText('sso-name');
    if (requiredClaimsOf(d.requiredClaims).length > MAX_REQUIRED_CLAIMS) {
      local['sso-required-claims'] = fieldText('sso-required-claims');
    }
    if (d.protocol === 'saml' && d.idpCertificates.trim() !== '') {
      if (pemBlocks(d.idpCertificates).length === 0) {
        local['sso-idp-certificates'] = fieldText('sso-idp-certificates');
      }
    }
    if (id === 'new' && d.protocol === 'oidc' && d.clientSecret === '') {
      local['sso-client-secret'] = fieldText('sso-client-secret');
    }
    this.errors.set(local);
    if (Object.keys(local).length > 0) {
      this.focusFirstError();
      return;
    }
    await this.run(async () => {
      try {
        const saved =
          id === 'new' || id === null
            ? await ok(
                this.ee.client.POST('/api/v0/ee/sso/connections', { body: this.createBody(d) }),
              )
            : await ok(
                this.ee.client.PATCH('/api/v0/ee/sso/connections/{id}', {
                  params: { path: { id } },
                  body: this.patchBody(d),
                }),
              );
        await this.load();
        this.draft.set(draftOf(saved));
        this.changeSecret.set(false);
        this.changeSpKey.set(false);
        this.test.set(null);
        this.preview.set(null);
        if (id === 'new') {
          this.editing.set(saved.id);
          await this.loadMappings(saved.id);
        }
        this.announcement.set(
          $localize`:@@sso.saved:${saved.name}:name: saved. Copy the values below into the identity provider.`,
        );
      } catch (err) {
        if (!this.markFields(err)) throw err;
      }
    });
  }

  /** Marks the fields a 422 (or a name conflict) names; false when it names none. */
  private markFields(err: unknown): boolean {
    if (err instanceof ApiError && err.status === 409 && err.code === 'SSO_CONNECTION_NAME_TAKEN') {
      this.errors.set({ 'sso-name': nameTakenText() });
      this.focusFirstError();
      return true;
    }
    if (!(err instanceof ApiError) || err.status !== 422) return false;
    const marked: Record<string, string> = {};
    for (const path of Object.keys(fieldErrors(err))) {
      const entry = FIELD_OF_PATH.find(([p]) => path === p || path.startsWith(`${p}.`));
      if (entry) marked[entry[1]] = fieldText(entry[1]);
    }
    if (Object.keys(marked).length === 0) return false;
    this.errors.set(marked);
    this.focusFirstError();
    return true;
  }

  private focusFirstError(): void {
    const first = FIELD_OF_PATH.map(([, id]) => id).find((id) => this.errors()[id] !== undefined);
    if (first) this.focus(first);
  }

  // ─── Test, metadata, delete ───────────────────────────────────────────────────────────────

  protected async runTest(connection: SsoConnection): Promise<void> {
    if (this.busy()) return;
    this.test.set(null);
    await this.run(async () => {
      this.test.set(
        await ok(
          this.ee.client.POST('/api/v0/ee/sso/connections/{id}/test', {
            params: { path: { id: connection.id } },
          }),
        ),
      );
    });
  }

  protected testText(code: string): string {
    return testProblemText(code);
  }

  protected async readMetadata(connection: SsoConnection): Promise<void> {
    if (this.busy()) return;
    this.preview.set(null);
    await this.run(async () => {
      try {
        this.preview.set(
          await ok(
            this.ee.client.POST('/api/v0/ee/sso/connections/{id}/saml/metadata', {
              params: { path: { id: connection.id } },
            }),
          ),
        );
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 422) throw err;
        this.errors.set({
          'sso-metadata-url':
            metadataProblemText(err.problem?.reason) ?? fieldText('sso-metadata-url'),
        });
        this.focus('sso-metadata-url');
      }
    });
  }

  protected discardPreview(): void {
    this.preview.set(null);
  }

  /** Saves what the metadata said: the entity id, the SSO URL and the certificates (§4.3). */
  protected async applyPreview(connection: SsoConnection): Promise<void> {
    const preview = this.preview();
    if (!preview || this.busy()) return;
    await this.run(async () => {
      const saved = await ok(
        this.ee.client.PATCH('/api/v0/ee/sso/connections/{id}', {
          params: { path: { id: connection.id } },
          body: {
            saml: {
              idpEntityId: preview.idpEntityId,
              idpSsoUrl: preview.idpSsoUrl,
              idpCertificates: preview.certificates.map((c) => c.pem),
            },
          },
        }),
      );
      await this.load();
      this.draft.set(draftOf(saved));
      this.preview.set(null);
      this.announcement.set(
        $localize`:@@sso.metadataSaved:The identity provider's metadata was saved.`,
      );
    });
  }

  protected async remove(connection: SsoConnection): Promise<void> {
    if (this.busy()) return;
    const tokens = await this.activeTokens(connection.id);
    const mappings = this.mappings().length;
    const question =
      tokens === null
        ? $localize`:@@sso.confirmDelete:Delete ${connection.name}:name:? Its linked identities, its ${mappings}:mappings: group mappings and its SCIM tokens are deleted: people who sign in only through it cannot sign in until an administrator sets a password. Memberships its group sync granted stay, as manual memberships.`
        : $localize`:@@sso.confirmDeleteTokens:Delete ${connection.name}:name:? Its linked identities, its ${mappings}:mappings: group mappings and its ${tokens}:tokens: active SCIM tokens are deleted: people who sign in only through it cannot sign in until an administrator sets a password. Memberships its group sync granted stay, as manual memberships.`;
    if (!window.confirm(question)) return;
    await this.run(async () => {
      await done(
        this.ee.client.DELETE('/api/v0/ee/sso/connections/{id}', {
          params: { path: { id: connection.id } },
        }),
      );
      this.reset();
      this.editing.set(null);
      await this.load();
      this.announcement.set($localize`:@@sso.deleted:${connection.name}:name: deleted.`);
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
  }

  /** The connection's active SCIM tokens, while `scim` is active; null when unknown. */
  private async activeTokens(id: string): Promise<number | null> {
    if (!this.scim()) return null;
    try {
      const tokens = await ok(
        this.ee.client.GET('/api/v0/ee/scim/tokens', { params: { query: { connectionId: id } } }),
      );
      return tokens.filter((t) => t.revokedAt === null).length;
    } catch {
      return null;
    }
  }

  // ─── Group mappings (§9.2) ────────────────────────────────────────────────────────────────

  private async loadMappings(id: string): Promise<void> {
    try {
      const rows = await ok(
        this.ee.client.GET('/api/v0/ee/sso/connections/{id}/mappings', {
          params: { path: { id } },
        }),
      );
      if (this.editing() !== id) return;
      this.mappings.set(rows.map((m) => ({ ...m })));
    } catch (err) {
      this.mappingsError.set(problemMessage(err));
    }
  }

  protected roleLabel(role: Role): string {
    return label('role', role);
  }

  /** Whether a role may be chosen for the new row: no admin on a project (§9.2). */
  protected roleDisabled(role: Role): boolean {
    return role === 'admin' && this.newProject() !== '';
  }

  protected setNewGroup(event: Event): void {
    this.newGroup.set(inputValue(event));
    this.newMappingError.set(null);
  }

  protected async setNewOrg(event: Event): Promise<void> {
    const id = inputValue(event);
    this.newOrg.set(id);
    this.newProject.set('');
    this.projects.set([]);
    if (!id) return;
    try {
      const page = await ok(
        this.api.client.GET('/api/v0/projects', {
          params: { query: { organizationId: id, limit: PROJECT_PAGE } },
        }),
      );
      if (this.newOrg() === id) {
        this.projects.set(page.items.map((p) => ({ id: p.id, key: p.key, name: p.name })));
      }
    } catch (err) {
      this.newMappingError.set(problemMessage(err));
    }
  }

  protected setNewProject(event: Event): void {
    this.newProject.set(inputValue(event));
    if (this.newProject() !== '' && this.newRole() === 'admin') this.newRole.set('member');
  }

  protected setNewRole(event: Event): void {
    this.newRole.set(inputValue(event) as Role);
  }

  protected addMapping(event: Event): void {
    event.preventDefault();
    const group = this.newGroup().trim();
    const org = this.org.orgs().find((o) => o.id === this.newOrg());
    const project = this.projects().find((p) => p.id === this.newProject()) ?? null;
    const role = this.newRole();
    if (group === '' || group.length > MAX_GROUP) {
      this.newMappingError.set(
        $localize`:@@sso.mapping.groupInvalid:Give the group as the identity provider sends it, 1 to 255 characters, or * for everyone of this connection.`,
      );
      this.focus('sso-mapping-group');
      return;
    }
    if (!org) {
      this.newMappingError.set(
        $localize`:@@sso.mapping.orgMissing:Choose the organization the group gives a role in.`,
      );
      this.focus('sso-mapping-org');
      return;
    }
    const duplicate = this.mappings().some(
      (m) =>
        m.group === group && m.organizationId === org.id && m.projectId === (project?.id ?? null),
    );
    if (duplicate || this.mappings().length >= MAX_MAPPINGS) {
      this.newMappingError.set(
        duplicate
          ? $localize`:@@sso.mapping.duplicate:This group already has a mapping to this organization or project.`
          : $localize`:@@sso.mapping.limit:A connection has at most 500 mappings.`,
      );
      return;
    }
    this.mappings.update((rows) => [
      ...rows,
      {
        group,
        organizationId: org.id,
        organizationKey: org.key,
        projectId: project?.id ?? null,
        projectKey: project?.key ?? null,
        role,
      },
    ]);
    this.mappingsDirty.set(true);
    this.newGroup.set('');
    this.newMappingError.set(null);
    this.focus('sso-mapping-group');
  }

  protected removeMapping(index: number): void {
    this.mappings.update((rows) => rows.filter((_, i) => i !== index));
    this.mappingsDirty.set(true);
    this.focus('sso-mapping-group');
  }

  /** `PUT` the whole list (§9.2): the table as it is now replaces what is stored. */
  protected async saveMappings(connection: SsoConnection): Promise<void> {
    if (this.busy()) return;
    this.mappingsError.set(null);
    await this.run(async () => {
      try {
        const saved = await ok(
          this.ee.client.PUT('/api/v0/ee/sso/connections/{id}/mappings', {
            params: { path: { id: connection.id } },
            body: this.mappings().map((m) => ({
              group: m.group,
              organizationId: m.organizationId,
              projectId: m.projectId,
              role: m.role,
            })),
          }),
        );
        this.mappings.set(saved.map((m) => ({ ...m })));
        this.mappingsDirty.set(false);
        this.announcement.set($localize`:@@sso.mappingsSaved:Group mappings saved.`);
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 422) throw err;
        this.mappingsError.set(
          $localize`:@@sso.mapping.invalid:A mapping is not valid: its organization or project may no longer exist, or a project mapping has the Organization admin role.`,
        );
      }
    });
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────────────────────

  private focus(id: string): void {
    afterNextRender(() => this.document.getElementById(id)?.focus(), { injector: this.injector });
  }

  private async run(action: () => Promise<void>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      this.error.set(ssoProblem(err, this.multi()));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}
