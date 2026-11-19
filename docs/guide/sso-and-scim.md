# Single sign-on and SCIM

Single sign-on lets people sign in to Qualor through your identity provider (IdP), with OIDC or
SAML 2.0. Accounts are created at the first sign-in or linked to existing ones, IdP groups can
grant roles, and password sign-in can be limited to break-glass admins. With SCIM, the IdP creates,
updates and deactivates the accounts for you.

Single sign-on needs a licence key listing `sso`. The Business plan allows one enabled connection
at a time. Several identity providers at once need `sso.multi`
([One connection or several](#one-connection-or-several)), and SCIM needs `scim`: both are in the
Enterprise plan only ([Plans and prices](./enterprise.md#plans-and-prices)). Without single
sign-on, people sign in with a user name and password. API and CI tokens work the same either way.

## Requirements

1. A licence key listing `sso`, applied as in [Apply a key](./enterprise.md#apply-a-key).
2. **`QUALOR_PUBLIC_URL`** set to the address people open Qualor at
   ([server settings](./install-server.md#server-settings)). The redirect URI, the SAML entity id
   and the ACS URL are made from it, so a connection cannot be enabled without it (409
   `PUBLIC_URL_REQUIRED`). If you change `QUALOR_PUBLIC_URL` later, give the IdP the new values.
3. An IdP the server can reach over `https`. An IdP on your internal network, or one on plain
   `http` (a test Keycloak), must be listed in **`QUALOR_SSO_INTERNAL_HOSTS`**: comma-separated
   host names, each with an optional port, such as `keycloak.corp.example.com` or
   `keycloak:8080`. A private CA needs `NODE_EXTRA_CA_CERTS`, as for GitLab.

Only the server talks to the IdP: to the OIDC issuer you entered and the token, JWKS and userinfo
endpoints its discovery document names, or to a SAML metadata URL when an admin asks Qualor to
read it. People's browsers go to the IdP's sign-in page; Qualor's server never calls it.

Connections live in **Settings → Single sign-on** (instance admins). Choose **Add an OpenID
Connect connection** or **Add a SAML connection**, fill in the form and **Save**. A saved
connection shows **Values for the identity provider** to copy, **Check the connection** with
**Test** (and **Read metadata** for SAML), and its **Group mappings**. **Edit** opens it again;
**Delete the connection** removes it.

The Keycloak steps below are tested automatically, against Keycloak 26.7.4. The Entra ID, Okta and
Google Workspace steps are not yet tested with real accounts.

## Add an OIDC connection

Qualor uses the authorization code flow with PKCE, a nonce and a state, and checks the ID token's
signature, issuer, audience, expiry and issue time. It needs a **confidential client**: a client
id and a client secret.

Copy this value into the IdP, from **Values for the identity provider**:

| Qualor's label | IdP asks for | Value |
|---|---|---|
| **Redirect URI** | redirect URI (callback, reply URL) | `https://qualor.example.com/api/v0/ee/sso/oidc/<connection id>/callback` |

Then fill in **New OpenID Connect connection** in Qualor:

| Field | What to enter |
|---|---|
| **Name** | the button text: "Sign in with" and this name |
| **Issuer URL** | the issuer **exactly as the IdP's discovery document names it, a trailing slash included**. Qualor keeps it as entered, and `/.well-known/openid-configuration` below it must name the same issuer, character for character |
| **Client id**, **Client secret** | from the IdP. The secret is stored encrypted and never shown again: the form says **Set. It is never shown again.**, and **Change** replaces it. A changed issuer needs the secret again |
| **Client authentication** | `client_secret_basic` (the default) or `client_secret_post` |
| **Scopes** | `openid email profile` by default; `openid` is required |
| **Also read the userinfo endpoint** | off by default. Turn it on for an IdP that sends the email or groups only there |
| **Username claim**, **Email claim**, **Display name claim**, **Groups claim** | where to read each: `preferred_username`, `email`, `name`, and `groups` once groups come from claims. Leave one empty to not read it. The username claim must be one **only the IdP's administrator can change**, never the user ([why](#choose-a-username-claim-the-user-cannot-change)) |

The **Accounts** part of the form is the same for OIDC and SAML:

- **Create an account at the first sign-in** and **Link to an existing account with the same
  verified email (never an instance administrator)**: see
  [Who gets an account](#who-gets-an-account).
- **Required claims (optional)**: one `claim=value` a line, at most 5, such as `hd=example.com`. A
  sign-in without that exact value is refused (`required_claim`).
- **Groups come from**: see [Group mappings and sync](#group-mappings-and-sync).

Press **Test** under **Check the connection**. It reads the discovery document and the JWKS, and
lists the **Authorization endpoint** (the page people's browsers open) and the **Token endpoint**,
**JWKS** and **Userinfo endpoint** that Qualor's server will call ("The test passed."). Then tick
**Enabled: show it on the sign-in page** and **Save**.

**Emails:** Qualor stores an OIDC email, and links by it, only when the IdP marks it verified
(`email_verified: true`, the JSON boolean). Entra ID marks it with `xms_edov: true` instead, which
counts the same ([Microsoft Entra ID](#microsoft-entra-id)). **An unverified email is never stored,
and never used to link an account.** An IdP that sends neither gives accounts without an email;
SCIM fills them in.

### Keycloak

1. In your realm, **Clients → Create client**: type OpenID Connect, a client id such as `qualor`,
   **Client authentication** on, **Standard flow** only.
2. **Valid redirect URIs:** the redirect URI above.
3. For groups: in the client's dedicated scope, add a **Group Membership** mapper, token claim name
   `groups`, **Full group path** off, added to the ID token.
4. In Qualor: issuer `https://<keycloak host>/realms/<realm>`, the client id, and the secret from
   the client's **Credentials** tab. Keycloak sends `preferred_username`, `email`,
   `email_verified` and `name`.

### Microsoft Entra ID

1. **App registrations → New registration**, platform **Web**, redirect URI as above. Under
   **Certificates & secrets**, create a client secret.
2. Issuer: **`https://login.microsoftonline.com/<tenant id>/v2.0`**, with your tenant's id. The
   multi-tenant `common` and `organizations` endpoints and Azure AD B2C are not supported: their
   discovery document names an issuer other than the URL it is read from, which Qualor refuses.
3. The username claim is `preferred_username` (the user principal name).
4. Emails: **Token configuration → Add optional claim**, token type **ID**, claims `email` and
   `xms_edov`. Entra sends no `email_verified`; `xms_edov` says your tenant verified the email's
   domain, and Qualor stores the email only with it. Without these claims, accounts have no email.
5. Groups: **Token configuration → Add groups claim**; the claim is `groups`. Entra sends each
   group's **object id**, not its name, so map the object ids in Qualor. A person in very many
   groups gets no groups claim at all (Entra points to Microsoft Graph instead), so prefer
   **Groups assigned to the application**.

### Okta

1. **Applications → Create App Integration**, OIDC, **Web Application**, **Sign-in redirect URI**
   as above, grant type Authorization Code.
2. Issuer: your Okta domain (`https://<your domain>.okta.com`) for the org authorization server,
   or the custom authorization server's issuer (`https://<your domain>.okta.com/oauth2/default`),
   as its discovery document shows it.
3. Groups: on the app's **Sign On** tab, set a **Groups claim filter** named `groups` (for example
   "Starts with `qualor-`"), and add `groups` to the scopes in Qualor. Okta sends group names.

### Google Workspace

1. In the Google Cloud console, **APIs & Services → Credentials → Create OAuth client ID**, type
   **Web application**, with the redirect URI as an authorised redirect URI.
2. Issuer: `https://accounts.google.com`.
3. Any Google account can sign in to such a client, so add `hd=example.com` (your Workspace
   domain) under **Required claims (optional)**.
4. Google sends no groups claim. To give everyone the same starting role, set **Groups come from**
   to **The groups claim at each sign-in** and add a `*` group mapping
   ([Group mappings](#group-mappings-and-sync)). Or manage memberships by hand.

## Add a SAML connection

Qualor uses SAML 2.0 Web SSO: requests by HTTP-Redirect, responses by HTTP-POST. Copy these values
into the IdP, from **Values for the identity provider**:

| Qualor's label | IdP asks for | Value |
|---|---|---|
| **ACS URL** | ACS URL (reply URL, single sign-on URL) | `https://qualor.example.com/api/v0/ee/sso/saml/<connection id>/acs` |
| **Entity id (SP)** | SP entity id (identifier, audience URI) | `https://qualor.example.com/api/v0/ee/sso/saml/<connection id>/metadata` |
| **SP metadata URL** | SP metadata, for IdPs that import it | the same URL: it serves Qualor's metadata XML |

Then give Qualor the IdP's side in **New SAML connection**, from its metadata URL or by hand. For
the metadata URL, save the connection first, then press **Read metadata**. Qualor reads it once,
never on a schedule, and shows **What the metadata would change**: the entity id, the SSO URL and
the **Signing certificates** with their **SHA-256** fingerprints. Nothing is saved until you press
**Save these values** (or **Discard**). The metadata document itself is not signed, so check the
fingerprints with the IdP first.

| Field | What to enter |
|---|---|
| **Identity provider entity id** | the IdP's issuer. Every response and assertion must name it |
| **SSO URL (HTTP-Redirect)** | the IdP's single sign-on URL. It may carry a query, such as Google's `?idpid=…` |
| **Metadata URL (optional)** | may carry a query too, such as Entra ID's `?appid=…` |
| **Signing certificates (PEM, 1 to 3)** | several while the IdP rotates its key: RSA of 2048 bits or more, or EC. Once saved, each is listed with its **SHA-256** fingerprint and "valid until" date. An **Expired** certificate still works: IdPs often sign with expired self-signed ones |
| **NameID format** | **Persistent (recommended)**, **Email address** or **Unspecified** |
| **Username claim**, **Email claim**, **Display name claim**, **Groups claim** | the attribute names (`email` and `displayName` by default). An empty username uses the NameID |
| **This identity provider verifies the email attribute** | off by default. SAML has no "verified" flag, so tick it only if the IdP's email attribute is one it verified. Without it, the email is not stored, and not used to link |
| **Also require a signature on the whole response** | off by default. The assertion itself must always be signed |

The **Accounts** fields are those of [OIDC](#add-an-oidc-connection).

**Send a username attribute.** Without one, the NameID becomes the Qualor user name. Keycloak's
persistent NameID, for example, is an opaque `G-<uuid>`, so a new account would be called
`G-3f2a…`. Name the IdP's username attribute in **Username claim** instead, and pick one only the
IdP's administrators can change ([why](#choose-a-username-claim-the-user-cannot-change)).

**Groups:** the whole sign-in, groups included, must fit in 16 KiB, and more than 1 000 group
values are refused. That is roughly 350 Entra group ids, fewer with long group names. A sign-in
over the limit is refused (`invalid_response`), never cut short. Send only the groups Qualor needs:
filter them at the IdP.

**SHA-256 or stronger is required.** Qualor refuses responses signed or digested with SHA-1, and
comments, DOCTYPEs and processing instructions anywhere in a response. If your IdP signs with
SHA-1, switch it:

| IdP | Setting |
|---|---|
| Keycloak | the client's **Signature algorithm**: `RSA_SHA256` |
| Entra ID | **SAML Signing Certificate → Signing Algorithm**: `SHA-256` |
| Okta | **Signature Algorithm**: `RSA_SHA256` |
| AD FS | the relying party trust's **Advanced → Secure hash algorithm**: `SHA-256` |

**The service provider key (optional).** By default Qualor's requests are unsigned and it refuses
encrypted assertions; TLS protects them. To sign requests and accept encrypted assertions, make a
key pair and paste both parts under **Service provider key (optional)**, as **Private key** and
**Certificate**:

```sh
openssl req -x509 -newkey rsa:3072 -nodes -keyout sp.key -out sp.crt -days 3650 -subj "/CN=qualor-sp"
```

The key must be an unencrypted PKCS#8 RSA key of 2048 to 4096 bits, which is what this command
writes. It is stored encrypted and never shown again. The SP metadata then offers the certificate,
so the IdP can encrypt to it.

### Keycloak (SAML)

1. **Clients → Create client**, type SAML, **Client ID** = the SP entity id; **Valid redirect
   URIs** and **Assertion Consumer Service POST Binding URL** = the ACS URL.
2. **Sign assertions** on, **Signature algorithm** `RSA_SHA256`, **Name ID format** `persistent`.
3. Mappers (in the client's dedicated scope): a **User Property** `email` → attribute `email`, a
   **User Property** `username` → attribute `username`, a **User Property** `firstName` (or a
   full name) → attribute `displayName`, and a **Group list** → attribute `groups` with **Full
   group path** off.
4. In Qualor: metadata URL `https://<keycloak host>/realms/<realm>/protocol/saml/descriptor`, and
   the attributes `username`, `email`, `displayName`, `groups`.

The automated test covers these steps except the `username` mapper. Add it anyway: without it,
accounts are named after the NameID (`G-<uuid>`).

### Microsoft Entra ID (SAML)

1. **Enterprise applications → New application → Create your own application** (non-gallery),
   then **Single sign-on → SAML**: **Identifier** = the SP entity id, **Reply URL** = the ACS URL.
2. **Unique User Identifier (Name ID)**: `user.objectid` with the format **Persistent**, so the
   subject survives a renamed user principal name.
3. Attribute names for Qualor: email
   `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, username
   `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`, display name
   `http://schemas.microsoft.com/identity/claims/displayname`, groups (after **Add a group claim**)
   `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`. Groups arrive as object ids.
4. Metadata URL: the **App Federation Metadata Url**, which ends in `?appid=…`.

### Okta (SAML)

1. **Applications → Create App Integration → SAML 2.0**: **Single sign-on URL** = the ACS URL,
   **Audience URI (SP Entity ID)** = the SP entity id, **Name ID format** Persistent.
2. **Attribute statements:** `username` → `user.login`, `email` → `user.email`, `displayName` →
   `user.displayName`. **Group attribute statements:** `groups`, with a filter such as "Starts
   with `qualor-`".
3. Metadata URL: the app's **Metadata URL** on its Sign On tab.

### Google Workspace (SAML)

In the Admin console, **Apps → Web and mobile apps → Add custom SAML app**: **ACS URL** and
**Entity ID** as above, then map **Primary email** to an attribute `email`. Google's SSO URL
carries `?idpid=…`, which Qualor accepts. Its NameID is the primary email, so set Qualor's
**NameID format** to **Email address**.

## Who gets an account

At each sign-in Qualor looks for the account in this order:

1. **The known link:** the IdP's subject (OIDC `sub`, SAML NameID) on this connection, linked
   before. Once linked, the email and user name no longer matter: a person whose email changes at
   the IdP keeps their Qualor account.
2. **A SCIM record** of this connection that has not signed in yet, matched by its SCIM user name
   against the sign-in's username claim. Without a username claim, OIDC falls back to the email,
   only when the IdP marks it verified, and SAML to the NameID. A SCIM record of an instance admin
   is never matched this way: that sign-in is refused (`no_account`), and the admin links the
   account under **Settings → Linked accounts** instead.
3. **A verified email**, only when the connection has **Link to an existing account with the same
   verified email** ticked (`linkByEmail`, off by default). The IdP must have verified the email,
   exactly one active Qualor user may have it, and that user must not be an instance admin.
   Qualor **never links by user name**, and never by an unverified email.
4. **A new account** (just-in-time), when the connection has **Create an account at the first
   sign-in** ticked (`jit`, on by default). The user name comes from the username claim, else the
   email's local part. If it is taken, `-2` to `-20` is appended; an existing account of that
   name is never used. The new account has no password, no role until a group mapping or an org
   admin gives one, and an email only when it is verified and nobody else has it.
5. Otherwise the sign-in is refused (`no_account`).

A new account whose **verified** email already belongs to another Qualor user is refused
(`email_in_use`) rather than created twice. That person signs in to their existing account with its
password and links it under **Settings → Linked accounts**, or an admin turns on linking by
verified email.

### Choose a username claim the user cannot change

Step 2 gives the account SCIM made for a name to whoever signs in with that name. So the username
claim (or SAML attribute) must be one only the IdP's administrator can change, never the user:
Entra ID's user principal name, Okta's login, or Keycloak's username with editing turned off.

An email never matches unverified. A username claim or attribute that is the email counts only
when the email is verified (OIDC `email_verified`; SAML only with **This identity provider verifies
the email attribute** ticked), and so does a SAML NameID of the **Email address** format. Don't
point the username claim at the email claim unless the IdP verifies every email.

### Linking by email trusts every connection

An account's email can come from any enabled connection or its SCIM, and linking looks at every
account, whichever connection gave it its email. Say a partner's IdP gives one of its users
`ceo@corp.example`, so that user's Qualor account gets the email. When the real owner of the
address first signs in through a connection that links by email, they are linked to the partner
user's account, with its access. Turn **Link to an existing account with the same verified email**
on only when every connection, and its SCIM, is trusted to assert emails.

### Linked accounts and sessions

Every user can see, link and unlink their own linked accounts in **Settings → Linked accounts**.
An instance admin is never linked by email: they sign in with their password and link the
connection there. Two refusals keep people from locking themselves out:

- 409 `SCIM_MANAGED_IDENTITY`: a link the IdP made through SCIM can be removed only by an instance
  admin (`DELETE /api/v0/ee/sso/users/<user id>/identities/<id>`).
- 409 `LAST_SIGN_IN_METHOD`: the link is the user's last way to sign in. A password counts only if
  the current password policy lets this user sign in with it
  ([Password sign-in](#password-sign-in-and-break-glass-admins)); the emergency switch does not
  count. Another link counts only on a connection in effect
  ([One connection or several](#one-connection-or-several)). A user without a password cannot set
  one themselves, because changing a password needs the current one. An instance admin sets one
  first with **Reset password** on the user's row in **Settings → Users**, which ends that user's
  sessions and revokes their personal tokens.

**A password an admin set.** When an admin sets a user's password, the user must choose their own
at their next password sign-in. A single sign-on sign-in does not ask for it, because that session
did not use the password; the next password sign-in still does.

A single sign-on session lasts `QUALOR_SESSION_TTL_HOURS`, like any other. Signing out of Qualor
ends the Qualor session only, and signing out of the IdP does not end it (no single logout).
Deactivating a user, in Qualor or through SCIM, ends every session at once.

## Group mappings and sync

Each connection's **Groups come from** (`groupSource` in the API) is one of:

- **Nowhere: no group mappings**, the default: memberships are managed by hand.
- **The groups claim at each sign-in** (`claims`): sync runs at each sign-in. A sign-in whose
  groups claim is missing counts as no groups, so only `*` mappings apply to it.
- **SCIM provisioning** (`scim`): sync runs at each SCIM change.

The connection's **Group mappings** map a **Group** to a **Role** in an **Organization**, for the
**Whole organization** or one **Project**. **Add** a row, then **Save mappings**. The roles are:

- in an organisation: Organization admin (`admin`), Project admin, Maintainer (`member`) or
  Viewer;
- on one project: Project admin, Maintainer or Viewer.

Every mapping needs only `sso`: roles themselves need no licence
([Roles and the audit log](./roles-and-audit.md)). A mapping never makes anyone an instance admin.
The group value is matched exactly, case included: a claim value, or a SCIM group's external id,
else its display name. The value **`*`** matches everyone who signs in through the connection, a
default membership. A connection holds up to 500 mappings.

Sync gives each person the strongest mapped role per organisation and per project, and **owns only
the memberships it created**:

- sync changes or removes a membership it created when the groups change;
- it never touches a membership an org admin made by hand, or another connection's;
- **Settings → Members** marks sync's organisation memberships "From SSO group sync:
  *connection*". Project grants made by sync are not marked;
- **an org admin who changes such a membership's role by hand takes it over:** it becomes a manual
  membership and sync leaves it alone. Removing one by hand works too, but the next sync adds it
  back while the group still maps;
- **the organisation's last Organization admin is kept**: sync never removes or demotes it, and
  writes `sync kept the last admin` to the server log instead;
- a project that already has 1 000 roles granted directly on it gets no new grant from sync, which
  writes `sync skipped a project at its grant limit` to the server log instead.

Deleting a connection deletes its account links, mappings and SCIM tokens. People who sign in only
through it cannot sign in until an admin sets them a password. The memberships its sync granted
stay, as manual ones. While password sign-in is limited to break-glass admins, the last enabled
connection cannot be disabled or deleted (409 `LAST_SSO_CONNECTION`). Set **Password sign-in**
back to **Everyone with a password** first, or, on the Enterprise plan, enable another connection
first.

## One connection or several

On the **Enterprise plan** (a key listing `sso.multi`), every enabled connection is in effect: each
is a button on the sign-in page, up to 10 connections. On the **Business plan** (`sso` without
`sso.multi`), one connection signs people in at a time:

- You can store up to 10 connections, but **enable only one**. A new connection is created
  disabled, and **Enabled: show it on the sign-in page** cannot be ticked while another connection
  is enabled. You can still prepare it fully: fill it in, give the IdP its values, press **Test**
  or **Read metadata**, and add its group mappings.
- Creating a connection enabled, or enabling one, while another is enabled is refused with 409
  `SSO_MULTI_NOT_LICENSED`, and nothing is saved.
- Everything else (editing any connection, testing it, its mappings, deleting it) works as on the
  Enterprise plan.

**Settings → Single sign-on** notes the Business plan's limit under its title, and marks an enabled
connection that does not sign people in **Not in effect**. On the Enterprise plan it counts the
connections ("*N* of 10 connections"). In the API, each connection has `inEffect`: `true` when it
signs people in.

### Switch identity provider on the Business plan

Nothing is deleted when you switch, so you can switch back the same way.

1. In **Settings → Single sign-on**, add the new connection and save it. It stays disabled while
   the old connection is enabled.
2. Prepare it: copy its values into the new IdP, press **Test** (and **Read metadata** for SAML),
   and add its group mappings. It is not on the sign-in page yet.
3. If **Settings → Sign-in** has **Password sign-in** set to **Only the break-glass
   administrators**, set it to **Everyone with a password** for the switch. Otherwise disabling the
   old connection, the last enabled one, is refused (409 `LAST_SSO_CONNECTION`; the page says "Set
   password sign-in back to everyone first (Settings → Sign-in).").
4. To keep people's existing accounts rather than create new ones, tick **Link to an existing
   account with the same verified email (never an instance administrator)** on the new connection.
   Accounts are linked to the old connection only, so at the first sign-in through the new one
   Qualor finds them as in [Who gets an account](#who-gets-an-account).
5. **Edit** the old connection, untick **Enabled: show it on the sign-in page**, and **Save**.
6. Straight away, **Edit** the new connection, tick **Enabled: show it on the sign-in page**, and
   **Save**. Between steps 5 and 6 nobody can sign in with single sign-on. Check that the sign-in
   page shows the new connection, and sign in with it.
7. If you changed it in step 3, set **Password sign-in** back to **Only the break-glass
   administrators**.

Instance admins link their accounts by hand under **Settings → Linked accounts** once the new
connection is enabled. The old connection keeps its linked accounts, mappings and SCIM tokens.

On the Enterprise plan, enable the new connection first and disable the old one when you are
ready; both work in between.

### After a move to the Business plan

When `sso.multi` goes (a Business key replaces an Enterprise one, or the feature lapses), nothing is
deleted, disabled or changed. Every connection keeps its **Enabled** setting, its configuration,
linked accounts, mappings and SCIM tokens. But **only the oldest enabled connection** (the first
one created) is in effect. The other enabled connections leave the sign-in page, and **Settings →
Single sign-on** marks them **Not in effect**. A sign-in through one of them, even one started
before the change, ends with `unavailable` ("This sign-in method is not available."); the server
log's detail is `oidc.not_in_effect` or `saml.not_in_effect`.

- **To choose which connection works**, disable the one in effect: the next oldest enabled
  connection takes over at once. You cannot enable the first one again while another is enabled.
- **People whose accounts are linked only to a connection not in effect** cannot sign in with
  single sign-on. They can sign in with a password if the password sign-in setting lets them.
  Otherwise make their connection the one in effect, or set them a password (**Reset password** on
  the user's row in **Settings → Users**).
- **Unlinking** counts only links on the connection in effect (409 `LAST_SIGN_IN_METHOD`).
- **SCIM tokens** of a connection not in effect keep working while `scim` is licensed. The
  Business plan does not list `scim`, so SCIM stops there anyway
  ([When the licence lapses](#when-the-licence-lapses)).

With an Enterprise key again, every enabled connection is in effect at once.

## Password sign-in and break-glass admins

**Settings → Sign-in** (instance admins; `PUT /api/v0/ee/sso/settings`) chooses who may sign in
with a password, under **Password sign-in**: **Everyone with a password** (`everyone`, the
default), or **Only the break-glass administrators** (`break_glass_only`). Pick the **Break-glass
administrators**: up to 10 instance admins who are active and have a password. Saving "Only the
break-glass administrators" needs at least one such admin and at least one enabled connection
(otherwise 422 `VALIDATION_FAILED`, naming what is missing). While this setting is stored, the last
enabled connection cannot be disabled or deleted (409 `LAST_SSO_CONNECTION`). If you are not in
the list yourself, the page warns you that you will sign in with SSO from then on.

With break-glass admins only:

- the sign-in page shows the single sign-on buttons, with the password form folded under
  **Emergency administrator sign-in**;
- anyone else who types a correct password gets the same answer as a wrong one (401
  `INVALID_CREDENTIALS`), so the answer never tells whether the password was right. The audit log
  records a failed sign-in with the reason `password_disabled`;
- **API and CI tokens keep working unchanged**, and users who have a password can still change it;
- **Forgot password?** follows the same rule: only the break-glass admins get a reset link, the
  page answers everyone else the same way, and the link is checked again when it is used;
- **Settings → Users** sends no invitations (409 `PASSWORD_SIGN_IN_DISABLED`): new users sign in
  with single sign-on;
- an instance admin can still set a user's password, which the user can use once the policy
  allows. Setting it ends that user's sessions and revokes their personal tokens.

**Keeping a break-glass admin.** While the stored setting is "break-glass admins only", Qualor
refuses to deactivate or demote the last listed admin who could still use a password (409
`LAST_BREAK_GLASS_ADMIN`; through SCIM, 400 `mutability`). This guard follows the **stored**
setting, even while the emergency switch is on or the licence has lapsed, so nobody is locked out
once the switch is removed or the licence renewed. To remove the last one, set password sign-in
back to everyone first.

## If your identity provider is down

`QUALOR_FORCE_PASSWORD_SIGN_IN=true` is the emergency switch. It re-enables password sign-in for
**every user who has a password**, whatever **Settings → Sign-in** says.

1. Set it, and restart the server. With the Compose file of
   [Install the server](./install-server.md#the-compose-file), add
   `QUALOR_FORCE_PASSWORD_SIGN_IN=true` to `.env` and run `docker compose up -d server`; that
   file passes the variable from `.env` to the server. A Compose file of your own that does not
   pass it needs `QUALOR_FORCE_PASSWORD_SIGN_IN: 'true'` under the server's `environment:`
   instead. With Helm, set `config.forcePasswordSignIn: true` and run `helm upgrade`.
2. Sign in with a password and fix the connection or the IdP.
3. Remove the variable, and restart again.

While it is set:

- the server logs a warning at every start: `password sign-in forced by
  QUALOR_FORCE_PASSWORD_SIGN_IN`;
- with the audit log licensed, each start records `auth.password_sign_in_forced` with the stored
  policy, and each password sign-in that only the switch allowed is recorded as a sign-in marked
  `forced: true`;
- instance admins see a banner on every page that asks them to remove it once single sign-on
  works again. **Settings → Sign-in** says so too, and that its own setting takes effect again
  once the variable is removed and the server restarted.

Any value other than `true`, `false` or empty stops the server at start, with a message naming the
variable. Sessions made while it was set stay valid after it is removed, until they expire.

## SCIM with Entra ID and Okta

SCIM needs the **Enterprise plan** (a key listing `scim`); on the Business plan every SCIM request
answers 403 `FEATURE_NOT_LICENSED`. With SCIM, the IdP creates, updates, deactivates and deletes
Qualor accounts, and pushes groups. SCIM belongs to one single sign-on connection: its accounts
sign in through that connection.

**The base URL**, shown as **SCIM base URL** in **Settings → SCIM** (IdPs call it the tenant URL):

```text
https://qualor.example.com/api/v0/ee/scim/v2
```

**The token.** In **Settings → SCIM**, press **New token** in the connection's panel, enter a
**Token name** (and, if you want, **Expires on (optional)**), and press **Create token**. The
**SCIM token** looks like `qlr_scim_…` and is **shown once**, in **Your new SCIM token**: copy it,
then press **Done**. Qualor stores only its hash; the list shows how it **Starts with** and when it
was **Last used**. A connection has **at most 5** active tokens (409 `SCIM_TOKEN_LIMIT_REACHED`). A
token has no expiry unless you set one. **Revoke** a token when you replace it. The IdP sends it as
`Authorization: Bearer …`. Qualor's Gitleaks rule (`qualor-token`) finds `qlr_scim_` tokens like
the other `qlr_` tokens, so a leaked one is reported as a secret.

- **Entra ID:** in the enterprise application, **Provisioning → Automatic**: **Tenant URL** = the
  base URL, **Secret Token** = the token. Press **Test Connection**, map the attributes (below) and
  start provisioning.
- **Okta:** in the app's **General** tab, enable SCIM provisioning. Then, in **Provisioning →
  Integration**: **SCIM connector base URL** = the base URL, **Unique identifier field for users**
  `userName`, **Authentication Mode** HTTP Header, and the token as the Bearer value. Enable
  Create, Update and Deactivate Users, and push groups with **Push Groups**.

The Entra ID and Okta SCIM steps are not yet tested with real accounts.

**What Qualor keeps** of a user: `userName` (unique on the connection), `externalId`, the name
parts, `displayName`, the email and `active`. The email is the primary one, else the first work
one, else the first; a SCIM email counts as verified. Everything else, passwords and the enterprise
extension included, is accepted and ignored. SCIM owns these values: **the IdP may overwrite a
change made in Qualor**. **Settings → Users** says so on SCIM users, which carry a **SCIM** badge.

**What Qualor understands:**

- Filters: one `eq` comparison, on `userName`, `externalId`, `emails.value` (or
  `emails[type eq "work"].value`) and `id` for users, and on `displayName`, `externalId` and `id`
  for groups. Anything else, `and`, `or` and other operators included, answers 400
  `invalidFilter`. Pages hold at most 100.
- PATCH: `add`, `replace` and `remove` in any case (Entra sends `Replace`), with or without a
  `path`. Booleans as `true`/`false` or as the strings `"True"`/`"False"` (Entra's form). User
  paths such as `active`, `userName`, `displayName`, `name.givenName` and
  `emails[type eq "work"].value`. Group `members` added or removed as a list, or removed by
  `members[value eq "<id>"]` (Entra's form). Extension attributes are ignored.
- Not supported: bulk operations, sorting, ETags and password changes. The service provider
  configuration says so.

**Deactivation** (`active: false`) ends **every session** of the person and **revokes every
personal token** they have, in the same step. Reactivating does not bring the tokens back. Their
memberships stay, so a reactivated person gets their access back. SCIM reactivation also
**overrides a deactivation an admin made in Qualor**: the IdP is the source of truth for SCIM
users, so deactivate them at the IdP.

**Delete** (`DELETE /Users/{id}`) deactivates the person the same way, removes them from the
connection's SCIM groups, and removes the SCIM link. **The Qualor user row stays**, deactivated,
since analyses, issue changes and audit events name it. Creating the same person again with the
**same email** is then refused with 409 `uniqueness`, because the old account still has that email.
Change the old account's email, or reactivate it in **Settings → Users** and turn on linking by
verified email, so the new SCIM user links to it.

SCIM never deactivates or deletes the last active instance admin, or the last break-glass admin
while password sign-in is limited (400 `mutability`), and never makes anyone an instance admin.

**Groups** pushed by SCIM feed the connection's group mappings when its **Groups come from** is
**SCIM provisioning** ([Group mappings and sync](#group-mappings-and-sync)). Every change of a
group's members syncs those people at once.

**Limits.** A connection's SCIM service accepts 1 200 requests a minute per token (then 429 with
`Retry-After`), request bodies of at most 1 MiB, and `application/scim+json` or
`application/json`. An address that sends 60 requests with a wrong or missing token in a minute
gets 429 instead of 401 for further wrong tokens until the minute ends. A valid token from that
address still works, so a script with a revoked token cannot stop your IdP. Behind a reverse proxy,
set `QUALOR_TRUST_PROXY` ([Install the server](./install-server.md)) so Qualor counts each client's
own address, not the proxy's. A request that collides with another change in the database changes
nothing and gets 503 with `Retry-After`; the IdP retries it.

## Limits and rate limits

| What | Limit |
|---|---|
| Starting a sign-in | 30 a minute per address |
| Linking an account | 10 a minute per user |
| The OIDC callback, the SAML ACS, and the SAML finish step | 60 a minute per address each |
| `GET /api/v0/auth/methods` | 60 a minute per address |
| SCIM | 1 200 requests a minute per token; 60 failed authentications a minute per address |
| Connections, mappings, break-glass admins, SCIM tokens | 10 connections, 500 mappings per connection, 10 break-glass admins, 5 active SCIM tokens per connection |

A browser sign-in beyond its limit ends on the sign-in page with "Too many sign-in attempts. Wait a
minute and try again." (`rate_limited`).

## When the licence lapses

Nothing is deleted or rewritten, and nobody is locked out for good.

After `sso` lapses:

- the sign-in page shows no single sign-on button, and every single sign-on route answers 403
  `FEATURE_NOT_LICENSED`;
- **password sign-in is open to everyone who has a password**, whatever **Settings → Sign-in**
  says;
- **users without a password cannot sign in** until an instance admin sets one with **Reset
  password** on their row in **Settings → Users** (the **No password** filter lists them). They
  choose their own at the next sign-in. Setting a password ends that user's sessions and revokes
  their personal tokens, so their CI jobs need a new token;
- existing sessions stay valid until they expire, and API and CI tokens keep working;
- memberships from group sync stay as they are, and nothing syncs until the renewal;
- connections, links, mappings and the sign-in setting are kept, and a renewed key restores them.

After `scim` lapses:

- every SCIM request answers 403 `FEATURE_NOT_LICENSED`, and the IdP reports provisioning failures;
- **deprovisioning stops**: a person removed at the IdP keeps their Qualor account and tokens until
  an admin deactivates them in **Settings → Users**;
- tokens, SCIM users and groups are kept, and a renewed key resumes provisioning.

After `sso.multi` lapses, or a Business key replaces an Enterprise one, only the oldest enabled
connection signs people in, and nothing is deleted
([After a move to the Business plan](#after-a-move-to-the-business-plan)).

## What Qualor does not do

- **Single logout**, OIDC or SAML: signing out of Qualor does not sign you out of the IdP, nor the
  reverse.
- **IdP-initiated SAML** (starting from the IdP's app launcher): every SAML response must answer a
  request Qualor sent. Start from Qualor's sign-in page.
- **SCIM bulk operations, sorting and ETags.**
- Entra ID's multi-tenant `common` issuer and Azure AD B2C, `private_key_jwt` client
  authentication, encrypted ID tokens, a connection per organisation, or making anyone an instance
  admin from a group.

See [Troubleshooting](./troubleshooting.md#single-sign-on-and-scim) for every sign-in error and
[Webhooks and REST API](./webhooks-and-api.md#single-sign-on-and-scim-enterprise) for the API.
