# Single sign-on and SCIM

Single sign-on (OIDC and SAML 2.0) needs an enterprise licence listing `sso`. The Business plan
gives one enabled connection at a time; several identity providers at once need the Enterprise
plan (`sso.multi`, see [One connection or several](#one-connection-or-several)). SCIM provisioning
needs a key listing `scim`, which only the Enterprise plan lists
([Plans and prices](./enterprise.md#plans-and-prices)). Without them, people sign in with a
user name and password, and API and CI tokens work the same with or without single sign-on.

## What it adds and what it needs

- **Sign-in through your identity provider (IdP).** An instance admin adds connections (at most 10),
  each OIDC or SAML. Each connection in effect is a button on the sign-in page: "Sign in with
  *name*". On the Business plan that is one connection; on the Enterprise plan, every enabled one.
- **Accounts on first sign-in** (just-in-time), or linked to an existing account (see
  [Who gets an account](#who-gets-an-account)).
- **Group mappings:** IdP groups become organisation or project roles, and are kept in step at
  each sign-in or SCIM change.
- **Password sign-in for break-glass admins only**, if you want it, with an emergency switch for
  the day the IdP is down.
- **SCIM 2.0** (Enterprise plan), so Entra ID or Okta create, update and deactivate Qualor
  accounts for you.

It needs:

1. A licence key listing `sso`, applied as in [Enterprise](./enterprise.md#apply-a-key). Several
   identity providers at once need `sso.multi` too, and provisioning needs `scim`: both are in
   the Enterprise plan only.
2. **`QUALOR_PUBLIC_URL`** set to the address people open Qualor at
   ([server settings](./install-server.md#server-settings)). The redirect URI, the SAML entity id
   and the ACS URL are made from it, so a connection cannot be enabled without it (409
   `PUBLIC_URL_REQUIRED`). If you change `QUALOR_PUBLIC_URL` later, give the IdP the new values.
3. An IdP the server can reach over `https`. An IdP on your internal network, or one on plain
   `http` (a test Keycloak), must be listed in **`QUALOR_SSO_INTERNAL_HOSTS`**: comma-separated
   host names, each with an optional port, such as `keycloak.corp.example.com` or
   `keycloak:8080`. A private CA needs `NODE_EXTRA_CA_CERTS`, as for GitLab.

Only the server talks to the IdP, and only to the OIDC issuer you entered and the token, JWKS and
userinfo endpoints its discovery document names, or to a SAML metadata URL when an admin asks
Qualor to read it. The browser goes to the IdP's sign-in page; Qualor never calls it.

Connections live in **Settings → Single sign-on** (instance admins): **Add an OpenID Connect
connection** or **Add a SAML connection**, fill in the form and **Save**. Once saved, the connection
shows **Values for the identity provider** to copy, **Check the connection** with **Test** (and
**Read metadata** for SAML), and its **Group mappings**. **Edit** opens it again; **Delete the
connection** removes it.

## Add an OIDC connection

Qualor uses the authorization code flow with PKCE, a nonce and a state, and checks the ID token's
signature, issuer, audience, expiry and issue time. It needs a **confidential client** (a client
id and a client secret).

Copy this value into the IdP, from **Values for the identity provider**:

| Qualor's label | IdP asks for | Value |
|---|---|---|
| **Redirect URI** | redirect URI (callback, reply URL) | `https://qualor.example.com/api/v0/ee/sso/oidc/<connection id>/callback` |

And fill in **New OpenID Connect connection** in Qualor:

| Field | What to enter |
|---|---|
| **Name** | the button text: the sign-in button says "Sign in with" and this name |
| **Issuer URL** | the issuer exactly as the IdP's discovery document names it. Qualor keeps it **exactly as entered, a trailing slash included**, and requires `/.well-known/openid-configuration` below it to name the same issuer, character for character |
| **Client id**, **Client secret** | from the IdP. The secret is stored encrypted and never shown again (**Set. It is never shown again.**; **Change** replaces it); a changed issuer needs the secret again |
| **Client authentication** | `client_secret_basic` (the default) or `client_secret_post` |
| **Scopes** | `openid email profile` by default; `openid` is required |
| **Also read the userinfo endpoint** | off by default; turn it on for an IdP that sends the email or groups only there |
| **Username claim**, **Email claim**, **Display name claim**, **Groups claim** | where to read each (`preferred_username`, `email`, `name`; the groups claim is `groups` once groups come from claims). Leave one empty to not read it. The username claim matches accounts SCIM made (see [Who gets an account](#who-gets-an-account)), so it must be one **only the IdP's administrator can change**, never the user: Entra ID's UPN, Okta's login, Keycloak's username with editing turned off. Don't point it at the email claim unless the IdP verifies every email; Qualor uses it for matching only when that sign-in's email is verified (`email_verified`) |

The **Accounts** part of the form is the same for both protocols: **Create an account at the first
sign-in**, **Link to an existing account with the same verified email (never an instance
administrator)**, **Required claims (optional)** (one `claim=value` a line, at most 5, such as
`hd=example.com`), and **Groups come from** (see [Group mappings](#group-mappings-and-sync)).

Press **Test** under **Check the connection**: it reads the discovery document and the JWKS now and
lists the **Authorization endpoint** (the page people's browsers open) and the **Token endpoint**,
**JWKS** and **Userinfo endpoint** that Qualor's server will call ("The test passed."). Then tick
**Enabled: show it on the sign-in page** and **Save**.

**Emails:** Qualor stores and links an OIDC email only when the IdP marks it verified
(`email_verified: true`, the JSON boolean). **An unverified email is never stored, and never used
to link an account.** An IdP that does not send `email_verified` gives Qualor accounts without an
email; SCIM (below) fills them in.

### Keycloak

Tested automatically, against Keycloak 26.7.4.

1. In your realm, **Clients → Create client**: type OpenID Connect, a client id such as `qualor`,
   **Client authentication** on, **Standard flow** only.
2. **Valid redirect URIs:** the redirect URI above.
3. For groups: in the client's dedicated scope, add a **Group Membership** mapper, token claim name
   `groups`, **Full group path** off, added to the ID token.
4. In Qualor: issuer `https://<keycloak host>/realms/<realm>`, the client id, and the secret from
   the client's **Credentials** tab. Keycloak sends `preferred_username`, `email`,
   `email_verified` and `name`.

### Microsoft Entra ID

Not yet tested with a real account.

1. **App registrations → New registration**, platform **Web**, redirect URI as above. Under
   **Certificates & secrets**, create a client secret.
2. Issuer: **`https://login.microsoftonline.com/<tenant id>/v2.0`**, with your tenant's id.
   **The multi-tenant `common` (and `organizations`) endpoints and Azure AD B2C are not supported
   yet**: their discovery document names an issuer other than the URL it is read from, which
   Qualor refuses.
3. The username claim is `preferred_username` (the user principal name).
4. Groups: **Token configuration → Add groups claim**. Entra sends each group's **object id**, not
   its name, so map the object ids in Qualor. A person in very many groups gets no groups claim at
   all from Entra (it points to Microsoft Graph instead), so prefer **Groups assigned to the
   application**. The claim is `groups`.

### Okta

Not yet tested with a real account.

1. **Applications → Create App Integration**, OIDC, **Web Application**; **Sign-in redirect URI**
   as above; grant type Authorization Code.
2. Issuer: your Okta domain (`https://<your domain>.okta.com`) for the org authorization server,
   or the custom authorization server's issuer (`https://<your domain>.okta.com/oauth2/default`),
   as its discovery document shows it.
3. Groups: on the app's **Sign On** tab, set a **Groups claim filter** named `groups` (for example
   "Starts with `qualor-`"), and add `groups` to the scopes in Qualor. Okta sends group names.

### Google Workspace

Not yet tested with a real account.

1. Google Cloud console, **APIs & Services → Credentials → Create OAuth client ID**, type **Web
   application**, with the redirect URI as an authorised redirect URI.
2. Issuer: `https://accounts.google.com`.
3. Any Google account can sign in to such a client, so add `hd=example.com` (your Workspace
   domain) under **Required claims (optional)**: a sign-in without that exact value is refused
   (`required_claim`). A connection takes up to 5 required claims.
4. Google sends no groups claim. To give everyone the same starting role, set **Groups come from**
   to **The groups claim at each sign-in** and add a `*` group mapping (see
   [Group mappings](#group-mappings-and-sync)); or manage memberships by hand.

## Add a SAML connection

Qualor uses SAML 2.0 Web SSO: requests by HTTP-Redirect, responses by HTTP-POST. Copy these values
into the IdP, from **Values for the identity provider**:

| Qualor's label | IdP asks for | Value |
|---|---|---|
| **ACS URL** | ACS URL (reply URL, single sign-on URL) | `https://qualor.example.com/api/v0/ee/sso/saml/<connection id>/acs` |
| **Entity id (SP)** | SP entity id (identifier, audience URI) | `https://qualor.example.com/api/v0/ee/sso/saml/<connection id>/metadata` |
| **SP metadata URL** | SP metadata, for IdPs that import it | the same URL: it serves Qualor's metadata XML |

Then give Qualor the IdP's side in **New SAML connection**, either **from its metadata URL** or
**by hand**. For the metadata URL, save it first, then press **Read metadata**: Qualor reads it
once (never on a schedule) and shows **What the metadata would change**, with the entity id, the
SSO URL and the **Signing certificates** with their **SHA-256** fingerprints. Nothing is saved
until you press **Save these values** (or **Discard**); check the fingerprints with the IdP first,
because the metadata document itself is not signed.

| Field | What to enter |
|---|---|
| **Identity provider entity id** | the IdP's issuer. Every response and assertion must name it |
| **SSO URL (HTTP-Redirect)** | the IdP's single sign-on URL. It may carry a query, such as Google's `?idpid=…` |
| **Metadata URL (optional)** | may carry a query too, such as Entra ID's `?appid=…` |
| **Signing certificates (PEM, 1 to 3)** | several while the IdP rotates its key: RSA of 2048 bits or more, or EC. Once saved, each is listed with its **SHA-256** fingerprint and "valid until" date. An **Expired** certificate still works, because IdPs often sign with expired self-signed ones |
| **NameID format** | **Persistent (recommended)**, **Email address** or **Unspecified** |
| **Username claim**, **Email claim**, **Display name claim**, **Groups claim** | the attribute names (`email` and `displayName` by default). An empty username uses the NameID |
| **This identity provider verifies the email attribute** | off by default. SAML has no "verified" flag, so tick it only if the IdP's email attribute is one it verified. Without it, the email is not stored, and not used to link |
| **Also require a signature on the whole response** | off by default. The assertion itself must always be signed |

The **Accounts** fields are those of OIDC above.

**Send a username attribute.** Without one, the NameID becomes the Qualor user name. Keycloak's
persistent NameID, for example, is an opaque `G-<uuid>`, so a new account would be called
`G-3f2a…`. Name the IdP's username attribute in **Username claim** instead. Pick one that only the
IdP's administrators can change (Entra ID's user principal name, Okta's login, Keycloak's username
with editing turned off), because Qualor uses it to match accounts provisioned by SCIM (see
[Who gets an account](#who-gets-an-account)).

**Groups:** the whole sign-in, groups included, must fit in 16 KiB, and more than 1 000 group
values are refused. That is roughly 350 Entra group ids, fewer with long group names. A sign-in
over the limit is refused (`invalid_response`), never cut short, because a cut would drop access at
random. Send only the groups Qualor needs (filter them at the IdP).

**SHA-256 or stronger is required.** Qualor refuses responses signed or digested with SHA-1, and
comments, DOCTYPEs and processing instructions anywhere in a response. If your IdP signs with
SHA-1, switch it: in Keycloak, the client's **Signature algorithm** `RSA_SHA256`; in Entra ID,
**SAML Signing Certificate → Signing Algorithm** `SHA-256`; in Okta, **Signature Algorithm**
`RSA_SHA256`; in AD FS, the relying party trust's **Advanced → Secure hash algorithm** `SHA-256`.

**The service provider key (optional).** By default Qualor's requests are unsigned and it refuses
encrypted assertions; TLS protects them. To sign requests and accept encrypted assertions, make a
key pair and paste both under **Service provider key (optional)**, **Private key** and
**Certificate**:

```sh
openssl req -x509 -newkey rsa:3072 -nodes -keyout sp.key -out sp.crt -days 3650 -subj "/CN=qualor-sp"
```

The key must be an unencrypted PKCS#8 RSA key of 2048 to 4096 bits (what this command writes). It is
stored encrypted and never shown again. The SP metadata then offers the certificate, so the IdP
can encrypt to it.

### Keycloak (SAML)

Qualor's automated test signs in through a Keycloak 26.7.4 SAML client with signed assertions,
`RSA_SHA256`, a persistent NameID and the `email`, `displayName` and `groups` mappers, but **no
username mapper**: it checks that the account is then named after the NameID (`G-<uuid>`). The
`username` mapper of step 3 is not part of that test; add it anyway, so accounts get readable
names.

1. **Clients → Create client**, type SAML, **Client ID** = the SP entity id; **Valid redirect
   URIs** and **Assertion Consumer Service POST Binding URL** = the ACS URL.
2. **Sign assertions** on, **Signature algorithm** `RSA_SHA256`, **Name ID format** `persistent`.
3. Mappers (in the client's dedicated scope): a **User Property** `email` → attribute `email`, a
   **User Property** `username` → attribute `username`, a **User Property** `firstName` (or a
   full name) → attribute `displayName`, and a **Group list** → attribute `groups` with **Full
   group path** off.
4. In Qualor: metadata URL `https://<keycloak host>/realms/<realm>/protocol/saml/descriptor`, and
   the attributes `username`, `email`, `displayName`, `groups`.

### Microsoft Entra ID (SAML)

Not yet tested with a real account.

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

Not yet tested with a real account.

1. **Applications → Create App Integration → SAML 2.0**: **Single sign-on URL** = the ACS URL,
   **Audience URI (SP Entity ID)** = the SP entity id, **Name ID format** Persistent.
2. **Attribute statements:** `username` → `user.login`, `email` → `user.email`, `displayName` →
   `user.displayName`. **Group attribute statements:** `groups`, with a filter such as "Starts
   with `qualor-`".
3. Metadata URL: the app's **Metadata URL** on its Sign On tab.

### Google Workspace (SAML)

Not yet tested with a real account. In the Admin console, **Apps → Web and mobile apps → Add custom
SAML app**: **ACS URL** and **Entity ID** as above, then map **Primary email** to an attribute
`email`. Google's SSO URL carries `?idpid=…`, which Qualor accepts. Its NameID is the primary email,
so set Qualor's **NameID format** to **Email address**.

## Who gets an account

At each sign-in Qualor looks for the account in this order:

1. **The known link:** the IdP's subject (OIDC `sub`, SAML NameID) on this connection, linked
   before. Once linked, the email and user name no longer matter: a person whose email changes at
   the IdP keeps their Qualor account.
2. **A SCIM record** of this connection that has not signed in yet, matched by its SCIM user name
   against the sign-in's username claim. Without a username claim, OIDC falls back to the email
   only when the IdP marks it verified, and SAML to the NameID. The username claim (or attribute)
   must be one only the IdP's administrator can change, since whoever can set it can take over
   the account SCIM made for that name. An email never matches unverified: a username claim or
   attribute that is the email one counts only when the email is verified (OIDC `email_verified`;
   SAML only with **This identity provider verifies the email attribute** ticked), and so does a
   SAML NameID of the **Email address** format. So don't point the username claim at the email
   claim unless the IdP verifies every email. A SCIM record of an instance admin is never matched
   this way: that sign-in is refused (`no_account`), and the admin links the account under
   **Settings → Linked accounts** instead.
3. **A verified email**, only when the connection has **Link to an existing account with the same
   verified email** ticked (`linkByEmail`, off by default): the email must be verified by the IdP,
   exactly one active Qualor user may have it, and that user must not be an instance admin.
   Qualor **never links by user name**, and never by an unverified email.
4. **A new account** (just-in-time), when the connection has **Create an account at the first
   sign-in** ticked (`jit`, on by default). The user name comes from the username claim, else the
   email's local part; if it is taken, `-2` to `-20` is appended, and an existing account of that
   name is never used. The new account has no password, no role until a group mapping or an org
   admin gives one, and an email only when it is verified and nobody else has it.
5. Otherwise the sign-in is refused (`no_account`).

A new account whose **verified** email already belongs to another Qualor user is refused
(`email_in_use`), rather than created a second time. That person signs in to their existing
account with its password and links it under **Settings → Linked accounts**, or an admin turns on
linking by verified email.

**Linking by email trusts every connection.** An account's email can come from any enabled
connection (a verified email at sign-in) or from its SCIM, and linking looks at every account,
whichever connection gave it its email. If a less trusted IdP (a partner's tenant, say) gives one
of its own users `ceo@corp.example`, the Qualor account of that user gets the email; when the real
owner of that address first signs in through a connection with linking by email on, they are
linked to the partner user's account, with its access. Turn **Link to an existing account with the
same verified email** on only when every connection, and its SCIM, is trusted to assert emails.

**Instance admins link by hand.** An instance admin is never linked by email: they sign in with
their password and use **Settings → Linked accounts** to link the connection. Every user can see
and unlink their own linked accounts there. Two refusals keep people from locking themselves out:

- 409 `SCIM_MANAGED_IDENTITY`: an account link the IdP made through SCIM can be removed only by an
  instance admin (`DELETE /api/v0/ee/sso/users/<user id>/identities/<id>`).
- 409 `LAST_SIGN_IN_METHOD`: the link is the last way this user can sign in. A password counts only
  if the current password policy lets this user sign in with it (see
  [Password sign-in](#password-sign-in-and-break-glass-admins)), and another link counts only on
  a connection in effect ([One connection or several](#one-connection-or-several)). A user
  without a password cannot set one themselves (changing a password needs the current one): ask
  an instance admin to set one first (**Settings → Users → Reset a password**), which ends that
  user's sessions and revokes their personal tokens. It counts only while password sign-in is
  allowed for them. The emergency switch below does not count.

Signing out of Qualor ends the Qualor session only: Qualor does no single logout, and signing out
of the IdP does not end a Qualor session. A session lasts `QUALOR_SESSION_TTL_HOURS`, like any
other. Deactivating a user, in Qualor or through SCIM, ends every session at once.

## Group mappings and sync

Each connection's **Groups come from** (`groupSource` in the API) is **Nowhere: no group
mappings** (the default: memberships are managed by hand), **The groups claim at each sign-in**
(`claims`), or **SCIM provisioning** (`scim`). The connection's **Group mappings** then map a
**Group** to a **Role** in an **Organization**, for the **Whole organization** or one **Project**
(**Add** a row, then **Save mappings**):

- in an **organisation**: Organization admin (`admin`), Project admin, Maintainer (`member`) or
  Viewer;
- or on **one project**: Project admin, Maintainer or Viewer.

Every role and every project mapping needs only `sso`: roles themselves need no licence
([Roles and the audit log](./roles-and-audit.md)). A mapping never makes anyone an instance admin.
The group value is matched exactly, case included: a claim value, or a SCIM group's external id,
else its display name. The value **`*`** matches everyone who signs in through the connection, a
default membership. A connection holds up to 500 mappings.

Sync gives each person the strongest mapped role per organisation and per project, and **owns only
the memberships it created**:

- a membership sync created is changed or removed by sync when the groups change;
- a membership an org admin made by hand, or another connection's, is never touched;
- **Settings → Members** marks sync's organisation memberships "From SSO group sync:
  *connection*" (project grants made by sync are not marked yet);
- **an org admin who changes such a membership's role by hand takes it over:** from then on it is a
  manual membership and sync leaves it alone. Removing one by hand works too, but the next sync adds
  it back while the group still maps;
- **the organisation's last Organization admin is kept**: sync never removes or demotes it, and
  writes `sync kept the last admin` to the server log instead;
- a project that already has 1 000 roles granted directly on it gets no new grant from sync, which
  writes `sync skipped a project at its grant limit` to the server log instead.

With groups from claims, sync runs at each sign-in; with SCIM, at each SCIM change. A sign-in
whose groups claim is missing counts as no groups, so only `*` mappings apply to it.

Deleting a connection deletes its account links, mappings and SCIM tokens: people who sign in only
through it cannot sign in until an admin sets them a password. The memberships its sync granted
stay, as manual ones. While password sign-in is limited to break-glass admins, the last enabled
connection cannot be disabled or deleted (409 `LAST_SSO_CONNECTION`): set **Password sign-in**
back to **Everyone with a password** first, or, on the Enterprise plan, enable another connection
first.

## One connection or several

On the **Enterprise plan** (a key listing `sso.multi`), every enabled connection is in effect: each
is a button on the sign-in page, up to 10 connections. On the **Business plan** (`sso` without
`sso.multi`), one connection signs people in at a time:

- You can still store up to 10 connections, but you can **enable only one**. A new connection is
  created disabled, and you can prepare it fully while another is enabled: fill it in, give the
  IdP its values, press **Test** or **Read metadata**, and add its group mappings.
- Creating a connection enabled, or enabling one, while another connection is enabled is refused
  with 409 `SSO_MULTI_NOT_LICENSED`: "Your plan allows one enabled single sign-on connection.
  Disable the enabled one first, or keep this one disabled; several enabled connections need the
  Enterprise plan." Nothing is saved.
- Everything else (editing any connection, testing it, its mappings, deleting it) works as on the
  Enterprise plan.

What **Settings → Single sign-on** shows:

- On the Business plan, a note under the title: "Your plan signs people in through one single
  sign-on connection at a time. Connecting several identity providers needs the Enterprise plan."
- While another connection is enabled, **Enabled: show it on the sign-in page** is unticked and
  cannot be ticked, with "It stays disabled while another connection is enabled."
- An enabled connection that is not in effect has a **Not in effect** badge, and the page adds
  "Only the oldest enabled connection signs people in on your plan. Disable the one in effect to
  use this one instead, or restore the Enterprise plan."
- On the Enterprise plan, the page counts the connections: "*N* of 10 connections".

In the API, each connection has `inEffect`: `true` when it signs people in.

### Switch identity provider on the Business plan

Nothing is deleted when you switch, so you can switch back the same way.

1. In **Settings → Single sign-on**, add the new connection. **Enabled: show it on the sign-in
   page** is already unticked, and cannot be ticked while the old connection is enabled. Save it.
2. Prepare it: copy its values into the new IdP, press **Test** (and **Read metadata** for SAML),
   and add its group mappings. It does not appear on the sign-in page yet.
3. If **Settings → Sign-in** has **Password sign-in** set to **Only the break-glass
   administrators**, set it to **Everyone with a password** for the switch. Otherwise disabling
   the old connection, the last enabled one, is refused (409 `LAST_SSO_CONNECTION`; the page
   says "Set password sign-in back to everyone first (Settings → Sign-in).").
4. **Edit** the old connection, untick **Enabled: show it on the sign-in page**, and **Save**.
5. **Edit** the new connection, tick **Enabled: show it on the sign-in page**, and **Save**. Check
   that the sign-in page shows it, and sign in with it.
6. If you changed it in step 3, set **Password sign-in** back to **Only the break-glass
   administrators**.

Between steps 4 and 5 nobody can sign in with single sign-on, so do them one after the other. The
old connection keeps its linked accounts, mappings and SCIM tokens. People's accounts are linked
to the old connection only: at their first sign-in through the new one, Qualor finds their account
as in [Who gets an account](#who-gets-an-account). To keep their existing accounts rather than
create new ones, tick **Link to an existing account with the same verified email (never an
instance administrator)** on the new connection before step 5; instance admins link theirs by hand
under **Settings → Linked accounts** once it is enabled.

On the Enterprise plan you enable the new connection first and disable the old one when you are
ready; both work in between.

### After a move to the Business plan

When `sso.multi` goes (a Business key replaces an Enterprise one, or the feature lapses), nothing is
deleted, disabled or changed. Every connection keeps its **Enabled** setting, its configuration,
linked accounts, mappings and SCIM tokens. But **only the oldest enabled connection** (the first
one created) is in effect. The other enabled connections are not on the sign-in page, and a
sign-in through one of them, even one started before the change, ends with `unavailable` ("This
sign-in method is not available."); the server log's detail is `oidc.not_in_effect` or
`saml.not_in_effect`. In **Settings → Single sign-on** those connections have a **Not in effect**
badge, with the note "Only the oldest enabled connection signs people in on your plan. Disable the
one in effect to use this one instead, or restore the Enterprise plan."

- **To choose which connection works**, disable the one in effect: the next oldest enabled
  connection takes over at once. You cannot enable the first one again while another is enabled.
- **People whose accounts are linked only to a connection not in effect** cannot sign in with
  single sign-on. They can sign in with a password if the password sign-in setting lets them; or
  make their connection the one in effect, or set them a password (**Settings → Users → Reset a
  password**).
- **Unlinking** counts only links on the connection in effect (409 `LAST_SIGN_IN_METHOD`).
- **SCIM tokens** of a connection not in effect keep working while `scim` is licensed. On the
  Business plan `scim` is not, so SCIM stops there anyway
  ([When the licence lapses](#when-the-licence-lapses)).

With an Enterprise key again, every enabled connection is in effect at once.

## Password sign-in and break-glass admins

**Settings → Sign-in** (instance admins; `PUT /api/v0/ee/sso/settings`) chooses who may sign in
with a password, under **Password sign-in**: **Everyone with a password** (`everyone`, the
default), or **Only the break-glass administrators** (`break_glass_only`). Pick the
**Break-glass administrators**: up to 10 instance admins, who must be active and have a password
(someone without one cannot be picked). Saving "Only the break-glass administrators" needs at least
one such admin and at least one enabled connection (422 `VALIDATION_FAILED` otherwise, naming
what is missing). Afterwards the last enabled connection cannot be disabled or deleted while this
setting is stored (409 `LAST_SSO_CONNECTION`). If you are not in the list yourself, the page
warns: "You are not a break-glass administrator: you will sign in with SSO from now on."

With break-glass admins only:

- the sign-in page shows the single sign-on buttons, with the password form folded under
  **Emergency administrator sign-in**;
- anyone else who types a correct password gets the same answer as a wrong one (401
  `INVALID_CREDENTIALS`), so the answer never tells whether the password was right. The audit log
  records it as a failed sign-in with the reason `password_disabled`;
- **API and CI tokens keep working unchanged**, and so does changing your own password (for users
  who have one);
- an instance admin can still set a user's password; the user can use it once the policy allows.
  Setting it ends that user's sessions and revokes their personal tokens.

**Keeping a break-glass admin.** While the stored setting says "break-glass admins only", Qualor
refuses to deactivate or demote the last listed admin who could still use a password (409
`LAST_BREAK_GLASS_ADMIN`; through SCIM, a 400 `mutability`). This guard follows the **stored**
setting, even while the emergency switch is on or the licence has lapsed, so nobody is locked out
once the switch is removed or the licence renewed. To remove the last one, set password sign-in
back to everyone first.

## If your identity provider is down

`QUALOR_FORCE_PASSWORD_SIGN_IN=true` re-enables password sign-in for **every user who has a
password**, whatever **Settings → Sign-in** says. It is the emergency switch:

1. Set it, and restart the server. With the Compose file of
   [Install the server](./install-server.md#the-compose-file), add
   `QUALOR_FORCE_PASSWORD_SIGN_IN=true` to `.env` and run `docker compose up -d server`; that
   file passes the variable from `.env` to the server. A Compose file of your own that does not
   pass it needs `QUALOR_FORCE_PASSWORD_SIGN_IN: 'true'` under the server's `environment:`
   instead. With Helm, set `config.forcePasswordSignIn: true` and run `helm upgrade`.
2. Sign in with a password and fix the connection (or the IdP).
3. Remove the variable, and restart again.

While it is set:

- the server writes a warning at every start: `password sign-in forced by
  QUALOR_FORCE_PASSWORD_SIGN_IN`;
- with the audit log licensed, each start records `auth.password_sign_in_forced`, with the stored
  policy; each password sign-in that only the switch allowed is recorded as a sign-in marked
  `forced: true`;
- instance admins see a banner on every page: "Password sign-in is forced on by
  QUALOR_FORCE_PASSWORD_SIGN_IN. Remove it once single sign-on works again." **Settings → Sign-in**
  says so too, and that its setting takes effect again once the variable is removed and the server
  restarted.

Any value other than `true`, `false` or empty stops the server at start, with a message naming the
variable. Sessions made while it was set stay valid after it is removed, until they expire.

## SCIM with Entra ID and Okta

SCIM needs the **Enterprise plan** (a key listing `scim`); on the Business plan every SCIM request
answers 403 `FEATURE_NOT_LICENSED`. SCIM lets the IdP create, update, deactivate and delete Qualor
accounts, and push groups. It belongs to one SSO connection: its accounts sign in through that
connection.

**The base URL** (the "tenant URL"), shown as **SCIM base URL** in **Settings → SCIM**:

```text
https://qualor.example.com/api/v0/ee/scim/v2
```

**The token.** In **Settings → SCIM**, in the connection's section, give a **Token name**
(and optionally **Expires on (optional)**) and press **Create token**. The **SCIM token** looks
like `qlr_scim_…`, is **shown once**, and is stored only as a hash; the list then shows only how
it **Starts with**, and when it was **Last used**. A connection has **at most 5** active tokens (409
`SCIM_TOKEN_LIMIT_REACHED`); a token may have an expiry (none by default); revoke one when you
replace it (**Revoke**). Qualor's Gitleaks rule (`qualor-token`) finds `qlr_scim_` tokens like the
other `qlr_` tokens, so a leaked one is reported as a secret. The IdP sends it as
`Authorization: Bearer …`.

- **Entra ID:** in the enterprise application, **Provisioning → Automatic**: **Tenant URL** = the
  base URL, **Secret Token** = the token; **Test Connection**, then map the attributes (below)
  and start provisioning. Not yet tested with a real account.
- **Okta:** in the app's **General** tab enable SCIM provisioning, then **Provisioning →
  Integration**: **SCIM connector base URL** = the base URL, **Unique identifier field for users**
  `userName`, **Authentication Mode** HTTP Header, the token as the Bearer value; enable Create,
  Update and Deactivate Users; push groups with **Push Groups**. Not yet tested with a real account.

**What Qualor keeps** of a user: `userName` (unique on the connection), `externalId`, the name
parts, `displayName`, the email (the primary one, else the first work one, else the first; a
SCIM email counts as verified) and `active`. Everything else, including passwords and the
enterprise extension, is accepted and ignored. SCIM owns these values: **the IdP may overwrite a
change made in Qualor** (**Settings → Users** says so on SCIM users, with a **SCIM** badge).

**What Qualor understands:**

- Filters: one `eq` comparison: `userName`, `externalId`, `emails.value` (or
  `emails[type eq "work"].value`) and `id` for users; `displayName`, `externalId` and `id` for
  groups. Anything else, `and`, `or` and other operators included, is 400 `invalidFilter`. Pages of
  at most 100.
- PATCH: `add`, `replace` and `remove` in any case (Entra sends `Replace`), with or without a
  `path`; booleans as `true`/`false` or as the strings `"True"`/`"False"` (Entra's form); user
  paths such as `active`, `userName`, `displayName`, `name.givenName`,
  `emails[type eq "work"].value`; group `members` added or removed as a list, or removed by
  `members[value eq "<id>"]` (Entra's form). Extension attributes are ignored.
- Not supported: bulk operations, sorting, ETags and password changes (the service provider
  configuration says so).

**Deactivation** (`active: false`) signs the person out everywhere (**every session ends**) and
**revokes every personal token** they have, in the same step; reactivating does not bring the
tokens back. Their memberships stay, so a reactivated person gets their access back. SCIM
reactivation also **overrides a deactivation an admin made in Qualor**: the IdP is the source of
truth for SCIM users, so deactivate them at the IdP.

**Delete** (`DELETE /Users/{id}`) deactivates the person the same way, removes them from the
connection's SCIM groups, and removes the SCIM link. **The Qualor user row stays**, deactivated,
because analyses, issue changes and audit events name it. Creating the same person again with the
**same email** is then refused with 409 `uniqueness`, because the old account still has that
email: change the old account's email, or reactivate it in **Settings → Users** and turn on
linking by verified email, so the new SCIM user links to it.

SCIM never deactivates or deletes the last active instance admin, or the last break-glass admin
while password sign-in is limited (400 `mutability`), and never makes anyone an instance admin.

**Groups:** groups pushed by SCIM are matched by their external id, else their display name,
against the connection's group mappings, when its **Groups come from** is **SCIM provisioning**.
Every change of a group's members syncs those people at once.

A connection's SCIM service accepts 1 200 requests a minute per token (then 429 with
`Retry-After`), request bodies of at most 1 MiB, and `application/scim+json` or
`application/json`. An address that sends 60 requests with a wrong or missing token in a minute
gets 429 instead of 401 for its further wrong tokens for the rest of that minute; a valid token
from the same address still works, so another client behind the same address (a script with a
revoked token, say) cannot stop your IdP. Behind a reverse proxy, set `QUALOR_TRUST_PROXY`
([Install the server](./install-server.md)) so Qualor counts each client's own address, not the
proxy's. A request that collides with another change in the database
changes nothing and gets 503 with `Retry-After`; the IdP retries it.

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
- **users without a password cannot sign in** until an instance admin sets one in **Settings →
  Users → Reset a password** (the **No password** filter lists them); they choose their own at the
  next sign-in. Setting a password ends that user's sessions and revokes their personal tokens,
  so their CI jobs need a new token;
- existing sessions stay valid until they expire, and API and CI tokens keep working;
- memberships from group sync stay as they are; nothing syncs until the renewal;
- connections, links, mappings and the sign-in setting are kept, and a renewed key restores them.

After `scim` lapses:

- every SCIM request answers 403 `FEATURE_NOT_LICENSED`, and the IdP reports provisioning failures;
- **deprovisioning stops**: a person removed at the IdP keeps their Qualor account and tokens until
  an admin deactivates them in **Settings → Users**;
- tokens, SCIM users and groups are kept, and a renewed key resumes provisioning.

After `sso.multi` lapses, or a Business key replaces an Enterprise one, only the oldest enabled
connection signs people in, and nothing is deleted (see
[After a move to the Business plan](#after-a-move-to-the-business-plan)).

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
