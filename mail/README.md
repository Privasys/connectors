# Mail Connector

Reads one mailbox on behalf of one attested agent, under a capability the
holder approved on their own device. **Today it drafts; it does not send.**

## What it does, and what it deliberately does not

An agent can see what arrived, read a message, follow a conversation, search
years of mail through the provider's own index, read the holder's own sent
text to learn how they write, label what it triaged, and leave a reply in the
Drafts folder for the holder to read and send themselves.

This release cannot send a message, delete mail, move anything between
folders, or write a label outside the `Privasys/` namespace. Those are not
settings. There is no send method on the driver interface, so "it does not
send" is a property of the shape of the code rather than a promise about its
behaviour.

Sending is on the way: an agent that has to hand every reply back to a
person automates half a process. It will arrive the way everything here
does, as a method on the driver and a permission of its own that the holder
grants on their device, never as a default switched on, and never implied by
the permission to read.

## Where things live

**The connector keeps no durable user state.** Literally: the mailbox
credential is at rest only on the holder's own device and in use only in the
memory of this attested process. The holder signs in once, or types an app
password once, on their wallet's approval screen; the wallet keeps what it
sent, and the one thing this service asked it to keep, and sends them again
the next time this service asks. There is no sealing key, no volume with
anything of the holder's on it, no storage peer and no second approval to
obtain before the first. The holder's revoke is honoured here, in the one
place the credential exists.

**A restart forgets everything**, credentials and capabilities alike. That is
the price the design accepts. Each holder then gets one request on their
phone at the next use, and their unattended runs wait until they answer it.

**Mail is never stored.** The provider stays the system of record; bodies live
in memory for the length of one call. Searching uses the provider's index,
which covers years of mail that this service does not hold a byte of.

## Reading a message

What an agent receives is not the raw MIME. The connector reads the first
non-attachment `text/plain` leaf, falling back to `text/html`, decodes the
transfer encoding, converts the charset, removes the quoted history and the
signature, and strips credentials. Attachments are listed, never fetched.

The credential filter is the connector's job rather than the skill's, because
it must hold when the model has been talked into something. The attack it
defeats is not persuasion but arithmetic: trigger a password reset somewhere,
wait for the mail, then ask the agent to read the code out. It removes
one-time codes, reset and magic links, one-click account-action links, bearer
tokens, API keys and private keys, replacing rather than deleting so a login
mail still reads as a login mail.

## Authorisation

Two independent facts must both hold before any tool call touches a mailbox.

The **acting user** is named by the calling app in `X-Privasys-On-Behalf-Of`,
on a leg the runtime has already authenticated. A call without one is refused,
not defaulted.

The **calling app** is the identity the runtime verified from the mutual
RA-TLS client certificate, and there must be a live capability for that app
and that user carrying the permission the call needs. Read and write are
separate checks, because they are separate sentences on the approval screen.

Enforcement fails closed and the switch is explicit, so a zero value cannot
quietly be permissive.

### The user who acts, and the user who decides

These are not the same question, and the connector answers them with different
evidence on purpose.

`X-Privasys-On-Behalf-Of` is written by the calling app. That is exactly right
for "read this person's mail under a capability they already approved", and
worthless for "this person approves a capability". If the same header were
good enough for both, the app that wants access could grant itself access and
no wallet screen would ever be drawn.

So the **holder-facing** endpoints (minting a capability, listing and
revoking approvals) never read it. A holder is established one of exactly two
ways:

- **`X-Privasys-Sub`**, which the runtime's session-relay middleware sets from
  a wallet-authenticated sealed session and strips from every inbound request
  before dispatch. That stripping is what makes it trustworthy.
- **A bearer token from the configured identity provider**, verified here
  against its key set. That is the wallet, dialling this connector directly
  over RA-TLS to approve a mailbox, with no relay in between.

Verification is offline apart from a cached key set, so a mailbox is never
opened by asking the platform about the person whose mail it is. An
unverifiable token is treated exactly as no token at all.

Which issuer is trusted is the whole of the configuration, and it is the hash
this service publishes into its own certificate. It decides whose approval
this deployment will honour.

## Connecting a mailbox

There is no page to do it on. The wallet reads what this service needs
(`GET /v1/capabilities/setup`), draws it on the approval screen, and sends
the answers with the mint (`POST /v1/capabilities`, `setup`). The first
question is the address alone, because the address decides everything that
follows: which server, which authorisation, and whether the mailbox can be
connected here at all. Nothing is approved first: this service asks for no
folder.

**A sign-in at Google or Microsoft**, for `gmail.com`, `googlemail.com`,
`outlook.com`, `hotmail.com`, `live.com` and their national variants, and
for any domain whose MX records point at Google or Microsoft (a Google
Workspace or Microsoft 365 tenant on its own domain). Both providers are
retiring passwords over IMAP, so a holder whose address is at either is never
offered a password field. The second step is one button, **Continue with
Google** or **Continue with Microsoft**. The wallet opens
`https://<this host>/v1/oauth/start` in an authentication session; this
service sends the browser to the provider with PKCE and the scopes below; the
provider sends it back to `https://<this host>/v1/oauth/callback`; this
service exchanges the code with its sealed client secret, reads the
signed-in address from the ID token, keeps the tokens in memory under a
one-time grant code, and sends the browser back to the wallet's own scheme
with that code and nothing else. The wallet puts the code in the mint's
`setup`; the service redeems it once, refuses a sign-in for any address but
the one the holder typed, proves the token set by opening the mailbox over
IMAP with SASL XOAUTH2 (`imap.gmail.com:993` or `outlook.office365.com:993`)
and listing one message, keeps it, and answers the mint with
`"keep": {"refresh_token": "..."}`.

That refresh token is the one thing this service asks the wallet to keep for
it. The holder never typed it, and without it the credential would not
outlive one access token: Gmail's expire within the hour, and this service
mints the next one from the refresh token at every dial, including the
reconnects a long read goes through. On a later mint the wallet sends the
token back as `setup.kept.refresh_token`; the service refreshes, proves the
new access token against the mailbox, and connects with no browser. A kept
token the provider no longer honours is a 502 with a sentence, and the
sign-in button again. Microsoft may hand a new refresh token at every
refresh; the newest is the one kept and the one handed back in `keep`
whenever a mint goes through this service. Google rotates nothing.

A deployment with no client configured for a provider answers a holder at
that provider with a 428 that says so and offers nothing: no button, and no
password instead, because Microsoft has none and Google's are on the way
out. The holder waits for the deployer.

**An app password**, for every other provider: iCloud, Fastmail, Yahoo, the
national ISPs, a company's own server. The second question is the password,
marked secret. The service finds the server from the address (a table of the
big providers, then the `_imaps._tcp` record, then Thunderbird's autoconfig
database, then two guesses), proves the password by opening the mailbox and
listing one message, keeps it in memory, and mints the capability, all on
the one tap. A server that cannot be found is one more question (428); a
server that refuses the details is its own error (502), shown beside the
fields. There is nothing for the wallet to keep on this service's behalf:
the credential is what the holder typed, and their device already keeps
that.

The mint's answer carries `capability_id`, `nonce`, `expires_unix`, a
`service_result` naming the mailbox, and `keep` for a sign-in.

### When the credential is not in memory

Every tool call, and the change feed, then answer **403** with

```json
{"error": "…", "credential_needed": true, "needs_holder": true}
```

The sentence is written for the agent: the mailbox details are on the user's
device, not here, so ask the user, then call `request_access` for their
`mail.mailbox` resource **with `ask_again`**. The device's own record may still
say this service is approved, and only `ask_again` makes it ask afresh; the
device then sends the details it kept (the password it was given, or the
refresh token it was asked to hold), or draws the sign-in button or the
password field again, on the approval screen. No retry loop, no page to
visit. A provider that no longer honours the kept sign-in is answered the
same way, as a 502 with the same sentence.

## Endpoints

| Path | Who calls it |
|---|---|
| `GET /` | anyone: what this service is, and that there is no page to connect on |
| `POST /tools/*` | the attested agent, eleven tools, see `privasys.json` |
| `GET /api/v1/mcp/tools` | the agent's MCP client: the catalogue |
| `POST /api/v1/mcp/tools/*` | the same eleven tools, at the path that client calls |
| `GET /v1/capabilities/setup` | the wallet: what the holder must answer |
| `POST /v1/capabilities` | the wallet, as the holder: connect and mint on one tap |
| `GET /v1/oauth/start`, `GET /v1/oauth/callback` | the holder's browser, held by the wallet: the Google or Microsoft sign-in |
| `GET /v1/capabilities` | the wallet: what has access, in the shared shape |
| `DELETE /v1/capabilities/{id}` | the wallet: revoke; with the last one go the credential and the mailbox connections |
| `GET /v1/apps`, `DELETE /v1/grants/{id}` | this service's older names for the same list and revoke |
| `GET /health`, `GET /readiness` | the platform |

The two tool paths are **one closure registered twice**, so the acting-user
check, the configure gate and the capability check are the same code rather
than equivalent code. A second copy of those checks is a second place for them
to be relaxed.

The catalogue is served from the embedded `privasys.json`, which is also the
label the control plane reads, so the descriptions a model sees are the ones
that were reviewed and a tool cannot be described two ways. `configure` is
filtered out of it: it names the identity provider whose word this deployment
takes on who a holder is, and the OAuth clients it signs mailboxes in with,
and an agent that could call it could decide whose approvals count.

**The catalogue is the one request served without an acting user**, because
the agent's client pulls it on a startup timer before anyone is acting. That
is safe only because nothing in it varies per holder, which is a property to
keep. It is also why a connector that does not serve this path is not merely
degraded: it mounts with no tools at all, and the agent then reports having no
mail tools, which reads exactly like a connector nobody configured.

## Building

```sh
./build.sh                      # IMAGE and TAG are overridable
```

Never `docker build` this directory directly. The tool catalogue reaches the
control plane as an image label, and pasting a second copy of it into the
Dockerfile is how a catalogue starts advertising tools the service does not
serve.

## Deploying

The image is `ghcr.io/privasys/mail-connector`, built by the publish
workflow on a push touching `mail/` or `sdk/`. Deploy it by digest, never by
tag.

Configure it once (`POST /configure`, through the platform). The fields:

| Field | What |
|---|---|
| `idp_issuer`, `idp_audience` | whose tokens prove which person is approving; empty means the platform's own |
| `google_client_id`, `google_client_secret` | the Google Cloud OAuth client this deployment signs Gmail and Google Workspace mailboxes in with; empty means those mailboxes cannot be connected here |
| `microsoft_client_id`, `microsoft_client_secret` | the Entra app registration for Outlook.com and Microsoft 365 mailboxes; empty means those cannot be connected here |

App-password providers need nothing here. A missing client is the one thing
a holder at that provider cannot get past, because no password is offered
instead; the service says which clients it has at boot.

The certificate carries a digest of the configuration: the two identity
fields, each client id, and the **hash** of each client secret rather than
its value, in that order, NUL-separated, so the certificate says which
clients this deployment speaks as without carrying a secret. The digest of a
deployment configured before the clients existed therefore changes when it is
reconfigured with them, as a reconfiguration should.

**The Google Cloud OAuth client** is the deployer's to create, in a Google
Cloud project of their own:

1. Enable the **Gmail API**. IMAP access with an OAuth token is governed by
   it even though no Gmail API call is ever made.
2. Configure the OAuth consent screen with the scopes
   `https://mail.google.com/`, `openid` and `email`. There is no narrower
   scope that Gmail's IMAP accepts: `mail.google.com` is the one it wants.
3. Create an OAuth client of type **Web application**, with the authorised
   redirect URI `https://<this host>/v1/oauth/callback`, where the host is the
   one the wallet reaches this service on. Nothing else is authorised: the
   wallet's own scheme never appears at Google.
4. Put the client id and secret into `configure`.

`https://mail.google.com/` is a **restricted** scope at Google. A client that
asks for it can be used **unverified by up to 100 users**, each of whom sees
Google's unverified-app warning at sign-in; past that, Google requires the
client to go through its verification, which for a restricted scope includes
an annual **CASA** security assessment by an authorised assessor. A client in
a Google Workspace organisation that is marked **Internal** on its consent
screen is exempt: it serves that organisation's users without verification
and without a cap. Plan the deployment on that basis.

**The Entra app registration**, for Microsoft, is the deployer's to create in
the Microsoft Entra admin centre:

1. Register an application with **Accounts in any organizational directory
   and personal Microsoft accounts**, so a work account and a personal one
   both sign in through the `common` tenant.
2. Add a **Web** redirect URI of `https://<this host>/v1/oauth/callback`.
3. Under API permissions add the **delegated** permission
   `IMAP.AccessAsUser.All` from **Office 365 Exchange Online** (not Microsoft
   Graph: it is a different resource, and a token is issued for one resource
   at a time, which is also why this service asks for no Graph permission
   beside it), plus `offline_access`, `openid`, `email` and `profile`. A
   tenant may require admin consent.
4. Create a client secret, and put the application (client) id and the secret
   into `configure`.

A Microsoft 365 tenant must also have IMAP enabled for the mailbox, and
personal Outlook.com accounts have it on. A mailbox with IMAP off signs in
and then fails the probe, which is reported at the mint as the mailbox not
opening, before anything is kept.

## Running it locally

There is no store to choose and nothing on disk but the configuration. A
local run needs one deliberate opt-out, which says what it is giving up.

```sh
export MAIL_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export MAIL_CONFIG=./config.json                  # where configure writes
export PORT=8123
./mail-connector
```

Configure it (an empty body takes the platform defaults and offers no
sign-in), then connect a mailbox the way the wallet does, as a holder the
relay would have named. The secret goes in the request body, never in argv,
where every process on the machine can read it and the shell keeps it.

```sh
curl -s -X POST localhost:8123/configure -d '{}'
EXP=$(( $(date +%s) + 86400 ))          # at most 180 days out
curl -s -X POST localhost:8123/v1/capabilities -H 'X-Privasys-Sub: user-1' -d @- <<JSON
{"nonce":"n","subject_app_id":"00000000000000000000000000000001","kind":"mail.mailbox",
 "permissions":["read"],"expires_unix":$EXP,
 "setup":{"user":"you@example.com","password":"…"}}
JSON
```

For a Gmail or Microsoft 365 mailbox, configure a client first, then do what
the wallet does: open the start URL for the provider in a browser with a
wallet-shaped `redirect_uri` and a nonce, take the grant code from the
redirect the callback answers with, and mint with it. The grant code is
single use and lives ten minutes. The mint's `keep` is what the wallet would
send back as `setup.kept` after a restart.

```sh
curl -s -X POST localhost:8123/configure -d '{"google_client_id":"…","google_client_secret":"…"}'
# in a browser: https://<this host>/v1/oauth/start?kind=mail.mailbox&provider=google&redirect_uri=privasys-wallet://setup/callback&nonce=abcdefgh12345678
curl -s -X POST localhost:8123/v1/capabilities -H 'X-Privasys-Sub: user-1' -d @- <<JSON
{"nonce":"n","subject_app_id":"00000000000000000000000000000001","kind":"mail.mailbox",
 "permissions":["read"],"expires_unix":$EXP,
 "setup":{"user":"you@gmail.com","grant":"<the grant code>"}}
JSON
```

Stop the process and it is gone.

## Known ground

Everything unusual in the IMAP driver was learned against a real
42,000-message mailbox, and the comments in the source say which rule came
from what. The three that matter most:

- **Never ask for `BODY[TEXT]`.** It is a section the server assembles from
  parts it stores separately, and on some shapes the literal it announces does
  not match the bytes it sends, so the read hangs. A 2 KB message was enough.
- **Always be able to skip a message.** One in 200 will not come back, twice,
  even alone. A driver that cannot carry on without one cannot read a real
  mailbox.
- **Always `SELECT` before reading by UID**, or an id that exists returns
  nothing and looks exactly like a deleted message.

## Where the credential lives, precisely

In two places and no third. On the holder's device, kept by their wallet: the
app password it was given on the approval screen, or the refresh token this
service asked it to hold. And in this process's memory, from the moment the
wallet sends them until the last capability over the mailbox is revoked, the
process stops, or the deployment is pointed at a different identity provider
(what was approved under the old one is forgotten). An access token lives
only here, and only until it expires. Nothing is written to the volume,
nothing goes to a storage service, and nothing is encrypted for later,
because there is no later.

A redeployed or wiped connector therefore leaves nothing behind at all. What
it costs is one tap: the wallet answers the next `setup` question with what
it kept, and the credential and the capability come back together, with no
browser for a sign-in whose refresh token the provider still honours.

## Known ground, and what is not

The IMAP driver's reads, drafts, labels and change feed were learned against
a real 42,000-message mailbox, over an app password. The sign-in is exercised
end to end against fake authorisation servers for both providers in the
tests: start, callback, grant code, mint, `keep`, the kept-token path after a
restart, the refusal of a sign-in for another address, a 502 on a refresh
token the provider refuses, Microsoft's refresh with the scope named and its
rotated refresh token. XOAUTH2 is pinned to Google's documented byte string
in a unit test.

**It has not been run against a real Google or Microsoft account with a
sign-in.** The first real run will be the first time Gmail's and Exchange
Online's XOAUTH2 answers, the shape of their ID tokens, and their token
endpoints are seen by this code.

## Not built yet

Removing a label, and deployment to a fleet.

## Where the code lives

What is the Mail Connector's is the IMAP driver and its two ways in, the
text handling, the server discovery, the two setup steps, the two sign-in
providers, the probe and the tool list. Who the holder is, who a call acts
for, the capability check, the credential in memory and its refusal, the
wallet-facing routes, the catalogue, the configure gate, the OAuth exchange
with the wallet holding the browser, and who hosts an address (`provider`)
are the sdk's (`../sdk`), the same code in every connector rather than
equivalent code, and the root README says why that split is a rule rather
than a tidiness.
