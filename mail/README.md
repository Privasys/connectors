# Mail Connector

Reads one mailbox on behalf of one attested agent, under a capability the
holder approved on their own device. **It cannot send.**

## What it does, and what it deliberately does not

An agent can see what arrived, read a message, follow a conversation, search
years of mail through the provider's own index, read the holder's own sent
text to learn how they write, label what it triaged, and leave a reply in the
Drafts folder for the holder to read and send themselves.

It cannot send a message, delete mail, move anything between folders, or write
a label outside the `Privasys/` namespace. Those are not settings. There is no
send method on the driver interface, so "it cannot send" is a property of the
shape of the code rather than a promise about its behaviour.

## Where things live

**The connector keeps no durable user state.** Literally: the mailbox
credential is at rest only on the holder's own device and in use only in the
memory of this attested process. The holder types it once, on their wallet's
approval screen; the wallet keeps the answers it sent and sends them again
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
(`GET /v1/capabilities/setup`: an address and an app password, the password
marked secret, nothing to approve first), draws it on the approval screen,
and sends the answers with the mint (`POST /v1/capabilities`, `setup`). The
service finds the server from the address, proves the credential by opening
the mailbox and listing one message, keeps it in memory, and mints the
capability, all on the one tap. A server that cannot be found is one more
question (428); a provider that refuses the details is its own error (502),
shown beside the fields.

The mint's answer carries `capability_id`, `nonce`, `expires_unix` and a
`service_result` naming the mailbox. It carries nothing for the wallet to keep
on this service's behalf, because for IMAP there is nothing: the credential is
what the holder typed, and their device already keeps that.

### When the credential is not in memory

Every tool call, and the change feed, then answer **403** with

```json
{"error": "…", "credential_needed": true, "needs_holder": true}
```

The sentence is written for the agent: the mailbox details are on the user's
device, not here, so ask the user, then call `request_access` for their
`mail.mailbox` resource **with `ask_again`**. The device's own record may still
say this service is approved, and only `ask_again` makes it ask afresh; the
device then sends the details it kept, or asks the holder for them, on the
approval screen. No retry loop, no page to visit.

## Endpoints

| Path | Who calls it |
|---|---|
| `GET /` | anyone: what this service is, and that there is no page to connect on |
| `POST /tools/*` | the attested agent, eleven tools, see `privasys.json` |
| `GET /api/v1/mcp/tools` | the agent's MCP client: the catalogue |
| `POST /api/v1/mcp/tools/*` | the same eleven tools, at the path that client calls |
| `GET /v1/capabilities/setup` | the wallet: what the holder must answer |
| `POST /v1/capabilities` | the wallet, as the holder: connect and mint on one tap |
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
takes on who a holder is, and an agent that could call it could decide whose
approvals count.

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

## Running it locally

There is no store to choose and nothing on disk but the configuration. A
local run needs one deliberate opt-out, which says what it is giving up.

```sh
export MAIL_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export MAIL_CONFIG=./config.json                  # where configure writes
export PORT=8123
./mail-connector
```

Configure it (an empty body takes the platform defaults), then connect a
mailbox the way the wallet does, as a holder the relay would have named. The
secret goes in the request body, never in argv, where every process on the
machine can read it and the shell keeps it.

```sh
curl -s -X POST localhost:8123/configure -d '{}'
EXP=$(( $(date +%s) + 86400 ))          # at most 180 days out
curl -s -X POST localhost:8123/v1/capabilities -H 'X-Privasys-Sub: user-1' -d @- <<JSON
{"nonce":"n","subject_app_id":"00000000000000000000000000000001","kind":"mail.mailbox",
 "permissions":["read"],"expires_unix":$EXP,
 "setup":{"user":"you@example.com","password":"…"}}
JSON
```

For Gmail the password must be an App Password, with 2-Step Verification on.
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

In two places and no third. On the holder's device, kept by their wallet as
the answers it gave on the approval screen. And in this process's memory,
from the moment the wallet sends them until the last capability over the
mailbox is revoked, the process stops, or the deployment is pointed at a
different identity provider (what was approved under the old one is
forgotten). Nothing is written to the volume, nothing goes to a storage
service, and nothing is encrypted for later, because there is no later.

A redeployed or wiped connector therefore leaves nothing behind at all. What
it costs is one tap: the wallet answers the next `setup` question with the
details it kept, and the credential and the capability come back together.

An OAuth refresh token, when the Graph and Gmail drivers land, is the one
thing this service would need the wallet to keep for it. The mint has a place
for that, unused today, so the shape of the deal does not change when it
arrives.

## Not built yet

The Microsoft Graph and Gmail API drivers, and deployment to a fleet.
