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

**The connector keeps no durable user state.** The one thing that must survive
a restart is the credential for the linked mailbox, and even that does not
live here: it is encrypted under a key sealed to this connector's measurement
and the ciphertext is written to the holder's own Drive. Two independent
things must hold for anyone else to use it, and revoking the Drive grant
strands it, which is what makes the holder's own revoke button the kill
switch rather than a request someone honours.

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

The **holder** is asserted by the platform in `X-Privasys-On-Behalf-Of`, on a
leg the runtime has already authenticated. A call without one is refused, not
defaulted: an app that could name its own subject could read anyone's mail.

The **calling app** is the identity the runtime verified from the mutual
RA-TLS client certificate, and there must be a live capability for that app
and that holder carrying the permission the call needs. Read and write are
separate checks, because they are separate sentences on the approval screen.

Enforcement fails closed and the switch is explicit, so a zero value cannot
quietly be permissive.

## Endpoints

| Path | Who calls it |
|---|---|
| `GET /` | the holder, in a browser: connect or disconnect a mailbox |
| `GET /v1/link` | the holder: which mailbox is connected |
| `POST /v1/link` | the holder: connect one, after it has been proved |
| `DELETE /v1/link` | the holder: disconnect |
| `POST /tools/*` | the attested agent, eleven tools, see `privasys.json` |
| `POST /v1/capabilities` | the wallet, as the holder, after approval |
| `GET /v1/apps` | the holder: what has access |
| `DELETE /v1/grants/{id}` | the holder: revoke |
| `GET /health`, `GET /readiness` | the platform |

## Building

```sh
./build.sh                      # IMAGE and TAG are overridable
```

Never `docker build` this directory directly. The tool catalogue reaches the
control plane as an image label, and pasting a second copy of it into the
Dockerfile is how a catalogue starts advertising tools the service does not
serve.

## Running it locally

The production credential store is not built yet, so a local run needs two
deliberate opt-ins, both of which say what they are giving up.

```sh
export MAIL_STORE=local                   # secrets on THIS host, not the holder's Drive
export MAIL_STORE_DIR=./.mail-store
export MAIL_STORE_KEY=$(openssl rand -hex 32)
export MAIL_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export PORT=8123

# Link a mailbox. The secret comes from a FILE outside the tree: a password in
# argv is visible to every process on the machine and lands in shell history.
./mail-connector -link user-1 -creds /path/to/creds.json

./mail-connector
```

```json
{"host":"imap.gmail.com:993","user":"you@example.com","password":"…",
 "own_domains":["example.com"]}
```

For Gmail the password must be an App Password, with 2-Step Verification on.

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

Two independent things must hold before anyone can use a linked mailbox. The
**ciphertext** sits in the holder's own Drive folder, which they can revoke
this app's access to. The **sealing key** sits on this app's encrypted volume
and only this measurement can read it. Neither alone is enough, and the holder
controls the first, which is what makes their revoke a kill switch rather than
a request someone honours. It also means a redeployed connector leaks nothing:
the ciphertext it left behind is inert.

The proof presented to Drive is minted per request and never stored. The
binding key never leaves the runtime; the connector asks the manager to sign
each proof, so a compromised connector can only act while it is still the app
the manager thinks it is.

**Operational rule:** the sealing key goes under the upgrade gate. A release
that rotates it is a re-link event for every holder and must be planned as
one rather than discovered.

## The attested leg

The call to Drive goes over RA-TLS, not ordinary TLS. Two reasons, and the
second is the real one: the enclave gateway refuses plaintext app traffic so
the call would not arrive, and server-auth TLS proves only that something
answered the name, on a leg that carries a holder's mailbox credential.

The peer's quote is bound to that handshake, so a replayed certificate cannot
pass. The peer's app id is then checked against , and its
build against  when one is pinned. All of it happens
before the connection is handed to the pool, so no byte of a credential
reaches a channel whose far end has not been checked.

This transport dials one host and refuses every other, which is narrower than
it needs to be today and stops a control plane that starts pointing this
connector elsewhere from moving its traffic.

The RA-TLS client module declares a non-fetchable path, so it is consumed as a
sibling checkout at an exact pin: cloned by the Dockerfile and by CI from the
same ref, symlinked for local work, never committed here.

## Not built yet

The Microsoft Graph and Gmail API drivers, and deployment to a fleet.
