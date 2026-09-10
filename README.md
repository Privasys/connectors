# Privasys Connectors

Attested connectors for the [Privasys Harness](https://github.com/Privasys/harness).
A connector is a confidential platform app that holds one credential for one
service on behalf of one user, and exposes that service to an attested agent as
a set of MCP tools.

## The rules every connector follows

1. **The connector holds no durable user state.** The one thing that must
   survive a restart is the credential, and even that is not kept here: it is
   encrypted under a key sealed to the connector's own measurement and stored
   in the **user's own Drive**, in the connector's `AppData/` folder. Revoking
   the Drive grant is therefore the kill switch for the connection.
2. **Whether anything else is stored is decided per connector, by one
   question: is the upstream provider a durable system of record for this
   content?** Mail and calendar: yes, so nothing is stored and the provider is
   queried on demand. Meeting transcripts: no, retention ages them out, so they
   are written to the user's Drive where they become searchable knowledge.
   Wherever a byte does rest, it rests in the user's Drive under the user's
   keys, never on the connector's disk.
3. **The user consents on their own device, to a named identity.** A connector
   is reached through the platform's capability protocol: the wallet verifies
   the connector's attestation and the resource service's, renders a sentence
   from a closed vocabulary, and mints a holder-of-key grant. The connector
   never receives the user's credentials, only the outcome.
4. **Every call is attributed.** Requests arrive over mutual RA-TLS from an
   attested peer, carrying the acting user in `X-Privasys-On-Behalf-Of`, and
   are checked against a live capability for that user before anything is
   fetched. The user pays for their own calls.
5. **Secrets never reach the agent.** One-time codes, password-reset links and
   login magic links are stripped from content before it leaves the connector,
   deterministically, so the filter holds even when the model does not.
6. **We read, we do not impersonate.** Connectors read what a provider already
   produced for a user who was there. They do not join meetings, do not record
   on their own initiative, and in v1 do not send.

## Licensing, and why it is split

| Path | Licence | Why |
|---|---|---|
| `sdk/` | **Apache-2.0** | The capability protocol, the Drive-sealed credential, the attested-caller check and the acting-subject stamp. This is the part a third-party connector gets dangerously wrong, so it is deliberately free to copy verbatim, including into proprietary connectors. We would rather our implementation spread than see it reimplemented badly. |
| every connector (`mail/`, later `calendar/`, `zoom/`, `teams/`) | **AGPL-3.0** | Our products, consistent with the harness, Drive, the CLI and the runtime. A modified version offered as a service comes back. |

Each directory carries its own `LICENSE`. Reused upstream code must be
permissively licensed and vendored at an exact pin, never tracked; the shell
around it is always ours, because the shell is what holds the credential.

## Layout

| Path | What |
|---|---|
| `sdk/` | Shared plumbing: capability protocol, sealed-credential store on Drive, attested-caller verification, MCP catalogue helpers. |
| `mail/` | **Mail Connector**: reads one mailbox for one attested agent under a capability the holder approved, and cannot send. The IMAP driver works; Microsoft Graph and the Gmail API come later, in that order, because that is the order of how much permission each needs from its vendor. See `mail/README.md`. |
| `mail/cmd/imap-spike/` | The throwaway harness that answered the questions the connector could not be designed without. Kept, because its findings are still the reason the driver looks the way it does. |

## Status

**The Mail Connector is deployed and running.** It serves its eleven tools,
exercised end to end against a real 42,000-message mailbox: list, read,
thread, search, sent, labels, mark read, drafts, and the change feed.
Credentials are proved at link time, sealed to the enclave's measurement and
kept in the holder's own Drive. Capability grants are minted and enforced, and
enforcement fails closed.

It also publishes what it was configured to trust into its own certificate, so
"this connector was told to talk to that storage service, accepting any build
of it" is something you can verify by attesting it rather than something you
have to take our word for.

Not built yet:

- **The wallet leg.** The capability endpoint is implemented and tested but a
  wallet has never called it, so approving a mailbox is not yet a thing a
  person can do on their phone.
- **Microsoft Graph and Gmail API drivers**, in that order, because that is
  the order of how much permission each needs from its vendor. Generic IMAP
  covers Gmail today through an app password, and every non-Google provider
  permanently.
- **Sending.** Deliberately, and not as an oversight to be closed quietly:
  there is no send method on the driver interface at all, so adding one is a
  change to the shape of the code rather than a flipped default.
