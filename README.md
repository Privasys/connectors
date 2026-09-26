# Privasys Connectors

Attested connectors for the [Privasys Harness](https://github.com/Privasys/harness).
A connector is a confidential platform app that holds one credential for one
service on behalf of one user, and exposes that service to an attested agent as
a set of MCP tools.

## The rules every connector follows

1. **The connector holds no durable user state.** Literally. The credential
   is at rest only on the **user's own device**, where their wallet keeps the
   answers it gave on the approval screen, and in use only in the memory of
   the connector's attested process. Nothing is sealed to a key, written to
   a volume or sent to a storage service. A restart forgets everything, and
   the user is asked once more on their phone at the next use; their wallet
   answers with what it kept. The one thing a connector may ask the wallet
   to keep for it is what the user never typed: an OAuth refresh token,
   handed back with the mint as `keep` and sent again as `setup.kept`.
2. **Whether anything else is stored is decided per connector, by one
   question: is the upstream provider a durable system of record for this
   content?** Mail and calendar: yes, so nothing is stored and the provider is
   queried on demand. Meeting transcripts: no, retention ages them out, so they
   are written to the user's Drive where they become searchable knowledge.
   Wherever a byte does rest, it rests in the user's Drive under the user's
   keys, never on the connector's disk.
3. **The user consents on their own device, to a named identity.** A connector
   is reached through the platform's capability protocol: the wallet verifies
   the connector's attestation and the requesting app's, renders a sentence
   from a closed vocabulary, and mints a holder-of-key grant. The user's
   credentials are typed on that same screen and make one attested hop, phone
   to connector; no agent, harness or page ever holds them. Where a provider
   wants a sign-in instead of a password, the wallet holds the browser and
   the connector runs the OAuth exchange; only a one-time code passes between
   them.
4. **Every call is attributed.** Requests arrive over mutual RA-TLS from an
   attested peer, carrying the acting user in `X-Privasys-On-Behalf-Of`, and
   are checked against a live capability for that user before anything is
   fetched. The user pays for their own calls.
5. **Secrets never reach the agent.** One-time codes, password-reset links and
   login magic links are stripped from content before it leaves the connector,
   deterministically, so the filter holds even when the model does not.
6. **Acting is something the user grants.** Connectors read what a provider
   already produced for a user who was there, and what they may do beyond
   reading is exactly what the user approved on their device, as a
   permission of its own, never implied by the permission to read. Today that
   is a draft: a reply in the Drafts folder, a tentative event on the user's
   own calendar, for the user to send or confirm themselves. Sending mail and
   sending invitations are on the way, on the same terms. Connectors never
   join a meeting and never record one on their own initiative.
7. **The shell is shared, and only the shell.** Everything above is enforced
   by code in `sdk/` that every connector uses as it is: who the holder is,
   who a call acts for, the capability, the credential in memory, the
   refusals, the routes, the catalogue, the configure gate, the OAuth
   exchange, the redaction. A connector is **a driver, a schema, a probe and
   a tool list**, and nothing else. A rule that lived in one connector's code
   would be a rule the next connector could forget.

## Licensing, and why it is split

| Path | Licence | Why |
|---|---|---|
| `sdk/` | **Apache-2.0** | The shell: the capability protocol, the holder and the acting user, the in-memory credential and its refusal, the MCP catalogue, the change-feed contract, configure-then-freeze and the certificate digest, the OAuth exchange with the wallet holding the browser, the redaction. This is the part a third-party connector gets dangerously wrong, so it is deliberately free to copy verbatim, including into proprietary connectors. We would rather our implementation spread than see it reimplemented badly. |
| every connector (`mail/`, `calendar/`, `files/`, `meetings/`) | **AGPL-3.0** | Our products, consistent with the harness, Drive, the CLI and the runtime. A modified version offered as a service comes back. |

Each directory carries its own `LICENSE`. Reused upstream code must be
permissively licensed and vendored at an exact pin, never tracked; the shell
around it is always ours, because the shell is what holds the credential.

## Layout

Three Go modules, tied together by `go.work` for a local build; each
connector's `go.mod` also replaces the sdk with the copy beside it, so an
image build needs no workspace.

| Path | What |
|---|---|
| `sdk/` | The shell. `connector` (the service: routes, the tool wrapper, the refusals), `holder` (who decides), `caller` (who acts, which app), `grant` (the capability), `credential` (the in-memory store, generic over the connector's shape), `configure` (configure-then-freeze, the digest, the extensions route), `mcp` (the catalogue from the embedded manifest), `feed` (the change-feed contract, park and poll), `oauth` (the sign-in with the wallet holding the browser), `provider` (who hosts an address: the providers' own domains, then MX), `redact`, `extract` (a document's text: docx, xlsx, pptx, pdf, html), `vtt` (captions to text), `drive` and `broker` (writing into the holder's own Drive, and asking for the folder), `web`. |
| `mail/` | **Mail Connector**: reads one mailbox for one attested agent under a capability the holder approved, and drafts replies (sending is on the way). IMAP everywhere: a sign-in at Google or Microsoft (XOAUTH2), an app password only for a provider reached directly. See `mail/README.md`. |
| `mail/cmd/imap-spike/` | The throwaway harness that answered the questions the connector could not be designed without. Kept, because its findings are still the reason the driver looks the way it does. |
| `calendar/` | **Calendar Connector**: reads one calendar account (a Google sign-in over CalDAV, a Microsoft sign-in over Graph, an app password over CalDAV elsewhere), and leaves tentative proposals (invitations are on the way). See `calendar/README.md`. |
| `files/` | **Files Connector**: reads and searches the files in OneDrive, SharePoint or Google Drive, saves into one folder it creates, never deletes, moves or shares. See `files/README.md`. |
| `meetings/` | **Meetings Connector**: reads the transcripts Zoom or Microsoft Teams produced for meetings the holder was in, and keeps them in the holder's own Drive. Never joins, never records. See `meetings/README.md`. |

## Status

**The Mail Connector is deployed and running.** It serves its eleven tools,
exercised end to end against a real 42,000-message mailbox: list, read,
thread, search, sent, labels, mark read, drafts, and the change feed. The
mailbox is connected on the wallet's approval screen: the credential is proved
against the mailbox on that tap, kept in the enclave's memory and nowhere
else, and the capability is minted over it in the same call. Grants are
enforced, and enforcement fails closed.

It also publishes what it was configured to trust into its own certificate, so
"this connector honours approvals from that identity provider" is something
you can verify by attesting it rather than something you have to take our
word for.

**All four connectors are deployed** on the Privasys test environment,
with a Google and a Microsoft sign-in configured, and Zoom for meetings. Every
sign-in leg has been checked from the outside, the way a browser meets it: each
connector sends the holder to the provider's own sign-in page, with its own
client and its own callback. The drivers behind those sign-ins (XOAUTH2 at
Gmail and Exchange Online, CalDAV and Graph calendars, Google Drive and Graph
files, Zoom and Teams transcripts) are tested against fakes of each provider;
their first runs against the real ones are next. Each connector's README says
exactly what its tests cover.

Not built yet:

- **Sending mail, and sending invitations.** Neither the mail nor the calendar
  driver interface has the method today, so each will arrive as a change to
  the shape of the code, reviewed as one, and under a permission of its own
  that the user grants, never as a flipped default.
- **Gmail API and Graph mail drivers.** IMAP with a Google or Microsoft
  sign-in covers both providers today, so these wait until something needs
  what only the native APIs offer.
