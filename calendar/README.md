# Calendar Connector

Reads one calendar account on behalf of one attested agent, under a capability
the holder approved on their own device, and leaves tentative proposals for
the holder to confirm. **Today it proposes; it does not invite.** You type your
address; the connector finds who hosts it and asks you to sign in there
(Google, Microsoft), or for an app password where there is no sign-in.

## What it does, and what it deliberately does not

An agent can see what is on the holder's calendars in a bounded window, read
one event, look something up, learn when the holder is busy, follow what
changed, and leave a tentative event on the holder's calendar: the calendar's
draft, marked as the assistant's, with the people it is for written into the
text and nobody invited.

This release cannot invite anyone, accept or decline anything, or change or
delete an event it did not create. Those are not settings. There is no method
for any of them on the driver interface, so "it does not invite" is a
property of the shape of the code rather than a promise about its behaviour.
Organising a meeting outright is on the way, as it is for sending mail: a
method of its own on the driver, under a permission the holder grants
explicitly, never a default.

## The tools

| Tool | What | Permission |
|---|---|---|
| `list_calendars()` | the holder's calendars, which is primary | read |
| `list_events(from, to, calendar?)` | occurrences in a window of at most 62 days, soonest first, never a full scan: id, calendar, title, start, end, all-day, location, attendees with their answers, organiser, description (credentials stripped), conference link, the recurrence in words, whether the holder is the host | read |
| `get_event(id)` | one event in full | read |
| `search(query, from, to)` | a text filter over the window: title, location, description, attendees, organiser | read |
| `free_busy(from, to)` | the holder's own busy time, merged; cancelled events, free-time events and the assistant's own proposals do not count | read |
| `propose_event(title, start, end, description?, location?, calendar?, attendees?, run_id?)` | a TENTATIVE event with no attendees, marked `X-PRIVASYS-PROPOSED` with the run id; returns it with its id | write |
| `update_event(id, ...)`, `delete_event(id)` | only an event carrying the mark; anything else is refused with a sentence (422) | write |
| `changes(since, wait_seconds)` | the feed the harness holds: `{"changes": [...], "cursor": "..."}` | read |
| `account()` | which account, which calendars, credential redacted | read |

Event ids encode the calendar, the object, the version it was read at, and
for a recurring event which occurrence. A stale id answers 409 rather than
addressing what the event has become; the fix is to list again. A recurring
event appears once per occurrence, expanded here from the rule, its
exceptions and its overrides.

## Two drivers

**CalDAV**, for Google (with a bearer) and for iCloud, Fastmail, Nextcloud
and any RFC 4791 server (with an app password). `changes` compares every
calendar's sync token (RFC 6578) and ctag with the cursor every 20 seconds
inside the held call. With a sync token the changes are the exact events,
`changed` or `removed`; a server with ctags alone can only say that a
calendar changed, and the feed says `calendar_changed` with the calendar's
id so the agent lists again.

**Microsoft Graph**, for a Microsoft account, because Microsoft serves no
CalDAV. The calendars come from `GET /me/calendars`; a window is
`GET /me/calendars/{id}/calendarView` with `Prefer: outlook.timezone="UTC"`
and text bodies, which expands a recurring event into its occurrences, each
with its own id; the sentence about the rule is read once per series from
the master. An event id carries Graph's `changeKey` as its version. Search
is the same windowed filter as on CalDAV, because Graph's `$search` on
events is not something to rely on; busy time is what the view shows as
busy, tentative or out of office. A proposal is `POST /me/calendars/{id}/events`
with `showAs: tentative`, `responseRequested: false`, no attendees (the
people it is for are named in the body text only) and a single-value
extended property carrying the proposal id; `update_event` and
`delete_event` read the event first and touch it only when it carries that
mark. `changes` follows `GET /me/calendarView/delta` on the default
calendar every 20 seconds inside the held call; a delta link is bound to a
window, so a cursor older than a week is followed one last time and then
minted afresh. Either way the cursor is opaque.

## Where things live

**The connector keeps no durable user state.** The credential is at rest only
on the holder's own device and in use only in the memory of this attested
process. There is no sealing key, no volume with anything of the holder's on
it, no storage peer. The holder's revoke is honoured here, in the one place
the credential exists. **Events are never stored**: the provider stays the
system of record, and every tool reads it on demand.

**A restart forgets everything**, credentials and capabilities alike. That is
the price the design accepts. Each holder then gets one request on their
phone at the next use, their wallet answers with what it kept, and their
unattended runs wait until it has.

## Connecting an account

There is no page to do it on. The wallet reads what this service needs
(`GET /v1/capabilities/setup`), draws it on the approval screen, and sends
the answers with the mint (`POST /v1/capabilities`, `setup`). **The first
question is the address alone**, because the address decides everything
that follows: who hosts the account (the sdk's `provider`: Google's and
Microsoft's own domains by name, then the domain's MX records for a custom
domain at Google Workspace or Microsoft 365, then "somewhere else"), and so
which server, which authorisation, and whether the account can be connected
here at all. The holder is never asked to pick a provider the domain already
names, and is never offered a step that cannot connect their account.

**A Google address** (`gmail.com`, `googlemail.com`, or a domain whose mail
is at Google) gets one button: **Continue with Google**. Google's CalDAV
endpoint takes a bearer, not a password. The wallet opens
`https://<this host>/v1/oauth/start?kind=calendar.events&provider=google` in
an authentication session; this service sends the browser to Google with
PKCE and the calendar scope; Google sends it back to
`https://<this host>/v1/oauth/callback`; this service exchanges the code
with its sealed client secret, reads the signed-in address, keeps the tokens
in memory under a one-time grant code, and sends the browser back to the
wallet's own scheme with that code and nothing else. The wallet puts the
code in the mint's `setup`; the service redeems it once, **refuses a sign-in
for any address but the one typed**, proves the tokens by listing the
calendars, and answers the mint with
`"keep": {"refresh_token": "…", "provider": "google"}`.

**A Microsoft address** (`outlook.com`, `hotmail.com`, `live.com` and their
national variants, or a domain whose MX is Microsoft 365) gets **Continue
with Microsoft**, and the account is served through Microsoft Graph rather
than CalDAV, which Microsoft does not offer: the same routes with
`provider=microsoft`, the Microsoft identity platform v2 on the `common`
tenant, the scopes `offline_access User.Read Calendars.ReadWrite`, and the
address read from `GET /me` at the callback and again on the kept path.
Microsoft's token endpoint is asked for a refresh with the scope named again,
which is what it wants.

**Any other address** gets an app password, for iCloud, Fastmail, Nextcloud,
and any RFC 4791 server. The second question is the password, marked secret.
The service finds the server from the address (a table of the big providers,
then the `_caldavs._tcp` record and its TXT path, then `/.well-known/caldav`,
then two guesses), proves the password by listing the calendars, keeps it in
memory, and mints the capability, all on the one tap. A server that cannot
be found is one more question (428); a server that refuses the password is
its own error (502), shown beside the fields. There is nothing for the
wallet to keep on this service's behalf: the credential is what the holder
typed, and their device already keeps that.

**A provider with no client configured here** is said plainly: a Google or
Microsoft address on a deployment without that client gets a 428 whose
message says so, with nothing to fill. It is never offered a password field,
because those accounts have no app password a CalDAV server would take.

The refresh token is the one thing this service asks the wallet to keep for
it, with the word for who issued it. The holder never typed it, and without
it the credential would not outlive one access token. On a later mint the
wallet sends it back as `setup.kept.refresh_token` beside the typed address,
the service mints an access token from it, proves it, checks the address,
and connects with no browser; `setup.kept.provider` says which sign-in it
was, so a resolver that cannot be reached at that moment never turns a kept
token into a password question. A kept token the provider no longer honours
is a 502 with a sentence, and the sign-in button again.

### When the credential is not in memory

Every tool call, and the change feed, then answer **403** with

```json
{"error": "…", "credential_needed": true, "needs_holder": true}
```

The sentence is written for the agent: the calendar details are on the user's
device, not here, so ask the user, then call `request_access` for their
`calendar.events` resource **with `ask_again`**. The device's own record may
still say this service is approved, and only `ask_again` makes it ask afresh;
the device then sends what it kept, or asks the holder, on the approval
screen. No retry loop, no page to visit.

## Authorisation

The same two facts as the Mail Connector, checked by the same code (the sdk's
package `connector`): the **acting user** the platform asserts in
`X-Privasys-On-Behalf-Of`, and a live capability for the **calling app** the
runtime verified from the mutual RA-TLS client certificate, carrying the
permission the call needs. Read and write are separate checks, because they
are separate sentences on the approval screen: a holder who approved
read-only must not find the agent proposing. Enforcement fails closed, and
the switch that turns it off is explicit and loud.

The **holder**, who decides, is established from the relay-asserted
`X-Privasys-Sub` or from a bearer verified against the configured issuer's
key set, never from the header the calling app writes. See the Mail
Connector's README for why that distinction is a privilege boundary.

## Endpoints

| Path | Who calls it |
|---|---|
| `GET /` | anyone: what this service is, and that there is no page to connect on |
| `POST /tools/*` | the attested agent, the tools above, see `privasys.json` |
| `GET /api/v1/mcp/tools` | the agent's MCP client: the catalogue |
| `POST /api/v1/mcp/tools/*` | the same tools, at the path that client calls |
| `GET /v1/capabilities/setup` | the wallet: what the holder must answer |
| `POST /v1/capabilities` | the wallet, as the holder: connect and mint on one tap |
| `GET /v1/capabilities`, `DELETE /v1/capabilities/{id}` | the wallet: list and revoke; with the last one go the credential and the connection |
| `GET /v1/apps`, `DELETE /v1/grants/{id}` | the older names for the same list and revoke |
| `GET /v1/oauth/start?provider=…`, `GET /v1/oauth/callback` | the holder's browser, held by the wallet, for a Google or a Microsoft sign-in |
| `GET /.well-known/attestation-extensions` | the runtime: the configuration digest for the certificate |
| `GET /health`, `GET /readiness` | the platform |

The two tool paths are one closure registered twice, so the acting-user
check, the configure gate, the credential check and the capability check are
the same code rather than equivalent code. `configure` is filtered out of the
catalogue.

## Deploying

The image is `ghcr.io/privasys/calendar-connector`, built by the publish
workflow on a push touching `calendar/` or `sdk/`. Deploy it by digest, never
by tag.

Configure it once (`POST /configure`, through the platform). The fields:

| Field | What |
|---|---|
| `idp_issuer`, `idp_audience` | whose tokens prove which person is approving; empty means the platform's own |
| `google_client_id`, `google_client_secret` | the Google Cloud OAuth client this deployment signs Google addresses in with; empty means a Google address cannot be connected here. The old names `oauth_client_id` and `oauth_client_secret` are still accepted for one release and folded into these |
| `microsoft_client_id`, `microsoft_client_secret` | the Entra app registration for Microsoft addresses; empty means a Microsoft address cannot be connected here |

The certificate carries a digest of the configuration: the two identity
fields, each client id, and the **hash** of each client secret rather than
its value, so the certificate says which clients this deployment speaks as
without carrying a secret. The providers' client secrets are long and
random, so the hash gives nothing away. A deployment with no Microsoft
client keeps the digest it had before that pair existed.

**The Google Cloud OAuth client** is the deployer's to create, in a Google
Cloud project of their own:

1. Enable the **Google Calendar API** (CalDAV is served under it).
2. Configure the OAuth consent screen with the scopes
   `https://www.googleapis.com/auth/calendar`, `openid` and `email`.
3. Create an OAuth client of type **Web application**, with the authorised
   redirect URI `https://<this host>/v1/oauth/callback`, where the host is the
   one the wallet reaches this service on. Nothing else is authorised: the
   wallet's own scheme never appears at Google.
4. Put the client id and secret into `configure`.

**The Entra app registration**, for Microsoft, is the deployer's to create
in the Microsoft Entra admin centre:

1. Register an application with **Accounts in any organizational directory
   and personal Microsoft accounts**, so a work account and a personal one
   both sign in through the `common` tenant.
2. Add a **Web** redirect URI of `https://<this host>/v1/oauth/callback`.
3. Under API permissions add the **delegated** Microsoft Graph permissions
   `offline_access`, `User.Read` and `Calendars.ReadWrite`. `ReadWrite` is
   what lets the connector leave a tentative proposal on the holder's own
   calendar; it still sends no invitation, because it never puts an attendee
   on an event.
4. Create a client secret, and put the application (client) id and the
   secret into `configure`.

## Running it locally

```sh
export CALENDAR_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export CALENDAR_CONFIG=./config.json                  # where configure writes
export PORT=8123
./calendar-connector
```

Configure it (an empty body takes the platform defaults and no sign-in
client), then connect an account the way the wallet does, as a holder the
relay would have named. The secret goes in the request body, never in argv.

```sh
curl -s -X POST localhost:8123/configure -d '{}'
EXP=$(( $(date +%s) + 86400 ))
curl -s -X POST localhost:8123/v1/capabilities -H 'X-Privasys-Sub: user-1' -d @- <<JSON
{"nonce":"n","subject_app_id":"00000000000000000000000000000001","kind":"calendar.events",
 "permissions":["read","write"],"expires_unix":$EXP,
 "setup":{"user":"you@icloud.com","password":"…"}}
JSON
```

## Known ground, and what is not

The CalDAV driver is exercised against a fake CalDAV server in its tests:
discovery with a redirect on the well-known path and a calendar home on
another origin, the time-range query, recurrence with overrides and
exceptions, versioned ids, proposals on the wire, the proposed-only guard,
sync-collection and the ctag fallback. The Graph driver is exercised against
a fake Graph: the calendar list, the calendar view across two calendars and
a page break, the series master's rule, the change key as the version, a
proposal posted tentative with no attendees and the mark, update and delete
refused on the holder's own event, and the delta feed with a removal, a 410
and a re-window. The two sign-ins are exercised end to end against fake
authorisation servers, including the kept-token path after a restart,
Microsoft's refresh with the scope named, and the refusal of a sign-in for
another address. The branching by address is tested on the providers' own
domains, on custom domains through a fake MX, with no client configured,
and with an address the sign-in did not match.

**It has not been run against a real provider.** No iCloud, Fastmail,
Nextcloud, Google or Microsoft account was available when it was written.
The first real run will be the first time the discovery table, the
providers' answers to the time-range query, Google's CalDAV endpoint, and
Graph's calendar view, extended properties and delta query are seen by this
code.

Three things `go-webdav` does not do are composed by hand, and only those:
the two PROPFINDs that find the principal and the calendar home (a provider
may put them on another host, and a redirect must stay a PROPFIND rather
than become a GET), the PROPFIND that reads a calendar's ctag and sync token,
and the conditional headers on writes.
