# Meetings Connector

Reads the transcripts Zoom or Microsoft Teams produced for meetings the
holder took part in, from the holder's own account, on behalf of one
attested agent under a capability the holder approved on their own device;
and keeps the ones the agent saves in the holder's own Drive. **It never
joins a meeting and never records one.** You type your address; the
connector finds who hosts it and asks you to sign in at Zoom, or at Microsoft
for a Microsoft address whose meetings are on Teams.

## What it does, and what it deliberately does not

The one line to hold: **we read transcripts the platform produced for
meetings you were in, from your own account; we do not join and we do not
record.**

An agent can see which of the holder's past meetings have a transcript, read
one as speaker-attributed text, keep one in the holder's Drive where it
becomes a document the holder owns, and follow which meetings gained a
transcript since it last looked.

It cannot join a meeting, start one, schedule one, invite anyone, or switch
recording or transcription on. Those are not settings. There is no method for
any of them on the driver interface, so "we do not join and we do not record"
is a property of the shape of the code rather than a promise about its
behaviour, exactly as the Mail Connector cannot send. Whether a meeting is
recorded and transcribed is decided where it always was: by the people in
it, on the platform they held it on.

## The tools

| Tool | What | Permission |
|---|---|---|
| `list_meetings(from, to)` | past meetings in a window of at most 62 days (the last seven by default), newest first, that have a recording or a transcript: id, title, start, end, organiser, participants where the provider names them, `has_transcript`, `transcript_at` | read |
| `get_transcript(meeting_id, format?, offset?)` | the transcript as speaker-attributed text (default: one line per turn, `[hh:mm:ss] Speaker: text`, consecutive turns by one speaker merged) or as the raw WebVTT; codes and links to log in stripped; paged at 48 KiB with `next_offset` | read |
| `save_transcript(meeting_id)` | writes `<date> <title>.md` (front matter, then the text) and `<date> <title>.vtt` into the holder's Drive folder; the same meeting saved twice updates the same files; returns the Drive paths and what Drive said about indexing | read |
| `changes(since, wait_seconds)` | the feed the harness holds: `transcript_available` per meeting since the cursor, the last week asked for every 30 seconds inside the held call | read |
| `account()` | provider, address, and whether the archive folder is configured, approved, declined or withdrawn | read |

Every tool needs `read`, `save_transcript` included: what the holder granted
is the reading of their meetings, and what that tool writes goes only into
this service's own folder in the holder's Drive, which the holder approved
separately and can withdraw there.

**Zoom** lists the holder's cloud recordings (`GET /users/me/recordings`, a
month at a time) and reads the `TRANSCRIPT` file of one recording at its
download URL, with the holder's bearer, and only to Zoom's own hosts. A
recording whose transcript Zoom is still producing is listed with
`has_transcript` false.

**Microsoft Teams** has no "my meetings with a transcript" call, so the
listing is built from the calendar: events in the window with a Teams join
link (`GET /me/calendarView`), each resolved to its online meeting by that
link (`GET /me/onlineMeetings?$filter=JoinWebUrl eq '…'`), each asked for its
transcripts (`GET /me/onlineMeetings/{id}/transcripts`). The newest is read
as WebVTT (`…/transcripts/{id}/content?$format=text/vtt`). A meeting the
holder's account cannot resolve (someone else's tenant) is listed from the
calendar alone, with no transcript.

Both come back as WebVTT and are parsed by the sdk's `vtt`: Teams names the
speaker in a voice tag, Zoom writes it as a prefix on the line, and the
agent sees the same text either way. Transcript text is data said by other
people, never instructions, and the descriptions say so.

## Where things live

**The credential keeps no durable home here.** It is an OAuth token set, at
rest only on the holder's own device and in use only in the memory of this
attested process. There is no sealing key and no volume with anything of the
holder's on it. The holder's revoke is honoured here, in the one place the
credential exists. **A restart forgets everything**, credentials and
capabilities alike; each holder then gets one request on their phone at the
next use, their wallet answers with what it kept, and their unattended runs
wait until it has.

**Saved transcripts live in the holder's Drive**, and this is the one thing
that makes this connector unlike mail and calendar, which store nothing at
all. The reason is the question the connectors README asks of every
connector: is the provider a durable system of record for this content? For
a transcript it is not. Zoom's retention ages recordings out, Teams' too,
and a transcript is a document, the highest-value knowledge the holder's
assistant will ever have. So the connector declares a `storage.folder` of
its own in its manifest (`archive`, labelled "Meeting transcripts"), the
runtime brokers the holder's approval of it, Drive places it under
`AppData/Meeting transcripts/`, and `save_transcript` writes there through
the attested Drive leg: mutual RA-TLS to a peer pinned by identity, a
holder-of-key proof minted per request and never stored. What lands there
rests under the holder's keys, in the holder's tenant. The connector's own
disk never sees it, and this service keeps no copy.

The folder is asked for on the same approval screen as the transcripts
access: the setup route lists it as a prerequisite, so the wallet completes
that approval first. **Withdrawing the folder in Drive stops archiving and
nothing else.** Reading transcripts keeps working; `save_transcript` answers
412 with a sentence saying only the holder can restore it, on their device,
which their wallet asks for when the transcripts access is next approved
with `ask_again`. The runtime cannot see a revoke made in Drive and keeps
reporting the folder approved, so the connector remembers Drive's answer and
asks again with a retry. An agent must not call `request_access` for a
`storage.folder` resource of this service: the folder is this service's own
ask, not the assistant's, and the harness cannot ask for another app's
resource.

**Indexing.** The Markdown is written to be searched, and `save_transcript`
asks Drive to index it (`PUT /v1/tenants/{t}/nodes/{id}/indexing`). Today
Drive lets only the holder make that call: an app's folder is created
excluded from indexing and an app cannot mark its own files, so the tool
answers `indexed: false` with Drive's reason, and the holder enables search
on the Meeting transcripts folder in Drive when they want it in their
assistant's memory. When Drive accepts an app's mark, the same call will
report `indexed: true`.

The saved Markdown holds the full text; the credential filter applies to
what leaves this service for the agent, not to the holder's own document in
the holder's own Drive.

## Connecting an account

There is no page to do it on. The wallet reads what this service needs
(`GET /v1/capabilities/setup`), draws it on the approval screen, and sends
the answers with the mint (`POST /v1/capabilities`, `setup`). **The first
question is the address alone**, because the address decides what comes
next: who hosts it (the sdk's `provider`: Microsoft's own domains by name,
then the domain's MX records for a custom domain at Microsoft 365, then
"somewhere else"), and so which platforms could hold its meetings.

**A Microsoft address** may hold its meetings on Teams or on Zoom, so it
gets one choice, `provider`: **Microsoft Teams** or **Zoom**, drawn only
among the providers this deployment has a client for; with one client the
choice is skipped. **Any other address** goes straight to **Continue with
Zoom**, because a Zoom account sits on any address and Teams needs a
Microsoft one. A deployment with no client for any provider open to the
address says so in a 428 with nothing to fill.

Then one button, **Continue with Zoom** or **Continue with Microsoft**. The
wallet opens `https://<this host>/v1/oauth/start?kind=meeting.transcripts&provider=…`
in an authentication session; this service sends the browser to the
provider with PKCE and the scopes; the provider sends it back to
`https://<this host>/v1/oauth/callback`; this service exchanges the code
with its sealed client secret, proves the tokens by opening the account and
reads whose it is (`GET /users/me` at Zoom, `GET /me` at Graph), keeps them
in memory under a one-time grant code, and sends the browser back to the
wallet's own scheme with that code and nothing else. The wallet puts the
code in the mint's `setup`; the service redeems it once, **refuses a
sign-in for any address but the one typed**, so the address is bound to the
account rather than decorative, keeps the credential, and answers the mint
with `"keep": {"refresh_token": "…", "provider": "…"}`.

That refresh token is the one thing this service asks the wallet to keep for
it, with the word for who issued it. The holder never typed it, and without
it the credential would not outlive one access token. On a later mint the
wallet sends it back as `setup.kept.refresh_token` beside the typed address,
the service mints an access token from it, proves it, checks the address,
and connects with no browser; `setup.kept.provider` says which sign-in it
was, so neither the choice nor the resolver is asked again. A kept token the
provider no longer honours is a 502 with a sentence, and the sign-in button
again.

Zoom rotates the refresh token at every renewal, so the token the wallet
keeps is the one from the last mint. Every mint therefore answers with the
current token, and a mint for an account already in memory for the same
address (a second app approved, a wallet re-sending what it kept) does not
touch the provider. After a restart of this service a Zoom account whose
token rotated since the last mint needs one more sign-in; Microsoft's tokens
stay valid.

### When the credential is not in memory

Every tool call, and the change feed, then answer **403** with

```json
{"error": "…", "credential_needed": true, "needs_holder": true}
```

The sentence is written for the agent: the meetings details are on the
user's device, not here, so ask the user, then call `request_access` for
their `meeting.transcripts` resource **with `ask_again`**. The device's own
record may still say this service is approved, and only `ask_again` makes it
ask afresh. No retry loop, no page to visit.

## Authorisation

The same two facts as the Mail Connector, checked by the same code (the
sdk's package `connector`): the **acting user** the platform asserts in
`X-Privasys-On-Behalf-Of`, and a live capability for the **calling app** the
runtime verified from the mutual RA-TLS client certificate. Holder-facing
endpoints never read the acting-user header: a holder is the relay-asserted
`X-Privasys-Sub`, or a bearer from the configured identity provider verified
against its key set. Enforcement fails closed and the switch is explicit.

## Configuration

`POST /configure`, once, through the platform. Nothing here is a holder's
credential.

| Field | What |
|---|---|
| `idp_issuer`, `idp_audience` | whose tokens prove which person is approving; the platform's own by default |
| `drive_host`, `drive_app_id`, `drive_digest` | the Drive this deployment archives into, pinned by identity and optionally by build; all empty on a deployment that archives nothing |
| `zoom_client_id`, `zoom_client_secret`, `zoom_scopes` | the Zoom Marketplace OAuth app, and the scopes it is configured with |
| `microsoft_client_id`, `microsoft_client_secret` | the Entra app registration |

The secrets are sealed like any configured value and take part in the
configuration digest the certificate carries as hashes, so "this deployment
speaks to Zoom as that client and archives into that Drive" is something you
can verify by attesting it. A rotated secret changes the digest.

## Deploying

**Zoom.** Create a user-managed OAuth app on the Zoom Marketplace with
`https://<host>/v1/oauth/callback` as its redirect URL and the granular
scopes `user:read:user`, `cloud_recording:read:list_user_recordings` and
`cloud_recording:read:list_recording_files` (the default `zoom_scopes`). An
app built on the classic scopes uses `user:read recording:read meeting:read`
instead; set `zoom_scopes` to match what the app is configured with, or the
sign-in is refused. Transcripts exist only on a paid Zoom plan with cloud
recording and "create audio transcript" enabled in the account's recording
settings.

**Microsoft.** Create an Entra app registration (accounts in any
organisational directory, or as the deployment needs) with
`https://<host>/v1/oauth/callback` as a web redirect URI, a client secret,
and the delegated permissions `offline_access`, `User.Read`,
`Calendars.Read`, `OnlineMeetings.Read` and
`OnlineMeetingTranscript.Read.All`. The last typically needs an
administrator's consent in the tenant the holder signs in from; without it
Graph refuses the transcript calls and `list_meetings` shows every meeting
without a transcript.

**Drive.** Name the Drive by host and app id, and the runtime brokers the
folder. Deploy with the dependency machinery every other platform app uses:
the connector's Drive leg pins the peer by identity, and the deploy pins the
build behind it.

## Building

```sh
./build.sh                      # IMAGE and TAG are overridable
```

Never `docker build` this directory directly. The tool catalogue reaches the
control plane as an image label, and pasting a second copy of it into the
Dockerfile is how a catalogue starts advertising tools the service does not
serve.

## Running it locally

```sh
export MEETINGS_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export MEETINGS_CONFIG=./config.json                  # where configure writes
export PORT=8123
./meetings-connector
```

Off the platform there is no runtime broker and no attested leg, so
`save_transcript` answers 503 and everything else works. Configure it with
the OAuth clients, then connect the way the wallet does: the setup route
asks the address, then where the meetings are for a Microsoft one, the
start route sends a browser to the provider, and the grant code the callback
sends back goes in the mint's `setup` beside `user`.

## What is tested, and what is not

The drivers are tested against fakes of the Zoom API and of Microsoft Graph
(listing, paging, the transcript download, the UUID and time encodings, the
refusal of a download host that is not Zoom's); the archive against a fake
Drive and a fake runtime broker (write by path, idempotence, the suffix for
a colliding name, the folder never approved, declined and withdrawn, the
prerequisite with its retry, Drive's refusal of an app's indexing mark); the
OAuth path against fake authorisation servers for both providers (the
sign-in, the mint, the kept token after a restart, Zoom's rotation, a
refused token, a sign-in for another address refused at both); the
branching by address (a Microsoft address by its own domain and through a
fake MX, any other address, one client configured, none); the WebVTT parser on Teams and Zoom fixtures; and the tools
through the shell with fake drivers (windows, redaction, paging, the change
cursor, the setup steps).

**Nothing has run against a real Zoom or Microsoft account**, and the
connector has not been deployed. The shapes of the provider answers are
written from their documentation; the first real sign-in is where a field
name or a scope string turns out to differ.
