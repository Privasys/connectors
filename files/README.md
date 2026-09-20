# Files Connector

Reads one file store on behalf of one attested agent, under a capability the
holder approved on their own device: OneDrive and SharePoint through
Microsoft Graph, or Google Drive. It writes into one folder of its own there
and nowhere else. **It never deletes, moves, renames or shares anything.**

## What it does, and what it deliberately does not

An agent can see which drives the holder has, walk a folder newest first,
search with the provider's own index, read a file as text (a Word document,
a spreadsheet, a slide deck, a PDF, a Google Doc), follow what changed, and
leave a note: a text or Markdown file under `Privasys/` at the root of the
holder's personal drive, under a name that does not exist there yet.

It cannot delete a file, move one, rename one, share one, or write outside
its own folder. Those are not settings. There is no method for any of them on
the driver interface, so "it never deletes" is a property of the shape of the
code rather than a promise about its behaviour, exactly as the Mail Connector
cannot send.

## The tools

| Tool | What | Permission |
|---|---|---|
| `list_drives()` | the holder's drives: OneDrive or My Drive (`personal`), the SharePoint document libraries of sites they follow or recently used (`sharepoint`, with the site's name), Google shared drives (`shared`) | read |
| `list_folder(drive?, path_or_id?, limit?, page?)` | the children of a folder, newest first, one page at a time: id, name, folder or file, size, media type, when and by whom it was last modified, where it sits, a web link; a Google Doc, Sheet or Slides file says so in `native` | read |
| `search(query, drive?, limit?)` | the provider's own search: Graph's `search(q=)` on the drive's root, Drive's `fullText contains` | read |
| `get_file(id, offset?)` | the metadata and the TEXT: `.txt .md .csv .json` as they are, HTML stripped, `.docx .xlsx .pptx` and `.pdf` extracted, Google Docs, Sheets and Slides exported by Google as text or CSV; anything else is metadata with a sentence saying why. Downloads stop at 25 MB, text comes in pages of 200 KB with `next_offset`, and credentials in it are removed before it is returned | read |
| `changes(since, wait_seconds)` | the feed the harness holds: `{"changes": [...], "cursor": "..."}`, files `changed` or `removed` with fresh ids, or `reset` when the provider dropped the cursor | read |
| `save_file(name, content, folder?)` | a text or Markdown file under `Privasys/`, or a subfolder of it, under a name that does not exist there yet (a numbered suffix otherwise); returns the file with its id and web link | write |
| `account()` | which account, at which provider, and its personal drive; credential redacted | read |

File ids encode the drive, the provider's item id, and the version the item
was listed at (Graph's eTag, Drive's version). A stale id answers 409 rather
than addressing what the file has become; the fix is to list or search again.
The ids the change feed hands out are fresh.

`changes` follows Graph's delta query on the personal drive's root, or
Drive's `changes.list` from a start page token, every 20 seconds inside the
held call. The cursor is the delta link or the page token, opaque; a Graph
link is checked to still point at Graph before a bearer is sent to it, because
a cursor is an input when it comes back.

## Reading a file

What an agent receives is text, not bytes. The Office formats are read from
the zip and the XML inside with the standard library alone: Word paragraphs
with table cells tab-separated, Excel sheet by sheet as CSV with the shared
strings resolved, PowerPoint slide by slide in order. PDF text comes from one
permissively licensed parser, pinned. HTML is stripped to its text. Every
extractor is bounded on both sides and answers a malformed file with an error
rather than a panic, because a file someone dropped into a shared folder must
not be able to stop the connector.

The credential filter runs on every page of text before it leaves, for the
same reason it runs on mail: it must hold when the model has been talked into
something. One-time codes, reset and magic links, tokens and keys are replaced
rather than deleted, so the text still reads as what it was.

## Where things live

**The connector keeps no durable user state.** The credential is an OAuth
token set: at rest only on the holder's own device, where their wallet keeps
the refresh token this service asked it to hold, and in use only in the memory
of this attested process. There is no sealing key, no volume with anything of
the holder's on it, no storage peer. The holder's revoke is honoured here, in
the one place the credential exists. **Files are never stored**: the provider
stays the system of record, and every tool reads it on demand.

**A restart forgets everything**, credentials and capabilities alike. That is
the price the design accepts. Each holder then gets one request on their
phone at the next use, their wallet answers with the refresh token it kept,
and their unattended runs wait until it has.

## Connecting an account

There is no page to do it on, and nothing is ever typed but the choice of
provider. The wallet reads what this service needs
(`GET /v1/capabilities/setup`), draws it on the approval screen, and sends the
answers with the mint (`POST /v1/capabilities`, `setup`). The first question is
the provider alone, **Microsoft** or **Google**, because what comes next
depends on it; an account address may be given beside it and is used only to
check that the sign-in matched.

The second step is one button for that provider: **Continue with Microsoft**
or **Continue with Google**. The wallet opens `https://<this host>/v1/oauth/start`
in an authentication session; this service sends the browser to the provider
with PKCE and the scopes below; the provider sends it back to
`https://<this host>/v1/oauth/callback`; this service exchanges the code with
its sealed client secret, keeps the tokens in memory under a one-time grant
code, and sends the browser back to the wallet's own scheme with that code and
nothing else. The wallet puts the code in the mint's `setup`; the service
redeems it once, proves the tokens with the provider's own probe (Graph:
`/me` and `/me/drive`; Drive: `about`), and answers the mint with
`"keep": {"refresh_token": "..."}`.

That refresh token is the one thing this service asks the wallet to keep for
it. The holder never typed it, and without it the credential would not
outlive one access token. On a later mint the wallet sends it back as
`setup.kept.refresh_token`, the service mints an access token from it, proves
it, and connects with no browser. A kept token the provider no longer honours
is a 502 with a sentence, and the sign-in button again.

Both providers sign in through the same two routes; the start URL names the
provider and the callback is matched to the sign-in that started it. Microsoft's
token endpoint is asked for a refresh with the scope named again, which is what
it wants.

### When the credential is not in memory

Every tool call, and the change feed, then answer **403** with

```json
{"error": "…", "credential_needed": true, "needs_holder": true}
```

The sentence is written for the agent: the file store details are on the
user's device, not here, so ask the user, then call `request_access` for their
`files.cloud` resource **with `ask_again`**. The device's own record may still
say this service is approved, and only `ask_again` makes it ask afresh; the
device then sends the token it kept, or draws the sign-in button again, on the
approval screen. No retry loop, no page to visit.

## Authorisation

The same two facts as the Mail Connector, checked by the same code (the sdk's
package `connector`): the **acting user** the platform asserts in
`X-Privasys-On-Behalf-Of`, and a live capability for the **calling app** the
runtime verified from the mutual RA-TLS client certificate, carrying the
permission the call needs. Read and write are separate checks, because they
are separate sentences on the approval screen: a holder who approved read-only
must not find the agent writing. Enforcement fails closed, and the switch that
turns it off is explicit and loud.

The **holder**, who decides, is established from the relay-asserted
`X-Privasys-Sub` or from a bearer verified against the configured issuer's key
set, never from the header the calling app writes. See the Mail Connector's
README for why that distinction is a privilege boundary.

## Endpoints

| Path | Who calls it |
|---|---|
| `GET /` | anyone: what this service is, and that there is no page to connect on |
| `POST /tools/*` | the attested agent, the tools above, see `privasys.json` |
| `GET /api/v1/mcp/tools` | the agent's MCP client: the catalogue |
| `POST /api/v1/mcp/tools/*` | the same tools, at the path that client calls |
| `GET /v1/capabilities/setup` | the wallet: what the holder must answer |
| `POST /v1/capabilities` | the wallet, as the holder: connect and mint on one tap |
| `GET /v1/capabilities`, `DELETE /v1/capabilities/{id}` | the wallet: list and revoke; with the last one go the credential and the driver |
| `GET /v1/apps`, `DELETE /v1/grants/{id}` | the older names for the same list and revoke |
| `GET /v1/oauth/start?provider=…`, `GET /v1/oauth/callback` | the holder's browser, held by the wallet, for the sign-in |
| `GET /.well-known/attestation-extensions` | the runtime: the configuration digest for the certificate |
| `GET /health`, `GET /readiness` | the platform |

The two tool paths are one closure registered twice, so the acting-user
check, the configure gate, the credential check and the capability check are
the same code rather than equivalent code. `configure` is filtered out of the
catalogue.

## Deploying

The image is `ghcr.io/privasys/files-connector`, built by the publish
workflow on a push touching `files/` or `sdk/`. Deploy it by digest, never by
tag.

Configure it once (`POST /configure`, through the platform). The fields:

| Field | What |
|---|---|
| `idp_issuer`, `idp_audience` | whose tokens prove which person is approving; empty means the platform's own |
| `microsoft_client_id`, `microsoft_client_secret` | the Entra app registration this deployment signs Microsoft accounts in with; empty means Microsoft accounts cannot be connected here |
| `google_client_id`, `google_client_secret` | the Google Cloud OAuth client for Google accounts; empty means Google accounts cannot be connected here |

The certificate carries a digest of the configuration: the two identity
fields, each client id, and the **hash** of each client secret rather than its
value, so the certificate says which clients this deployment speaks as without
carrying a secret.

**The Entra app registration**, for Microsoft, is the deployer's to create in
the Microsoft Entra admin centre:

1. Register an application with **Accounts in any organizational directory
   and personal Microsoft accounts**, so a work account and a personal one
   both sign in through the `common` tenant.
2. Add a **Web** redirect URI of `https://<this host>/v1/oauth/callback`,
   where the host is the one the wallet reaches this service on. Nothing else
   is authorised: the wallet's own scheme never appears at Microsoft.
3. Under API permissions add the **delegated** Microsoft Graph permissions
   `offline_access`, `User.Read`, `Files.Read.All`, `Sites.Read.All` and
   `Files.ReadWrite`. `Files.ReadWrite` is what lets the connector create its
   own folder and write into it; `Sites.Read.All` is what lists SharePoint
   libraries. A tenant may require admin consent for the Sites permission.
4. Create a client secret, and put the application (client) id and the secret
   into `configure`.

**The Google Cloud OAuth client**, for Google, is the deployer's to create in
a Google Cloud project of their own:

1. Enable the **Google Drive API**.
2. Configure the OAuth consent screen with the scopes `openid`, `email`,
   `https://www.googleapis.com/auth/drive.readonly` and
   `https://www.googleapis.com/auth/drive.file`.
3. Create an OAuth client of type **Web application**, with the authorised
   redirect URI `https://<this host>/v1/oauth/callback`.
4. Put the client id and secret into `configure`.

`drive.readonly` is a **restricted** scope at Google. A client that asks for
it can be used **unverified by up to 100 users**, each of whom sees Google's
unverified-app warning at sign-in; past that, Google requires the client to go
through its verification, including a security assessment. A client in a
Google Workspace organisation that is marked **Internal** on its consent
screen is exempt: it serves that organisation's users without verification
and without a cap. Plan the deployment on that basis.

## Running it locally

```sh
export FILES_ALLOW_UNGRANTED=yes-i-am-developing   # no capability checks
export FILES_CONFIG=./config.json                  # where configure writes
export PORT=8123
./files-connector
```

Configure it with at least one client, then connect an account the way the
wallet does: read the setup, open the start URL for the provider in a browser
with a wallet-shaped `redirect_uri` and a nonce, take the grant code from the
redirect the callback answers with, and mint with it as a holder the relay
would have named. The grant code is single use and lives ten minutes.

```sh
curl -s -X POST localhost:8123/configure -d '{"google_client_id":"…","google_client_secret":"…"}'
curl -s localhost:8123/v1/capabilities/setup -H 'X-Privasys-Sub: user-1'
EXP=$(( $(date +%s) + 86400 ))
curl -s -X POST localhost:8123/v1/capabilities -H 'X-Privasys-Sub: user-1' -d @- <<JSON
{"nonce":"n","subject_app_id":"00000000000000000000000000000001","kind":"files.cloud",
 "permissions":["read","write"],"expires_unix":$EXP,
 "setup":{"provider":"Google","grant":"<the grant code>"}}
JSON
```

## Known ground, and what is not

Both drivers are exercised against fakes of their providers in their tests: a
fake Graph with a personal drive and a SharePoint library, the content
redirect, the delta feed, folder creation and the upload; a fake Drive with
My Drive and a shared drive, the query shapes the driver writes, export,
`changes.list` and the multipart upload. The sign-in is exercised end to end
against fake authorisation servers for both providers, including the
kept-token path after a restart and Microsoft's refresh with the scope named.
The extractors are tested on fixtures built in the tests and fuzzed.

**It has not been run against a real tenant or a real Google account.** No
Microsoft 365 tenant, personal Microsoft account or Google account was
available when it was written. The first real run will be the first time
Graph's answers to the site and insights queries, its `$orderby` support per
library, Drive's `corpora` behaviour on search, and both providers' token
endpoints are seen by this code.

## Where the code lives

What is the Files Connector's is the two drivers, the setup schema, the
probes, the text a file becomes and the tool list. Who the holder is, who a
call acts for, the capability check, the credential in memory and its refusal,
the wallet-facing routes, the catalogue, the configure gate, the OAuth dance
and the redaction are the sdk's (`../sdk`), the same code in every connector
rather than equivalent code, and the root README says why that split is a rule
rather than a tidiness. The extractors are in the sdk too (`sdk/extract`),
Apache-2.0, because the next connector that hands an agent a document will
need them unchanged.
