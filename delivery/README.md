# Private delivery component

This component implements the accepted Machine Monitor private-update channel. It
contains no account, resource, origin, owner credential, recipient credential or
publisher key. Source availability grants no binary redistribution permission;
repository proprietary terms and independent third-party notices still apply.

## Wire contract

The only public routes are `GET /` and `GET /download.js`. The page discloses no
release metadata until access validation. Protected requests carry the recipient
credential exclusively in `Authorization: Bearer …`, never a URL or cookie.

| Route | Behavior |
| --- | --- |
| `POST /v1/access/check` | JSON `{app_id, channel}`; returns `schema=machine-monitor/access-status/v1`, `app_id`, `channel`, opaque `grant_id`, integer Unix-seconds `expires_at` |
| `GET /v1/apps/{app}/channels/{stable\|qualification}/manifest` | Exact current release JSON; authorization and release selection share one primary D1 query |
| `GET /v1/apps/{app}/releases/{release}/{archive\|package}/parts` | Closed descriptor binding ordered piece indexes, sizes and hashes to the authorized ZIP |
| `GET`/`HEAD /v1/apps/{app}/releases/{release}/{archive\|package}/parts/{index}` | One independently authenticated piece, at most 1 MiB |
| Unsuffixed `archive`/`package` locators | Unavailable after authorization; no whole-file concatenation fallback |

Release JSON follows `machine-monitor/release/v1`. Both `archive` and required
`first_install` descriptors have `{path,size,sha256,ed25519_signature}`; paths use
exact same-origin `archive` and `package` locators with the same release ID. Clients
append `/parts` and `/parts/{index}`; response data cannot select another URL. The app,
bundle, team, platform, schema and origin trust invariants are fixed by the
accepted interface. The closed version string is one to four numeric components without leading zeros; release and qualification IDs use one to 128 ASCII letters, digits, underscores or hyphens. Build
is a positive safe integer. Archives are bounded to 512 MiB. Native consumers
ignore the first-install package for updates. The browser hashes the first-install
package against the authorized manifest; macOS verifies the signed applications
on opening. Native updater signature and code/platform checks remain mandatory.

`machine-monitor/artifact-parts/v1` has exactly `schema`, `app_id`, `release_id`,
`kind`, `artifact_sha256`, `artifact_size`, `part_size=1048576` and `parts`.
Each part has exactly `{index,size,sha256}` with contiguous zero-based indexes,
at most 512 entries and exact full-size non-final pieces. Metadata is bounded to
128 KiB; duplicate/unknown keys, incorrect identity, totals and bounds are rejected.
Native and browser downloaders validate each piece and assemble the ZIP locally
within one 300-second operation deadline. Cancellation removes the native owned
partial file or browser references. Native full-ZIP SHA256/Ed25519 verification
and code validation still precede installation.

Every protected request creates a fresh `DB.withSession('first-primary')` and
performs authorization in its first query. A session's subsequent reads may use
replicas, so it is never retained across requests. Expired/revoked/unknown grants
fail closed. Qualification requires both an owner grant and an explicit
qualification entitlement, enforced by SQL and the Worker. Owner status alone
grants no stable access. Every response is private/no-store, including errors and
HEADs. There is no Cache API, redirect, CORS, generic asset fallback, object URL,
conditional-304 response or range bypass. Authenticated ranges return 416.
Database/storage/invalid-release failures return 503 without internal diagnostics.
Revocation affects subsequent requests; it cannot revoke in-flight/downloaded bytes.

Access files are bounded to 4096 bytes:

```json
{"schema":"machine-monitor/access/v1","app_id":"com.kleinperkins.machine-monitor","origin":"https://OWNER_APPROVED_DOWNLOAD_HOST","token":"GENERATED_ONLY_IN_THE_PRIVATE_OWNER_PROCESS"}
```

There is no channel override in a file. Native builds select their compiled
channel. The public page always selects stable. Imported files cannot change the
current site's trusted origin. Browser reset/pagehide aborts requests, clears file
and token references and revokes object URLs; this does not claim secure memory
erasure. Nothing is stored in localStorage/sessionStorage/cookies. No analytics,
third-party assets, telemetry or service worker is installed.

## Free-only owner tooling interface

This is a source/synthetic implementation of the approved Free-only successor,
not a live hosting or zero-charge qualification receipt. Every provider mutation
requires a fresh, explicit owner observation that the configured account is on
**Workers Free**. There is no R2 binding, subscription/upgrade command, paid
fallback, public object URL, or `--assume-free` bypass. An independent account
owner can change its plan; this tool cannot prevent that. Unknown/paid/stale or
wrong-account evidence blocks creation, deployment and publication.

`scripts/delivery.py` is import-safe. Use an explicit canonical owner-owned
mode-0600 configuration outside Git. `owner-config.example.json` lists every key.
`assets_directory` must already exist outside Git, be owner-owned and mode 0700.
Its descendants must be mode-0700 directories and mode-0600 regular part files;
symlinks, foreign ownership, unrelated files, `_headers`, `_redirects`, HTML/SPA
fallbacks and routing control files are rejected. Artifact bytes and private
observations never belong in source or public CI output.

`free_plan_proof` names a separate private mode-0600 JSON file with **exactly**:

```json
{
  "schema": "machine-monitor/free-plan-observation/v1",
  "account_id": "OWNER_EXPLICIT_ACCOUNT_ID",
  "observed_plan": "Workers Free",
  "source": "owner-dashboard-observation",
  "source_reference": "OWNER_ACTUAL_DASHBOARD_OR_MESSAGE_REFERENCE",
  "observed_at": 0,
  "expires_at": 0
}
```

The zero timestamps are placeholders that fail closed. Actual timestamps are Unix
integer seconds: observation must not be in the future, expiry must be after now
and at most one hour after observation. This records the owner's dashboard
observation with its provenance; it is **not independent provider API proof**.
Renew it only from a new actual observation. No actual owner account, URL,
observation, access file or artifact is included in this repository.

Wrangler must be preinstalled at exactly **4.158.0**, and Node at **26.4.0**
(`MONITOR_NODE` can select the executable). Configure the absolute JavaScript
entry point, `wrangler/bin/wrangler.js`; the tool executes it through the verified
Node binary, regardless of the interpreter selected by `PATH`. The original owner HOME/auth context
is retained. `wrangler auth token --json` output is captured only in process
memory; no token enters argv/config/logs/recipient apps. OAuth/API-token auth is
supported; global key/email auth is refused. Wrangler's normal `log` level is
required because quieter levels suppress its JSON output. All stdout/stderr stay
captured; disk logging, metrics, error reporting, observability and inherited
output-file overrides are disabled. API redirects and nonofficial origins deny.

Owner archive readback and native HTTP requests send descriptive application
`User-Agent` headers. This follows Cloudflare's
[workers.dev client guidance](https://developers.cloudflare.com/support/troubleshooting/http-status-codes/cloudflare-1xxx-errors/error-1010/)
for requests rejected when a library-default identifier is used.

- `--config /private/config.json deploy` checks Free evidence, exact account-owned
  `{worker}.{subdomain}.workers.dev` origin and the complete private asset tree,
  applies the additive D1 schema and deploys one version at 100 percent. Generated
  configuration always uses `assets.binding=ASSETS`, unconditional boolean
  `run_worker_first=true`, `html_handling=none`, `not_found_handling=none` and
  `preview_urls=false`. No negative routing patterns or static-first route exist.
  Custom domains and zone routes are currently refused: they require a separately
  qualified fail-closed profile. The canonical workers.dev hostname is the only
  supported origin; default aliases and preview/version hosts deny in the Worker.
- `deployment_state` is an explicit private, atomically replaced mode-0600 receipt
  binding the successful Wrangler-reported version ID, provider version etag,
  exact local source/configuration and complete retained asset inventory. The tool
  reads the active deployment back, including entries at **0 percent**; exactly
  one recognized version at 100 percent is required. It checks preview/default
  settings, account custom domains and every account-owned zone's Worker routes.
  Missing permissions or unknown API shape fail closed. This receipt is operation
  provenance, not independent live CPU/quota/signing qualification. Lost/unknown
  state is a blocker, never permission to replace existing deployment history.
- `--config /private/config.json check-privacy` repeats the exact active-version,
  source/configuration/origin/preview/route readbacks without altering retention.
- `create-grant --label OPAQUE_LABEL --expires-at UNIX_SECONDS --output /private/recipient.machine-monitor-access`
  creates a 256-bit random recipient token, stores only SHA256(token), and writes
  a new mode-0600 file. Qualification needs `--owner --channel qualification` and
  finite expiry. `revoke-grant --grant-id OPAQUE_UUID` revokes future requests.
  The owner shares access files privately; this tool sends no messages.
- `publish --manifest /private/release.json --receipt /private/qualification.json --archive /private/update.zip --package /private/first-install.zip`
  validates qualification evidence and full artifact sizes/hashes; splits each ZIP
  into ordered pieces of at most **1 MiB**, below the 25-MiB file limit; retains
  the full asset set and deploys it **before** publishing any D1 release/channel.
  Immutable D1 part metadata binds each ordered path/length/hash to app, release,
  kind and full-artifact hash. The full SHA256/Ed25519 manifest descriptors and
  archive/package identity locators are unchanged. A temporary owner-only
  qualification grant reads the descriptor and every authenticated piece back;
  exact hash/length verification precedes channel advancement. A readback failure
  may retain an immutable qualification row but never advances its channel.
  New stored part rows use compact JSON. The Worker validates their closed,
  scalar-only shape before requiring a lossless native JSON round trip; duplicate
  keys, escaped aliases and noncanonical encodings fail before any asset read.
  External wire JSON keeps its existing duplicate-key parser. Piece requests
  validate the complete bounded layout without constructing the descriptor
  response used by `/parts`; authorization and EOF checks are unchanged.
- Stable publication uses the same command with stable/qualified manifest and no
  archive/package inputs. The existing qualification manifest must match exactly
  except channel/qualified. Both retained artifacts are read back again; stable
  promotion never stages or uploads replacement bytes. Equal/decreasing builds
  cannot move a channel backward. Exact retries are idempotent.

Every later deployment preserves **all** previously deployed and D1-referenced
parts, including current, candidate and required rollback assets. There is no
retention deletion operation or automatic garbage collection. Preflight hashes
all local retained files and rejects more than 20,000 assets or any file over
20 MiB, preserving old immutable assets without serving old aggregate requests.
New artifacts remain bounded to 512 MiB (at most 512 one-MiB pieces); both
ZIPs/candidates/rollback sets count toward the file bound. Empty initial asset
sets are supported if the pinned provider tool accepts them; failure is a blocker.
Direct `Cloudflare` mutation methods enforce the same Free gate. Narrow guarded
`create_database(name)` and `create_subdomain(name)` bootstrap methods permit an
explicit new D1 database (known available Free count below ten) or a previously
unclaimed account subdomain. They never replace an existing subdomain, activate
billing or create storage subscriptions. Bootstrap still requires separate owner
authorization; source imports do not execute these methods.

Qualification receipts use `schema=machine-monitor/qualification/v1`, exact
`qualification_id`, `source_revision`, `app_id`, `build`, both artifact SHA256/size
pairs and true checks `ci_required`, `merged_source`, `developer_id`,
`notarization`, `stapled_ticket`, `gatekeeper`, `archive_signature`,
`recovery_packaged`. Stable additionally requires `private_upgrade=true` for the
same bytes. A JSON assertion is not actual qualification evidence.

The Worker authenticates in the **first query of a fresh first-primary D1
session**, before any asset binding fetch. It constructs credential-free internal
piece requests and checks status/length. Each byte request reads at most one
1-MiB piece plus a guard byte, with 30-second fetch/read bounds and an EOF check
before success. It never concatenates or hashes a complete artifact. Each request
has one authorization query and at most one asset fetch, independent of ZIP size.
Missing/truncated/oversized/quota-failed pieces fail unavailable; recipient
full hash/signature validation rejects incomplete or tampered bytes. Cancellation
stops the current reader. External guessed part paths deny, even with a token.
Conditional requests deny after authorization; ranges return 416. Override
headers deny, and every active version must be reviewed because the provider can
route an override to a zero-percent version **before** executing Worker code.

Workers Free request exhaustion can return 429/platform error 1027 before Worker
execution; D1/asset quota errors deny or abort. Unconditional worker-first avoids
static fallback. Installed local monitoring remains available. Live acceptance
still must measure Free CPU under 10 ms, memory under 128 MB, account-shared daily
request/D1 quotas, D1 database/storage capacity, all active versions and alias/
override/route behavior, plus actual signed older-to-newer upgrades. Synthetic
fixtures prove source behavior only and create no provider resources.

## Synthetic validation

`scripts/release.py` prepares artifacts locally from the exact current merged
`main` after its latest GitHub Actions `ci-required` passes. Run it in the pinned
Python/development/build environment, with an existing mode-0700 output directory
outside Git and explicit arguments:

```sh
python scripts/release.py --source-revision MERGED_MAIN_SHA \
  --version VERSION --build-number BUILD --release-id RELEASE_ID \
  --qualification-id QUALIFICATION_ID --update-config /private/public-settings.json \
  --signing-identity CERTIFICATE_SHA --notary-profile PROFILE_NAME \
  --sparkle-account APP_SPECIFIC_ACCOUNT --output /private/releases
```

The settings file contains only `origin`, `channel` and `public_ed25519_key`.
When the upstream download is unavailable, `--sparkle-archive /private/Sparkle-2.10.1.tar.xz`
accepts the official archive obtained separately. It requires an owned bounded
canonical regular file and verifies the same pinned SHA256 before extraction,
even if a cache already exists. Only ignored build output in the fresh checkout
is seeded; the builder revalidates the complete cache. Source parity, signing,
notarization, Gatekeeper and archive-signature gates still run normally. The input
choice is recorded in private provenance without recording the local path.
Signing identity, notary profile and Sparkle account are references to existing
owner-managed secure material. The tool never exports keys. It builds an isolated
checkout, signs inside-out, requires accepted notarization and validated stapling,
checks Gatekeeper and packages the final bytes. Outputs include a main-only
updater archive, a separate first-install package with Recovery and instructions,
manifest, qualification receipt and provenance. Child output, deadlines and
process groups are bounded. Output always remains unqualified on the owner-only
qualification channel; a real private upgrade and exact-byte stable promotion
remain separate steps. This command performs no deployment or installation.

`tests/test_update_channel.py` runs the actual Worker against Node's in-memory
SQLite and fixture Static Assets (not a rewritten authorization model), plus owner-tool
checks. `tests/test_update_download_layout.py` and
`tests/test_update_download_lifecycle.py` launch a bounded loopback HTTPS fixture
using a disposable self-signed certificate and a fresh Chromium context. Test TLS
exceptions exist only in that browser fixture; production TLS is unchanged.

The wrappers require pinned Node 26.4.0 and Playwright 1.64.1. Missing runtimes
fail; no test silently skips. Tests own and stop all processes/servers and close
the in-memory DB, browser and context. Optional `MONITOR_TEST_OUTPUT` captures
360/768/1280 light/dark screenshots. Actual Cloudflare deployment, owner account
qualification, signing/notarization, VoiceOver UAT and a real signed private
older/newer upgrade remain independent release gates.

Primary implementation references:
[D1 Sessions API](https://developers.cloudflare.com/d1/worker-api/d1-database/#withsession),
[Static Assets Free limits](https://developers.cloudflare.com/workers/static-assets/billing-and-limitations/),
[Worker-first routing](https://developers.cloudflare.com/workers/static-assets/routing/worker-script/),
[Version overrides including zero-percent versions](https://developers.cloudflare.com/workers/versions-and-deployments/version-overrides/),
[Wrangler owner auth](https://developers.cloudflare.com/workers/wrangler/commands/general/#auth-token),
[Workers versions API](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/versions/methods/get/),
[Wrangler config](https://developers.cloudflare.com/workers/wrangler/configuration/).

Pinned-source checks for this owner-auth path: [4.158.0 auth command](https://github.com/cloudflare/workers-sdk/blob/wrangler%404.158.0/packages/wrangler/src/user/commands.ts), [JSON logger and disk-log opt-out](https://github.com/cloudflare/workers-sdk/blob/wrangler%404.158.0/packages/wrangler/src/logger.ts).

Account-owned primary origin reference: [Get a Workers Subdomain](https://developers.cloudflare.com/api/resources/workers/subresources/subdomains/methods/get/).
