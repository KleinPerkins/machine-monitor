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
| `GET`/`HEAD /v1/apps/{app}/releases/{release}/archive` | One-main-app updater ZIP, authenticated for the release's channel |
| `GET`/`HEAD /v1/apps/{app}/releases/{release}/package` | First-install ZIP containing main app, separate Recovery app and Finder instructions; independently authenticated |

Release JSON follows `machine-monitor/release/v1`. Both `archive` and required
`first_install` descriptors have `{path,size,sha256,ed25519_signature}`; paths use
exact same-origin `archive` and `package` routes with the same release ID. The app,
bundle, team, platform, schema and origin trust invariants are fixed by the
accepted interface. The closed version string is one to four numeric components without leading zeros; release and qualification IDs use one to 128 ASCII letters, digits, underscores or hyphens. Build
is a positive safe integer. Archives are bounded to 512 MiB. Native consumers
ignore the first-install package for updates. The browser hashes the first-install
package against the authorized manifest; macOS verifies the signed applications
on opening. Native updater signature and code/platform checks remain mandatory.

Every protected request creates a fresh `DB.withSession('first-primary')` and
performs authorization in its first query. A session's subsequent reads may use
replicas, so it is never retained across requests. Expired/revoked/unknown grants
fail closed. Qualification requires both an owner grant and an explicit
qualification entitlement, enforced by SQL and the Worker. Owner status alone
grants no stable access. Every response is private/no-store, including errors and
HEADs. There is no Cache API, redirect, CORS, public asset binding, object URL,
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

## Owner tooling interface

`scripts/delivery.py` is import-safe. All operations require an explicit canonical,
owner-owned mode-0600 config **outside every Git repository**. Copy
`owner-config.example.json` into a private directory and supply explicit existing
bindings; `wrangler.template.json` illustrates generated bindings only. Wrangler
must be preinstalled at exactly **4.158.0**; Node must be exactly **26.4.0**
(`MONITOR_NODE` may select the pinned executable). There is no unpinned installer.

The CLI captures `wrangler auth token --json` directly into process memory using
the original owner HOME/auth context and refresh behavior. It never displays or
persists that output, never puts credentials in argv, suppresses upstream raw
output, rejects API redirects and disables Wrangler metrics/Worker observability.
It supports OAuth/API-token auth; global API-key/email auth is refused. Only the
normal Cloudflare API origin receives the owner credential. The CLI is never
executed by the public UI, Worker or recipient applications.

- `--config /private/config.json check-privacy` reads current R2 domain settings:
  managed `enabled=false` and no custom domains are required. Unknown state fails.
- `--config /private/config.json deploy` repeats that gate, applies the additive
  fixed D1 schema, and deploys the Worker with existing explicit bindings,
  workers.dev/preview URLs disabled and the selected custom hostname. No account,
  database, bucket, paid plan or account upgrade is created/enabled. This operation
  still requires the owner-authorized deployment gate.
- `--config /private/config.json create-grant --label OPAQUE_LABEL --expires-at UNIX_SECONDS --output /private/recipient.machine-monitor-access`
  generates 32 random bytes, stores SHA256(token) only and writes a new mode-0600
  file without overwriting any existing path. Add `--owner --channel qualification`
  for a finite owner-only qualification grant. Share files privately through the
  owner's chosen channel; this tooling sends no messages.
- `--config /private/config.json revoke-grant --grant-id OPAQUE_UUID` revokes that
  grant. No credential is required as a command argument.
- `--config /private/config.json publish --manifest /private/release.json --receipt /private/qualification.json --archive /private/update.zip --package /private/first-install.zip`
  publishes a qualification release. The tool takes bounded private snapshots,
  checks both sizes/hashes, uploads content-addressed private objects, downloads
  and hashes each readback, and appends the immutable release record before
  advancing its channel. D1 triggers prevent update/deletion of release rows.
  Equal or decreasing builds cannot move a channel backward. Exact publication
  retries are idempotent; a reused ID with different metadata fails.
- For stable promotion use the same `publish` command with stable/qualified release
  JSON and omit archive/package arguments. It must match the existing qualification
  manifest exactly except channel/qualified. Both retained objects are downloaded
  and reverified; no replacement archive may be uploaded during promotion.

The private qualification receipt is
`schema=machine-monitor/qualification/v1`, with exact `qualification_id`,
`source_revision`, `app_id`, `build`, `archive_sha256`, `archive_size`,
`first_install_sha256`, `first_install_size`, and `checks`. Required true checks are
`ci_required`, `merged_source`, `developer_id`, `notarization`, `stapled_ticket`,
`gatekeeper`, `archive_signature`, `recovery_packaged`. Stable additionally requires
`private_upgrade=true`, bound to the same exact archive hashes. These are owner
release-gate assertions backed by actual release evidence; merely creating JSON
is not qualification. The component does not manufacture evidence or activate
publishing on source merge.

Private bucket settings must remain disabled in account governance after deploy;
Cloudflare account administrators can change bindings/public access, and source
code cannot prevent an administrator from doing so. Content-addressed object
names and owner-tool readback verification preserve the immutable-byte contract
within this tool; publisher signatures and recipient verification detect external
storage tampering. No public GitHub binary assets are created.

## Synthetic validation

`tests/test_update_channel.py` runs the actual Worker against Node's in-memory
SQLite and fixture R2 (not a rewritten authorization model), plus owner-tool
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
[R2 Worker API](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/),
[Wrangler owner auth](https://developers.cloudflare.com/workers/wrangler/commands/general/#auth-token),
[R2 domain settings API](https://developers.cloudflare.com/api/resources/r2/subresources/buckets/subresources/domains/),
[Wrangler config](https://developers.cloudflare.com/workers/wrangler/configuration/).
