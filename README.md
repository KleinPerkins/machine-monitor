# Machine Monitor

A local performance dashboard with a dedicated macOS window. Apple Silicon and macOS 26 or later are required for the app. No hosted service or outbound telemetry is used.

## Run locally

Create an environment and install the pinned runtime dependency:

```sh
uv venv .venv
uv pip install --python .venv/bin/python -r requirements.txt
./start.sh
```

Open the localhost address printed by the service. `./start.sh --port 8767` selects another port. Start a 30-second scan, choose 60 seconds, or take a snapshot. Stop ends collection early. Results remain in service memory until the service quits. Control-C or **Stop local service** shuts it down.

## Build the Mac app

```sh
uv pip install --python .venv/bin/python -r requirements-build.txt
.venv/bin/python build_mac_app.py
```

The output is `dist/Machine Monitor.app`. Building does not install or replace an application. Copy that output to your Applications folder if desired, then open it from Finder or Spotlight and choose **Options → Keep in Dock** from its Dock menu. The app bundles its Python service and opens a dedicated AppKit/WKWebView window. Python, Codex, Homebrew and a browser are not required to run the resulting bundle. The build is locally signed; signed distribution and notarization are separate work.

Each fresh app launch starts one 30-second scan at approximately one-second intervals after its window becomes visible. Collection then goes dormant. **Start 30-second scan** starts another run without reloading. Reloading, restoring or unhiding does not start another automatic scan. Hiding, minimizing or fully occluding the window stops collection; restoring it leaves collection dormant. Closing the window or quitting stops the app-owned service. A native parent-exit notification also stops the service after forced app termination. No login item or launch agent is installed.

The app uses a dynamically allocated loopback port. Clicking its Dock icon while it is running brings the existing window forward. Startup and connection errors offer **Try again**; Command-R reloads the monitor. External documentation links explicitly clicked in the app open in the default browser. Browser threshold preferences are scoped to their local origin.

## Read the dashboard

Hover or focus a chart and use the arrow keys to inspect a historical moment. Process tables follow that moment. Rows combine a parent and its observed descendants. Expand **+** to see each member's own CPU, memory and thread values. Independent roots remain separate even when they share a name; system launchers are boundaries. Missing parents are marked. Parent creation times prevent reused PIDs from claiming older children.

Group CPU, resident memory, memory percentage, threads and process counts sum disjoint membership. Every readable process belongs to exactly one group. Partial CPU baselines are marked `~`. Resident memory is an RSS sum and can count shared pages more than once. Group memory growth includes starts, exits and membership changes; it is not proof of a leak. Hover keeps chart and table dimensions stable and preserves table scrolling.

## Metrics and limits

- **CPU:** whole-machine utilization, user/system/idle deltas, logical-core utilization and load averages. Process CPU is CPU-time growth over the actual interval, normalized to one core.
- **Memory:** physical total, OS-available and derived used memory, native pressure state, wired and physically compressed bytes. Breakdown values provide context and are not additive.
- **Swap:** allocated, used and unused current allocation, plus swap-in/out rates from native page-counter deltas. Allocation is dynamic; unused allocation is not maximum capacity.
- **Disk:** startup APFS data-volume capacity and available space, represented once for the shared pool. Device I/O is aggregate throughput, not latency or per-process attribution.
- **Thermals:** read-only Apple SMC CPU/GPU temperatures where a supported mapping is available. The current M2-family mapping includes up to 12 CPU and two GPU sensors. Unknown platforms, inaccessible sensors and invalid readings remain unavailable. The hottest mapped reading is not guaranteed to be the chip junction hotspot. Native OS thermal state is shown separately; its chart strip follows that state.
- **GPU:** best-effort driver activity and in-use system memory. Driver keys vary. GPU allocations share physical RAM and are not added to RAM usage.
- **Context:** power/battery, low-power mode, uptime, readable/skipped processes, threads, interface throughput, collector resource use and collection duration. Network totals may include loopback and tunnels. Storage latency, private process footprint, per-process disk/GPU attribution and task-speed prediction are unavailable.

Core readings update approximately once per second. GPU and battery context update approximately every five seconds with age shown. Scans have an immutable deadline and a three-second visibility lease. Hiding or leaving requests an immediate stop; lease expiry stops sampling if that request cannot arrive. In-flight subprocesses are cancellable and bounded. Multiple browser views share one browser-service scan; visibility changes stop it conservatively.

All assets and telemetry stay local. Host validation, a session cookie, same-origin checks and a custom request header protect telemetry and mutations. Only three UI assets are served. Process arguments and environments are not read or exposed. See `THIRD-PARTY-NOTICES.md` for source and license references.

## Scores and alerts

Health is the minimum of disk, memory-pressure and native thermal-state factors. Missing domains mark the score partial. Numeric temperatures and GPU utilization are outside that score and coverage says so. High CPU use does not reduce health. Headroom is the minimum of CPU idle percentage, scaled available memory, memory-pressure and thermal factors. It describes current workload headroom, not a benchmark.

Default low-disk warnings apply below 10% or 20 GiB available; critical alerts apply below 5% or 10 GiB. Pressure and OS thermal warnings are immediate. CPU at or above 90% must persist five seconds; it clears after three seconds below that level. Gaps reset persistence. Threshold changes apply to the next scan. Process RSS growth above 256 MiB over at least 15 observed seconds produces a short-window growth observation, not a leak diagnosis. Recommendations are advisory.

## Development verification

Install the pinned development dependencies:

```sh
uv pip install --python .venv/bin/python -r requirements-dev.txt
.venv/bin/python -m unittest -v test_monitor test_temperatures
```

Browser regressions use a test-only synthetic collector, an isolated service on an available port, and a separate output directory:

```sh
.venv/bin/python tests/browser_support.py test_hover_layout.py /tmp/monitor-hover
```

The harness owns and stops its service. Synthetic process names, metrics and temperatures keep CI independent of real host inventories, retained scans and sensor access. Fixture modules are not part of the production entrypoint. Real-device temperature qualification and physical Dock/VoiceOver behavior remain local acceptance probes.

The six verification selections are `governance`, `core`, `service`, `browser-layout`, `browser-lifecycle` and `native-app`. `make verify` runs all selections and the aggregate locally; `make verify-shard SHARD=core` runs one selection. Install the browser pinned by Playwright with `.venv/bin/python -m playwright install chromium` before running the browser shards. The native-app shard requires build dependencies and a logged-in macOS desktop session; it builds and verifies the production bundle without launching it, then builds a separate synthetic-only app for lifecycle tests and preserves installed applications.

`.github/test-shards.json` assigns every discovered test file exactly once. Adding an unassigned test, deleting a shard, or omitting a command fails validation. `ci-required` validates a complete set of successful reports bound to the source revision and contract digest. Local synthetic-candidate runs do not establish GitHub CI or reviewer-App activation.

`make probe-device` performs a separate local read-only sensor probe. It is deliberately excluded from CI. Do not commit its output or captured host telemetry.

## Reviewed App delivery

The authoring agent coordinates review and delivery automatically. Before opening a ready PR, it captures a fresh independent review using the PR-creation Codex account and the enrollment in `.github/review-enrollments.json`. Work and personal accounts are distinct even when they use the same GitHub username. Prefer an enrolled same-account cloud route when available; otherwise use `scripts/local_review.py`. The local route is owner-enrolled operational trust, not provider-signed identity proof.

The agent freezes the repository ID, head, current base, merge base, canonical Git diff hash and trusted policy hash; retains the actual report; and fixes actionable findings. It then uses `scripts/create_review_pr.py` to create the ready PR and publish a separate creation-origin witness. The agent posts the unedited passing review receipt as a comment beginning with `<!-- g1-review-receipt:v1 -->`. A review receipt alone cannot establish the originating account. Changed head, current base or trusted policy requires a fresh review. The operator does not initiate or perform technical review.

The trusted-main Reviewer App accepts owner-created PRs only after matching the creation witness, review, complete six-shard CI run, merge commit, current base and effective controls. This includes automation-source changes; substantive independent review remains required. The App alone approves the exact head and requests native squash. Unknown origin, incomplete review, failing or stale CI, and changed controls block delivery. Agents must not merge, manipulate PR auto-merge, or bypass checks. Source delivery does not authorize binary publication, installation or a product release.

Keep the PR's original `g1-pr-creation` nonce when updating its description. If creation or origin publication returns an ambiguous result, preserve the private journal and inspect the actual branch, nonce, PR and comment IDs read-only. Do not retry creation blindly, duplicate the PR, or invent origin evidence. Keep account configuration, journals and raw runtime events outside this public repository.

## Reviewer App setup

An owner provisions the existing Chaos Scheduler App (ID `4217367`) for this repository and stores its approved key in the encrypted `AUTOMERGE_APP_PRIVATE_KEY` secret. The pinned workflow mints a repository-scoped token; private credentials never belong in source, PRs or logs.

Keep `REVIEWER_APP_ENABLED` unset or false during setup. After current-main CI succeeds, set `REVIEWER_APP_QUALIFY=true` and dispatch `reviewer-app.yml` on `main` with `mode=app-current`. This checks current-main CI, App identity/scope and effective controls without approval or merge writes. The coordinator also reads every contributing ruleset with owner access: only the declared owner/admin exception is allowed, with no Integration/App bypass. App-scoped omissions remain unknown, never evidence that bypass actors are absent.

After read-only readiness, enable the App writer through the authorized setup path and verify an ordinary reviewed PR receives its exact-head App approval and native squash merge, followed by passing merged-main CI. Missing installation access, credentials, qualification or controls blocks activation. Local tests and source enrollment alone do not establish operational delivery.
