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

## Reviewer App setup

Reviewer automation is staged separately from CI. It executes only the trusted workflow revision, reads immutable base/head changed-file comparisons, rejects protected governance/verification/packaging changes, and checks current GitHub Actions CI plus live merge controls before approval and before requesting native squash auto-merge. Changes at the comparison API's 300-file boundary or above use the owner path. Dependabot changes use the owner path as well.

An owner must grant the reviewer App access to this repository and provision `AUTOMERGE_APP_ID` and `AUTOMERGE_APP_PRIVATE_KEY` through encrypted GitHub Actions secrets. Use the App owner's secure credential source; do not retrieve another repository's secret values or paste credentials into a chat, source file or log. The workflow mints a token scoped only to `KleinPerkins/machine-monitor`.

Keep `REVIEWER_APP_ENABLED` unset until secure setup and qualification are complete. With credentials provisioned, the owner can set `REVIEWER_APP_QUALIFY=true` and run CI on `main`. The trusted follow-up workflow produces a 14-day readiness artifact after checking immutable repository identity, current merged-main CI, token scope and effective merge protections. This read-only receipt establishes readiness for an ordinary-head canary; it does not establish approval or merge behavior. Enable `REVIEWER_APP_ENABLED=true` only through the authorized owner setup path, then verify an eligible ordinary PR receives the App's exact-head approval, native squash auto-merge and passing merged-main CI. The App's policy approval is not substantive engineering review.

Missing installation access, credentials, qualification or effective controls blocks App activation. It does not justify weaker checks or protections. Source files and local fixture tests alone do not prove that the App is operational.
