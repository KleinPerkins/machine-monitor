# machine-monitor agent entrypoint

This repository is born under doc-warden v2 governance.

<!-- doc-warden:begin -->
## Documentation governance

| Artifact type | Location |
|---|---|
| Project, roadmap, and state | `.planning/` |
| Phase plans | `.planning/phases/` |
| ADRs | `docs/adr/` |
| Runbooks | `docs/runbooks/` |

**Policy:** `~/dev/_ops/doc-warden/POLICY.md`
**Engine:** `~/dev/_ops/bin/doc-warden.sh doctor repo --repo .`
<!-- doc-warden:end -->

## Pull request delivery

Before creating a ready PR, the authoring agent automatically captures a fresh independent review from the PR-creation Codex account using scripts/local_review.py, then creates it using scripts/create_review_pr.py. Work and personal accounts are distinct even when their GitHub user is shared. Publish the unedited review receipt after fixing findings; repeat review after head, current base or trusted policy changes. Prefer a qualified same-account cloud route when available; otherwise use the enrolled local adapter. Unknown origin/runtime blocks delivery without another-account or human technical-review fallback. The trusted-main Reviewer App alone approves and requests native squash after matching origin, review and exact CI evidence. Never manually merge, arm auto-merge or bypass checks. Initial policy admission and activation remain separately administered.
