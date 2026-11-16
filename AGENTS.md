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

The authoring agent coordinates three automatic steps: capture fresh independent review using scripts/local_review.py, create the ready PR and its origin witness using scripts/create_review_pr.py, then post the unedited passing receipt to that PR with the `<!-- g1-review-receipt:v1 -->` marker. The creation adapter owns origin publication only; the agent owns review-receipt publication as a separate step, without asking a human to perform either task. Work and personal accounts are distinct even when their GitHub user is shared. Fix findings and repeat review after head, current base or trusted policy changes. Prefer a qualified same-account cloud route when available; otherwise use the enrolled local adapter. Unknown origin/runtime blocks delivery without another-account or human technical-review fallback. The trusted-main Reviewer App alone approves and requests native squash after matching origin, review and exact CI evidence. Never manually merge, arm auto-merge or bypass checks.

Before activation, the delivery coordinator uses owner-authenticated access to verify exact bypass actors on every contributing ruleset. This is a separate administrative check: App credentials may redact bypass actors, which the App reports as unknown rather than absent. Visible unexpected actors always reject; Integration/App bypass is never authorized. Read-only App qualification does not attest hidden administrative settings or replace the owner-visible check. This operational boundary does not claim protection against a privileged administrator changing controls after qualification.
