#!/usr/bin/env python3
"""Trusted workflow revision only. App approval is policy approval, not code review."""
import fnmatch
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from github_automation import (REPO, SHA, AutomationError, Reporter, api, pages, same_repo_pr,
                               dependabot_author, reviewer_identity, approve_and_arm, enable_merge)

from merge_controls import verify_controls

PROTECTED = (
    '.github/*', '.githooks/*', '.gitleaks*', '.gitignore', '.planning/*',
    '.codex/*', '.cursor/*', '.claude/*', '.agents/*', '_ops/*', 'docs/*',
    'AGENTS.md', 'README.md', 'SECURITY.md', 'CODEOWNERS', 'LICENSE*', 'THIRD-PARTY-NOTICES.md',
    'Makefile', 'scripts/*', 'tests/*', 'test_*.py', 'requirements*.txt',
    'build_mac_app.py', 'mac/*', 'start.sh',
    'delivery/*', 'update_*.py', 'PRIVATE-BINARY-LICENSE',
)


def complete_changed_files(pr, entries):
    count = pr.get('changed_files')
    if type(count) is not int or not 0 < count <= 3000 or len(entries) != count:
        raise AutomationError('Incomplete changed-file evidence')
    files, current = [], set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise AutomationError('Malformed changed-file evidence')
        name = entry.get('filename')
        names = [name]
        if 'previous_filename' in entry:
            names.append(entry['previous_filename'])
        for value in names:
            if (not isinstance(value, str) or not value or value.startswith('/')
                    or '\\' in value or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    or any(part in ('', '.', '..') for part in value.split('/'))):
                raise AutomationError('Unsafe changed-file path')
        if name in current:
            raise AutomationError('Duplicate changed-file evidence')
        current.add(name)
        files.extend(names)
    return files


def immutable_changed_files(pr, request):
    base, head = pr.get('base', {}).get('sha'), pr.get('head', {}).get('sha')
    if not isinstance(base, str) or not SHA.fullmatch(base) or not isinstance(head, str) or not SHA.fullmatch(head):
        raise AutomationError('Immutable base/head revisions required')
    # GitHub compare caps files at 300. At that boundary completeness is
    # ambiguous, so those changes and larger ones use the owner path.
    count = pr.get('changed_files')
    if type(count) is not int or not 0 < count < 300:
        raise AutomationError('Change exceeds bounded immutable-file coverage')
    observed = request(f'repos/{REPO}/compare/{base}...{head}')
    if not isinstance(observed, dict) or observed.get('base_commit', {}).get('sha') != base:
        raise AutomationError('Immutable comparison identity mismatch')
    entries = observed.get('files')
    if not isinstance(entries, list):
        raise AutomationError('Immutable changed-file evidence unavailable')
    return base, complete_changed_files(pr, entries)


def eligible(pr, run, files, *, base_sha):
    if run.get('event') != 'pull_request' or run.get('conclusion') != 'success':
        return False
    if run.get('path') != '.github/workflows/ci.yml':
        return False
    if run.get('head_repository', {}).get('full_name') != REPO or not same_repo_pr(pr):
        return False
    if pr['head']['sha'] != run.get('head_sha') or pr.get('base', {}).get('sha') != base_sha:
        return False
    if pr['head'].get('ref', '').startswith(('release-please--', 'dependabot/')) or dependabot_author(pr):
        return False
    if pr.get('author_association') not in ('OWNER', 'MEMBER', 'COLLABORATOR'):
        return False
    # Git is case-sensitive; the supported Mac filesystem may not be.
    return bool(files) and not any(fnmatch.fnmatchcase(path.casefold(), pattern.casefold())
                                  for path in files for pattern in PROTECTED)


def verify_repository_identity(event, expected_id, request):
    if type(expected_id) is not int or expected_id <= 0:
        raise AutomationError('Missing immutable repository identity')
    observed = request('repos/' + REPO)
    for value in (event.get('repository', {}), observed):
        if value.get('full_name') != REPO or value.get('id') != expected_id:
            raise AutomationError('Repository identity changed')
    if observed.get('visibility') != 'public' or observed.get('default_branch') != 'main':
        raise AutomationError('Public main-branch delivery identity is required')
    head = event.get('workflow_run', {}).get('head_repository', {})
    if head.get('full_name') != REPO or head.get('id') != expected_id:
        raise AutomationError('Foreign workflow source')


def main():
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run'
            or os.environ.get('GITHUB_REPOSITORY') != REPO):
        raise AutomationError('Only the trusted repository workflow may invoke this entrypoint')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    profile = json.loads((ROOT / '.planning/doc-warden.json').read_text())
    verify_repository_identity(event, profile.get('github_repository_id'), api)
    run = event['workflow_run']
    if not SHA.fullmatch(run.get('head_sha', '')):
        raise AutomationError('Invalid workflow source revision')
    if run.get('path') != '.github/workflows/ci.yml':
        raise AutomationError('Unexpected verification workflow')
    candidates = pages(api, f"repos/{REPO}/commits/{run['head_sha']}/pulls?per_page=100")
    report = Reporter(os.environ.get('GITHUB_STEP_SUMMARY'))
    reviewer = None
    for candidate in candidates:
        number = candidate.get('number')
        if type(number) is not int or number <= 0:
            raise AutomationError('Invalid pull request number')
        path = f'repos/{REPO}/pulls/{number}'
        pr = api(path)
        base_sha, files = immutable_changed_files(pr, api)
        if not eligible(pr, run, files, base_sha=base_sha):
            report(f'PR #{number}: protected change or ineligible current head; owner path required.')
            continue
        if reviewer is None:
            reviewer = reviewer_identity(api, os.environ.get('REVIEWER_LOGIN', ''))
        def controls():
            verify_repository_identity(event, profile.get('github_repository_id'), api)
            verify_controls(api('repos/' + REPO), api('repos/' + REPO + '/rules/branches/main'))
        approve_and_arm(pr, request=api, merge=enable_merge, reviewer=reviewer, controls=controls,
                        eligible=lambda latest: eligible(latest, run, files, base_sha=base_sha),
                        read_token=os.environ.get('CI_READ_TOKEN', ''), report=report)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # Never print raw transport output, credential values or request arguments.
        reason = str(error) if isinstance(error, AutomationError) else type(error).__name__
        Reporter(os.environ.get('GITHUB_STEP_SUMMARY'))('Reviewer automation failed: ' + reason, error=True)
        sys.exit(1)
