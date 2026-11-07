#!/usr/bin/env python3
"""Read-only App readiness probe executed from a trusted workflow revision."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from auto_merge import verify_repository_identity
from github_automation import (REPO, ACTIONS_APP_ID, AutomationError, api, ci_passed,
                               reviewer_identity)


from merge_controls import verify_controls


def qualify(event, expected_id, request, login, read_token):
    verify_repository_identity(event, expected_id, request)
    run = event['workflow_run']
    if (run.get('path') != '.github/workflows/ci.yml' or run.get('conclusion') != 'success'
            or run.get('event') not in ('push', 'workflow_dispatch') or run.get('head_branch') != 'main'):
        raise AutomationError('A successful main-branch CI run is required')
    head = request('repos/' + REPO + '/commits/main').get('sha')
    if head != run.get('head_sha') or not ci_passed(head, request, read_token):
        raise AutomationError('Current merged-main verification is required')
    scoped = request('installation/repositories')
    repositories = scoped.get('repositories', [])
    if (scoped.get('total_count') != 1 or len(repositories) != 1
            or repositories[0].get('id') != expected_id or repositories[0].get('full_name') != REPO):
        raise AutomationError('Reviewer token must be scoped to this repository only')
    reviewer = reviewer_identity(request, login)
    repository = request('repos/' + REPO)
    rules = request('repos/' + REPO + '/rules/branches/main')
    verify_controls(repository, rules)
    return dict(schema='machine-monitor/reviewer-readiness/v1', repository=REPO,
                repository_id=expected_id, source_revision=head, reviewer_login=reviewer['login'],
                reviewer_id=reviewer['id'], status='ready-for-ordinary-head-canary',
                limits='Read-only readiness; does not prove approval, auto-merge arming or a merged ordinary PR.')


if __name__ == '__main__':
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_EVENT_NAME') != 'workflow_run'
            or os.environ.get('GITHUB_REPOSITORY') != REPO):
        raise SystemExit('Trusted repository workflow required')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    profile = json.loads((ROOT / '.planning/doc-warden.json').read_text())
    result = qualify(event, profile.get('github_repository_id'), api,
                     os.environ.get('REVIEWER_LOGIN', ''), os.environ.get('CI_READ_TOKEN', ''))
    output = Path('outputs/reviewer-readiness.json')
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
