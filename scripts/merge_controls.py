"""Live merge-control gates shared by qualification and each App write path."""
from github_automation import ACTIONS_APP_ID, AutomationError


def verify_controls(repository, rules):
    if not isinstance(rules, list):
        raise AutomationError('Effective branch rules unavailable')
    for key, expected in dict(allow_squash_merge=True, allow_merge_commit=False, allow_rebase_merge=False,
                              allow_auto_merge=True, delete_branch_on_merge=True).items():
        if repository.get(key) is not expected:
            raise AutomationError('Repository merge setting mismatch: ' + key)
    by_type = {}
    for rule in rules:
        if not isinstance(rule, dict) or not isinstance(rule.get('type'), str):
            raise AutomationError('Malformed effective rule')
        by_type.setdefault(rule['type'], []).append(rule.get('parameters') or {})
    for name in ('required_linear_history', 'deletion', 'non_fast_forward'):
        if name not in by_type:
            raise AutomationError('Missing effective rule: ' + name)
    if not any(value.get('required_approving_review_count', 0) >= 1
               and value.get('dismiss_stale_reviews_on_push') is True
               and value.get('required_review_thread_resolution') is True
               for value in by_type.get('pull_request', [])):
        raise AutomationError('One current approval and resolved conversations are required')
    expected = dict(context='ci-required', integration_id=ACTIONS_APP_ID)
    if not any(value.get('strict_required_status_checks_policy') is True
               and expected in value.get('required_status_checks', [])
               for value in by_type.get('required_status_checks', [])):
        raise AutomationError('Strict ci-required from GitHub Actions is required')
