"""Shared, dependency-free GitHub App transport and exact-head policy gates."""
import json
import os
from pathlib import Path
import re
import subprocess

REPO = 'KleinPerkins/machine-monitor'
DEPENDABOT_ID = 49699333
ACTIONS_APP_ID = 15368
SHA = re.compile(r'[a-f0-9]{40}')


class AutomationError(RuntimeError):
    pass


def api(path, *, payload=None, token=None, paginate=False, method=None):
    args = ['gh', 'api', '--hostname', 'github.com', path]
    if paginate:
        args += ['--paginate', '--slurp']
    if method or payload is not None:
        args += ['--method', method or 'POST']
    if payload is not None:
        args += ['--input', '-']
    env = dict(os.environ)
    if token is not None:
        if not token:
            raise AutomationError('Missing read-only CI token')
        env['GH_TOKEN'] = token
    result = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True, env=env, timeout=30)
    if result.returncode:
        status = re.search(r'HTTP \d{3}', result.stderr)
        # Avoid raw server/CLI output or command arguments containing credentials.
        reason = status.group() if status else f'CLI exit {result.returncode}'
        raise AutomationError(f'{method or ("POST" if payload is not None else "GET")} {path.split("?")[0]} failed ({reason})')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise AutomationError('GitHub returned an invalid JSON response') from None


def pages(request, path, *, token=None, key=None):
    batches = request(path, paginate=True, **({'token': token} if token is not None else {}))
    if not isinstance(batches, list):
        raise AutomationError('Malformed paginated GitHub response')
    result = []
    for batch in batches:
        values = batch.get(key) if key and isinstance(batch, dict) else batch
        if not isinstance(values, list):
            raise AutomationError('Malformed GitHub result page')
        result.extend(values)
    return result


def same_repo_pr(pr):
    head, base = pr.get('head') or {}, pr.get('base') or {}
    return (pr.get('state') == 'open' and pr.get('draft') is False
            and type(pr.get('number')) is int and pr['number'] > 0
            and base.get('ref') == 'main'
            and (base.get('repo') or {}).get('full_name') == REPO
            and (head.get('repo') or {}).get('full_name') == REPO
            and isinstance(head.get('sha'), str) and SHA.fullmatch(head['sha']) is not None)


def dependabot_author(pr):
    user = pr.get('user') or {}
    return user.get('login') == 'dependabot[bot]' or user.get('id') == DEPENDABOT_ID


def dependency_pr(pr):
    user = pr.get('user') or {}
    return (same_repo_pr(pr) and user.get('login') == 'dependabot[bot]'
            and user.get('id') == DEPENDABOT_ID and user.get('type') == 'Bot'
            and pr['head'].get('ref', '').startswith('dependabot/'))


def ci_passed(sha, request, read_token):
    if not SHA.fullmatch(sha) or not read_token:
        raise AutomationError('Expected a commit SHA and read-only CI token')
    checks = pages(request, f'repos/{REPO}/commits/{sha}/check-runs?check_name=ci-required&filter=latest&per_page=100',
                   token=read_token, key='check_runs')
    # A similarly named check from a different App cannot satisfy this policy.
    gates = [check for check in checks if check.get('name') == 'ci-required'
             and check.get('app', {}).get('id') == ACTIONS_APP_ID]
    return bool(gates) and all(check.get('head_sha') == sha and check.get('status') == 'completed'
                               and check.get('conclusion') == 'success' for check in gates)


def reviewer_identity(request, login):
    if not re.fullmatch(r'[a-z0-9-]+\[bot\]', login or ''):
        raise AutomationError('Missing installed App reviewer identity')
    reviewer = request(f'users/{login}')
    if reviewer.get('login') != login or reviewer.get('type') != 'Bot' or type(reviewer.get('id')) is not int:
        raise AutomationError('Installed App reviewer identity could not be verified')
    return reviewer


def already_approved(pr_number, sha, request, reviewer):
    reviews = pages(request, f'repos/{REPO}/pulls/{pr_number}/reviews?per_page=100')
    own = [review for review in reviews if review.get('user', {}).get('id') == reviewer['id']
           and review.get('user', {}).get('login') == reviewer['login'] and review.get('state') != 'COMMENTED']
    latest = max(own, key=lambda review: review['id'], default={})
    return latest.get('state') == 'APPROVED' and latest.get('commit_id') == sha


def enable_merge(number, sha):
    result = subprocess.run(['gh', 'pr', 'merge', str(number), '--repo', REPO,
                             '--auto', '--squash', '--match-head-commit', sha], capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise AutomationError(f'PR #{number}: native auto-merge failed (exit {result.returncode}); check permissions, head changes and branch rules')


def approve_and_arm(pr, *, request, merge, reviewer, eligible, read_token, report, controls):
    number, sha = pr['number'], pr['head']['sha']
    path = f'repos/{REPO}/pulls/{number}'
    controls()
    approved = already_approved(number, sha, request, reviewer)
    latest = request(path)
    if not eligible(latest) or latest['head']['sha'] != sha:
        report(f'PR #{number}: identity or head changed; deferred.')
        return
    if not ci_passed(sha, request, read_token):
        report(f'PR #{number}: current-commit ci-required is not successful; waiting.')
        return
    controls()
    if not approved:
        request(path + '/reviews', payload={'event': 'APPROVE', 'commit_id': sha,
                'body': 'Policy-based automatic approval: required CI passed for this commit. This is not substantive code review.'})
    latest = request(path)
    if not eligible(latest) or latest['head']['sha'] != sha:
        report(f'PR #{number}: changed after approval; merge not armed.')
        return
    controls()
    if not ci_passed(sha, request, read_token):
        report(f'PR #{number}: verification changed after approval; merge not armed.')
        return
    if latest.get('auto_merge') is None:
        merge(number, sha)
        report(f'PR #{number}: policy approval recorded; native squash auto-merge requested for {sha}.')
    else:
        if latest['auto_merge'].get('merge_method', '').lower() != 'squash':
            raise AutomationError(f'PR #{number}: existing auto-merge is not squash')
        report(f'PR #{number}: current commit already approved and squash auto-merge enabled.')


class Reporter:
    def __init__(self, summary=None):
        self.summary = Path(summary) if summary else None

    def __call__(self, message, *, error=False):
        if error:
            escaped = message.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
            print('::error::' + escaped)
        else:
            print(message)
        if self.summary:
            with self.summary.open('a') as output:
                output.write(('- ERROR: ' if error else '- ') + message.replace('\n', ' ').replace('\r', ' ') + '\n')
