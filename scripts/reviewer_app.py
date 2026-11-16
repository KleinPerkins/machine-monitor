#!/usr/bin/env python3
"""Trusted-default-branch G1 gate. Candidate Git objects are data, never executed.

Q16 trusts enrolled local capture operationally; receipts are not anti-forgery
attestations against a principal holding the same local/GitHub privileges.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request

REPOSITORY = 'KleinPerkins/machine-monitor'
REPOSITORY_ID = 1449284973
APP_ID = 4217367
APP_SLUG = 'chaos-scheduler-automerge'
BOT_ID = 299927791
CI_JOBS = ('verify (governance)', 'verify (core)', 'verify (service)', 'verify (browser-layout)', 'verify (browser-lifecycle)', 'verify (native-app)', 'ci-required')
OWNER_ID = 49759187
CI_APP_ID = 15368
MARKER = '<!-- g1-review-receipt:v1 -->\n'
ORIGIN_MARKER = '<!-- g1-pr-origin:v1 -->\n'
MAX_RECEIPT = 60000
MAX_DIFF = 5000000
MERGE_SETTINGS_QUERY = ('query CanaryMergeSettings { repository(owner:"KleinPerkins",'
    'name:"machine-monitor") { databaseId nameWithOwner mergeCommitAllowed '
    'rebaseMergeAllowed squashMergeAllowed autoMergeAllowed } }')
ROOT = Path(__file__).resolve().parents[1]

class Rejected(RuntimeError):
    pass

def require(condition, message):
    if not condition:
        raise Rejected(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()

def digest(value):
    return hashlib.sha256(value).hexdigest()

def timestamp(value):
    result = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    require(result.tzinfo is not None, 'timestamp has no timezone')
    return result

class API:
    def __init__(self, token, writable=False):
        require(bool(token), 'missing API credential')
        self.token, self.writable = token, writable
    def request(self, path, method='GET', data=None):
        # A fixed, argument-free GraphQL query is read-only despite HTTP POST.
        fixed_read = path == '/graphql' and method == 'POST' and data == {'query': MERGE_SETTINGS_QUERY}
        require(method == 'GET' or self.writable or fixed_read, 'read-only API cannot mutate')
        require(path.startswith('/') and not path.startswith('//'), 'invalid API path')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2022-11-28'}
        if data is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request('https://api.github.com' + path, headers=headers,
                                     method=method, data=None if data is None else canonical(data))
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                raw = response.read(8000001)
                require(len(raw) <= 8000000, 'API response exceeds bound')
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raise Rejected('GitHub API refused request: HTTP ' + str(error.code)) from None
    def job_log(self, job_id):
        require(type(job_id) is int and job_id > 0, 'invalid log job ID')
        class LogRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                require(urllib.parse.urlsplit(newurl).scheme == 'https', 'unsafe log redirect')
                redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
                if redirected is not None:
                    redirected.remove_header('Authorization')
                return redirected
        request = urllib.request.Request('https://api.github.com/repos/' + REPOSITORY +
            '/actions/jobs/' + str(job_id) + '/logs', headers={
                'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'})
        try:
            with urllib.request.build_opener(LogRedirect()).open(request, timeout=30) as response:
                raw = response.read(8000001)
                require(len(raw) <= 8000000, 'aggregate log exceeds bound')
                return raw.decode('utf-8')
        except urllib.error.HTTPError as error:
            raise Rejected('aggregate log unavailable: HTTP ' + str(error.code)) from None
    def pages(self, path, key=None):
        rows = []
        for page in range(1, 101):
            data = self.request(path + ('&' if '?' in path else '?') + f'per_page=100&page={page}')
            batch = data[key] if key else data
            require(isinstance(batch, list), 'invalid pagination payload')
            rows.extend(batch)
            if len(batch) < 100:
                return rows
        raise Rejected('pagination bound exhausted')

def repository_snapshot(api):
    repo = api.request('/repos/' + REPOSITORY)
    result = api.request('/graphql', 'POST', {'query': MERGE_SETTINGS_QUERY})
    require(isinstance(result, dict) and not result.get('errors'), 'merge settings query failed')
    data = result.get('data')
    require(isinstance(data, dict) and isinstance(data.get('repository'), dict), 'merge settings unavailable')
    settings = data['repository']
    require(settings.get('databaseId') == REPOSITORY_ID and settings.get('nameWithOwner') == REPOSITORY,
            'merge settings repository mismatch')
    fields = {'allow_squash_merge': 'squashMergeAllowed', 'allow_merge_commit': 'mergeCommitAllowed',
              'allow_rebase_merge': 'rebaseMergeAllowed', 'allow_auto_merge': 'autoMergeAllowed'}
    # GitHub omits these REST fields for read-only credentials. GraphQL exposes
    # the same current repository settings without broader credential permissions.
    for rest, graphql in fields.items():
        value = settings.get(graphql)
        require(type(value) is bool, 'missing/invalid merge setting')
        require(rest not in repo or repo[rest] is value, 'merge settings changed between reads')
        repo[rest] = value
    return repo

def validate_controls(repo, rules, rulesets, *, require_legacy=False, require_successor_only=False):
    require(repo['id'] == REPOSITORY_ID and repo['full_name'] == REPOSITORY, 'repository mismatch')
    require(repo['default_branch'] == 'main' and not repo.get('archived') and not repo.get('private'), 'repository posture')
    require(repo.get('allow_squash_merge') is True and repo.get('allow_merge_commit') is False
            and repo.get('allow_rebase_merge') is False and repo.get('allow_auto_merge') is True, 'merge methods')
    by_type = {}
    for rule in rules:
        by_type.setdefault(rule['type'], []).append(rule.get('parameters', {}))
    required = by_type.get('required_status_checks', [])
    require(not (require_legacy and require_successor_only), 'conflicting qualification stages')
    if require_successor_only:
        require(not any(c.get('integration_id') == 4274739
                        or str(c.get('context', '')).startswith('pr-automation /')
                        for r in required for c in r.get('required_status_checks', [])),
                'current qualification rejects retired controller blockers')
    if require_legacy:
        contexts = {(c.get('context'), c.get('integration_id')) for r in required
                    if r.get('strict_required_status_checks_policy') is True
                    for c in r.get('required_status_checks', [])}
        require({('pr-automation / verify', 4274739),
                 ('pr-automation / job:repo.machine-monitor.m3-verify', 4274739)} <= contexts,
                'bootstrap qualification requires both legacy blockers')
    require(any(r.get('strict_required_status_checks_policy') is True and
                any(c.get('context') == 'ci-required' and c.get('integration_id') == CI_APP_ID
                    for c in r.get('required_status_checks', [])) for r in required), 'strict CI15368 required')
    require(any(r.get('required_approving_review_count', 0) >= 1 and r.get('dismiss_stale_reviews_on_push') is True
                and r.get('required_review_thread_resolution') is True and r.get('allowed_merge_methods') == ['squash']
                for r in by_type.get('pull_request', [])), 'review controls missing')
    require(all(name in by_type for name in ('required_linear_history', 'deletion', 'non_fast_forward')), 'history protection missing')
    # Preserve distinct owner/admin history-only and PR-only exceptions. App-scoped reads
    # may redact bypass_actors; absence is unknown, never evidence of emptiness.
    source_ids = {r['ruleset_id'] for r in rules}
    require(source_ids and source_ids <= {r['id'] for r in rulesets}, 'rule source unavailable')
    for rule in rulesets:
        if rule['id'] in source_ids:
            require(rule.get('enforcement') == 'active', 'protection enforcement gap')
            if 'bypass_actors' in rule:
                effective_types = {r['type'] for r in rules if r['ruleset_id'] == rule['id']}
                declared_types = {r['type'] for r in rule.get('rules', [])}
                history_only = effective_types == declared_types == {'deletion', 'non_fast_forward'}
                allowed = {'actor_id': 5, 'actor_type': 'RepositoryRole', 'bypass_mode': 'always' if history_only else 'pull_request'}
                require(rule['bypass_actors'] == [allowed],
                        'owner bypass exception changed')

def validate_receipt(receipt, producer, current, policy_hash, now):
    fields = {'schema','capture_id','trust_model','tuple','reviewer_enrollment_id','reviewer_origin_account',
              'workspace_binding','instructions_sha256','runtime','started_at','completed_at','review','report_sha256'}
    require(isinstance(receipt, dict) and set(receipt) == fields, 'closed receipt schema mismatch')
    require(all(isinstance(receipt[k], str) and receipt[k] for k in fields-{'tuple','runtime','review'}), 'receipt field type')
    require(re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', receipt['capture_id']) is not None,
            'capture identifier missing/malformed')
    require(receipt.get('schema') == 'g1-local-review/v1' and receipt.get('trust_model') == 'q16-operational-local', 'receipt schema/trust')
    require(receipt.get('reviewer_enrollment_id') == producer['id'] and producer.get('enabled') is True, 'producer not enrolled')
    require(receipt['tuple'] == dict(current, origin_account=producer['origin_account']), 'receipt tuple drift')
    require(current['policy_sha256'] == policy_hash, 'policy drift')
    require(receipt.get('reviewer_origin_account') == producer['origin_account'], 'review origin mismatch')
    require(receipt.get('workspace_binding') == 'owner-declared-enrollment', 'workspace binding missing')
    require(receipt.get('instructions_sha256') == producer['instructions_sha256'], 'review instruction drift')
    runtime = receipt['runtime']
    runtime_fields = {'cli_version','credential_store','thread_id','turn_id','status','event_stream_sha256','startup_notice_sha256'}
    require(isinstance(runtime, dict) and set(runtime) == runtime_fields, 'closed runtime schema mismatch')
    require(runtime['turn_id'] is None and all(isinstance(runtime[k], str) and runtime[k]
            for k in runtime_fields-{'turn_id','startup_notice_sha256'}), 'runtime field type')
    require(runtime.get('status') == 'completed' and isinstance(runtime.get('thread_id'), str)
            and len(runtime['thread_id']) >= 8 and runtime.get('cli_version') == producer['cli_version']
            and runtime.get('credential_store') == producer['credential_store'], 'review runtime incomplete')
    require(re.fullmatch('[0-9a-f]{64}', runtime.get('event_stream_sha256', '')) is not None, 'missing direct capture digest')
    notices = runtime.get('startup_notice_sha256', [])
    require('startup_notices' not in runtime, 'public receipt contains raw runtime notices')
    allowed_notices = producer.get('allowed_startup_notice_sha256', [])
    require(isinstance(notices, list) and isinstance(allowed_notices, list)
            and all(isinstance(n, str) and re.fullmatch('[0-9a-f]{64}', n) and n in allowed_notices for n in notices), 'unqualified runtime notice')
    started, completed = timestamp(receipt['started_at']), timestamp(receipt['completed_at'])
    require(started <= completed <= now and now - started <= dt.timedelta(hours=24), 'stale/future review')
    review = receipt['review']
    require(isinstance(review, dict) and set(review) == {'verdict','coverage','summary','findings','unresolved_findings'},
            'closed review schema mismatch')
    require(review.get('verdict') == 'pass' and review.get('coverage') == 'complete'
            and review.get('findings') == [] and review.get('unresolved_findings') == []
            and isinstance(review.get('summary'), str) and review['summary'].strip(), 'review incomplete or findings')
    require(receipt.get('report_sha256') == digest(canonical(review)), 'report digest mismatch')

def choose_origin(comments, enrollments, pr, now):
    # Creation evidence is captured by the trusted adapter around the create API,
    # independently of any later review. A review never selects the PR origin.
    records = []
    for comment in comments:
        body = comment.get('body', '')
        if not body.startswith(ORIGIN_MARKER):
            continue
        sender = comment.get('user', {})
        if sender.get('id') != OWNER_ID or sender.get('type') != 'User':
            continue
        require(len(body.encode()) <= MAX_RECEIPT, 'origin exceeds bound')
        require(comment['created_at'] == comment['updated_at'], 'edited creation binding')
        try:
            record = json.loads(body[len(ORIGIN_MARKER):])
        except ValueError:
            raise Rejected('invalid origin JSON') from None
        records.append((comment, record))
    require(len(records) == 1, 'exactly one independent creation binding required')
    comment, origin = records[0]
    fields = {'schema','trust_model','creation_id','repository','repository_id','pull_request',
              'pull_request_node_id','github_user_id','origin_account','creator_enrollment_id',
              'workspace_binding','initial_head_sha','initial_base_sha','pr_created_at','started_at',
              'completed_at','runtime','creation_adapter_sha256','capture_adapter_sha256'}
    require(isinstance(origin, dict) and set(origin) == fields, 'closed creation binding schema')
    numeric = {'repository_id','pull_request','github_user_id'}
    require(all(type(origin[k]) is int and origin[k] > 0 for k in numeric), 'creation identity type')
    require(all(isinstance(origin[k], str) and origin[k] for k in fields-numeric-{'runtime'}), 'creation field type')
    require(origin['schema'] == 'g1-pr-origin/v1' and origin['trust_model'] == 'q16-operational-local'
            and origin['workspace_binding'] == 'owner-declared-enrollment', 'creation trust model')
    require(re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', origin['creation_id']) is not None,
            'invalid creation nonce')
    require(origin['repository'] == REPOSITORY and origin['repository_id'] == REPOSITORY_ID
            and origin['pull_request'] == pr['number'] and origin['pull_request_node_id'] == pr['node_id']
            and origin['github_user_id'] == OWNER_ID == pr['user']['id'] and pr['user']['type'] == 'User'
            and pr['head']['repo']['id'] == pr['base']['repo']['id'] == REPOSITORY_ID,
            'creation PR identity mismatch')
    require(origin['pr_created_at'] == pr['created_at'], 'creation server timestamp mismatch')
    nonces = re.findall(r'<!-- g1-pr-creation:([^>]+) -->', pr.get('body') or '')
    require(nonces == [origin['creation_id']], 'PR creation nonce missing or conflicting')
    require(all(re.fullmatch('[0-9a-f]{40}', origin[k]) for k in ('initial_head_sha','initial_base_sha')),
            'creation revision missing')
    producers = [p for p in enrollments['producers'] if p.get('id') == origin['creator_enrollment_id']]
    require(len(producers) == 1, 'unknown or duplicate creation producer')
    producer = producers[0]
    require(producer.get('enabled') is True and producer.get('github_user_id') == OWNER_ID
            and producer.get('origin_account') == origin['origin_account'], 'creation enrollment mismatch')
    for key in ('creation_adapter_sha256','capture_adapter_sha256'):
        require(re.fullmatch('[0-9a-f]{64}', origin[key]) is not None and origin[key] == producer.get(key),
                'unqualified creation adapter')
    runtime = origin['runtime']
    require(isinstance(runtime, dict) and set(runtime) == {'cli_version','credential_store','account_checked_before','account_checked_after'}
            and runtime['cli_version'] == producer.get('cli_version') and runtime['credential_store'] == producer.get('credential_store')
            and runtime['account_checked_before'] is True and runtime['account_checked_after'] is True,
            'incomplete account-bound creation')
    started, created, completed, posted = map(timestamp, [origin['started_at'], origin['pr_created_at'], origin['completed_at'], comment['created_at']])
    # GitHub server timestamps have second precision; local timestamps may not.
    slack = dt.timedelta(seconds=1)
    require(started <= created + slack and created <= completed <= posted + slack
            and started <= completed <= now and posted <= now
            and posted - started <= dt.timedelta(minutes=10), 'creation operation timing invalid')
    return origin

def choose_receipt(comments, enrollments, current, policy_hash, now, origin):
    producers = {p['id']: p for p in enrollments['producers']}
    eligible = []
    for comment in comments:
        body = comment.get('body', '')
        if not body.startswith(MARKER):
            continue
        # Unknown senders cannot bind or refresh origin.
        sender = comment.get('user', {})
        if sender.get('id') != OWNER_ID or sender.get('type') != 'User':
            continue
        require(len(body.encode()) <= MAX_RECEIPT, 'receipt exceeds bound')
        require(comment['created_at'] == comment['updated_at'], 'edited receipt cannot establish origin')
        try:
            receipt = json.loads(body[len(MARKER):])
        except ValueError:
            raise Rejected('invalid receipt JSON') from None
        producer = producers.get(receipt.get('reviewer_enrollment_id'))
        require(producer is not None and producer.get('github_user_id') == sender['id'], 'unknown receipt producer')
        require(producer.get('enabled') is True, 'disabled producer')
        require(receipt['tuple']['repository_id'] == REPOSITORY_ID and receipt['tuple']['repository'] == REPOSITORY,
                'binding repository mismatch')
        require(receipt['tuple']['origin_account'] == producer['origin_account'] and
                receipt.get('reviewer_origin_account') == producer['origin_account'], 'binding origin mismatch')
        eligible.append((comment['id'], receipt, producer))
    require(bool(eligible), 'no authenticated enrolled receipt')
    eligible.sort(key=lambda item: item[0])
    require(all(r['tuple']['origin_account'] == origin['origin_account'] for _, r, _ in eligible), 'frozen PR origin mismatch')
    _, receipt, producer = eligible[-1]
    validate_receipt(receipt, producer, current, policy_hash, now)
    return receipt

def bounded_merge_base(command, base, head):
    for depth in (256, 512, 1024, 2048, 4096):
        command('fetch', '--no-tags', '--no-recurse-submodules', '--depth='+str(depth),
                'https://github.com/' + REPOSITORY + '.git', base, head)
        value = command('merge-base', base, head, no_common_base_ok=True)
        if value is not None:
            merge_base = value.decode().strip()
            require(re.fullmatch('[0-9a-f]{40}', merge_base) is not None, 'invalid merge base')
            return merge_base
    raise Rejected('common ancestry exceeds bounded review route')

def git_tuple(head, base, token):
    for sha in (head, base):
        require(re.fullmatch('[0-9a-f]{40}', sha) is not None, 'invalid Git object')
    with tempfile.TemporaryDirectory(prefix='g1-objects-') as temporary:
        env = {'PATH': '/usr/bin:/bin', 'HOME': temporary, 'LANG': 'C', 'LC_ALL': 'C',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_ATTR_NOSYSTEM': '1',
               'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'http.https://github.com/.extraheader',
               'GIT_CONFIG_VALUE_0': 'AUTHORIZATION: basic ' + base64.b64encode(('x-access-token:' + token).encode()).decode()}
        def command(*args, no_common_base_ok=False):
            with tempfile.TemporaryFile() as output:
                # Bound downloaded packs/output and CPU; no checkout, hooks, filters,
                # submodules, external diff, textconv, or inherited credential helpers.
                def limits():
                    import resource
                    resource.setrlimit(resource.RLIMIT_FSIZE, (32000000, 32000000))
                    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
                result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'credential.helper=',
                    '-c', 'protocol.file.allow=never', '-c', 'core.attributesFile=/dev/null', *args], cwd=temporary,
                    env=env, stdout=output, stderr=subprocess.DEVNULL, timeout=60, preexec_fn=limits)
                if no_common_base_ok and result.returncode == 1:
                    return None
                require(result.returncode == 0, 'isolated Git data inspection failed')
                output.seek(0)
                data = output.read(MAX_DIFF + 1)
                require(len(data) <= MAX_DIFF, 'diff/output exceeds bound')
                return data
        command('init', '--bare', '.')
        merge_base = bounded_merge_base(command, base, head)
        patch = command('-c', 'color.ui=false', 'diff', '--no-ext-diff', '--no-textconv', '--binary', base+'...'+head, '--')
        return merge_base, digest(patch)

def validate_ci_log(log, pr, merge_sha, run):
    marker = 'MACHINE_MONITOR_CI_AGGREGATE_V1 '
    receipts = []
    for line in log.splitlines():
        # Job log API prefixes each emitted line with an RFC3339 UTC timestamp.
        line = re.sub(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z ', '', line)
        if line.startswith(marker):
            try:
                receipts.append(json.loads(line[len(marker):]))
            except ValueError:
                raise Rejected('malformed aggregate receipt') from None
    require(len(receipts) == 1, 'aggregate receipt missing/duplicated')
    ref = f"refs/pull/{pr['number']}/merge" if pr is not None else 'refs/heads/main'
    expected = {'repository': REPOSITORY, 'repository_id': str(REPOSITORY_ID), 'event': 'pull_request' if pr is not None else run['event'],
        'revision': merge_sha, 'workflow_sha': merge_sha, 'run_id': str(run['id']),
        'run_attempt': str(run['run_attempt']), 'ref': ref, 'head_sha': pr['head']['sha'] if pr is not None else '',
        'base_sha': pr['base']['sha'] if pr is not None else '', 'workflow_ref': REPOSITORY + '/.github/workflows/ci.yml@' + ref,
        'workflow': 'CI'}
    require(receipts[0] == {'schema': 'machine-monitor-ci-aggregate/v1', 'identity': expected, 'result': 'success'},
            'tested CI revision/base/head/run drift')

def validate_ci(api, prefix, pr, merge_sha):
    workflow = api.request(prefix + '/actions/workflows/ci.yml')
    require(workflow['path'] == '.github/workflows/ci.yml' and workflow['state'] == 'active', 'CI workflow identity')
    runs = api.pages(prefix + '/actions/workflows/' + str(workflow['id']) + '/runs?event=pull_request&head_sha=' + pr['head']['sha'], 'workflow_runs')
    runs = [r for r in runs if any(p['number'] == pr['number'] for p in r.get('pull_requests', []))]
    require(bool(runs), 'no CI run for PR')
    run = max(runs, key=lambda r: (r['id'], r.get('run_attempt', 1)))
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success' and run.get('event') == 'pull_request'
            and run.get('head_sha') == pr['head']['sha'] and run['repository']['id'] == REPOSITORY_ID
            and run['head_repository']['id'] == REPOSITORY_ID, 'CI run not current successful origin')
    bindings = [p for p in run['pull_requests'] if p['number'] == pr['number']]
    require(len(bindings) == 1 and bindings[0]['head']['sha'] == pr['head']['sha']
            and bindings[0]['base']['sha'] == pr['base']['sha'], 'CI base/head drift')
    validate_ci_jobs(api, prefix, pr, merge_sha, run)
    return run['id'], run['run_attempt']

def validate_ci_jobs(api, prefix, pr, merge_sha, run):
    jobs = api.pages(prefix + f"/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", 'jobs')
    require(len(jobs) == len(CI_JOBS) and {j.get('name') for j in jobs} == set(CI_JOBS), 'unexpected CI job set')
    for name in CI_JOBS:
        matching = [j for j in jobs if j['name'] == name]
        require(len(matching) == 1, 'missing/duplicate CI job ' + name)
        job = matching[0]
        require(job['status'] == 'completed' and job['conclusion'] == 'success' and job['run_id'] == run['id'], 'failed/skipped CI shard')
        check_id = job['check_run_url'].rsplit('/', 1)[-1]
        require(check_id.isdecimal(), 'invalid check ID')
        check = api.request(prefix + '/check-runs/' + check_id)
        require(check['app']['id'] == CI_APP_ID and check['name'] == name and check['status'] == 'completed'
                and check['conclusion'] == 'success' and check['head_sha'] in ((pr['head']['sha'], merge_sha) if pr is not None else (merge_sha,))
                and check['check_suite']['id'] == run['check_suite_id'], 'wrong CI producer/suite')
        if name == 'ci-required':
            validate_ci_log(api.job_log(job['id']), pr, merge_sha, run)

def snapshot(api, number, policy, policy_hash, now):
    prefix = '/repos/' + REPOSITORY
    repo = repository_snapshot(api)
    pr = api.request(prefix + '/pulls/' + str(number))
    require(pr['state'] == 'open' and not pr['draft'] and not pr.get('merged'), 'PR is not open ready')
    require(pr['user']['id'] == OWNER_ID and pr['user']['type'] == 'User', 'author policy')
    require(pr['head']['repo']['id'] == REPOSITORY_ID and pr['base']['repo']['id'] == REPOSITORY_ID
            and pr['base']['ref'] == 'main', 'fork/base repository mismatch')
    base = api.request(prefix + '/git/ref/heads/main')['object']['sha']
    require(base == pr['base']['sha'], 'base moved')
    require(pr.get('mergeable') is True and pr.get('mergeable_state') in ('clean', 'blocked'), 'mergeability unknown/conflicting')
    rules = api.request(prefix + '/rules/branches/main')
    summaries = api.pages(prefix + '/rulesets?includes_parents=true')
    rulesets = [api.request(prefix + '/rulesets/' + str(s['id'])) for s in summaries]
    validate_controls(repo, rules, rulesets)
    merge_sha = api.request(prefix + f'/git/ref/pull/{number}/merge')['object']['sha']
    merge = api.request(prefix + '/git/commits/' + merge_sha)
    require([p['sha'] for p in merge['parents']] == [base, pr['head']['sha']], 'synthetic merge tuple drift')
    merge_base, diff_hash = git_tuple(pr['head']['sha'], base, api.token)
    current = {'repository': REPOSITORY, 'repository_id': REPOSITORY_ID, 'head_sha': pr['head']['sha'],
               'base_sha': base, 'merge_base_sha': merge_base, 'diff_sha256': diff_hash, 'policy_sha256': policy_hash}
    comments = api.pages(prefix + f'/issues/{number}/comments')
    origin = choose_origin(comments, policy, pr, now)
    receipt = choose_receipt(comments, policy, current, policy_hash, now, origin)
    ci = validate_ci(api, prefix, pr, merge_sha)
    return {'tuple': current, 'origin': origin, 'receipt': receipt, 'ci': ci, 'merge_sha': merge_sha,
            'node_id': pr['node_id'], 'bypass_visibility': {str(r['id']): ('visible' if 'bypass_actors' in r else 'redacted-or-unavailable') for r in rulesets}, 'controls_sha256': digest(canonical([{k: repo[k] for k in ('id', 'default_branch', 'private', 'allow_squash_merge', 'allow_merge_commit', 'allow_rebase_merge', 'allow_auto_merge')}, rules, rulesets]))}

def controls_snapshot(api, *, require_legacy=False, require_successor_only=False):
    prefix = '/repos/' + REPOSITORY
    repo = repository_snapshot(api)
    rules = api.request(prefix + '/rules/branches/main')
    summaries = api.pages(prefix + '/rulesets?includes_parents=true')
    rulesets = [api.request(prefix + '/rulesets/' + str(s['id'])) for s in summaries]
    validate_controls(repo, rules, rulesets, require_legacy=require_legacy,
                      require_successor_only=require_successor_only)
    return {'controls_sha256': digest(canonical([repo, rules, rulesets])),
            'bypass_visibility': {str(r['id']): ('visible' if 'bypass_actors' in r else 'redacted-or-unavailable') for r in rulesets}}

def validate_app_identity(read_api, app_api, app_slug, installation_id):
    # Issuer proof is the trusted workflow's pinned create-token action with fixed
    # App4217367 input and its unmodified outputs, not public bot metadata alone.
    require(app_slug == APP_SLUG, 'wrong reviewer App slug')
    require(isinstance(installation_id, str) and installation_id.isdecimal()
            and int(installation_id) > 0, 'missing pinned-action installation identity')
    bot = read_api.request('/users/' + app_slug + '[bot]')
    require(bot.get('type') == 'Bot' and bot.get('login') == APP_SLUG + '[bot]'
            and bot.get('id') == BOT_ID, 'wrong reviewer bot identity')
    repositories = app_api.pages('/installation/repositories', 'repositories')
    require(len(repositories) == 1 and repositories[0].get('id') == REPOSITORY_ID
            and repositories[0].get('full_name') == REPOSITORY, 'App token is not repository scoped')
    return {'app_id': APP_ID, 'slug': app_slug, 'bot_id': BOT_ID, 'installation_id': installation_id,
            'repository_id': REPOSITORY_ID, 'issuer_proof': 'trusted-pinned-create-token-action'}

def qualify_app(read_api, app_api, trusted, app_slug, installation_id, *, stage='bootstrap'):
    require(not app_api.writable, 'qualification credential API must be read-only')
    require(stage in ('bootstrap', 'current'), 'unknown qualification stage')
    prefix = '/repos/' + REPOSITORY
    require(read_api.request(prefix + '/git/ref/heads/main')['object']['sha'] == trusted, 'main moved before qualification')
    identity = validate_app_identity(read_api, app_api, app_slug, installation_id)
    options = {'require_legacy': True} if stage == 'bootstrap' else {'require_successor_only': True}
    controls = controls_snapshot(app_api, **options)
    workflow = read_api.request(prefix + '/actions/workflows/ci.yml')
    require(workflow['path'] == '.github/workflows/ci.yml' and workflow['state'] == 'active', 'CI workflow identity')
    runs = read_api.pages(prefix + '/actions/workflows/' + str(workflow['id']) + '/runs?branch=main&head_sha=' + trusted, 'workflow_runs')
    require(bool(runs), 'no current-main CI')
    run = max(runs, key=lambda r: (r['id'], r.get('run_attempt', 1)))
    require(run.get('status') == 'completed' and run.get('conclusion') == 'success' and run.get('event') in ('push', 'workflow_dispatch')
            and run.get('head_branch') == 'main' and run.get('head_sha') == trusted
            and run['repository']['id'] == REPOSITORY_ID and run['head_repository']['id'] == REPOSITORY_ID,
            'main CI not current successful origin')
    validate_ci_jobs(read_api, prefix, None, trusted, run)
    require(read_api.request(prefix + '/git/ref/heads/main')['object']['sha'] == trusted, 'main moved during qualification')
    require(controls_snapshot(app_api, **options) == controls, 'controls moved during qualification')
    return dict(status='qualified-app-read-only', qualification_stage=stage, revision=trusted, ci=[run['id'], run['run_attempt']],
                app=identity, mutated=False, **controls)

def mutation_result(result, operation, failure):
    # Keep diagnostics bounded and free of arbitrary API message/input text.
    require(isinstance(result, dict), failure)
    if result.get('errors'):
        errors = result['errors']
        kinds = sorted({e['type'] for e in errors if isinstance(e, dict)
                        and isinstance(e.get('type'), str)
                        and re.fullmatch(r'[A-Z_]{1,64}', e['type'])}) if isinstance(errors, list) else []
        raise Rejected(failure + ' (GraphQL error types: ' + ','.join(kinds[:10]) + ')')
    value = result
    for field in ('data', operation, 'pullRequest'):
        require(isinstance(value, dict) and isinstance(value.get(field), dict), failure)
        value = value[field]
    return value


def confirm_native_merge(read_api, number, proof, response):
    failure = 'native merge requires read-only reconciliation'
    commit = response.get('mergeCommit')
    require(response.get('id') == proof['node_id'] and response.get('merged') is True
            and isinstance(commit, dict) and isinstance(commit.get('oid'), str)
            and re.fullmatch(r'[0-9a-f]{40}', commit['oid']), failure)
    merged_sha = commit['oid']
    prefix = '/repos/' + REPOSITORY
    pr = read_api.request(prefix + f'/pulls/{number}')
    require(pr.get('merged') is True and pr.get('state') == 'closed'
            and pr.get('node_id') == proof['node_id'] and pr.get('number') == number
            and pr.get('head', {}).get('sha') == proof['tuple']['head_sha']
            and pr.get('base', {}).get('ref') == 'main'
            and pr.get('base', {}).get('repo', {}).get('id') == REPOSITORY_ID
            and pr.get('merge_commit_sha') == merged_sha
            and pr.get('merged_by', {}).get('id') == BOT_ID
            and pr.get('merged_by', {}).get('login') == APP_SLUG + '[bot]', failure)
    admitted = read_api.request(prefix + '/git/commits/' + merged_sha)
    tested = read_api.request(prefix + '/git/commits/' + proof['merge_sha'])
    require([p['sha'] for p in admitted['parents']] == [proof['tuple']['base_sha']]
            and admitted['tree']['sha'] == tested['tree']['sha'], failure)
    current_main = read_api.request(prefix + '/git/ref/heads/main')['object']['sha']
    if current_main != merged_sha:
        ancestry = read_api.request(prefix + '/compare/' + merged_sha + '...' + current_main)
        require(ancestry.get('merge_base_commit', {}).get('sha') == merged_sha, failure)
    return {'status': 'merged', 'head_sha': proof['tuple']['head_sha'], 'merged': True,
            'merge_sha': merged_sha, 'base_sha': proof['tuple']['base_sha']}


def deliver(read_api, write_api, number, policy, policy_hash, now, app_slug, installation_id):
    require(policy.get('enabled') is True, 'App writes disabled by trusted enrollment policy')
    validate_app_identity(read_api, write_api, app_slug, installation_id)
    first = snapshot(read_api, number, policy, policy_hash, now)
    # Re-read all mutable gates immediately before every write. Native strict
    # required checks and stale-approval dismissal arbitrate races after this read.
    require(snapshot(read_api, number, policy, policy_hash, now) == first, 'admission drift before approval')
    head = first['tuple']['head_sha']
    approval = write_api.request('/repos/' + REPOSITORY + f'/pulls/{number}/reviews', 'POST',
        {'event': 'APPROVE', 'commit_id': head, 'body': 'G1: completed enrolled local review and current CI/control gates verified. Q16 operational trust applies.'})
    require(approval['state'] == 'APPROVED' and approval['commit_id'] == head
            and approval['user']['login'] == app_slug + '[bot]' and approval['user']['id'] == BOT_ID
            and approval['user']['type'] == 'Bot', 'approval identity/result mismatch')
    require(snapshot(read_api, number, policy, policy_hash, now) == first, 'admission drift after approval; auto-merge not armed')
    # Select the native operation from a fresh observed state, never from a failed
    # mutation. Like gh --auto, a ready PR uses native merge; a blocked PR is armed.
    prefix = '/repos/' + REPOSITORY
    latest = read_api.request(prefix + f'/pulls/{number}')
    require(latest.get('node_id') == first['node_id'] and latest.get('state') == 'open'
            and latest.get('merged') is False and latest.get('draft') is False
            and latest.get('head', {}).get('sha') == head
            and latest.get('base', {}).get('sha') == first['tuple']['base_sha']
            and latest.get('base', {}).get('ref') == 'main'
            and latest.get('head', {}).get('repo', {}).get('id') == REPOSITORY_ID
            and latest.get('base', {}).get('repo', {}).get('id') == REPOSITORY_ID
            and read_api.request(prefix + '/git/ref/heads/main')['object']['sha'] == first['tuple']['base_sha']
            and latest.get('mergeable') is True
            and latest.get('mergeable_state') in ('clean', 'blocked'), 'native delivery state drift')
    # Both native operations atomically check the head, not the base. Native
    # strict checks still arbitrate subsequent base races; the App has no bypass.
    inputs = {'pullRequestId': first['node_id'], 'expectedHeadOid': head, 'mergeMethod': 'SQUASH'}
    if latest['mergeable_state'] == 'clean':
        result = write_api.request('/graphql', 'POST', {
            'query': 'mutation($input:MergePullRequestInput!){mergePullRequest(input:$input){pullRequest{id merged mergeCommit{oid}}}}',
            'variables': {'input': inputs}})
        response = mutation_result(result, 'mergePullRequest', 'native squash merge not confirmed')
        return confirm_native_merge(read_api, number, first, response)
    result = write_api.request('/graphql', 'POST', {
        'query': 'mutation($input:EnablePullRequestAutoMergeInput!){enablePullRequestAutoMerge(input:$input){pullRequest{autoMergeRequest{mergeMethod}}}}',
        'variables': {'input': inputs}})
    response = mutation_result(result, 'enablePullRequestAutoMerge', 'native auto-merge not confirmed')
    confirmation = response.get('autoMergeRequest')
    require(isinstance(confirmation, dict), 'native auto-merge not confirmed')
    require(confirmation.get('mergeMethod') == 'SQUASH', 'native auto-merge not confirmed')
    return {'status': 'armed', 'head_sha': head, 'merged': False}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pr', type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--write', action='store_true')
    mode.add_argument('--qualify-app', action='store_true')
    parser.add_argument('--qualification-stage', choices=('bootstrap', 'current'))
    args = parser.parse_args()
    require(args.qualify_app or args.qualification_stage is None, 'stage requires read-only App qualification')
    require(args.qualify_app or (args.pr is not None and args.pr > 0), 'invalid PR')
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'wrong workflow repository')
    trusted = os.environ.get('TRUSTED_WORKFLOW_SHA', '')
    require(re.fullmatch('[0-9a-f]{40}', trusted) is not None, 'missing trusted workflow revision')
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == trusted, 'untrusted checkout')
    policy_bytes = (ROOT / '.github/review-enrollments.json').read_bytes()
    policy = json.loads(policy_bytes)
    require(policy.get('schema') == 'g1-review-enrollments/v1' and policy.get('repository_id') == REPOSITORY_ID, 'enrollment policy identity')
    read = API(os.environ.get('CI_READ_TOKEN'))
    require(read.request('/repos/' + REPOSITORY + '/git/ref/heads/main')['object']['sha'] == trusted, 'trusted default revision moved')
    now = dt.datetime.now(dt.timezone.utc)
    if args.qualify_app:
        require(os.environ.get('REVIEWER_APP_QUALIFY') == 'true', 'App qualification flag disabled')
        require(os.environ.get('REVIEWER_APP_ENABLED') != 'true', 'qualification requires writer flag OFF')
        result = qualify_app(read, API(os.environ.get('APP_TOKEN')), trusted, os.environ.get('APP_SLUG'),
                             os.environ.get('APP_INSTALLATION_ID'), stage=args.qualification_stage or 'bootstrap')
    elif args.write:
        require(os.environ.get('REVIEWER_APP_ENABLED') == 'true', 'App write flag disabled')
        result = deliver(read, API(os.environ.get('APP_TOKEN'), writable=True), args.pr, policy, digest(policy_bytes), now, os.environ.get('APP_SLUG'), os.environ.get('APP_INSTALLATION_ID'))
    else:
        proof = snapshot(read, args.pr, policy, digest(policy_bytes), now)
        result = {'status': 'qualified-read-only', 'tuple': proof['tuple'], 'ci': proof['ci'], 'bypass_visibility': proof['bypass_visibility'], 'mutated': False}
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__':
    try:
        main()
    except (Rejected, KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as error:
        # Errors contain control reasons, never HTTP payloads/headers or tokens.
        print(json.dumps({'status': 'rejected', 'reason': str(error)[:300]}))
        raise SystemExit(1)
