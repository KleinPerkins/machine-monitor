"""One-use Q16 operational PR creation witness; not provider attestation."""
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import quote
import uuid

_spec = importlib.util.spec_from_file_location('creation_local_review', Path(__file__).with_name('local_review.py'))
review = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(review)
require = review.require
REPOSITORY = 'KleinPerkins/machine-monitor'
REPOSITORY_ID = 1449284973
OWNER_ID = 49759187
PREFIX = '/repos/' + REPOSITORY
ORIGIN_MARKER = '<!-- g1-pr-origin:v1 -->\n'
GH = '/opt/homebrew/bin/gh'
LIMIT = 2 * 1024 * 1024


def timestamp(value):
    require(isinstance(value, str) and value.endswith('Z'), 'UTC timestamp required')
    result = dt.datetime.fromisoformat(value[:-1] + '+00:00')
    require(result.utcoffset() == dt.timedelta(0), 'UTC timestamp required')
    return result


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def private_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                and not info.st_mode & 0o077 and info.st_size <= LIMIT, 'private regular input required')
        data = source.read(LIMIT + 1)
        require(len(data) <= LIMIT, 'input exceeds bound')
        return data


def private_destination(path):
    path = Path(path).absolute()
    require(path.parent.resolve() == path.parent, 'symlink destination parent')
    info = path.parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and not info.st_mode & 0o077, 'private destination directory required')
    require(not os.path.lexists(path), 'existing output or journal; never retry creation')
    return path


def exclusive(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')


def write_state(stream, value):
    stream.seek(0)
    stream.write(review.canonical(value) + '\n')
    stream.truncate()
    stream.flush()
    os.fsync(stream.fileno())


def validate_receipt(receipt, request, enrollment, now):
    fields = {'schema', 'capture_id', 'trust_model', 'tuple', 'reviewer_enrollment_id',
              'reviewer_origin_account', 'workspace_binding', 'instructions_sha256', 'runtime',
              'started_at', 'completed_at', 'review', 'report_sha256'}
    require(isinstance(receipt, dict) and set(receipt) == fields, 'closed review receipt required')
    require(receipt['schema'] == review.SCHEMA and receipt['trust_model'] == 'q16-operational-local', 'review trust mismatch')
    require(isinstance(receipt['capture_id'], str) and str(uuid.UUID(receipt['capture_id'])) == receipt['capture_id'], 'review capture ID invalid')
    require(receipt['tuple'] == request and receipt['reviewer_origin_account'] == request['origin_account']
            and receipt['reviewer_enrollment_id'] == enrollment['id'], 'review binding mismatch')
    require(receipt['workspace_binding'] == 'owner-declared-enrollment'
            and receipt['instructions_sha256'] == review.digest(review.INSTRUCTIONS), 'review instructions mismatch')
    runtime = receipt['runtime']
    keys = {'cli_version', 'credential_store', 'thread_id', 'turn_id', 'status', 'event_stream_sha256', 'startup_notice_sha256'}
    require(isinstance(runtime, dict) and set(runtime) == keys, 'closed review runtime required')
    require(runtime['cli_version'] == enrollment['cli_version'] and runtime['credential_store'] == enrollment['credential_store']
            and runtime['status'] == 'completed' and runtime['turn_id'] is None
            and isinstance(runtime['thread_id'], str) and len(runtime['thread_id']) >= 8, 'review runtime incomplete')
    require(isinstance(runtime['event_stream_sha256'], str)
            and re.fullmatch('[0-9a-f]{64}', runtime['event_stream_sha256']), 'direct event capture missing')
    allowed = {review.digest(item) for item in review.STARTUP_NOTICES}
    require(isinstance(runtime['startup_notice_sha256'], list)
            and all(isinstance(item, str) and item in allowed for item in runtime['startup_notice_sha256']), 'unqualified review notice')
    start, end = timestamp(receipt['started_at']), timestamp(receipt['completed_at'])
    require(start <= end <= now and now - start <= dt.timedelta(hours=24), 'review stale or future')
    report = review.validate_report(receipt['review'])
    require(report['verdict'] == 'pass' and report['coverage'] == 'complete'
            and report['findings'] == [] and report['unresolved_findings'] == [], 'passing complete review required')
    require(receipt['report_sha256'] == review.digest(review.canonical(report)), 'report digest mismatch')


class Github:
    def call(self, method, path, payload=None):
        argv = [GH, 'api', '--hostname', 'github.com', '--method', method, path,
                '-H', 'Accept: application/vnd.github+json', '-H', 'X-GitHub-Api-Version: 2022-11-28']
        if payload is not None:
            argv += ['--input', '-']
        # No shell, candidate commands, credential export, or automatic retry.
        raw = review.run(argv, input_data=b'' if payload is None else review.canonical(payload).encode(), timeout=30)
        return strict_json(raw)


def repository_identity(value):
    require(isinstance(value, dict) and type(value.get('id')) is int and value['id'] == REPOSITORY_ID
            and value.get('full_name') == REPOSITORY and value.get('private') is False, 'repository identity mismatch')


def owner(value):
    require(isinstance(value, dict) and type(value.get('id')) is int and value['id'] == OWNER_ID
            and value.get('type') == 'User', 'GitHub owner identity mismatch')


def remote_preflight(api, branch, request):
    owner(api.call('GET', '/user'))
    repository = api.call('GET', PREFIX)
    repository_identity(repository)
    require(repository.get('default_branch') == 'main' and repository.get('archived') is False, 'repository state mismatch')
    for name, sha in ((branch, request['head_sha']), ('main', request['base_sha'])):
        ref = api.call('GET', PREFIX + '/git/ref/heads/' + quote(name, safe=''))
        require(ref.get('ref') == 'refs/heads/' + name and ref.get('object', {}).get('type') == 'commit'
                and ref['object'].get('sha') == sha, 'remote tuple changed')
    existing = api.call('GET', PREFIX + '/pulls?state=open&head=' + quote('KleinPerkins:' + branch, safe='') + '&base=main&per_page=100')
    require(isinstance(existing, list) and not existing, 'existing or unknown PR; do not duplicate')


def validate_pr(pr, branch, request, marker, started):
    require(isinstance(pr, dict) and type(pr.get('number')) is int and pr['number'] > 0
            and isinstance(pr.get('node_id'), str) and pr['node_id'], 'PR identity missing')
    owner(pr.get('user'))
    require(pr.get('state') == 'open' and pr.get('draft') is False, 'ready open PR required')
    require(isinstance(pr.get('body'), str) and pr['body'].count('<!-- g1-pr-creation:') == 1
            and marker in pr['body'], 'creation nonce mismatch')
    for side, ref, sha in (('head', branch, request['head_sha']), ('base', 'main', request['base_sha'])):
        value = pr.get(side, {})
        repository_identity(value.get('repo'))
        require(value.get('ref') == ref and value.get('sha') == sha, 'created PR tuple mismatch')
    require(pr.get('html_url') == 'https://github.com/' + REPOSITORY + '/pull/' + str(pr['number']), 'PR URL mismatch')
    created = timestamp(pr.get('created_at'))
    require(started - dt.timedelta(seconds=1) <= created <= timestamp(review.utc())
            and created - started <= dt.timedelta(minutes=10), 'creation timestamp mismatch')


def create(repo, request, policy, enrollment, receipt, title, body, output, journal, cli='codex', api=None):
    output, journal = private_destination(output), private_destination(journal)
    require(output != journal, 'output and journal must differ')
    require(isinstance(title, str) and 0 < len(title.strip()) <= 256
            and isinstance(body, str) and len(body.encode()) <= 60000
            and '<!-- g1-pr-' not in body, 'invalid title/body or supplied origin marker')
    require(request.get('repository') == REPOSITORY and request.get('repository_id') == REPOSITORY_ID, 'wrong repository request')
    account = review.account_read(cli, enrollment['credential_store'])
    review.validate_enrollment(enrollment, account, request['origin_account'])
    version = review.run([cli, '--version']).decode().strip()
    require(version == enrollment['cli_version'], 'unenrolled CLI version')
    payload = review.frozen_input(repo, request, policy)
    validate_receipt(receipt, request, enrollment, timestamp(review.utc()))
    branch = review.git(repo, 'symbolic-ref', '--quiet', '--short', 'HEAD').decode().strip()
    require(branch and branch != 'main' and not any(c.isspace() for c in branch), 'delivery branch required')
    nonce, started = str(uuid.uuid4()), review.utc()
    marker = '<!-- g1-pr-creation:' + nonce + ' -->'
    state = {'schema': 'g1-pr-creation-journal/v1', 'creation_id': nonce, 'started_at': started, 'status': 'prepared'}
    api = api or Github()
    # Reserve both names before network access. Empty output is never an envelope.
    with exclusive(journal) as journal_file:
        write_state(journal_file, state)
        try:
            with exclusive(output) as output_file:
                remote_preflight(api, branch, request)
                require(review.account_read(cli, enrollment['credential_store']) == account, 'account changed before create')
                require(review.frozen_input(repo, request, policy) == payload, 'tuple changed before create')
                state['status'] = 'create-attempted'
                write_state(journal_file, state)
                pr = api.call('POST', PREFIX + '/pulls', {'title': title, 'body': body + '\n\n' + marker,
                                                        'head': branch, 'base': 'main', 'draft': False})
                # Save bounded identifiers immediately, before account or response validation.
                if isinstance(pr, dict):
                    state['partial_pr'] = {key: pr[key] for key in ('number', 'node_id', 'created_at')
                                           if key in pr and isinstance(pr[key], (str, int)) and len(str(pr[key])) <= 256}
                state['status'] = 'created-unverified'
                write_state(journal_file, state)
                validate_pr(pr, branch, request, marker, timestamp(started))
                require(review.account_read(cli, enrollment['credential_store']) == account, 'account changed during creation')
                review.validate_enrollment(enrollment, account, request['origin_account'])
                require(review.run([cli, '--version']).decode().strip() == version, 'CLI changed during creation')
                require(review.frozen_input(repo, request, policy) == payload, 'tuple changed during creation')
                # Current API state must still be the exact created tuple before origin publication.
                owner(api.call('GET', '/user'))
                current = api.call('GET', PREFIX + '/pulls/' + str(pr['number']))
                validate_pr(current, branch, request, marker, timestamp(started))
                require(all(current[k] == pr[k] for k in ('number', 'node_id', 'created_at')), 'created identity changed')
                completed = review.utc()
                require(timestamp(completed) - timestamp(started) <= dt.timedelta(minutes=10), 'creation window exceeded')
                origin = {'schema': 'g1-pr-origin/v1', 'trust_model': 'q16-operational-local', 'creation_id': nonce,
                          'repository': REPOSITORY, 'repository_id': REPOSITORY_ID, 'pull_request': pr['number'],
                          'pull_request_node_id': pr['node_id'], 'github_user_id': OWNER_ID,
                          'origin_account': enrollment['origin_account'], 'creator_enrollment_id': enrollment['id'],
                          'workspace_binding': 'owner-declared-enrollment', 'initial_head_sha': request['head_sha'],
                          'initial_base_sha': request['base_sha'], 'pr_created_at': pr['created_at'], 'started_at': started,
                          'completed_at': completed, 'runtime': {'cli_version': version, 'credential_store': enrollment['credential_store'],
                          'account_checked_before': True, 'account_checked_after': True},
                          'creation_adapter_sha256': review.digest(Path(__file__).read_bytes()),
                          'capture_adapter_sha256': review.digest(Path(review.__file__).read_bytes())}
                comments_path = PREFIX + '/issues/' + str(pr['number']) + '/comments'
                comments = api.call('GET', comments_path + '?per_page=100')
                require(isinstance(comments, list) and not comments, 'existing or unknown comments; no first origin')
                comment_body = ORIGIN_MARKER + review.canonical(origin)
                state['status'] = 'comment-attempted'
                write_state(journal_file, state)
                comment = api.call('POST', comments_path, {'body': comment_body})
                owner(comment.get('user'))
                require(type(comment.get('id')) is int and comment['id'] > 0 and comment.get('body') == comment_body
                        and comment.get('created_at') == comment.get('updated_at')
                        and comment.get('issue_url') == 'https://api.github.com' + PREFIX + '/issues/' + str(pr['number']), 'origin comment response mismatch')
                posted = timestamp(comment['created_at'])
                require(timestamp(completed) - dt.timedelta(seconds=1) <= posted <= timestamp(review.utc())
                        and posted - timestamp(started) <= dt.timedelta(minutes=10), 'comment window exceeded')
                write_state(output_file, origin)
                state.update(status='complete', comment_id=comment['id'], completed_at=completed)
                write_state(journal_file, state)
                return pr['html_url'], comment['id']
        except BaseException:
            state['status_before_failure'] = state['status']
            state['status'] = 'incomplete-no-retry'
            write_state(journal_file, state)
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'request', 'policy', 'enrollment', 'review', 'title', 'body', 'output', 'journal'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--cli', default='codex')
    args = parser.parse_args()
    try:
        url, comment_id = create(Path(args.repo).resolve(), strict_json(private_read(args.request)), private_read(args.policy),
                                 strict_json(private_read(args.enrollment)), strict_json(private_read(args.review)),
                                 private_read(args.title).decode(), private_read(args.body).decode(), args.output, args.journal, args.cli)
        print(url)
        print(comment_id)
    except (review.CaptureError, OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired):
        parser.exit(1, 'PR creation refused or incomplete. Inspect private journal; do not retry or recreate.\n')


if __name__ == '__main__':
    main()
