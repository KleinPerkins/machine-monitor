import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('create_review_pr', Path(__file__).parents[1] / 'scripts/create_review_pr.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class FakeGithub:
    def __init__(self):
        self.calls = []
        self.repo = {'id': m.REPOSITORY_ID, 'full_name': m.REPOSITORY, 'private': False, 'default_branch': 'main', 'archived': False}
        self.user = {'id': m.OWNER_ID, 'type': 'User'}
        self.existing = []
        self.comments = []
        self.head = 'a' * 40
        self.base = 'b' * 40
        self.pr = None
        self.fail = None
        self.change_pr = None
        self.change_comment = None
        self.after_create = None

    def call(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if self.fail == (method, path):
            raise m.review.CaptureError('ambiguous network failure')
        if path == '/user':
            return copy.deepcopy(self.user)
        if path == m.PREFIX:
            return copy.deepcopy(self.repo)
        if '/git/ref/heads/' in path:
            name = path.split('/git/ref/heads/')[1].replace('%2F', '/')
            return {'ref': 'refs/heads/' + name, 'object': {'type': 'commit', 'sha': self.base if name == 'main' else self.head}}
        if path.startswith(m.PREFIX + '/pulls?'):
            return self.existing
        if method == 'POST' and path == m.PREFIX + '/pulls':
            self.pr = {'number': 19, 'node_id': 'PR_node19', 'user': copy.deepcopy(self.user), 'state': 'open', 'draft': False,
                       'body': payload['body'], 'head': {'repo': copy.deepcopy(self.repo), 'sha': self.head, 'ref': 'feat/delivery'},
                       'base': {'repo': copy.deepcopy(self.repo), 'sha': self.base, 'ref': 'main'},
                       'html_url': 'https://github.com/' + m.REPOSITORY + '/pull/19', 'created_at': m.review.utc()}
            if self.change_pr:
                self.change_pr(self.pr)
            if self.after_create:
                self.after_create()
            return copy.deepcopy(self.pr)
        if path == m.PREFIX + '/pulls/19':
            return copy.deepcopy(self.pr)
        if '/comments?' in path:
            return self.comments
        if method == 'POST' and path == m.PREFIX + '/issues/19/comments':
            comment = {'id': 27, 'user': copy.deepcopy(self.user), 'body': payload['body'], 'created_at': m.review.utc(),
                       'issue_url': 'https://api.github.com' + m.PREFIX + '/issues/19'}
            comment['updated_at'] = comment['created_at']
            if self.change_comment:
                self.change_comment(comment)
            self.posted_comment = copy.deepcopy(comment)
            return comment
        raise AssertionError((method, path))


class CreationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.output = self.root / 'origin.json'
        self.journal = self.root / 'journal.json'
        self.api = FakeGithub()
        self.enrollment = {'id': 'work-local', 'origin_account': 'work', 'email': 'owner@example.invalid',
                           'workspace': 'private-workspace', 'cli_version': 'codex-cli 0.148.0', 'credential_store': 'keyring',
                           'codex_home': str(Path(os.environ.get('CODEX_HOME', str(Path.home() / '.codex'))).resolve())}
        self.request = {'repository': m.REPOSITORY, 'repository_id': m.REPOSITORY_ID, 'head_sha': 'a' * 40,
                        'base_sha': 'b' * 40, 'merge_base_sha': 'c' * 40, 'diff_sha256': 'd' * 64,
                        'policy_sha256': m.review.digest(b'policy'), 'origin_account': 'work'}
        report = {'verdict': 'pass', 'coverage': 'complete', 'summary': 'All supplied changed lines examined.', 'findings': [], 'unresolved_findings': []}
        self.receipt = {'schema': m.review.SCHEMA, 'capture_id': '11111111-1111-4111-8111-111111111111',
                        'trust_model': 'q16-operational-local', 'tuple': copy.deepcopy(self.request),
                        'reviewer_enrollment_id': 'work-local', 'reviewer_origin_account': 'work',
                        'workspace_binding': 'owner-declared-enrollment', 'instructions_sha256': m.review.digest(m.review.INSTRUCTIONS),
                        'runtime': {'cli_version': self.enrollment['cli_version'], 'credential_store': 'keyring',
                                    'thread_id': 'fresh-thread', 'turn_id': None, 'status': 'completed',
                                    'event_stream_sha256': 'e' * 64, 'startup_notice_sha256': []},
                        'started_at': m.review.utc(), 'completed_at': m.review.utc(), 'review': report,
                        'report_sha256': m.review.digest(m.review.canonical(report))}
        self.account = {'type': 'chatgpt', 'email': self.enrollment['email']}
        self.account_mock = self.start(patch.object(m.review, 'account_read', return_value=self.account))
        self.run_mock = self.start(patch.object(m.review, 'run', return_value=self.enrollment['cli_version'].encode()))
        self.frozen = self.start(patch.object(m.review, 'frozen_input', return_value={'immutable': True}))
        self.start(patch.object(m.review, 'git', return_value=b'feat/delivery\n'))

    def start(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def create(self, **kwargs):
        args = dict(repo=self.root, request=self.request, policy=b'policy', enrollment=self.enrollment,
                    receipt=self.receipt, title='Reviewed change', body='Concrete behavior and validation.',
                    output=self.output, journal=self.journal, api=self.api)
        args.update(kwargs)
        return m.create(**args)

    def assert_no_origin(self):
        self.assertFalse(self.output.exists() and self.output.read_text().strip())

    def assert_no_create(self):
        self.assertFalse(any(method == 'POST' and path == m.PREFIX + '/pulls' for method, path, _ in self.api.calls))

    def test_positive_direct_witness_exact_public_bytes_and_private_journal(self):
        url, comment = self.create()
        origin = json.loads(self.output.read_text())
        self.assertEqual(url, 'https://github.com/' + m.REPOSITORY + '/pull/19')
        self.assertEqual(comment, 27)
        self.assertEqual(origin['origin_account'], 'work')
        self.assertEqual(origin['creator_enrollment_id'], 'work-local')
        self.assertEqual(origin['capture_adapter_sha256'], m.review.digest(Path(m.review.__file__).read_bytes()))
        self.assertEqual(origin['creation_adapter_sha256'], m.review.digest(Path(m.__file__).read_bytes()))
        posted = [payload['body'] for method, path, payload in self.api.calls if method == 'POST' and '/comments' in path][0]
        self.assertEqual(posted, m.ORIGIN_MARKER + self.output.read_text().rstrip('\n'))
        self.assertIn('<!-- g1-pr-creation:' + origin['creation_id'] + ' -->', self.api.pr['body'])
        for private in ('owner@example.invalid', 'private-workspace', self.enrollment['codex_home']):
            self.assertNotIn(private, self.output.read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(self.journal.read_text())['status'], 'complete')
        self.assertEqual(self.account_mock.call_count, 3)

    def test_wrong_account_cli_profile_origin_block_before_api(self):
        cases = [lambda: self.account_mock.configure_mock(return_value={'type': 'chatgpt', 'email': 'other@example.invalid'}),
                 lambda: self.run_mock.configure_mock(return_value=b'codex-cli unexpected'),
                 lambda: self.enrollment.update(codex_home='/unrelated-profile'),
                 lambda: self.enrollment.update(origin_account='personal')]
        for change in cases:
            with self.subTest(change=change):
                old = copy.deepcopy(self.enrollment)
                change()
                with self.assertRaises(m.review.CaptureError):
                    self.create()
                self.assertEqual(self.api.calls, [])
                self.enrollment = old
                self.account_mock.return_value = self.account
                self.run_mock.return_value = old['cli_version'].encode()

    def test_wrong_github_repo_head_base_refuse_before_create(self):
        cases = [('owner', lambda: self.api.user.update(id=7)), ('repo', lambda: self.api.repo.update(id=7)),
                 ('private', lambda: self.api.repo.update(private=True)), ('default', lambda: self.api.repo.update(default_branch='other')),
                 ('head', lambda: setattr(self.api, 'head', 'f' * 40)), ('base', lambda: setattr(self.api, 'base', 'f' * 40))]
        for name, change in cases:
            with self.subTest(name=name):
                change()
                with self.assertRaises(m.review.CaptureError):
                    self.create()
                self.assert_no_create()
                self.assert_no_origin()
                self.output.unlink(missing_ok=True)
                self.journal.unlink(missing_ok=True)
                self.api = FakeGithub()

    def test_account_drift_before_or_after_create(self):
        other = {'type': 'chatgpt', 'email': 'other@example.invalid'}
        for sequence, created in (([self.account, other], False), ([self.account, self.account, other], True)):
            with self.subTest(created=created):
                self.account_mock.side_effect = sequence
                with self.assertRaises(m.review.CaptureError):
                    self.create()
                self.assertEqual(self.api.pr is not None, created)
                self.assert_no_origin()
                self.assertFalse(any('/comments' in path for _, path, _ in self.api.calls))
                self.output.unlink(missing_ok=True)
                self.journal.unlink(missing_ok=True)
                self.api = FakeGithub()

    def test_existing_unknown_pr_and_origin_refused(self):
        for existing in ([{'number': 2}], {}, None):
            self.api.existing = existing
            with self.assertRaises(m.review.CaptureError):
                self.create()
            self.assert_no_create()
            self.output.unlink(missing_ok=True)
            self.journal.unlink(missing_ok=True)
            self.api = FakeGithub()
        self.api.comments = [{'body': m.ORIGIN_MARKER + '{}'}]
        with self.assertRaises(m.review.CaptureError):
            self.create()
        self.assert_no_origin()
        self.assertFalse(any(method == 'POST' and '/comments' in path for method, path, _ in self.api.calls))

    def test_malformed_stale_wrong_binding_receipts(self):
        base = copy.deepcopy(self.receipt)
        changes = [lambda r: r.update(author_pass=True), lambda r: r.update(reviewer_origin_account='personal'),
                   lambda r: r.update(reviewer_enrollment_id='other'), lambda r: r.update(instructions_sha256='f' * 64),
                   lambda r: r['tuple'].update(base_sha='f' * 40), lambda r: r.update(report_sha256='f' * 64),
                   lambda r: r['runtime'].update(status='running'), lambda r: r['runtime'].update(event_stream_sha256=''),
                   lambda r: r['runtime'].update(startup_notice_sha256=['f' * 64]),
                   lambda r: r.update(started_at='2020-01-01T00:00:00Z'), lambda r: r.update(completed_at='2999-01-01T00:00:00Z'),
                   lambda r: r['review'].update(coverage='incomplete'), lambda r: r['review'].update(summary='')]
        for change in changes:
            self.receipt = copy.deepcopy(base)
            change(self.receipt)
            with self.subTest(receipt=self.receipt), self.assertRaises(m.review.CaptureError):
                self.create()
            self.assertEqual(self.api.calls, [])

    def test_preexisting_output_journal_or_supplied_nonce_prevent_reuse(self):
        for target in (self.output, self.journal):
            target.write_text('prior-state')
            with self.assertRaises(m.review.CaptureError):
                self.create()
            self.assertEqual(target.read_text(), 'prior-state')
            self.assertEqual(self.api.calls, [])
            target.unlink()
        with self.assertRaises(m.review.CaptureError):
            self.create(body='<!-- g1-pr-creation:forged -->')
        self.assertEqual(self.api.calls, [])

    def test_ambiguous_create_is_journaled_and_never_retried(self):
        self.api.fail = ('POST', m.PREFIX + '/pulls')
        with self.assertRaises(m.review.CaptureError):
            self.create()
        state = json.loads(self.journal.read_text())
        self.assertEqual(state['status'], 'incomplete-no-retry')
        self.assertEqual(state['status_before_failure'], 'create-attempted')
        self.assertIn('creation_id', state)
        before = len(self.api.calls)
        with self.assertRaises(m.review.CaptureError):
            self.create()
        self.assertEqual(before, len(self.api.calls))
        self.assert_no_origin()

    def test_comment_failure_retains_partial_pr_without_output(self):
        self.api.fail = ('POST', m.PREFIX + '/issues/19/comments')
        with self.assertRaises(m.review.CaptureError):
            self.create()
        state = json.loads(self.journal.read_text())
        self.assertEqual(state['partial_pr']['number'], 19)
        self.assertEqual(state['status_before_failure'], 'comment-attempted')
        self.assert_no_origin()

    def test_created_response_identity_draft_nonce_and_tuple_checked(self):
        changes = [lambda pr: pr.update(draft=True), lambda pr: pr.update(body='wrong nonce'),
                   lambda pr: pr['user'].update(id=1), lambda pr: pr['base'].update(sha='f' * 40),
                   lambda pr: pr['head']['repo'].update(id=1), lambda pr: pr.update(html_url='https://example.invalid'),
                   lambda pr: pr.update(number=True), lambda pr: pr.update(created_at='2020-01-01T00:00:00Z')]
        for change in changes:
            self.api.change_pr = change
            with self.assertRaises(m.review.CaptureError):
                self.create()
            self.assert_no_origin()
            self.assertIn('partial_pr', json.loads(self.journal.read_text()))
            self.output.unlink(missing_ok=True)
            self.journal.unlink(missing_ok=True)
            self.api = FakeGithub()

    def test_comment_must_match_owner_bytes_and_unedited_identity(self):
        self.api.change_comment = lambda c: c.update(body='different')
        with self.assertRaises(m.review.CaptureError):
            self.create()
        self.assert_no_origin()

    def test_local_drift_after_creation_blocks_origin(self):
        self.frozen.side_effect = [{'immutable': True}, {'immutable': True}, {'immutable': False}]
        with self.assertRaises(m.review.CaptureError):
            self.create()
        self.assert_no_origin()
        self.assertIsNotNone(self.api.pr)

    def test_private_inputs_exclusive_destinations_and_duplicate_keys(self):
        value = self.root / 'private.json'
        value.write_text('{}')
        value.chmod(0o600)
        self.assertEqual(m.private_read(value), b'{}')
        value.chmod(0o644)
        with self.assertRaises(m.review.CaptureError):
            m.private_read(value)
        symlink = self.root / 'link'
        symlink.symlink_to(value)
        with self.assertRaises(OSError):
            m.private_read(symlink)
        with self.assertRaises(m.review.CaptureError):
            m.strict_json('{"key":1,"key":2}')

    def test_transport_uses_absolute_gh_json_stdin_no_shell(self):
        self.run_mock.return_value = b'{"number":19}'
        self.assertEqual(m.Github().call('POST', m.PREFIX + '/pulls', {'title': 'literal `text` $(x)'}), {'number': 19})
        args, kwargs = self.run_mock.call_args
        self.assertEqual(args[0][0], '/opt/homebrew/bin/gh')
        self.assertIn('--hostname', args[0])
        self.assertEqual(args[0][-2:], ['--input', '-'])
        self.assertEqual(json.loads(kwargs['input_data']), {'title': 'literal `text` $(x)'})
        self.assertLessEqual(kwargs['timeout'], 30)

    def test_helper_origin_passes_app_and_wrong_first_review_cannot_select_origin(self):
        app_spec = importlib.util.spec_from_file_location('creation_app_seam', Path(__file__).parents[1] / 'scripts/reviewer_app.py')
        app = importlib.util.module_from_spec(app_spec)
        app_spec.loader.exec_module(app)
        self.create()
        actual = json.loads(self.output.read_text())
        producer = {'id': self.enrollment['id'], 'origin_account': 'work', 'github_user_id': m.OWNER_ID, 'enabled': True,
                    'cli_version': self.enrollment['cli_version'], 'credential_store': 'keyring',
                    'instructions_sha256': m.review.digest(m.review.INSTRUCTIONS), 'allowed_startup_notice_sha256': [],
                    'creation_adapter_sha256': m.review.digest(Path(m.__file__).read_bytes()),
                    'capture_adapter_sha256': m.review.digest(Path(m.review.__file__).read_bytes())}
        enrollments = {'producers': [producer, dict(producer, id='personal-local', origin_account='personal')]}
        now = m.timestamp(m.review.utc())
        origin = app.choose_origin([self.api.posted_comment], enrollments, self.api.pr, now)
        self.assertEqual(origin, actual)
        current = {k: v for k, v in self.request.items() if k != 'origin_account'}
        stamp = m.review.utc()
        work_comment = {'id': 29, 'user': self.api.user, 'created_at': stamp, 'updated_at': stamp,
                        'body': app.MARKER + m.review.canonical(self.receipt)}
        self.assertEqual(app.choose_receipt([work_comment], enrollments, current, self.request['policy_sha256'],
                                           m.timestamp(m.review.utc()), origin), self.receipt)
        wrong = copy.deepcopy(self.receipt)
        wrong.update(reviewer_enrollment_id='personal-local', reviewer_origin_account='personal')
        wrong['tuple']['origin_account'] = 'personal'
        first = dict(work_comment, id=28, body=app.MARKER + m.review.canonical(wrong))
        with self.assertRaisesRegex(app.Rejected, 'frozen PR origin mismatch'):
            app.choose_receipt([first, work_comment], enrollments, current, self.request['policy_sha256'],
                               m.timestamp(m.review.utc()), origin)
        self.assertEqual(origin['origin_account'], 'work')


if __name__ == '__main__':
    unittest.main()
