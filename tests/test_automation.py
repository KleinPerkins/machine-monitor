"""Synthetic reviewer policy tests. Never mint tokens or call GitHub."""
import copy
from pathlib import Path
import unittest

from scripts import auto_merge as policy
import github_automation as shared

HEAD = 'a' * 40
REPO = 'KleinPerkins/machine-monitor'


def pull():
    return dict(number=7, state='open', draft=False, changed_files=1, author_association='OWNER',
                user=dict(login='KleinPerkins', id=49759187, type='User'),
                head=dict(sha=HEAD, ref='feat/fixture', repo=dict(full_name=REPO)),
                base=dict(ref='main', sha='c'*40, repo=dict(full_name=REPO)), auto_merge=None)


def run():
    return dict(event='pull_request', conclusion='success', path='.github/workflows/ci.yml',
                head_sha=HEAD, head_repository=dict(full_name=REPO, id=12345))


class OrdinaryHeadPolicy(unittest.TestCase):
    def test_current_ordinary_owner_head_is_eligible(self):
        self.assertTrue(policy.eligible(pull(), run(), ['app.js'], base_sha='c'*40))

    def test_owner_changes_are_eligible_for_every_path(self):
        names = ['.github/workflows/ci.yml', '.github/test-shards.json', '.github/CODEOWNERS',
                 '.planning/doc-warden.json', '_ops/POLICY.md', 'AGENTS.md', 'README.md', 'SECURITY.md',
                 'Makefile', 'LICENSE', 'THIRD-PARTY-NOTICES.md', 'requirements.txt',
                 'build_mac_app.py', 'mac/MachineMonitor.swift', 'scripts/verify.py',
                 'tests/test_service.py', 'test_monitor.py', '.gitignore', '.githooks/pre-commit',
                 'delivery/wrangler.template.json','delivery/worker.mjs','delivery/schema.sql',
                 'update_contract.py','update_preflight.py','update_recovery.py','PRIVATE-BINARY-LICENSE']
        for name in names:
            self.assertTrue(policy.eligible(pull(), run(), [name], base_sha='c'*40), name)
            self.assertTrue(policy.eligible(pull(), run(), [name.upper()], base_sha='c'*40), name)
            other = pull();other['user'] = dict(login='fixture-member', id=100, type='User')
            self.assertFalse(policy.eligible(other, run(), [name], base_sha='c'*40), name)

    def test_rename_paths_do_not_restrict_owner_but_still_restrict_other_authors(self):
        files = policy.complete_changed_files(pull(), [dict(filename='app.js', previous_filename='scripts/verify.py')])
        self.assertTrue(policy.eligible(pull(), run(), files, base_sha='c'*40))
        other = pull();other['user'] = dict(login='fixture-member', id=100, type='User')
        self.assertFalse(policy.eligible(other, run(), files, base_sha='c'*40))

    def test_missing_duplicate_or_unsafe_file_evidence_refuses(self):
        for entries in ([], [dict(filename='../app.js')], [dict(filename='/app.js')],
                        [dict(filename='app.js', previous_filename='')]):
            with self.assertRaises(shared.AutomationError):
                policy.complete_changed_files(pull(), entries)
        pr = pull();pr['changed_files'] = 2
        with self.assertRaises(shared.AutomationError):
            policy.complete_changed_files(pr, [dict(filename='app.js'), dict(filename='app.js')])

    def test_stale_foreign_draft_and_bot_heads_are_ineligible(self):
        changes = [dict(draft=True), dict(state='closed'),
                   dict(head=dict(sha='b'*40, ref='feat/fixture', repo=dict(full_name=REPO))),
                   dict(head=dict(sha=HEAD, ref='feat/fixture', repo=dict(full_name='foreign/repo'))),
                   dict(user=dict(login='dependabot[bot]', id=shared.DEPENDABOT_ID, type='Bot'))]
        for change in changes:
            pr = pull();pr.update(change)
            self.assertFalse(policy.eligible(pr, run(), ['app.js'], base_sha='c'*40))
        for change in (dict(conclusion='cancelled'), dict(event='push'), dict(path='.github/workflows/other.yml')):
            event = run();event.update(change)
            self.assertFalse(policy.eligible(pull(), event, ['app.js'], base_sha='c'*40))

    def test_owner_identity_requires_login_numeric_id_and_user_type(self):
        for change in (dict(login='somebody-else'), dict(id=100), dict(id='49759187'),
                       dict(type='Bot'), dict(id=None)):
            pr = pull();pr['user'].update(change)
            self.assertFalse(policy.eligible(pr, run(), ['scripts/auto_merge.py'], base_sha='c'*40))
        pr = pull();pr.pop('user')
        self.assertFalse(policy.eligible(pr, run(), ['scripts/auto_merge.py'], base_sha='c'*40))

    def test_owner_branch_names_and_association_do_not_restrict_approval(self):
        for branch in ('dependabot/owner-authored', 'release-please--owner-authored'):
            pr = pull();pr['head']['ref'] = branch;pr['author_association'] = 'NONE'
            self.assertTrue(policy.eligible(pr, run(), ['scripts/auto_merge.py'], base_sha='c'*40))

    def test_non_owner_ordinary_changes_keep_existing_policy(self):
        pr = pull();pr['user'] = dict(login='fixture-member', id=100, type='User')
        self.assertTrue(policy.eligible(pr, run(), ['app.js'], base_sha='c'*40))
        pr['author_association'] = 'NONE'
        self.assertFalse(policy.eligible(pr, run(), ['app.js'], base_sha='c'*40))

    def test_immutable_public_identity_is_required(self):
        event = dict(repository=dict(full_name=REPO, id=12345), workflow_run=run())
        observed = dict(full_name=REPO, id=12345, visibility='public', default_branch='main')
        policy.verify_repository_identity(event, 12345, lambda _: observed)
        for change in (dict(id=999), dict(full_name='foreign/repo'), dict(visibility='private')):
            with self.assertRaises(shared.AutomationError):
                policy.verify_repository_identity(event, 12345, lambda _, change=change: dict(observed, **change))
        with self.assertRaises(shared.AutomationError):
            policy.verify_repository_identity(event, None, lambda _: observed)

    def test_privileged_workflow_uses_only_trusted_code_and_scoped_app_token(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / '.github/workflows/reviewer-app.yml').read_text()
        for literal in ("vars.REVIEWER_APP_ENABLED == 'true'", 'ref: ${{ github.workflow_sha }}',
                        'persist-credentials: false', 'repositories: machine-monitor',
                        'owner: KleinPerkins', 'timeout-minutes: 5'):
            self.assertIn(literal, source)
        self.assertNotIn('download-artifact', source)
        self.assertNotIn('pull_request.head', source)
        for line in source.splitlines():
            if 'uses:' in line:
                self.assertRegex(line, r'@[0-9a-f]{40}')


class ExactHeadApproval(unittest.TestCase):
    def setUp(self):
        self.pr = pull()
        self.reviewer = dict(id=400, login='fixture-reviewer[bot]', type='Bot')
        self.check = dict(name='ci-required', head_sha=HEAD, status='completed', conclusion='success',
                          app=dict(id=shared.ACTIONS_APP_ID))
        self.writes = []
        self.merges = []
        self.pr_reads = 0
        self.change_after_approval = False
        self.preapproved = False
        self.control_calls = 0
        self.weaken_at = None

    def controls(self):
        self.control_calls += 1
        if self.control_calls == self.weaken_at:
            raise shared.AutomationError('Synthetic control drift')

    def request(self, path, **kwargs):
        if '/check-runs?' in path:
            self.assertEqual(kwargs['token'], 'fixture-read-token')
            return [dict(check_runs=[self.check])]
        if '/reviews?' in path:
            if self.preapproved:
                return [[dict(id=1, user=self.reviewer, state='APPROVED', commit_id=HEAD)]]
            return [[]]
        if path.endswith('/reviews'):
            self.writes.append(kwargs['payload'])
            return {}
        if path.endswith('/pulls/7'):
            self.pr_reads += 1
            value = copy.deepcopy(self.pr)
            if self.change_after_approval and self.pr_reads >= 2:
                value['head']['sha'] = 'b' * 40
            return value
        raise AssertionError('Unexpected API request: ' + path)

    def execute(self):
        shared.approve_and_arm(self.pr, request=self.request,
            merge=lambda number, head: self.merges.append((number, head)), reviewer=self.reviewer,
            eligible=lambda pr: policy.eligible(pr, run(), ['app.js'], base_sha='c'*40),
            read_token='fixture-read-token', report=lambda *_: None, controls=self.controls)

    def test_trusted_entrypoint_approves_large_owner_policy_change(self):
        import contextlib
        import io
        import json
        import os
        import tempfile
        from unittest.mock import patch

        repository = dict(full_name=REPO, id=12345, visibility='public', default_branch='main',
            allow_squash_merge=True, allow_merge_commit=False, allow_rebase_merge=False,
            allow_auto_merge=True, delete_branch_on_merge=True)
        rules = [dict(type=name) for name in ('required_linear_history', 'deletion', 'non_fast_forward')]
        rules += [dict(type='pull_request', parameters=dict(required_approving_review_count=1,
            dismiss_stale_reviews_on_push=True, required_review_thread_resolution=True)),
            dict(type='required_status_checks', parameters=dict(strict_required_status_checks_policy=True,
            required_status_checks=[dict(context='ci-required', integration_id=shared.ACTIONS_APP_ID)]))]
        event = dict(repository=dict(full_name=REPO, id=12345), workflow_run=run())
        self.pr['changed_files'] = 3001
        self.pr['head']['ref'] = 'release-please--owner-policy-change'
        reads = []

        def request(path, **kwargs):
            reads.append(path)
            if path == 'repos/' + REPO:
                return repository
            if path.endswith('/rules/branches/main'):
                return rules
            if path == f'repos/{REPO}/commits/{HEAD}/pulls?per_page=100':
                self.assertTrue(kwargs['paginate'])
                return [[copy.deepcopy(self.pr)]]
            if path == 'users/' + self.reviewer['login']:
                return self.reviewer
            # The fixture refuses unknown requests; no transport can reach GitHub.
            return self.request(path, **kwargs)

        with tempfile.TemporaryDirectory(prefix='monitor-owner-entrypoint-') as temporary:
            root = Path(temporary)
            (root / '.planning').mkdir()
            (root / '.planning/doc-warden.json').write_text(json.dumps(dict(github_repository_id=12345)))
            event_path = root / 'event.json'
            event_path.write_text(json.dumps(event))
            environment = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='workflow_run',
                GITHUB_REPOSITORY=REPO, GITHUB_EVENT_PATH=str(event_path),
                CI_READ_TOKEN='fixture-read-token', REVIEWER_LOGIN=self.reviewer['login'],
                GITHUB_STEP_SUMMARY='')
            with patch.dict(os.environ, environment), patch.object(policy, 'ROOT', root), \
                 patch.object(policy, 'api', request), \
                 patch.object(policy, 'enable_merge', lambda number, head: self.merges.append((number, head))), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(policy.main(), 0)
        self.assertEqual(len(self.writes), 1)
        self.assertEqual(self.writes[0]['event'], 'APPROVE')
        self.assertEqual(self.writes[0]['commit_id'], HEAD)
        self.assertEqual(self.merges, [(7, HEAD)])
        self.assertEqual(reads.count('repos/' + REPO + '/rules/branches/main'), 3)
        self.assertFalse(any('/compare/' in path for path in reads))

    def test_only_verified_current_commit_is_approved_and_armed(self):
        self.execute()
        self.assertEqual(self.writes[0]['commit_id'], HEAD)
        self.assertEqual(self.writes[0]['event'], 'APPROVE')
        self.assertEqual(self.merges, [(7, HEAD)])

    def test_wrong_app_failed_skipped_cancelled_and_missing_gate_do_not_approve(self):
        for outcome in ('failure', 'skipped', 'cancelled', None):
            self.check['conclusion'] = outcome
            self.execute()
        self.check['conclusion'] = 'success';self.check['app']['id'] = 999
        self.execute()
        self.check['app']['id'] = shared.ACTIONS_APP_ID;self.check['head_sha'] = 'b' * 40
        self.execute()
        self.assertFalse(self.writes)
        self.assertFalse(self.merges)
        self.assertFalse(shared.ci_passed(HEAD, lambda *a, **kw: [dict(check_runs=[])], 'fixture-read-token'))

    def test_push_after_approval_cannot_arm_new_head(self):
        self.change_after_approval = True
        self.execute()
        self.assertEqual(self.writes[0]['commit_id'], HEAD)
        self.assertFalse(self.merges)

    def test_existing_exact_app_approval_is_idempotent(self):
        self.preapproved = True
        self.execute()
        self.assertFalse(self.writes)
        self.assertEqual(self.merges, [(7, HEAD)])

    def test_foreign_or_missing_reviewer_identity_refuses(self):
        for login, value in [('', {}), ('person', {}), ('fixture[bot]', dict(login='foreign[bot]', type='Bot', id=4))]:
            with self.assertRaises(shared.AutomationError):
                shared.reviewer_identity(lambda _: value, login)

    def test_weakened_controls_prevent_approval_and_merge(self):
        for phase in (1, 2):
            self.control_calls = 0;self.weaken_at = phase
            with self.assertRaises(shared.AutomationError):
                self.execute()
            self.assertFalse(self.writes)
            self.assertFalse(self.merges)

    def test_controls_changed_after_approval_prevent_merge(self):
        self.weaken_at = 3
        with self.assertRaises(shared.AutomationError):
            self.execute()
        self.assertEqual(self.writes[0]['commit_id'], HEAD)
        self.assertFalse(self.merges)


class EffectiveMergeControls(unittest.TestCase):
    def setUp(self):
        self.repository = dict(allow_squash_merge=True, allow_merge_commit=False, allow_rebase_merge=False,
                               allow_auto_merge=True, delete_branch_on_merge=True)
        self.rules = [dict(type=name) for name in ('required_linear_history', 'deletion', 'non_fast_forward')]
        self.rules += [dict(type='pull_request', parameters=dict(required_approving_review_count=1,
                       dismiss_stale_reviews_on_push=True, required_review_thread_resolution=True)),
                       dict(type='required_status_checks', parameters=dict(strict_required_status_checks_policy=True,
                       required_status_checks=[dict(context='ci-required', integration_id=shared.ACTIONS_APP_ID)]))]

    def test_complete_effective_controls_pass(self):
        from scripts.qualify_reviewer import verify_controls
        verify_controls(self.repository, self.rules)

    def test_weakened_settings_and_missing_or_wrong_app_rules_refuse(self):
        from scripts.qualify_reviewer import verify_controls
        for key in self.repository:
            changed = dict(self.repository);changed[key] = not changed[key]
            with self.assertRaises(shared.AutomationError):
                verify_controls(changed, self.rules)
        for index in range(len(self.rules)):
            with self.assertRaises(shared.AutomationError):
                verify_controls(self.repository, self.rules[:index] + self.rules[index+1:])
        changed = copy.deepcopy(self.rules)
        changed[-1]['parameters']['required_status_checks'][0]['integration_id'] = 999
        with self.assertRaises(shared.AutomationError):
            verify_controls(self.repository, changed)


class ImmutableFileEvidence(unittest.TestCase):
    def test_A_B_A_switch_cannot_substitute_ordinary_paths_for_protected_A(self):
        pr = pull();pr['user'] = dict(login='fixture-member', id=100, type='User')
        observed_paths = []
        mutable_head = [HEAD]
        def request(path):
            observed_paths.append(path)
            mutable_head[0] = 'b' * 40
            # The mutable PR now has ordinary B; immutable A still changes policy.
            if '/compare/' in path:
                self.assertTrue(path.endswith('c'*40 + '...' + HEAD))
                result = dict(base_commit=dict(sha='c'*40), files=[dict(filename='scripts/verify.py')])
            else:
                raise AssertionError('Mutable PR file endpoint must never be read')
            mutable_head[0] = HEAD
            return result
        base, files = policy.immutable_changed_files(pr, request)
        self.assertEqual(mutable_head[0], HEAD)
        self.assertFalse(policy.eligible(pr, run(), files, base_sha=base))
        self.assertEqual(len(observed_paths), 1)

    def test_missing_truncated_or_wrong_base_comparison_refuses(self):
        for observed in ({}, dict(base_commit=dict(sha='d'*40), files=[dict(filename='app.js')]),
                         dict(base_commit=dict(sha='c'*40), files=[])):
            with self.assertRaises(shared.AutomationError):
                other = pull();other['user'] = dict(login='fixture-member', id=100, type='User')
                policy.immutable_changed_files(other, lambda _: observed)
        for count in (300, 301):
            pr = pull();pr['changed_files'] = count
            pr['user'] = dict(login='fixture-member', id=100, type='User')
            with self.assertRaises(shared.AutomationError):
                policy.immutable_changed_files(pr, lambda _: self.fail('Boundary/over-limit comparison must not execute'))

    def test_owner_changes_do_not_depend_on_comparison_file_limits(self):
        for count in (1, 300, 301, 3001):
            pr = pull();pr['changed_files'] = count
            base, files = policy.immutable_changed_files(pr, lambda _: self.fail('Owner paths need no comparison'))
            self.assertTrue(policy.eligible(pr, run(), files, base_sha=base))
        for field in ('head', 'base'):
            pr = pull();pr[field]['sha'] = 'invalid'
            with self.assertRaises(shared.AutomationError):
                policy.immutable_changed_files(pr, lambda _: self.fail('Malformed revisions must refuse'))

    def test_base_change_invalidates_old_file_evidence(self):
        pr = pull();pr['base']['sha'] = 'd'*40
        self.assertFalse(policy.eligible(pr, run(), ['app.js'], base_sha='c'*40))


class ReadOnlyReadiness(unittest.TestCase):
    def setUp(self):
        self.event = dict(repository=dict(full_name=REPO, id=12345), workflow_run=dict(run(), event='push', head_branch='main'))
        self.repository = dict(full_name=REPO, id=12345, visibility='public', default_branch='main',
            allow_squash_merge=True, allow_merge_commit=False, allow_rebase_merge=False,
            allow_auto_merge=True, delete_branch_on_merge=True)
        self.rules = [dict(type=name) for name in ('required_linear_history', 'deletion', 'non_fast_forward')]
        self.rules += [dict(type='pull_request', parameters=dict(required_approving_review_count=1,
            dismiss_stale_reviews_on_push=True, required_review_thread_resolution=True)),
            dict(type='required_status_checks', parameters=dict(strict_required_status_checks_policy=True,
            required_status_checks=[dict(context='ci-required', integration_id=shared.ACTIONS_APP_ID)]))]
        self.scoped = dict(total_count=1, repositories=[dict(id=12345, full_name=REPO)])
        self.main = HEAD
        self.calls = []

    def request(self, path, **kwargs):
        self.assertNotIn('payload', kwargs)
        self.assertNotIn('method', kwargs)
        self.calls.append(path)
        if path == 'repos/' + REPO:
            return self.repository
        if path.endswith('/commits/main'):
            return dict(sha=self.main)
        if '/check-runs?' in path:
            return [dict(check_runs=[dict(name='ci-required', head_sha=HEAD, status='completed',
                conclusion='success', app=dict(id=shared.ACTIONS_APP_ID))])]
        if path == 'installation/repositories':
            return self.scoped
        if path.startswith('users/'):
            return dict(login='fixture-reviewer[bot]', id=400, type='Bot')
        if path.endswith('/rules/branches/main'):
            return self.rules
        raise AssertionError('Unexpected read: ' + path)

    def test_readiness_is_scoped_read_only_and_does_not_claim_runtime_canary(self):
        from scripts.qualify_reviewer import qualify
        result = qualify(self.event, 12345, self.request, 'fixture-reviewer[bot]', 'fixture-read-token')
        self.assertEqual(result['source_revision'], HEAD)
        self.assertEqual(result['status'], 'ready-for-ordinary-head-canary')
        self.assertIn('does not prove approval', result['limits'])
        self.assertTrue(self.calls)

    def test_other_repository_token_scope_and_stale_main_refuse(self):
        from scripts.qualify_reviewer import qualify
        self.scoped['total_count'] = 2
        with self.assertRaises(shared.AutomationError):
            qualify(self.event, 12345, self.request, 'fixture-reviewer[bot]', 'fixture-read-token')
        self.scoped['total_count'] = 1
        self.scoped['repositories'][0]['id'] = 999
        with self.assertRaises(shared.AutomationError):
            qualify(self.event, 12345, self.request, 'fixture-reviewer[bot]', 'fixture-read-token')
        self.scoped['repositories'][0]['id'] = 12345
        self.main = 'b' * 40
        with self.assertRaises(shared.AutomationError):
            qualify(self.event, 12345, self.request, 'fixture-reviewer[bot]', 'fixture-read-token')
