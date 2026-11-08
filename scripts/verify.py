#!/usr/bin/env python3
"""Select the same bounded verification shards locally and in credential-free CI."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.processes import run_owned
from scripts.shard_contract import IDS, aggregate, contract, parse


def run_suite(files):
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in files:
        suite.addTests(loader.loadTestsFromName(name.removesuffix('.py').replace('/', '.')))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun < 1 or result.skipped:
        raise RuntimeError('failed, empty or skipped suite')
    return result.testsRun


def execute(identity, files, output):
    if identity in ('service', 'browser-layout', 'browser-lifecycle', 'native-app'):
        from scripts.toolchain import node
        os.environ['MONITOR_NODE'] = str(node())
    if identity == 'governance':
        from scripts.workflow_lint import lint
        lint(ROOT)
    if identity.startswith('browser-'):
        from tests.browser_support import run
        count = 0
        for name in files:
            destination = output / Path(name).stem
            destination.mkdir(parents=True, exist_ok=True)
            if name.startswith('tests/'):
                # Delivery UI wrappers own a separate synthetic HTTPS service.
                # Do not create an unrelated metrics collector for these tests.
                previous = os.environ.get('MONITOR_TEST_OUTPUT')
                os.environ['MONITOR_TEST_OUTPUT'] = str(destination)
                try:
                    count += run_suite([name])
                finally:
                    if previous is None:
                        os.environ.pop('MONITOR_TEST_OUTPUT', None)
                    else:
                        os.environ['MONITOR_TEST_OUTPUT'] = previous
            else:
                run(name, destination)
                count += 1
        return count
    if identity == 'native-app':
        from scripts.sparkle import distribution
        os.environ['MONITOR_SPARKLE_FRAMEWORK_DIR'] = str(distribution())
        from tests.build_fixture_app import build
        app = build(output / 'Machine Monitor Fixture Tests.app')
        os.environ['MONITOR_TEST_SERVICE'] = str(app / 'Contents/Resources/service/monitor-service')
        os.environ['MONITOR_TEST_APP'] = str(app)
        os.environ['MONITOR_TEST_OUTPUT'] = str(output)
    return run_suite(files)


def revision():
    import subprocess
    return subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()


def run_identity(explicit, *, aggregate_only=False):
    if explicit:
        value = explicit
    elif os.environ.get('GITHUB_RUN_ID') and os.environ.get('GITHUB_RUN_ATTEMPT'):
        value = 'github-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    elif aggregate_only:
        raise ValueError('Local aggregation requires --run-id; use all for one owned invocation')
    else:
        value = str(uuid.uuid4())
    if not re.fullmatch(r'[A-Za-z0-9-]{1,100}', value):
        raise ValueError('Invalid invocation identity')
    return value


def evidence(output, identity, run_id, current, digest):
    path = output / f'invocation-{identity}.json'
    value = parse(path.read_bytes())
    expected = dict(schema='machine-monitor/shard-invocation/v1', shard=identity,
                    run_id=run_id, revision=current, contract_sha256=digest)
    if value != expected:
        raise ValueError('Missing, stale or mixed shard invocation evidence')



def run_shard(identity, output, value, current, run_id):
    result = dict(schema='dev-test-shard-result/v1', shard=identity, revision=current,
                  contract_sha256=value['contract_sha256'], status='running', tests=0)
    report = output / f'result-{identity}.json'
    # Write non-success first. SIGKILL or a failed child cannot preserve old green evidence.
    report.write_text(json.dumps(result, indent=2) + '\n')
    invocation = dict(schema='machine-monitor/shard-invocation/v1', shard=identity,
                      run_id=run_id, revision=current, contract_sha256=value['contract_sha256'])
    (output / f'invocation-{identity}.json').write_text(json.dumps(invocation, indent=2) + '\n')
    result['status'] = 'failed'
    try:
        timeout = next(item['timeout_seconds'] for item in value['shards'] if item['id'] == identity)
        with tempfile.TemporaryDirectory(prefix=identity + '-', dir=output) as temporary:
            environment = dict(os.environ, MONITOR_OWNED_SHARD_GROUP='1')
            run_owned([sys.executable, __file__, identity, '--worker', '--output', temporary,
                       '--revision', current], timeout=timeout, env=environment)
            count = parse((Path(temporary) / 'worker-result.json').read_bytes())['tests']
            if type(count) is not int or count < 1:
                raise ValueError('Empty shard result')
            result['tests'] = count
            result['status'] = 'passed'
    finally:
        report.write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('shard', choices=(*IDS, 'all', 'aggregate'))
    parser.add_argument('--output', type=Path, default=ROOT / 'outputs')
    parser.add_argument('--revision')
    parser.add_argument('--run-id')
    parser.add_argument('--job-result')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    value = contract(ROOT)
    current = args.revision or revision()
    if not re.fullmatch(r'[0-9a-f]{40}', current):
        raise ValueError('Exact revision required')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.worker:
        if args.shard not in IDS or os.environ.get('MONITOR_OWNED_SHARD_GROUP') != '1':
            raise ValueError('Worker requires its bounded supervisor')
        files = next(item['tests'] for item in value['shards'] if item['id'] == args.shard)
        count = execute(args.shard, files, output)
        (output / 'worker-result.json').write_text(json.dumps({'tests': count}))
        return
    run_id = run_identity(args.run_id, aggregate_only=args.shard == 'aggregate')
    if args.shard == 'all':
        # Invalidate the previous complete set before any test is dispatched.
        for identity in IDS:
            for prefix in ('result-', 'invocation-'):
                (output / f'{prefix}{identity}.json').unlink(missing_ok=True)
        for identity in IDS:
            run_shard(identity, output, value, current, run_id)
        args.shard = 'aggregate'
    if args.shard == 'aggregate':
        if args.job_result is not None and args.job_result != 'success':
            raise RuntimeError('required matrix did not succeed: ' + args.job_result)
        for identity in IDS:
            evidence(output, identity, run_id, current, value['contract_sha256'])
        reports = [parse(path.read_bytes()) for path in sorted(output.glob('result-*.json'))]
        print(json.dumps(aggregate(value, reports, current), indent=2))
        return
    run_shard(args.shard, output, value, current, run_id)


if __name__ == '__main__':
    main()
