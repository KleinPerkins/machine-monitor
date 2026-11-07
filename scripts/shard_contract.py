"""Repository-local shard validation. Commands are declared, never executed here."""
import hashlib
import json
from pathlib import Path
import re

IDS = ('governance', 'core', 'service', 'browser-layout', 'browser-lifecycle', 'native-app')
MANIFEST = '.github/test-shards.json'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(data):
    return json.loads(data, object_pairs_hook=unique)


def closed(value, keys):
    require(isinstance(value, dict) and set(value) == set(keys.split()), 'unknown or missing fields')


def contract(root):
    root = Path(root)
    raw = (root / MANIFEST).read_bytes()
    value = parse(raw)
    closed(value, 'schema state aggregate discovery shards')
    require(value['schema'] == 'dev-test-sharding/v1' and value['state'] == 'configured', 'verification is pending')
    require(value['aggregate'] == 'ci-required', 'aggregate must be ci-required')
    require(value['discovery'] == {'include': ['test_*.py', 'tests/**/test_*.py'], 'exclude': []}, 'test discovery changed')
    require(isinstance(value['shards'], list) and len(value['shards']) == len(IDS), 'all six shards required')
    discovered = set()
    for pattern in value['discovery']['include']:
        for path in root.glob(pattern):
            require(not path.is_symlink(), 'symlinked test')
            if path.is_file():
                discovered.add(path.relative_to(root).as_posix())
    ids, assigned = set(), set()
    for shard in value['shards']:
        closed(shard, 'id tests command timeout_seconds')
        identity = shard['id']
        require(identity in IDS and identity not in ids, 'unknown or duplicate shard')
        ids.add(identity)
        require(shard['command'] == ['python3', 'scripts/verify.py', identity], 'missing or unknown command')
        require(type(shard['timeout_seconds']) is int and 1 <= shard['timeout_seconds'] <= 1800, 'invalid timeout')
        require(isinstance(shard['tests'], list) and shard['tests'], 'empty shard')
        for name in shard['tests']:
            require(isinstance(name, str) and name in discovered, 'unknown test')
            path = root / name
            require(not any(part in ('.', '..', '') for part in name.split('/')) and not path.is_symlink(), 'unsafe test')
            require(name not in assigned, 'duplicate assignment')
            assigned.add(name)
    require(assigned == discovered and discovered, 'unassigned tests')
    return dict(value, contract_sha256=hashlib.sha256(raw).hexdigest())


def aggregate(value, reports, revision):
    require(isinstance(revision, str) and re.fullmatch('[0-9a-f]{40}', revision), 'exact revision required')
    require(isinstance(reports, list) and len(reports) == len(IDS), 'missing shard result')
    seen = set()
    for result in reports:
        closed(result, 'schema shard revision contract_sha256 status tests')
        require(result['schema'] == 'dev-test-shard-result/v1', 'invalid result')
        require(result['shard'] in IDS and result['shard'] not in seen, 'unknown or duplicate result')
        seen.add(result['shard'])
        require(result['revision'] == revision and result['contract_sha256'] == value['contract_sha256'], 'stale result')
        require(result['status'] == 'passed', 'failed, cancelled or skipped shard')
        require(type(result['tests']) is int and result['tests'] > 0, 'empty test report')
    return {'status': 'passed', 'shards': sorted(seen), 'revision': revision}
