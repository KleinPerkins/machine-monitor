#!/usr/bin/env python3
"""Explicit local sensor qualification; excluded from all CI shards."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from temperatures import SMCTemperatures

if __name__ == '__main__':
    print(json.dumps(SMCTemperatures().read(), indent=2, allow_nan=False))
