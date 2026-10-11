"""Shared external-target catalogue policy; never executes template code."""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'security/catalog-scope.json').read_text(encoding='utf-8'))


def exclusion_reason(rel, text, doc=None):
    for prefix, reason in POLICY['excluded_prefixes'].items():
        if rel.startswith(prefix):
            return reason
    if (doc is not None and doc.get('self-contained') is True) or re.search(
        r'(?m)^self-contained:\s*true\s*(?:#.*)?$', text
    ):
        return 'self-contained: check is not bound to the selected external target'
    if re.search(r'(?m)^file:\s*(?:#.*)?$', text):
        return 'file protocol: scans files on the runner'
    return None
