#!/usr/bin/env python3
"""
Check every field the CrowdStrike fetchers read against CrowdStrike's own
published API schema.

Why this exists
---------------
These fetchers were written without access to a Falcon tenant, so the response
field names started life as educated guesses. A hand-written test double cannot
catch a wrong guess, because the double is built from the same guess — the
fetcher and the fixture agree with each other and both disagree with reality.
That is not hypothetical: the Zero Trust Assessment fetcher read a nested list
of findings where the API actually returns a map of signal name to score, and
every test passed while the real analysis would have come back empty.

The fix is an *independent* source of truth. CrowdStrike publishes one:
gofalcon, their official Go SDK, whose model structs are generated from the
same OpenAPI specification that serves the API. The `json:"..."` struct tags
are therefore the real wire field names, straight from the vendor.

    https://github.com/CrowdStrike/gofalcon/tree/main/falcon/models

Usage
-----
    python tools/crowdstrike_schema_check.py            # check against the snapshot
    python tools/crowdstrike_schema_check.py --refresh  # re-download, rewrite snapshot

The snapshot (`crowdstrike_schema_snapshot.json`, beside this file) is what the
test suite reads, so CI stays offline. Refresh it when CrowdStrike ships API
changes, and review the diff — a field disappearing is a real signal.

Only field *names* are stored. Those are interface facts, not authorship.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, Set

RAW_BASE = "https://raw.githubusercontent.com/CrowdStrike/gofalcon/main/falcon/models"

SNAPSHOT_PATH = Path(__file__).resolve().parent / "crowdstrike_schema_snapshot.json"

# Which gofalcon models describe the responses each fetcher parses. A fetcher
# may read several nested objects, so each entry lists every model involved.
FETCHER_MODELS: Dict[str, List[str]] = {
    "hosts": [
        "deviceapi_device_swagger",
    ],
    "spotlight_vulnerabilities": [
        "domain_api_vulnerability_v2",
        "domain_api_vulnerability_c_v_e_details_facet_v2",
        "domain_api_vulnerability_host_facet_v2",
        "domain_api_vulnerability_remediation_facet_v2",
    ],
    "detections": [
        "detects_alert",
    ],
    "prevention_policies": [
        "prevention_policy_v1",
        "prevention_category_resp_v1",
        "prevention_setting_resp_v1",
    ],
    "zero_trust_assessment": [
        "common_c_id_audit_result",
        "common_o_s_audit",
    ],
    # Kept separate from the audit: a different endpoint returning a different
    # shape. Merging the two hid the fact that the host summary had never been
    # checked against anything.
    "zero_trust_assessment_hosts": [
        "domain_zero_trust_simple_assessment",
    ],
    # The firewall fetcher reads four shapes across two API families. Kept as
    # four entries rather than one flat list for the same reason the Zero Trust
    # host scores were split out: merged, a name that exists on one model looks
    # like proof for a different model that never had it.
    "firewall_policies": [
        "firewall_policy_v1",
        "host_groups_host_group_v1",
    ],
    "firewall_policy_containers": [
        "fwmgr_firewall_policy_container_v1",
    ],
    "firewall_rule_groups": [
        "fwmgr_api_rule_group_v1",
    ],
    "firewall_rules": [
        "fwmgr_firewall_rule_v1",
        "fwmgr_firewall_address_range",
        "fwmgr_firewall_port_range",
        "fwmgr_firewall_monitoring",
        "fwmgr_firewall_rule_group_summary_v1",
    ],
    "filevantage": [
        "changes_change",
        "changes_host",
        "changes_host_group",
        "changes_policy",
        "changes_policy_rule_group",
        "changes_attribute",
        "changes_diff",
    ],
}

JSON_TAG = re.compile(r'json:"([^",]+)')


def fetch_model_fields(model: str) -> Set[str]:
    """Return the wire field names declared by one gofalcon model, or an empty
    set if that model does not exist (names drift between SDK releases)."""
    url = f"{RAW_BASE}/{model}.go"
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            if response.status != 200:
                return set()
            source = response.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - a missing model is data, not a crash
        print(f"  ! could not fetch {model}: {e}", file=sys.stderr)
        return set()

    return {tag for tag in JSON_TAG.findall(source) if tag != "-"}


def build_snapshot() -> Dict[str, Dict[str, List[str]]]:
    snapshot: Dict[str, Dict[str, List[str]]] = {}
    for fetcher, models in FETCHER_MODELS.items():
        print(f"{fetcher}:")
        per_model: Dict[str, List[str]] = {}
        for model in models:
            fields = fetch_model_fields(model)
            print(f"  {model}: {len(fields)} fields")
            per_model[model] = sorted(fields)
        snapshot[fetcher] = per_model
    return snapshot


def known_fields(snapshot: Dict[str, Dict[str, List[str]]], fetcher: str) -> Set[str]:
    """Every field name the vendor schema declares anywhere in this fetcher's
    models. Deliberately flat: it answers "does this name exist in the API at
    all", not "is it at this nesting depth", which is as much as a name-level
    check can honestly claim."""
    out: Set[str] = set()
    for fields in snapshot.get(fetcher, {}).values():
        out.update(fields)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--refresh", action="store_true", help="re-download models and rewrite the snapshot"
    )
    args = parser.parse_args()

    if args.refresh:
        snapshot = build_snapshot()
        SNAPSHOT_PATH.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
        print(f"\nWrote {SNAPSHOT_PATH}")
        return 0

    if not SNAPSHOT_PATH.exists():
        print(f"No snapshot at {SNAPSHOT_PATH}. Run with --refresh first.", file=sys.stderr)
        return 1

    snapshot = json.loads(SNAPSHOT_PATH.read_text())
    for fetcher in sorted(FETCHER_MODELS):
        fields = known_fields(snapshot, fetcher)
        print(f"{fetcher}: {len(fields)} known field names from {len(snapshot.get(fetcher, {}))} models")
    return 0


if __name__ == "__main__":
    sys.exit(main())
