#!/usr/bin/env python3
"""
CrowdStrike Falcon FileVantage (file integrity monitoring)

Collects file integrity changes recorded over a lookback window and summarizes
them by action type, monitored entity, policy, host and severity.

Speaks to KSI-CMT-01 (log and monitor system modifications — the statement this
evidence matches most directly), KSI-CMT-02 (detect and control configuration
drift) and KSI-SVC-04 (centrally manage and enforce configuration, via the
policy governing each recorded change).

Deliberately NOT claimed: KSI-SVC-05 (enforce data integrity using
cryptography). A `ChangesDiffHash` model carrying `sha256` does exist in
FileVantage's schema, but it hangs off `ChangesDiffType` and is **not reachable
from `ChangesChange`** — the change record's own `diff` resolves to
`ChangesDiff` → `ChangesAfter`, which is `{id, name}` and no digest. So the
records this fetcher collects evidence modification *monitoring*, not
cryptographic integrity verification, and claiming the latter would overstate
what is in the file.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from falcon_client import (  # type: ignore  # noqa: E402
    FalconAuthError,
    build_client,
    evidence,
    evidence_error,
    run_fetcher,
)

logger = logging.getLogger("crowdstrike_filevantage")

QUERY_PATH = "/filevantage/queries/changes/v3"
ENTITY_PATH = "/filevantage/entities/changes/v2"

# v3 is the high-volume query: an `after` cursor rather than the numeric offset
# v2 uses. An offset walk over a busy estate re-reads shifting pages; the cursor
# does not. v2 remains in the SDK and is the wrong choice here.
QUERY_PAGE_SIZE = 5000

# Unlike the host and alert entity lookups, this one is a GET taking its IDs as
# repeated query parameters, and it accepts 500 per call rather than the 100 the
# other endpoints cap at. Both numbers come from the endpoint's own parameter
# spec — sending 5000 because the query returned that many would be a 400.
ENTITY_BATCH_SIZE = 500

DEFAULT_LOOKBACK_DAYS = 30

# Changes that alter who may execute or read a file are the ones a reviewer
# cares about first; a plain content edit to a monitored file is ordinary.
ELEVATED_ACTION_TYPES = {"PermissionsChange", "OwnershipChange", "Deleted", "Renamed"}


def parse_falcon_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def lookback_filter(days: int) -> str:
    """
    FQL restricting the query to a recent window.

    `action_timestamp` is one of the two filter fields FileVantage's own
    parameter documentation names (`host.name` is the other); the rest of the
    legal set is not enumerated publicly, so nothing else is filtered on here.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return f"action_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"


def summarize(records: List[Dict[str, Any]], lookback_days: int) -> Dict[str, Any]:
    """
    Reduce the raw changes to the shape a reviewer reads first.

    Counts are over records actually returned. A record that does not match the
    documented shape is counted in `unrecognized_records` rather than being
    summarized as a zero — an empty summary over a valid response is the failure
    mode that made the Zero Trust fetcher report a silent all-clear.
    """
    action_types: Counter = Counter()
    entity_types: Counter = Counter()
    policies: Counter = Counter()
    hosts: Counter = Counter()
    severities: Counter = Counter()
    suppressed = 0
    elevated = 0
    unrecognized = 0
    earliest: Optional[datetime] = None
    latest: Optional[datetime] = None

    for record in records:
        if not isinstance(record, dict) or "action_type" not in record:
            unrecognized += 1
            continue

        action = record.get("action_type") or "unknown"
        action_types[action] += 1
        if action in ELEVATED_ACTION_TYPES:
            elevated += 1

        entity_types[record.get("entity_type") or "unknown"] += 1
        severities[record.get("severity") or "unspecified"] += 1

        if record.get("is_suppressed"):
            suppressed += 1

        policy = record.get("policy")
        if isinstance(policy, dict):
            policies[policy.get("name") or "unnamed"] += 1

        host = record.get("host")
        if isinstance(host, dict):
            hosts[host.get("name") or "unnamed"] += 1

        stamp = parse_falcon_timestamp(record.get("action_timestamp"))
        if stamp is not None:
            earliest = stamp if earliest is None else min(earliest, stamp)
            latest = stamp if latest is None else max(latest, stamp)

    return {
        "lookback_days": lookback_days,
        "total_changes": len(records),
        "unrecognized_records": unrecognized,
        "hosts_reporting_changes": len(hosts),
        "policies_in_effect": len(policies),
        # A monitored estate that recorded nothing is materially different from
        # one that was never monitored, and the two are indistinguishable from
        # the count alone. The reviewer is told which this is.
        "recorded_no_changes_in_window": len(records) == 0,
        "suppressed_changes": suppressed,
        "elevated_changes": elevated,
        "changes_by_action_type": dict(action_types.most_common()),
        "changes_by_entity_type": dict(entity_types.most_common()),
        "changes_by_severity": dict(severities.most_common()),
        "top_policies": dict(policies.most_common(10)),
        "top_hosts": dict(hosts.most_common(10)),
        "earliest_change": earliest.isoformat() if earliest else None,
        "latest_change": latest.isoformat() if latest else None,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    try:
        lookback_days = int(os.environ.get("CROWDSTRIKE_FILEVANTAGE_LOOKBACK_DAYS", DEFAULT_LOOKBACK_DAYS))
    except ValueError:
        logger.warning(
            "CROWDSTRIKE_FILEVANTAGE_LOOKBACK_DAYS is not an integer; using %s",
            DEFAULT_LOOKBACK_DAYS,
        )
        lookback_days = DEFAULT_LOOKBACK_DAYS

    change_ids = client.paginate_after(
        QUERY_PATH,
        params={"filter": lookback_filter(lookback_days), "sort": "action_timestamp|desc"},
        limit=QUERY_PAGE_SIZE,
    )

    # No changes is a legitimate result for a quiet estate, not an error — but
    # evidence() reports it as partial_or_empty so it is never mistaken for a
    # collection that returned data.
    records = (
        client.get_entities(
            ENTITY_PATH,
            change_ids,
            method="GET",
            batch_size=ENTITY_BATCH_SIZE,
        )
        if change_ids
        else []
    )

    return evidence(
        client=client,
        endpoint=ENTITY_PATH if change_ids else QUERY_PATH,
        records=records,
        analysis=summarize(records, lookback_days),
        empty_message=f"No file integrity changes recorded in the last {lookback_days} days",
        queried_id_count=len(change_ids),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_filevantage.json", logger))
