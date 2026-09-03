#!/usr/bin/env python3
"""
CrowdStrike Falcon Detections

Collects detection alerts raised over a lookback window and summarizes them by
severity, workflow status, MITRE tactic/technique, and time-to-resolution.

Speaks to KSI-MLA-01 (centralized logging), KSI-MLA-02 (regularly review and
audit logs — the status mix is what shows alerts are actually being worked) and
KSI-CNA-07 (host security best practices).

Uses the Alerts API (/alerts/*), which supersedes the legacy /detects/*
endpoints. Alerts are keyed by composite ID, not the plain resource ID used
elsewhere in Falcon.
"""

import logging
import os
import statistics
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

logger = logging.getLogger("crowdstrike_detections")

QUERY_PATH = "/alerts/queries/alerts/v2"
ENTITY_PATH = "/alerts/entities/alerts/v2"

# Alerts are keyed by composite ID (`<cid>:ind:<id>`), not the plain resource id
# used elsewhere in Falcon, and this endpoint's body key differs to match. The
# wrong key returns an empty result rather than an error, so every alert would
# quietly vanish from the evidence. Named rather than inlined so a test can
# assert it against CrowdStrike's request model.
ENTITY_BODY_KEY = "composite_ids"

DEFAULT_LOOKBACK_DAYS = 30


def parse_falcon_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def build_filter() -> str:
    explicit = os.environ.get("CROWDSTRIKE_DETECTION_FILTER", "").strip()
    if explicit:
        return explicit

    try:
        lookback = int(os.environ.get("CROWDSTRIKE_DETECTION_LOOKBACK_DAYS", DEFAULT_LOOKBACK_DAYS))
    except ValueError:
        logger.warning(
            "CROWDSTRIKE_DETECTION_LOOKBACK_DAYS is not an integer; using %s", DEFAULT_LOOKBACK_DAYS
        )
        lookback = DEFAULT_LOOKBACK_DAYS

    since = datetime.now(timezone.utc) - timedelta(days=lookback)
    return f"created_timestamp:>'{since.strftime('%Y-%m-%dT%H:%M:%SZ')}'"


# Only these mean the alert is finished. "reopened" explicitly does not: an
# alert that was closed and reopened is open work again, and counting it as
# resolved would both overstate the resolved count and pollute the timing with
# the gap before it was reopened.
RESOLVED_STATUSES = {"closed", "resolved"}

# Falcon carries severity twice: `severity_name` (a label) and `severity`
# (0-100). Real responses frequently populate only the number — every EPP alert
# in the recorded samples had `severity: 30` and no name — so bucketing on the
# label alone files most of a real tenant's alerts as "unknown". Bands are
# CrowdStrike's documented ones.
SEVERITY_BANDS = ((20, "Informational"), (40, "Low"), (70, "Medium"), (90, "High"))
SEVERITY_CRITICAL = "Critical"


def severity_label(record: Dict[str, Any]) -> str:
    """
    Prefer the label Falcon supplied; fall back to banding the numeric score.

    Never overrides a present `severity_name` — the recorded samples contain an
    alert whose label disagrees with its own number, and the vendor's label is
    what a reviewer sees in the Falcon console.
    """
    name = record.get("severity_name")
    if isinstance(name, str) and name.strip():
        return name.strip()

    score = record.get("severity")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
        for ceiling, label in SEVERITY_BANDS:
            if score < ceiling:
                return label
        return SEVERITY_CRITICAL

    return "unknown"


def count_normalized(records: List[Dict[str, Any]], field: str) -> Dict[str, int]:
    """
    Count a label field, merging spelling variants of the same value.

    Real Falcon data returns both "Credential Access" and "CredentialAccess"
    for one tactic, which a raw Counter reports as two tactics and halves each
    count. Values are keyed on a space-, punctuation- and case-insensitive
    form; the label shown is the most readable variant seen (the one with the
    most word breaks), so the evidence stays human-legible.
    """
    counts: Counter = Counter()
    labels: Dict[str, str] = {}

    for record in records:
        raw = record.get(field)
        value = raw.strip() if isinstance(raw, str) and raw.strip() else "unknown"
        key = value.replace(" ", "").replace("-", "").replace("_", "").casefold()
        counts[key] += 1
        best = labels.get(key)
        if best is None or value.count(" ") > best.count(" "):
            labels[key] = value

    return {labels[key]: count for key, count in counts.items()}


def resolution_hours(record: Dict[str, Any]) -> Optional[float]:
    """
    Approximate time-to-resolution as created → last-updated.

    Falcon does not expose a dedicated resolved-at timestamp on the alert, so
    this is the closest available proxy and is only computed for alerts in a
    terminal state. It is an upper bound: any edit after closure (a tag, an
    assignment) also moves updated_timestamp.
    """
    if str(record.get("status", "")).lower() not in RESOLVED_STATUSES:
        return None

    created = parse_falcon_timestamp(record.get("created_timestamp"))
    updated = parse_falcon_timestamp(record.get("updated_timestamp"))
    if created is None or updated is None:
        return None

    delta = (updated - created).total_seconds() / 3600.0
    return round(delta, 2) if delta >= 0 else None


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    resolution_times = [h for h in (resolution_hours(r) for r in records) if h is not None]

    # Counted from status, not from how many produced a usable duration — an
    # alert with an unparseable timestamp is still resolved, and deriving the
    # count from the timings would quietly report it as outstanding work.
    resolved_count = sum(
        1 for r in records if str(r.get("status", "")).lower() in RESOLVED_STATUSES
    )

    affected_hosts = {r.get("device_id") or (r.get("device") or {}).get("device_id") for r in records}
    affected_hosts.discard(None)

    return {
        "total_detections": len(records),
        "by_severity": dict(Counter(severity_label(r) for r in records)),
        "by_status": dict(Counter((r.get("status") or "unknown") for r in records)),
        "by_tactic": count_normalized(records, "tactic"),
        "by_technique": count_normalized(records, "technique"),
        "by_product": dict(Counter((r.get("product") or "unknown") for r in records)),
        "affected_host_count": len(affected_hosts),
        "resolved_count": resolved_count,
        "unresolved_count": len(records) - resolved_count,
        "timed_resolution_sample": len(resolution_times),
        "mean_time_to_resolution_hours": (
            round(statistics.fmean(resolution_times), 2) if resolution_times else None
        ),
        "median_time_to_resolution_hours": (
            round(statistics.median(resolution_times), 2) if resolution_times else None
        ),
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    alert_filter = build_filter()

    composite_ids = client.paginate_offset(QUERY_PATH, params={"filter": alert_filter})
    records = (
        client.get_entities(ENTITY_PATH, composite_ids, body_key=ENTITY_BODY_KEY)
        if composite_ids
        else []
    )

    return evidence(
        client=client,
        endpoint=ENTITY_PATH if composite_ids else QUERY_PATH,
        records=records,
        analysis=summarize(records),
        empty_message="No detections returned for the configured window",
        filter=alert_filter,
        queried_id_count=len(composite_ids),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_detections.json", logger))
