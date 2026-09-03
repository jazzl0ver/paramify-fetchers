#!/usr/bin/env python3
"""
CrowdStrike Spotlight Vulnerabilities

Collects open vulnerability findings from Falcon Spotlight and summarizes them
by severity, ExPRT rating, exploit status, remediation availability and age.

Speaks to KSI-MLA-03 (detect and remediate vulnerabilities), KSI-MLA-06
(centrally track vulnerabilities), KSI-SVC-07 (risk-informed patching) and
KSI-TPR-04 (upstream third-party vulnerabilities).

Spotlight is a separately licensed Falcon module. A tenant without it returns
403 with a scope error, which lands in api_failures and exits non-zero — a
licensing gap is a real collection failure, not something to paper over.
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timezone
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

logger = logging.getLogger("crowdstrike_spotlight_vulnerabilities")

COMBINED_PATH = "/spotlight/combined/vulnerabilities/v1"

DEFAULT_FILTER = "status:['open','reopen']"
# Facets pull the CVE, host and remediation detail into the same response, so
# the summary needs no follow-up calls.
FACETS = ["cve", "host_info", "remediation"]
OLDEST_SAMPLE_SIZE = 25


def parse_falcon_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def open_age_days(record: Dict[str, Any], now: datetime) -> Optional[int]:
    created = parse_falcon_timestamp(record.get("created_timestamp"))
    if created is None:
        return None
    return (now - created).days


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)

    severities: Counter = Counter()
    exprt_ratings: Counter = Counter()
    statuses: Counter = Counter()
    exploit_status: Counter = Counter()
    with_remediation = 0
    aged: List[Dict[str, Any]] = []

    for record in records:
        cve = record.get("cve") or {}
        severities[(cve.get("severity") or "UNKNOWN").upper()] += 1
        exprt_ratings[(cve.get("exprt_rating") or "UNKNOWN").upper()] += 1
        statuses[record.get("status") or "unknown"] += 1

        # exploit_status is an int score in the Spotlight schema; presence of a
        # non-zero value means a known exploit exists.
        raw_exploit = cve.get("exploit_status")
        exploit_status["known_exploit" if raw_exploit else "no_known_exploit"] += 1

        remediation = record.get("remediation") or {}
        if remediation.get("entities"):
            with_remediation += 1

        age = open_age_days(record, now)
        if age is not None:
            aged.append(
                {
                    "id": record.get("id"),
                    "cve_id": cve.get("id"),
                    "severity": cve.get("severity"),
                    "open_days": age,
                    "hostname": (record.get("host_info") or {}).get("hostname"),
                    "status": record.get("status"),
                }
            )

    aged.sort(key=lambda item: item["open_days"], reverse=True)
    affected_hosts = {
        (r.get("host_info") or {}).get("host_id") or (r.get("host_info") or {}).get("hostname")
        for r in records
    }
    affected_hosts.discard(None)

    return {
        "total_findings": len(records),
        "by_severity": dict(severities),
        "by_exprt_rating": dict(exprt_ratings),
        "by_status": dict(statuses),
        "by_exploit_status": dict(exploit_status),
        "findings_with_remediation_available": with_remediation,
        "distinct_cves": len({(r.get("cve") or {}).get("id") for r in records if (r.get("cve") or {}).get("id")}),
        "affected_host_count": len(affected_hosts),
        "oldest_open_days": aged[0]["open_days"] if aged else None,
        "oldest_findings": aged[:OLDEST_SAMPLE_SIZE],
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    vuln_filter = os.environ.get("CROWDSTRIKE_VULN_FILTER", "").strip() or DEFAULT_FILTER
    include_raw = os.environ.get("CROWDSTRIKE_VULN_INCLUDE_RAW", "true").strip().lower() != "false"

    records = client.paginate_after(
        COMBINED_PATH,
        params={"filter": vuln_filter, "facet": FACETS},
    )

    return evidence(
        client=client,
        endpoint=COMBINED_PATH,
        records=records,
        analysis=summarize(records),
        empty_message="No vulnerability findings returned for the configured filter",
        filter=vuln_filter,
        # `record_count` stays the true finding count even when the raw records
        # are suppressed — a large estate can drop the payload without the
        # evidence claiming it found nothing.
        data=records if include_raw else [],
        raw_findings_included=include_raw,
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_spotlight_vulnerabilities.json", logger))
