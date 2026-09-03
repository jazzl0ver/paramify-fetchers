#!/usr/bin/env python3
"""
CrowdStrike Zero Trust Assessment

Collects the tenant-wide ZTA audit report — CrowdStrike's own scoring of how
far managed endpoints meet its security-configuration baseline, broken out by
sensor and OS posture.

Speaks to KSI-CNA-07 (host and container security best practices), KSI-SVC-01
(harden and consistently configure services) and KSI-IAM-05 (zero-trust design
principles).

The audit endpoint takes no parameters and returns one record per CID, so this
is a single call for the whole tenant. Per-host scores are available behind
include_host_assessments but are off by default — see fetcher.yaml.
"""

import logging
import os
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))

from falcon_client import (  # type: ignore  # noqa: E402
    FalconAuthError,
    build_client,
    evidence,
    evidence_error,
    run_fetcher,
)

logger = logging.getLogger("crowdstrike_zero_trust_assessment")

AUDIT_PATH = "/zero-trust-assessment/entities/audit/v1"
HOST_QUERY_PATH = "/zero-trust-assessment/queries/assessments/v1"

DEFAULT_HOST_FILTER = "score:>=0"

# How many of the worst-scoring configuration signals to surface per platform.
LOWEST_SIGNALS = 5


def summarize_audit(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Summarize the tenant-wide ZTA audit report.

    Record shape, from CrowdStrike's own OpenAPI models (gofalcon
    `CommonCIDAuditResult` / `CommonOSAudit`):

        {"cid": str, "average_overall_score": float, "num_aids": int,
         "platforms": [{"name": str, "average_overall_score": float,
                        "num_aids": int, "audit": {signal_name: score}}]}

    Note `audit` is a MAP of signal name to score, not a list of findings —
    there is no per-signal remediation flag to count. The compliance-relevant
    reading is therefore "which configuration signals score worst", which is
    what `lowest_scoring_signals` surfaces.

    Records that match no known shape are reported in `unrecognized_records`
    rather than summarized as zeros. An empty analysis over a non-empty
    response would read as a clean result, which is the worst way for a
    schema change to fail in a compliance tool.
    """
    summary: Dict[str, Any] = {"cid_count": len(records), "by_cid": [], "unrecognized_records": 0}

    for record in records:
        platform_entries = record.get("platforms")
        if not isinstance(platform_entries, list):
            summary["unrecognized_records"] += 1
            continue

        platforms: List[Dict[str, Any]] = []
        for platform in platform_entries:
            if not isinstance(platform, dict):
                continue
            audit = platform.get("audit")
            signals = (
                {k: v for k, v in audit.items() if isinstance(v, (int, float))}
                if isinstance(audit, dict)
                else {}
            )
            ranked = sorted(signals.items(), key=lambda kv: kv[1])
            platforms.append(
                {
                    "name": platform.get("name"),
                    "average_overall_score": platform.get("average_overall_score"),
                    "num_aids": platform.get("num_aids"),
                    "signal_count": len(signals),
                    "lowest_scoring_signals": [
                        {"signal": name, "score": score} for name, score in ranked[:LOWEST_SIGNALS]
                    ],
                }
            )

        summary["by_cid"].append(
            {
                "cid": record.get("cid"),
                "average_overall_score": record.get("average_overall_score"),
                "num_aids": record.get("num_aids"),
                "platform_names": sorted(
                    str(p["name"]) for p in platforms if p.get("name") is not None
                ),
                "platforms": platforms,
            }
        )

    return summary


def summarize_hosts(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    # Bound with a walrus so the isinstance guard actually narrows the type.
    # Calling .get() twice reads as equivalent but leaves the element type
    # Optional, and the statistics calls below raise on a None that the guard
    # has in fact already excluded.
    scores = [
        score for r in records if isinstance(score := r.get("score"), (int, float))
    ]
    if not scores:
        return {"host_count": len(records), "scored_host_count": 0}

    return {
        "host_count": len(records),
        "scored_host_count": len(scores),
        "mean_score": round(statistics.fmean(scores), 2),
        "median_score": round(statistics.median(scores), 2),
        "min_score": min(scores),
        "max_score": max(scores),
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    audit_body = client.request("GET", AUDIT_PATH)
    audit_records = (audit_body or {}).get("resources") or []

    # Unlike the other fetchers in this category, `data` here is a dict rather
    # than a list: the audit report and the optional per-host assessments are
    # two different shapes from two different endpoints, and flattening them
    # into one list would lose which is which. evidence() takes the override.
    data: Dict[str, Any] = {"audit": audit_records}
    analysis: Dict[str, Any] = {"audit": summarize_audit(audit_records)}
    extra: Dict[str, Any] = {}

    if os.environ.get("CROWDSTRIKE_ZTA_INCLUDE_HOSTS", "false").strip().lower() == "true":
        host_filter = os.environ.get("CROWDSTRIKE_ZTA_HOST_FILTER", "").strip() or DEFAULT_HOST_FILTER
        host_records = client.paginate_after(HOST_QUERY_PATH, params={"filter": host_filter})
        data["host_assessments"] = host_records
        analysis["host_assessments"] = summarize_hosts(host_records)
        extra["host_assessment_filter"] = host_filter

    return evidence(
        client=client,
        endpoint=AUDIT_PATH,
        # The audit report drives record_count and status; the host assessments
        # are supplementary and opt-in.
        records=audit_records,
        analysis=analysis,
        empty_message="Zero Trust Assessment audit report returned no records",
        data=data,
        **extra,
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_zero_trust_assessment.json", logger))
