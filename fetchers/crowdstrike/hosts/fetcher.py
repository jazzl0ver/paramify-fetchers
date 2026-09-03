#!/usr/bin/env python3
"""
CrowdStrike Falcon Managed Hosts

Collects the managed host inventory — one record per endpoint running the
Falcon sensor — and summarizes agent coverage: platform mix, sensor versions,
reduced-functionality mode, and hosts that have stopped checking in.

Speaks to KSI-PIY-01 (asset inventory), KSI-CNA-07 (host security best
practices) and KSI-SVC-07 (risk-informed patching, via sensor version spread).
"""

import logging
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
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

logger = logging.getLogger("crowdstrike_hosts")

QUERY_PATH = "/devices/queries/devices-scroll/v1"
ENTITY_PATH = "/devices/entities/devices/v2"

DEFAULT_STALE_DAYS = 30


def parse_falcon_timestamp(value: Any) -> Any:
    """Falcon emits RFC3339 with a trailing Z; datetime wants +00:00."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def in_reduced_functionality_mode(record: Dict[str, Any]) -> bool:
    """
    A sensor in RFM is installed but not fully protecting the host, so it must
    not be counted as covered. Falcon spells the field "yes"/"no" rather than a
    bool, and omits it entirely on platforms that cannot enter RFM.
    """
    return str(record.get("reduced_functionality_mode", "")).strip().lower() in {"yes", "true", "1"}


def summarize(records: List[Dict[str, Any]], stale_days: int) -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=stale_days)

    stale_hosts: List[Dict[str, Any]] = []
    unknown_last_seen = 0
    for record in records:
        last_seen = parse_falcon_timestamp(record.get("last_seen"))
        if last_seen is None:
            unknown_last_seen += 1
            continue
        if last_seen < stale_cutoff:
            stale_hosts.append(
                {
                    "device_id": record.get("device_id"),
                    "hostname": record.get("hostname"),
                    "last_seen": record.get("last_seen"),
                    "platform_name": record.get("platform_name"),
                }
            )

    rfm_hosts = [r.get("device_id") for r in records if in_reduced_functionality_mode(r)]

    return {
        "total_hosts": len(records),
        "by_platform": dict(Counter(r.get("platform_name") or "unknown" for r in records)),
        "by_product_type": dict(Counter(r.get("product_type_desc") or "unknown" for r in records)),
        "by_os_version": dict(Counter(r.get("os_version") or "unknown" for r in records)),
        "by_sensor_version": dict(Counter(r.get("agent_version") or "unknown" for r in records)),
        "by_status": dict(Counter(r.get("status") or "unknown" for r in records)),
        "distinct_sensor_versions": len({r.get("agent_version") for r in records if r.get("agent_version")}),
        "reduced_functionality_mode_count": len(rfm_hosts),
        "reduced_functionality_mode_hosts": rfm_hosts,
        "stale_host_threshold_days": stale_days,
        "stale_host_count": len(stale_hosts),
        "stale_hosts": stale_hosts,
        "hosts_with_unknown_last_seen": unknown_last_seen,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    try:
        stale_days = int(os.environ.get("CROWDSTRIKE_STALE_HOST_DAYS", DEFAULT_STALE_DAYS))
    except ValueError:
        logger.warning("CROWDSTRIKE_STALE_HOST_DAYS is not an integer; using %s", DEFAULT_STALE_DAYS)
        stale_days = DEFAULT_STALE_DAYS

    device_ids = client.paginate_scroll(QUERY_PATH)
    records = client.get_entities(ENTITY_PATH, device_ids) if device_ids else []

    return evidence(
        client=client,
        # On an empty query no entity lookup happened, so the query path is the
        # honest endpoint to report.
        endpoint=ENTITY_PATH if device_ids else QUERY_PATH,
        records=records,
        analysis=summarize(records, stale_days),
        empty_message="No managed hosts returned",
        queried_id_count=len(device_ids),
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_hosts.json", logger))
