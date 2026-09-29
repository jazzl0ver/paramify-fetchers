#!/usr/bin/env python3
"""Every Splunk index with its retention, what happens to frozen data, and whether data integrity control is on."""

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parent / "_shared"))
from splunk_client import (  # noqa: E402
    as_bool,
    as_int,
    client_for,
    finish,
    iso,
    now_epoch,
    report_failure,
    target_from_env,
    write_evidence,
)

FETCHER = "splunk_index_retention"
logger = logging.getLogger(FETCHER)

# list_indexes reads properties/indexes and runs eventcount to prove the index list is complete.
REQUIRED_CAPABILITIES = ["search", "rest_properties_get"]
AUDIT_INDEX = "_audit"
SECONDS_PER_DAY = 86400


def retention_days(content):
    """frozenTimePeriodInSecs in whole days; 0 (freeze immediately) stays 0, an unreadable value is None."""
    seconds = as_int(content.get("frozenTimePeriodInSecs"))
    return None if seconds is None or seconds < 0 else seconds // SECONDS_PER_DAY


def archives_on_freeze(content):
    """Splunk deletes frozen buckets unless coldToFrozenDir or coldToFrozenScript archives them."""
    return any(str(content.get(k) or "").strip() for k in ("coldToFrozenDir", "coldToFrozenScript"))


def index_row(entry):
    c, name = entry["content"], entry["name"]
    disabled = as_bool(c.get("disabled"))
    return {
        "name": name,
        "datatype": c.get("datatype"),
        "enabled": None if disabled is None else not disabled,
        "internal": name.startswith("_"),
        "data_integrity_control": as_bool(c.get("enableDataIntegrityControl")),
        "retention_days": retention_days(c),
        "archives_on_freeze": archives_on_freeze(c),
        "cold_to_frozen_dir": c.get("coldToFrozenDir") or None,
        "max_total_size_mb": as_int(c.get("maxTotalDataSizeMB")),
        "app": (entry.get("acl") or {}).get("app"),
    }


def summarize(rows):
    retention = [r["retention_days"] for r in rows if r["retention_days"] is not None]
    return {
        "indexes_total": len(rows),
        "data_integrity_control_enabled": [r["name"] for r in rows if r["data_integrity_control"] is True],
        "data_integrity_control_disabled": [r["name"] for r in rows if r["data_integrity_control"] is False],
        "data_integrity_control_unreadable": [r["name"] for r in rows if r["data_integrity_control"] is None],
        "shortest_retention_days": min(retention) if retention else None,
        "indexes_archiving_on_freeze": [r["name"] for r in rows if r["archives_on_freeze"]],
        "audit_index": next((r for r in rows if r["name"] == AUDIT_INDEX), None),
    }


def main():
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    try:
        target = target_from_env()
    except ValueError as exc:
        report_failure(str(exc), "bad_config")
        return 1

    client = client_for(target)
    now = now_epoch()
    version = client.server_version()
    entries = client.list_indexes() if client.require_capabilities(REQUIRED_CAPABILITIES) else None
    rows = None if entries is None else [index_row(e) for e in sorted(entries, key=lambda e: e["name"])]

    evidence = {
        "metadata": {
            "collected_at": iso(now),
            "target": target["name"],
            "base_url": target["base_url"],
            "tls_verified": client.tls_verified,
            "splunk_version": version,
            **client.failure_metadata(),
        },
        "summary": summarize(rows) if rows is not None else {},
        "indexes": rows or [],
    }
    return finish(logger, write_evidence(FETCHER, target["name"], evidence), client)


if __name__ == "__main__":
    sys.exit(main())
