#!/usr/bin/env python3
"""
CrowdStrike Prevention Policies

Collects Falcon prevention policies with their full setting trees and host-group
assignments. This is the configuration half of the endpoint story: hosts.json
shows the agent is installed, this shows what the agent is enforcing.

Speaks to KSI-SVC-01 (harden and consistently configure services), KSI-SVC-04
(centrally manage and enforce configuration), KSI-CNA-07 (host and container
best practices) and KSI-CMT-02 (detect and control configuration drift).

A policy that is disabled, or enabled but assigned to no host groups, enforces
nothing — both are called out in the summary because neither is visible from a
policy count alone.
"""

import logging
import sys
from collections import Counter
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

logger = logging.getLogger("crowdstrike_prevention_policies")

COMBINED_PATH = "/policy/combined/prevention/v1"


def classify_setting(setting: Dict[str, Any]) -> tuple:
    """
    Falcon prevention settings carry a `value` whose shape depends on type:
    a toggle is {"enabled": bool}; an mlslider is
    {"detection": "...", "prevention": "..."} where "DISABLED" means off.

    Returns (is_enabled, levels). A slider counts as enabled when any level is
    off DISABLED, but the levels are returned alongside because
    detection-without-prevention is a materially different posture from full
    prevention and a bare boolean would hide that.
    """
    value = setting.get("value")

    if isinstance(value, dict):
        if "enabled" in value:
            return bool(value["enabled"]), None
        levels = {k: v for k, v in value.items() if isinstance(v, str)}
        if levels:
            active = any(str(v).strip().upper() not in {"DISABLED", ""} for v in levels.values())
            return active, levels

    return bool(value), None


def flatten_settings(policy: Dict[str, Any]) -> Dict[str, Any]:
    enabled: List[str] = []
    disabled: List[str] = []
    slider_levels: Dict[str, Any] = {}
    detection_only: List[str] = []

    for group in policy.get("prevention_settings") or []:
        for setting in group.get("settings") or []:
            label = f"{group.get('name', 'unknown')}.{setting.get('name', 'unknown')}"
            is_enabled, levels = classify_setting(setting)
            (enabled if is_enabled else disabled).append(label)

            if levels:
                slider_levels[label] = levels
                prevention = str(levels.get("prevention", "")).strip().upper()
                if is_enabled and prevention in {"DISABLED", ""}:
                    detection_only.append(label)

    return {
        "enabled_settings": enabled,
        "disabled_settings": disabled,
        "enabled_setting_count": len(enabled),
        "total_setting_count": len(enabled) + len(disabled),
        "slider_levels": slider_levels,
        "detection_only_settings": detection_only,
    }


def summarize(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    per_policy = []
    unassigned = []
    enabled_count = 0

    for policy in records:
        settings = flatten_settings(policy)
        groups = policy.get("groups") or []
        is_enabled = bool(policy.get("enabled"))
        if is_enabled:
            enabled_count += 1
        if is_enabled and not groups:
            unassigned.append({"id": policy.get("id"), "name": policy.get("name")})

        per_policy.append(
            {
                "id": policy.get("id"),
                "name": policy.get("name"),
                "platform_name": policy.get("platform_name"),
                "enabled": is_enabled,
                "host_group_count": len(groups),
                "host_groups": [g.get("name") for g in groups],
                **settings,
            }
        )

    return {
        "total_policies": len(records),
        "enabled_policies": enabled_count,
        "disabled_policies": len(records) - enabled_count,
        "by_platform": dict(Counter((p.get("platform_name") or "unknown") for p in records)),
        "enabled_but_unassigned_count": len(unassigned),
        "enabled_but_unassigned": unassigned,
        "policies_with_detection_only_settings": [
            p["name"] for p in per_policy if p.get("detection_only_settings")
        ],
        "policies": per_policy,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    records = client.paginate_offset(COMBINED_PATH, limit=100)

    return evidence(
        client=client,
        endpoint=COMBINED_PATH,
        records=records,
        analysis=summarize(records),
        empty_message="No prevention policies returned",
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_prevention_policies.json", logger))
