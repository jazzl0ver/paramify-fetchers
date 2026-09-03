#!/usr/bin/env python3
"""
CrowdStrike Falcon Firewall Policies

Collects host firewall policies, the policy containers that say whether each one
is actually enforced, the rule groups attached to them, and the individual rules.

Speaks to KSI-CNA-RNT (machine-based information resources are persistently
reviewed to ensure they are appropriately configured to limit inbound and
outbound network traffic — this evidence is close to a restatement of it) and
KSI-CNA-MAT (minimal attack surface, lateral movement minimized if compromised).
Both are CR26 mnemonic IDs; the `ksis:` field in fetcher.yaml carries the
repo's pre-CR26 numbered equivalents until the repo standardizes on one catalog.

Why four calls instead of one
-----------------------------
`/policy/combined/firewall/v1` returns the policy but NOT whether it is being
enforced. The `enforce`, `test_mode` and `default_inbound`/`default_outbound`
fields live on a separate object — the policy container, under `/fwmgr/` — and
those are the fields that decide whether any traffic is actually restricted. A
fetcher that stopped at the first call would report a fully configured firewall
estate that might be enforcing nothing at all.

Deliberately NOT claimed: anything about traffic that was actually blocked.
These are the rules as configured, not observed enforcement. Firewall *events*
are a different endpoint (`/fwmgr/queries/events/v1`) and would be a separate
evidence set.
"""

import logging
import sys
from collections import Counter
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

logger = logging.getLogger("crowdstrike_firewall_policies")

POLICIES_PATH = "/policy/combined/firewall/v1"
CONTAINERS_PATH = "/fwmgr/entities/policies/v1"
RULE_GROUPS_QUERY_PATH = "/fwmgr/queries/rule-groups/v1"
RULE_GROUPS_PATH = "/fwmgr/entities/rule-groups/v1"
RULES_PATH = "/fwmgr/entities/rules/v1"

# The /fwmgr/ entity endpoints take their IDs as repeated query params and
# publish no batch cap. 100 is the shared default and matches every other
# GET-by-ids endpoint in this fetcher set — conservative on purpose, since
# guessing high here would 414 on the URL length rather than fail cleanly.
ENTITY_BATCH_SIZE = 100

# Falcon spells the default actions in caps. Anything that is not a denial is
# treated as permissive, rather than matching "ALLOW" exactly, so an unfamiliar
# third value fails toward flagging it for a human instead of silently passing.
DENY_ACTIONS = {"DENY", "DENIED", "BLOCK", "BLOCKED"}


def is_monitored(rule: Dict[str, Any]) -> Optional[bool]:
    """
    Whether a rule actually logs its matches.

    `monitor` is NOT a boolean. gofalcon types it as FwmgrFirewallMonitoring —
    `{count, period_ms}`, both strings — and marks it `Required: true`, so it is
    present on every rule whether or not monitoring is switched on. Testing the
    object for truthiness therefore counts *every* rule as monitored, which on a
    real tenant makes `monitored_rules` equal `total_rules` no matter what the
    estate is doing. The mock did not catch it because it omits `monitor` from
    three of its four rules — fixture and fetcher agreeing with each other and
    both disagreeing with the API, the same trap as the Zero Trust audit shape.

    Monitoring is on when the rate limit permits at least one log line, i.e.
    `count` parses to a positive integer. An unrecognized shape returns None
    rather than a guess: overstating a logging control is the dangerous
    direction, so unknown is reported separately instead of counted as either.
    """
    monitor = rule.get("monitor")
    if not isinstance(monitor, dict):
        # A rule with no monitor object at all is not monitored. Absent is a
        # answerable state; a shape we do not recognize is not.
        return False if monitor is None else None
    count = monitor.get("count")
    try:
        return int(str(count).strip()) > 0
    except (TypeError, ValueError):
        return None


def is_permissive(action: Any) -> bool:
    """True when a default action does not deny. Unset counts as permissive:
    a policy that does not say what it does with unmatched traffic has not
    demonstrated that it limits it."""
    if not isinstance(action, str) or not action.strip():
        return True
    return action.strip().upper() not in DENY_ACTIONS


def index_by(records: List[Dict[str, Any]], key: str) -> Dict[str, Dict[str, Any]]:
    return {
        r[key]: r
        for r in records
        if isinstance(r, dict) and isinstance(r.get(key), str)
    }


def summarize_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_action: Counter = Counter()
    by_direction: Counter = Counter()
    by_protocol: Counter = Counter()
    disabled = 0
    monitored = 0
    monitor_unknown = 0
    fqdn_rules = 0
    deleted = 0
    live: List[Dict[str, Any]] = []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        # `deleted` is Required on FwmgrFirewallRuleV1, so the API distinguishes
        # removed rules from live ones and a caller that ignores the flag counts
        # dead config as posture. Counted, then excluded from every other total.
        if rule.get("deleted"):
            deleted += 1
            continue
        live.append(rule)
        by_action[(rule.get("action") or "unknown")] += 1
        by_direction[(rule.get("direction") or "unknown")] += 1
        by_protocol[(rule.get("protocol") or "unknown")] += 1
        if not rule.get("enabled"):
            disabled += 1
        monitoring = is_monitored(rule)
        if monitoring is None:
            monitor_unknown += 1
        elif monitoring:
            monitored += 1
        if rule.get("fqdn_enabled"):
            fqdn_rules += 1

    return {
        "total_rules": len(live),
        "deleted_rules": deleted,
        "disabled_rules": disabled,
        "monitored_rules": monitored,
        "rules_with_unrecognized_monitor": monitor_unknown,
        "fqdn_rules": fqdn_rules,
        "rules_by_action": dict(by_action.most_common()),
        "rules_by_direction": dict(by_direction.most_common()),
        "rules_by_protocol": dict(by_protocol.most_common()),
    }


def summarize(
    policies: List[Dict[str, Any]],
    containers: List[Dict[str, Any]],
    rule_groups: List[Dict[str, Any]],
    rules: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Reduce the four collections to the posture a reviewer reads first.

    The headline is `fully_enforcing_policies`: enabled, assigned to at least
    one host group, enforcing, and not in test mode. Each of those four ways to
    fail is also listed by name, because a policy can be present and correct in
    every visible respect and still restrict no traffic at all.
    """
    by_policy_id = index_by(containers, "policy_id")

    per_policy: List[Dict[str, Any]] = []
    unassigned: List[Dict[str, Any]] = []
    not_enforcing: List[Dict[str, Any]] = []
    test_mode: List[Dict[str, Any]] = []
    permissive_inbound: List[Dict[str, Any]] = []
    permissive_outbound: List[Dict[str, Any]] = []
    no_rule_groups: List[Dict[str, Any]] = []
    missing_container: List[Dict[str, Any]] = []
    fully_enforcing = 0
    enabled_count = 0

    for policy in policies:
        if not isinstance(policy, dict):
            continue
        pid = policy.get("id")
        name = policy.get("name")
        ident = {"id": pid, "name": name}
        groups = policy.get("groups") or []
        enabled = bool(policy.get("enabled"))
        if enabled:
            enabled_count += 1

        container = by_policy_id.get(pid) if isinstance(pid, str) else None
        if container is None:
            # No container means the enforcement fields are simply unknown for
            # this policy. Reported rather than defaulted, so it is never
            # counted as enforcing on the strength of a missing record.
            missing_container.append(ident)

        enforce = bool(container.get("enforce")) if container else None
        in_test = bool(container.get("test_mode")) if container else None
        inbound = container.get("default_inbound") if container else None
        outbound = container.get("default_outbound") if container else None
        group_ids = (container.get("rule_group_ids") or []) if container else []

        if enabled and not groups:
            unassigned.append(ident)
        if container is not None and not enforce:
            not_enforcing.append(ident)
        if in_test:
            test_mode.append(ident)
        if container is not None and is_permissive(inbound):
            permissive_inbound.append({**ident, "default_inbound": inbound})
        if container is not None and is_permissive(outbound):
            permissive_outbound.append({**ident, "default_outbound": outbound})
        if container is not None and not group_ids:
            no_rule_groups.append(ident)

        if enabled and groups and enforce and not in_test:
            fully_enforcing += 1

        per_policy.append(
            {
                **ident,
                "platform_name": policy.get("platform_name"),
                "enabled": enabled,
                "host_group_count": len(groups),
                "host_groups": [g.get("name") for g in groups if isinstance(g, dict)],
                "enforce": enforce,
                "test_mode": in_test,
                "local_logging": bool(container.get("local_logging"))
                if container
                else None,
                "default_inbound": inbound,
                "default_outbound": outbound,
                "rule_group_count": len(group_ids),
            }
        )

    # Attachment is read from the rule group's own `policy_ids` first.
    #
    # Deriving it only from the containers' `rule_group_ids` — which this did —
    # makes the orphan check depend on a call that is allowed to fail: a policy
    # whose container 403s or simply does not come back is already reported in
    # `policies_missing_container`, and every group attached to it was then
    # reported as unattached as well. That is a fabricated finding in a
    # compliance report, and it fires in exactly the case the fetcher has
    # already noticed and named.
    #
    # gofalcon gives the direct answer: FwmgrAPIRuleGroupV1 carries
    # `policy_ids` (Required), the group's own back-reference to the policies
    # using it. The container-derived set is unioned in rather than dropped, so
    # a group whose own list is stale is still counted as attached — the two
    # signals can only add evidence of attachment, never remove it.
    attached_group_ids = {
        gid
        for container in containers
        if isinstance(container, dict)
        for gid in (container.get("rule_group_ids") or [])
    }
    live_groups = [
        g for g in rule_groups if isinstance(g, dict) and not g.get("deleted")
    ]
    deleted_groups = sum(
        1 for g in rule_groups if isinstance(g, dict) and g.get("deleted")
    )

    def is_attached(group: Dict[str, Any]) -> bool:
        if group.get("policy_ids"):
            return True
        return group.get("id") in attached_group_ids

    orphan_groups = [
        {"id": g.get("id"), "name": g.get("name")}
        for g in live_groups
        if not is_attached(g)
    ]
    disabled_groups = [
        {"id": g.get("id"), "name": g.get("name")}
        for g in live_groups
        if not g.get("enabled")
    ]

    return {
        "total_policies": len(policies),
        "enabled_policies": enabled_count,
        "disabled_policies": len(policies) - enabled_count,
        "fully_enforcing_policies": fully_enforcing,
        "by_platform": dict(
            Counter(
                (p.get("platform_name") or "unknown")
                for p in policies
                if isinstance(p, dict)
            )
        ),
        "enabled_but_unassigned": unassigned,
        "policies_not_enforcing": not_enforcing,
        "policies_in_test_mode": test_mode,
        "policies_permissive_inbound": permissive_inbound,
        "policies_permissive_outbound": permissive_outbound,
        "policies_without_rule_groups": no_rule_groups,
        "policies_missing_container": missing_container,
        "total_rule_groups": len(live_groups),
        "deleted_rule_groups": deleted_groups,
        "disabled_rule_groups": disabled_groups,
        "rule_groups_not_attached_to_a_policy": orphan_groups,
        **summarize_rules(rules),
        "policies": per_policy,
    }


def collect() -> Dict[str, Any]:
    try:
        client = build_client()
    except (FalconAuthError, RuntimeError) as e:
        return evidence_error(str(e))

    policies = client.paginate_offset(POLICIES_PATH, limit=100)

    policy_ids = [
        p["id"]
        for p in policies
        if isinstance(p, dict) and isinstance(p.get("id"), str)
    ]
    containers = client.get_entities(
        CONTAINERS_PATH, policy_ids, method="GET", batch_size=ENTITY_BATCH_SIZE
    )

    # Every rule group in the tenant, not only the ones a policy references —
    # a group attached to nothing is config sprawl a reviewer wants named, and
    # it is invisible if the group list is derived from the policy containers.
    # The container IDs are unioned in anyway, so a group the query misses but a
    # policy uses still gets collected.
    group_ids = [
        gid
        for gid in client.paginate_after(RULE_GROUPS_QUERY_PATH, limit=500)
        if isinstance(gid, str)
    ]
    for container in containers:
        if isinstance(container, dict):
            group_ids.extend(
                gid
                for gid in (container.get("rule_group_ids") or [])
                if isinstance(gid, str)
            )

    rule_groups: List[Dict[str, Any]] = []
    if group_ids:
        rule_groups = client.get_entities(
            RULE_GROUPS_PATH, group_ids, method="GET", batch_size=ENTITY_BATCH_SIZE
        )

    rule_ids: List[str] = []
    for group in rule_groups:
        if isinstance(group, dict):
            rule_ids.extend(
                rid for rid in (group.get("rule_ids") or []) if isinstance(rid, str)
            )

    rules: List[Dict[str, Any]] = []
    if rule_ids:
        rules = client.get_entities(
            RULES_PATH, rule_ids, method="GET", batch_size=ENTITY_BATCH_SIZE
        )

    return evidence(
        client=client,
        endpoint=POLICIES_PATH,
        records=policies,
        analysis=summarize(policies, containers, rule_groups, rules),
        empty_message="No firewall policies returned",
        policy_containers=containers,
        rule_groups=rule_groups,
        rules=rules,
    )


if __name__ == "__main__":
    sys.exit(run_fetcher(collect, "crowdstrike_firewall_policies.json", logger))
