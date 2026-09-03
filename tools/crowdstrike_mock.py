#!/usr/bin/env python3
"""
A local stand-in for the CrowdStrike Falcon API, for developing and testing the
crowdstrike fetchers without a Falcon tenant.

It implements only the endpoints the fetchers call, with response shapes and
pagination taken from CrowdStrike's SDK (github.com/CrowdStrike/falconpy). The
fixtures are deliberately awkward — a stale host, a host in reduced
functionality mode, a disabled policy, an enabled-but-unassigned policy, a
mixture of severities — so the summary code is exercised rather than just the
happy path.

    python tools/crowdstrike_mock.py --port 8787

    export CROWDSTRIKE_API_BASE_URL=http://127.0.0.1:8787
    export CROWDSTRIKE_CLIENT_ID=mock-id
    export CROWDSTRIKE_CLIENT_SECRET=mock-secret

Bad credentials return a Falcon-shaped 401 so the auth-failure path can be
tested too:

    CROWDSTRIKE_CLIENT_ID=wrong ... -> 401 with an errors[] body

This is a test double, not a simulator: it does not enforce FQL filters, and
its record counts are small enough to read by eye.
"""

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

VALID_CLIENT_ID = "mock-id"
VALID_CLIENT_SECRET = "mock-secret"

MOCK_CID = "abcdefabcdefabcdefabcdefabcdef01"

# --- optional real-response corpus -------------------------------------------
#
# Set CROWDSTRIKE_MOCK_CORPUS to a directory produced by tools/crowdstrike_corpus.py
# and the mock serves *real recorded CrowdStrike responses* in place of the
# hand-written fixtures below. That is the difference between proving the
# fetchers are self-consistent and proving they handle what Falcon actually
# sends: the built-in fixtures were written from the same assumptions as the
# fetchers, so the two can be wrong together.
#
# Endpoints with no corpus coverage keep their built-in fixtures, so a partial
# corpus still exercises everything.

CORPUS_ENV = "CROWDSTRIKE_MOCK_CORPUS"


def _load_corpus() -> Dict[str, List[Dict[str, Any]]]:
    """Group every corpus file's records by the fetcher they belong to."""
    root = os.environ.get(CORPUS_ENV, "").strip()
    if not root:
        return {}

    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for path in sorted(Path(root).glob("*.ndjson")):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        records = doc.get("records")
        if isinstance(records, list) and records:
            grouped.setdefault(str(doc.get("fetcher")), []).extend(records)
    return grouped


# Cached per corpus directory rather than read once at import.
#
# Import-time loading meant the environment variable had to be set before the
# module was first imported, so a test wanting the corpus had to
# importlib.reload() it — mutating shared module state that another test module
# may be serving from concurrently. That produced an intermittent failure.
# Reading lazily makes the switch order-independent.
_CORPUS_CACHE: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}


def corpus() -> Dict[str, List[Dict[str, Any]]]:
    root = os.environ.get(CORPUS_ENV, "").strip()
    if root not in _CORPUS_CACHE:
        _CORPUS_CACHE[root] = _load_corpus()
    return _CORPUS_CACHE[root]


def _corpus_or(fetcher: str, fallback: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return corpus().get(fetcher) or fallback


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now() -> datetime:
    return datetime.now(timezone.utc)


def _builtin_devices() -> List[Dict[str, Any]]:
    recent = iso(now() - timedelta(hours=2))
    stale = iso(now() - timedelta(days=95))
    return [
        {
            "device_id": "dev0000000000000000000000000001",
            "cid": MOCK_CID,
            "hostname": "web-prod-01",
            "platform_name": "Linux",
            "os_version": "Amazon Linux 2023",
            "product_type_desc": "Server",
            "agent_version": "7.16.18604.0",
            "status": "normal",
            "reduced_functionality_mode": "no",
            "last_seen": recent,
            "first_seen": iso(now() - timedelta(days=400)),
            "local_ip": "10.0.1.20",
        },
        {
            "device_id": "dev0000000000000000000000000002",
            "cid": MOCK_CID,
            "hostname": "web-prod-02",
            "platform_name": "Linux",
            "os_version": "Amazon Linux 2023",
            "product_type_desc": "Server",
            "agent_version": "7.16.18604.0",
            "status": "normal",
            "reduced_functionality_mode": "no",
            "last_seen": recent,
            "first_seen": iso(now() - timedelta(days=400)),
            "local_ip": "10.0.1.21",
        },
        {
            "device_id": "dev0000000000000000000000000003",
            "cid": MOCK_CID,
            "hostname": "build-runner-01",
            "platform_name": "Linux",
            "os_version": "Ubuntu 22.04",
            "product_type_desc": "Server",
            # An older sensor: shows up as a second distinct version.
            "agent_version": "7.10.17604.0",
            "status": "normal",
            "reduced_functionality_mode": "yes",
            "last_seen": recent,
            "first_seen": iso(now() - timedelta(days=120)),
            "local_ip": "10.0.2.44",
        },
        {
            "device_id": "dev0000000000000000000000000004",
            "cid": MOCK_CID,
            "hostname": "laptop-decommissioned",
            "platform_name": "Windows",
            "os_version": "Windows 11",
            "product_type_desc": "Workstation",
            "agent_version": "7.10.17604.0",
            "status": "normal",
            "reduced_functionality_mode": "no",
            "last_seen": stale,
            "first_seen": iso(now() - timedelta(days=700)),
            "local_ip": "192.168.1.55",
        },
        {
            "device_id": "dev0000000000000000000000000005",
            "cid": MOCK_CID,
            "hostname": "mac-eng-07",
            "platform_name": "Mac",
            "os_version": "Sequoia (15)",
            "product_type_desc": "Workstation",
            "agent_version": "7.16.18604.0",
            "status": "normal",
            "reduced_functionality_mode": "no",
            "last_seen": recent,
            "first_seen": iso(now() - timedelta(days=200)),
            "local_ip": "192.168.1.31",
        },
    ]


def _builtin_vulnerabilities() -> List[Dict[str, Any]]:
    return [
        {
            "id": "vuln0001",
            "cid": MOCK_CID,
            "aid": "dev0000000000000000000000000001",
            "created_timestamp": iso(now() - timedelta(days=210)),
            "updated_timestamp": iso(now() - timedelta(days=3)),
            "status": "open",
            "cve": {
                "id": "CVE-2024-3094",
                "severity": "CRITICAL",
                "base_score": 10.0,
                "exprt_rating": "CRITICAL",
                "exploit_status": 90,
            },
            "host_info": {"host_id": "dev0000000000000000000000000001", "hostname": "web-prod-01"},
            "remediation": {"entities": [{"id": "rem001", "action": "Update xz-utils to 5.6.2"}]},
        },
        {
            "id": "vuln0002",
            "cid": MOCK_CID,
            "aid": "dev0000000000000000000000000002",
            "created_timestamp": iso(now() - timedelta(days=45)),
            "updated_timestamp": iso(now() - timedelta(days=1)),
            "status": "open",
            "cve": {
                "id": "CVE-2023-44487",
                "severity": "HIGH",
                "base_score": 7.5,
                "exprt_rating": "HIGH",
                "exploit_status": 30,
            },
            "host_info": {"host_id": "dev0000000000000000000000000002", "hostname": "web-prod-02"},
            "remediation": {"entities": [{"id": "rem002", "action": "Update nginx to 1.25.3"}]},
        },
        {
            "id": "vuln0003",
            "cid": MOCK_CID,
            "aid": "dev0000000000000000000000000003",
            "created_timestamp": iso(now() - timedelta(days=12)),
            "updated_timestamp": iso(now() - timedelta(days=12)),
            "status": "reopen",
            "cve": {
                "id": "CVE-2022-42889",
                "severity": "MEDIUM",
                "base_score": 5.3,
                "exprt_rating": "MEDIUM",
                "exploit_status": 0,
            },
            "host_info": {"host_id": "dev0000000000000000000000000003", "hostname": "build-runner-01"},
            # No remediation available — exercises the "not all findings are
            # patchable" branch of the summary.
            "remediation": {},
        },
    ]


def _builtin_alerts() -> List[Dict[str, Any]]:
    return [
        {
            "composite_id": f"{MOCK_CID}:ind:aaaa0001",
            "id": "ldt:aaaa0001",
            "cid": MOCK_CID,
            "device_id": "dev0000000000000000000000000001",
            "created_timestamp": iso(now() - timedelta(days=6)),
            "updated_timestamp": iso(now() - timedelta(days=6) + timedelta(hours=4)),
            "severity": 70,
            "severity_name": "High",
            "status": "closed",
            "tactic": "Defense Evasion",
            "technique": "Masquerading",
            "product": "epp",
            "pattern_disposition": 2048,
        },
        {
            "composite_id": f"{MOCK_CID}:ind:aaaa0002",
            "id": "ldt:aaaa0002",
            "cid": MOCK_CID,
            "device_id": "dev0000000000000000000000000003",
            "created_timestamp": iso(now() - timedelta(days=2)),
            "updated_timestamp": iso(now() - timedelta(days=2)),
            "severity": 50,
            "severity_name": "Medium",
            "status": "new",
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter",
            "product": "epp",
            "pattern_disposition": 0,
        },
        {
            "composite_id": f"{MOCK_CID}:ind:aaaa0003",
            "id": "ldt:aaaa0003",
            "cid": MOCK_CID,
            "device_id": "dev0000000000000000000000000005",
            "created_timestamp": iso(now() - timedelta(days=1)),
            "updated_timestamp": iso(now() - timedelta(days=1) + timedelta(hours=1)),
            "severity": 30,
            "severity_name": "Low",
            "status": "in_progress",
            "tactic": "Discovery",
            "technique": "System Information Discovery",
            "product": "epp",
            "pattern_disposition": 0,
        },
    ]


def _prevention_policies() -> List[Dict[str, Any]]:
    def toggle(name: str, enabled: bool) -> Dict[str, Any]:
        return {"id": name.lower(), "name": name, "type": "toggle", "value": {"enabled": enabled}}

    def slider(name: str, detection: str, prevention: str) -> Dict[str, Any]:
        return {
            "id": name.lower(),
            "name": name,
            "type": "mlslider",
            "value": {"detection": detection, "prevention": prevention},
        }

    return [
        {
            "id": "pol0000000000000000000000000001",
            "name": "Production Servers",
            "description": "Hardened baseline for production Linux hosts",
            "platform_name": "Linux",
            "enabled": True,
            "created_by": "security@example.gov",
            "modified_timestamp": iso(now() - timedelta(days=20)),
            "groups": [{"id": "grp001", "name": "Production Linux"}],
            "prevention_settings": [
                {
                    "name": "Sensor Anti-malware",
                    "settings": [
                        slider("Cloud Anti-malware", "AGGRESSIVE", "MODERATE"),
                        slider("Sensor Anti-malware", "MODERATE", "MODERATE"),
                    ],
                },
                {
                    "name": "Execution Blocking",
                    "settings": [
                        toggle("Suspicious Processes", True),
                        toggle("Script-Based Execution Monitoring", True),
                        toggle("Intelligence-Sourced Threats", True),
                    ],
                },
            ],
        },
        {
            "id": "pol0000000000000000000000000002",
            "name": "Workstations",
            "description": "Default workstation policy",
            "platform_name": "Windows",
            "enabled": True,
            "created_by": "security@example.gov",
            "modified_timestamp": iso(now() - timedelta(days=60)),
            # Enabled but assigned to nothing — enforces nothing in practice.
            "groups": [],
            "prevention_settings": [
                {
                    "name": "Execution Blocking",
                    "settings": [
                        toggle("Suspicious Processes", True),
                        slider("Cloud Anti-malware", "MODERATE", "DISABLED"),
                    ],
                }
            ],
        },
        {
            "id": "pol0000000000000000000000000003",
            "name": "Legacy Audit Only",
            "description": "Retired policy kept for reference",
            "platform_name": "Windows",
            "enabled": False,
            "created_by": "security@example.gov",
            "modified_timestamp": iso(now() - timedelta(days=400)),
            "groups": [],
            "prevention_settings": [
                {
                    "name": "Execution Blocking",
                    "settings": [
                        toggle("Suspicious Processes", False),
                        slider("Cloud Anti-malware", "DISABLED", "DISABLED"),
                    ],
                }
            ],
        },
    ]


def _zta_audit() -> List[Dict[str, Any]]:
    """
    Shape taken from CrowdStrike's published OpenAPI models
    (gofalcon `CommonCIDAuditResult` / `CommonOSAudit`): one record per CID,
    each holding a list of platforms, each with an `audit` MAP of signal name
    to score.

    An earlier version of this fixture invented a nested list of findings with
    `requires_remediation` flags. It was wrong, and because the fetcher was
    written against the same wrong guess, every test passed while the real
    analysis would have come back empty. Fixtures are only worth as much as
    their provenance — do not hand-write one from the fetcher's expectations.
    """
    return [
        {
            "cid": MOCK_CID,
            "average_overall_score": 71.4,
            "num_aids": 5,
            "platforms": [
                {
                    "name": "Windows",
                    "average_overall_score": 78.0,
                    "num_aids": 3,
                    "audit": {
                        "sensor_version": 95.0,
                        "prevention_policy": 88.0,
                        "sensor_tampering_protection": 42.0,
                        "firewall_policy": 30.5,
                        "usb_device_policy": 61.0,
                        "host_retention_policy": 99.0,
                    },
                },
                {
                    "name": "Mac",
                    "average_overall_score": 64.2,
                    "num_aids": 1,
                    "audit": {
                        "sensor_version": 90.0,
                        "prevention_policy": 55.0,
                        "full_disk_access": 12.0,
                    },
                },
                {
                    "name": "Linux",
                    "average_overall_score": 58.0,
                    "num_aids": 1,
                    "audit": {"sensor_version": 70.0, "prevention_policy": 46.0},
                },
            ],
        }
    ]


def _host_assessments() -> List[Dict[str, Any]]:
    return [
        {"aid": "dev0000000000000000000000000001", "cid": MOCK_CID, "score": 89},
        {"aid": "dev0000000000000000000000000002", "cid": MOCK_CID, "score": 91},
        {"aid": "dev0000000000000000000000000003", "cid": MOCK_CID, "score": 54},
        {"aid": "dev0000000000000000000000000005", "cid": MOCK_CID, "score": 78},
    ]


def _filevantage_changes() -> List[Dict[str, Any]]:
    """
    Field names from gofalcon's ChangesChange and its nested ChangesHost,
    ChangesPolicy and ChangesDiff models.

    Deliberately awkward, so the summary logic is exercised rather than the
    happy path: a permissions change (which the summary must count as elevated),
    a suppressed change (present in the data but excluded from the reviewer's
    working set), a registry entity on Windows alongside file entities, and one
    record missing `action_type` entirely so the unrecognized-record counter is
    not always zero.
    """
    return [
        {
            "id": "fv0000000000000000000000000001",
            "action_type": "Written",
            "entity_type": "file",
            "entity_path": "/etc/ssh/sshd_config",
            "action_timestamp": "2026-08-18T04:11:02Z",
            "severity": "High",
            "is_suppressed": False,
            "host": {"name": "web-prod-01", "agent_version": "7.14.18604.0", "groups": [{"name": "prod"}]},
            "policy": {"name": "Linux Critical Config", "rule_group": {"name": "etc-ssh"}},
        },
        {
            "id": "fv0000000000000000000000000002",
            "action_type": "PermissionsChange",
            "entity_type": "file",
            "entity_path": "/etc/sudoers",
            "action_timestamp": "2026-08-18T06:40:55Z",
            "severity": "High",
            "is_suppressed": False,
            "host": {"name": "web-prod-01", "agent_version": "7.14.18604.0", "groups": [{"name": "prod"}]},
            "policy": {"name": "Linux Critical Config", "rule_group": {"name": "etc-sudoers"}},
        },
        {
            "id": "fv0000000000000000000000000003",
            "action_type": "Written",
            "entity_type": "registry",
            "entity_path": "HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "action_timestamp": "2026-08-17T22:03:19Z",
            "severity": "Medium",
            # Suppressed by a scheduled exclusion — still returned by the API.
            "is_suppressed": True,
            "host": {"name": "win-app-02", "agent_version": "7.14.18604.0", "groups": [{"name": "prod"}]},
            "policy": {"name": "Windows Baseline", "rule_group": {"name": "services"}},
        },
        {
            "id": "fv0000000000000000000000000004",
            "action_type": "Deleted",
            "entity_type": "file",
            "entity_path": "/var/log/audit/audit.log",
            "action_timestamp": "2026-08-16T13:27:41Z",
            "severity": "Critical",
            "is_suppressed": False,
            "host": {"name": "db-prod-03", "agent_version": "7.13.18102.0", "groups": [{"name": "prod"}]},
            "policy": {"name": "Linux Critical Config", "rule_group": {"name": "audit-logs"}},
        },
        {
            # No action_type: the summary must count this rather than treat it
            # as a normal record or crash on it.
            "id": "fv0000000000000000000000000005",
            "entity_path": "/opt/app/config.yaml",
            "action_timestamp": "2026-08-15T09:02:00Z",
        },
    ]


# Serve real recorded responses when a corpus is present, hand-written fixtures
# otherwise. The fetchers cannot tell the difference — which is the point.


def _firewall_policies() -> List[Dict[str, Any]]:
    """
    Field names from gofalcon's FirewallPolicyV1.

    Four policies chosen so every way a firewall policy can look correct and
    enforce nothing is exercised: one genuinely enforcing, one in test mode,
    one enabled but assigned to no host groups, and one whose policy container
    is absent from /fwmgr/ entirely.
    """
    return [
        {
            "id": "fw00000000000000000000000000001",
            "cid": MOCK_CID,
            "name": "Windows Servers - Enforced",
            "description": "Default deny both directions",
            "platform_name": "Windows",
            "enabled": True,
            "groups": [{"id": "hg000000000000000000000000001", "name": "prod-servers"}],
            "created_by": "admin@example.com",
            "created_timestamp": iso(now() - timedelta(days=200)),
            "modified_timestamp": iso(now() - timedelta(days=9)),
            "rule_set_id": "rs00000000000000000000000000001",
        },
        {
            "id": "fw00000000000000000000000000002",
            "cid": MOCK_CID,
            "name": "Mac Laptops - Test Mode",
            "description": "Staged rollout, not yet enforcing",
            "platform_name": "Mac",
            "enabled": True,
            "groups": [{"id": "hg000000000000000000000000002", "name": "laptops"}],
            "created_by": "admin@example.com",
            "created_timestamp": iso(now() - timedelta(days=40)),
            "modified_timestamp": iso(now() - timedelta(days=2)),
            "rule_set_id": "rs00000000000000000000000000002",
        },
        {
            "id": "fw00000000000000000000000000003",
            "cid": MOCK_CID,
            "name": "Linux Build Hosts",
            "description": "Enabled, assigned to nothing, not enforcing",
            "platform_name": "Linux",
            "enabled": True,
            "groups": [],
            "created_by": "ci@example.com",
            "created_timestamp": iso(now() - timedelta(days=120)),
            "modified_timestamp": iso(now() - timedelta(days=118)),
            "rule_set_id": "rs00000000000000000000000000003",
        },
        {
            "id": "fw00000000000000000000000000004",
            "cid": MOCK_CID,
            "name": "Legacy Policy",
            "description": "Disabled; no policy container exists for it",
            "platform_name": "Windows",
            "enabled": False,
            "groups": [{"id": "hg000000000000000000000000001", "name": "prod-servers"}],
            "created_by": "admin@example.com",
            "created_timestamp": iso(now() - timedelta(days=900)),
            "modified_timestamp": iso(now() - timedelta(days=700)),
            "rule_set_id": "rs00000000000000000000000000004",
        },
    ]


def _firewall_containers() -> List[Dict[str, Any]]:
    """
    Field names from gofalcon's FwmgrFirewallPolicyContainerV1.

    Deliberately only three, for four policies — the fourth policy has no
    container, which is how the fetcher's "enforcement is unknown, do not
    assume it is on" branch gets exercised.
    """
    return [
        {
            "policy_id": "fw00000000000000000000000000001",
            "platform_id": "0",
            "default_inbound": "DENY",
            "default_outbound": "DENY",
            "enforce": True,
            "test_mode": False,
            "local_logging": True,
            "is_default_policy": False,
            "deleted": False,
            "rule_group_ids": ["rg00000000000000000000000000001"],
            "tracking": "trk-1",
            "modified_by": "admin@example.com",
            "modified_on": iso(now() - timedelta(days=9)),
        },
        {
            "policy_id": "fw00000000000000000000000000002",
            "platform_id": "1",
            "default_inbound": "DENY",
            "default_outbound": "ALLOW",
            "enforce": True,
            "test_mode": True,
            "local_logging": False,
            "is_default_policy": False,
            "deleted": False,
            "rule_group_ids": ["rg00000000000000000000000000002"],
            "tracking": "trk-2",
            "modified_by": "admin@example.com",
            "modified_on": iso(now() - timedelta(days=2)),
        },
        {
            "policy_id": "fw00000000000000000000000000003",
            "platform_id": "2",
            "default_inbound": "ALLOW",
            "default_outbound": "ALLOW",
            "enforce": False,
            "test_mode": False,
            "local_logging": False,
            "is_default_policy": False,
            "deleted": False,
            "rule_group_ids": [],
            "tracking": "trk-3",
            "modified_by": "ci@example.com",
            "modified_on": iso(now() - timedelta(days=118)),
        },
    ]


def _firewall_rule_groups() -> List[Dict[str, Any]]:
    """
    Field names from gofalcon's FwmgrAPIRuleGroupV1.

    Three groups for two that are attached: the third is referenced by no
    policy container, which is the only way the orphan-group check is anything
    other than permanently empty.
    """
    return [
        {
            "id": "rg00000000000000000000000000001",
            "customer_id": MOCK_CID,
            "name": "Windows server baseline",
            "description": "Inbound management ports only",
            "enabled": True,
            "deleted": False,
            "platform": "windows",
            "policy_ids": ["fw00000000000000000000000000001"],
            "rule_ids": [
                "fr00000000000000000000000000001",
                "fr00000000000000000000000000002",
            ],
            "created_by": "admin@example.com",
            "created_on": iso(now() - timedelta(days=200)),
            "modified_on": iso(now() - timedelta(days=9)),
            "tracking": "rgtrk-1",
        },
        {
            "id": "rg00000000000000000000000000002",
            "customer_id": MOCK_CID,
            "name": "Mac laptop baseline",
            "description": "Outbound allowed while staged",
            "enabled": True,
            "deleted": False,
            "platform": "mac",
            "policy_ids": ["fw00000000000000000000000000002"],
            "rule_ids": ["fr00000000000000000000000000003"],
            "created_by": "admin@example.com",
            "created_on": iso(now() - timedelta(days=40)),
            "modified_on": iso(now() - timedelta(days=2)),
            "tracking": "rgtrk-2",
        },
        {
            "id": "rg00000000000000000000000000003",
            "customer_id": MOCK_CID,
            "name": "Retired DMZ rules",
            "description": "Attached to no policy, and disabled",
            "enabled": False,
            "deleted": False,
            "platform": "windows",
            "policy_ids": [],
            "rule_ids": ["fr00000000000000000000000000004"],
            "created_by": "admin@example.com",
            "created_on": iso(now() - timedelta(days=600)),
            "modified_on": iso(now() - timedelta(days=400)),
            "tracking": "rgtrk-3",
        },
    ]


def _firewall_rules() -> List[Dict[str, Any]]:
    """Field names from gofalcon's FwmgrFirewallRuleV1, including the nested
    FwmgrFirewallAddressRange, FwmgrFirewallPortRange and
    FwmgrFirewallMonitoring shapes.

    `monitor` is on every rule because gofalcon marks it Required — it is the
    rate limit on match logging (`{count, period_ms}`), not a boolean, and it is
    sent whether monitoring is on or off. Three of these four omitted it, which
    is precisely why a fetcher that tested the object for truthiness passed here
    and would have called every rule on a real tenant monitored. The four cases
    are now: monitoring on, rate-limited to zero, on with a longer period, and a
    shape that parses to nothing."""
    return [
        {
            "id": "fr00000000000000000000000000001",
            "family": "0",
            "name": "Allow RDP from jump hosts",
            "description": "Inbound 3389 from the bastion range only",
            "enabled": True,
            "deleted": False,
            "action": "ALLOW",
            "direction": "IN",
            "protocol": "6",
            "address_family": "IP4",
            "local_address": [{"address": "0.0.0.0", "netmask": 0}],
            "local_port": [{"start": 3389, "end": 3389}],
            "remote_address": [{"address": "10.10.0.0", "netmask": 24}],
            "remote_port": [],
            "fqdn_enabled": False,
            "platform_ids": ["0"],
            "monitor": {"count": "5", "period_ms": "60000"},
            "version": 3,
            "rule_group": {"id": "rg00000000000000000000000000001", "name": "Windows server baseline"},
        },
        {
            "id": "fr00000000000000000000000000002",
            "family": "0",
            "name": "Block outbound SMB",
            "description": "Stops lateral movement over 445",
            "enabled": True,
            "deleted": False,
            "action": "DENY",
            "direction": "OUT",
            "protocol": "6",
            "address_family": "IP4",
            "local_address": [],
            "local_port": [],
            "remote_address": [{"address": "0.0.0.0", "netmask": 0}],
            "remote_port": [{"start": 445, "end": 445}],
            "fqdn_enabled": False,
            "platform_ids": ["0"],
            "monitor": {"count": "0", "period_ms": "0"},
            "version": 1,
            "rule_group": {"id": "rg00000000000000000000000000001", "name": "Windows server baseline"},
        },
        {
            "id": "fr00000000000000000000000000003",
            "family": "0",
            "name": "Allow update service by name",
            "description": "FQDN rule, and disabled",
            "enabled": False,
            "deleted": False,
            "action": "ALLOW",
            "direction": "OUT",
            "protocol": "6",
            "address_family": "IP4",
            "fqdn": "updates.example.com",
            "fqdn_enabled": True,
            "local_address": [],
            "local_port": [],
            "remote_address": [],
            "remote_port": [{"start": 443, "end": 443}],
            "platform_ids": ["1"],
            "monitor": {"count": "10", "period_ms": "300000"},
            "version": 2,
            "rule_group": {"id": "rg00000000000000000000000000002", "name": "Mac laptop baseline"},
        },
        {
            "id": "fr00000000000000000000000000004",
            "family": "0",
            "name": "Retired DMZ allow-any",
            "description": "In the orphaned group",
            "enabled": True,
            "deleted": False,
            "action": "ALLOW",
            "direction": "IN",
            "protocol": "ANY",
            "address_family": "IP4",
            "local_address": [],
            "local_port": [],
            "remote_address": [],
            "remote_port": [],
            "fqdn_enabled": False,
            "platform_ids": ["0"],
            "monitor": {"count": "", "period_ms": ""},
            "version": 1,
            "rule_group": {"id": "rg00000000000000000000000000003", "name": "Retired DMZ rules"},
        },
    ]


def _devices() -> List[Dict[str, Any]]:
    return _corpus_or("hosts", _builtin_devices())


def _vulnerabilities() -> List[Dict[str, Any]]:
    return _corpus_or("spotlight_vulnerabilities", _builtin_vulnerabilities())


def _alerts() -> List[Dict[str, Any]]:
    return _corpus_or("detections", _builtin_alerts())


def envelope(
    resources: List[Any],
    pagination: Dict[str, Any] | None = None,
    errors: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    """
    A Falcon response body: {meta, errors, resources}.

    `trace_id` and `query_time` are required by MsaMetaInfo, so they are always
    present — a fixture that omits them is not a legal response.

    `errors` exists because Falcon reports **partial** failures as HTTP 200 with
    a populated errors[] rather than a non-2xx status. Set
    CROWDSTRIKE_MOCK_PARTIAL_ERRORS=1 to make every response carry one, which is
    how that path gets tested.
    """
    meta: Dict[str, Any] = {
        "query_time": 0.01,
        "powered_by": "crowdstrike-mock",
        "trace_id": "00000000-0000-0000-0000-000000000000",
    }
    if pagination is not None:
        meta["pagination"] = pagination

    body_errors = list(errors or [])
    if os.environ.get("CROWDSTRIKE_MOCK_PARTIAL_ERRORS", "").strip() == "1":
        body_errors.append({"code": 207, "message": "partial content: 1 resource unavailable"})

    return {"meta": meta, "errors": body_errors, "resources": resources}


class FalconMockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # --- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        status = args[1] if len(args) > 1 else ""
        print(f"  mock  {self.command or '?':5} {self.path.split('?')[0]}  ->  {status}")

    def _send(self, status: int, body: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _error(self, status: int, message: str) -> None:
        self._send(status, {"meta": {}, "errors": [{"code": status, "message": message}], "resources": []})

    def _authorized(self) -> bool:
        return self.headers.get("Authorization", "").startswith("Bearer mock-token")

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except ValueError:
            return {}

    # --- routes -----------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        path = urlparse(self.path).path

        if path == "/oauth2/token":
            length = int(self.headers.get("Content-Length") or 0)
            form = parse_qs(self.rfile.read(length).decode())
            client_id = (form.get("client_id") or [""])[0]
            client_secret = (form.get("client_secret") or [""])[0]
            if client_id != VALID_CLIENT_ID or client_secret != VALID_CLIENT_SECRET:
                self._error(401, "access denied, invalid bearer token")
                return
            # Falcon names the tenant's own cloud here. CROWDSTRIKE_MOCK_REGION
            # sets it so the GovCloud path can be exercised without GovCloud.
            self._send(
                201,
                {
                    "access_token": "mock-token",
                    "expires_in": 1799,
                    "token_type": "bearer",
                },
                {"X-CS-Region": os.environ.get("CROWDSTRIKE_MOCK_REGION", "us-1")},
            )
            return

        if not self._authorized():
            self._error(401, "access denied, invalid bearer token")
            return

        if path == "/devices/entities/devices/v2":
            wanted = set(self._body().get("ids") or [])
            self._send(200, envelope([d for d in _devices() if d["device_id"] in wanted]))
            return

        if path == "/alerts/entities/alerts/v2":
            wanted = set(self._body().get("composite_ids") or [])
            self._send(200, envelope([a for a in _alerts() if a["composite_id"] in wanted]))
            return

        self._error(404, f"no mock route for POST {path}")

    # --- fault injection ------------------------------------------------
    #
    # The shared client has a retry loop, a page cap and a cursor-stall guard.
    # All of it was written and none of it was ever exercised: a happy-path
    # double never rate-limits, never revokes a token and never returns an
    # endless cursor. These switches make those paths reachable from a test.
    #
    #   CROWDSTRIKE_MOCK_RATE_LIMIT=n   first n calls per path return 429
    #   CROWDSTRIKE_MOCK_FORBID=/path   that path returns 403 (unlicensed module)
    #   CROWDSTRIKE_MOCK_ENDLESS=1      scroll cursor never terminates

    _rate_limited: Dict[str, int] = {}

    def _inject_fault(self, path: str) -> bool:
        """Returns True if a fault was sent and the handler should stop."""
        forbid = os.environ.get("CROWDSTRIKE_MOCK_FORBID", "").strip()
        if forbid and path == forbid:
            # Falcon's shape for an unlicensed module: 403 naming the scope.
            self._error(403, f"access denied, authorization failed for {path}")
            return True

        try:
            budget = int(os.environ.get("CROWDSTRIKE_MOCK_RATE_LIMIT", "0"))
        except ValueError:
            budget = 0
        if budget:
            seen = FalconMockHandler._rate_limited.get(path, 0)
            if seen < budget:
                FalconMockHandler._rate_limited[path] = seen + 1
                self.send_response(429)
                self.send_header("Retry-After", "0")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True
        return False

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if not self._authorized():
            self._error(401, "access denied, invalid bearer token")
            return

        if self._inject_fault(path):
            return

        if path == "/devices/queries/devices-scroll/v1":
            # Two pages, to exercise offset-token pagination.
            ids = [d["device_id"] for d in _devices()]
            offset = (query.get("offset") or [""])[0]
            if not offset:
                self._send(200, envelope(ids[:3], {"offset": "page2", "total": len(ids), "limit": 3}))
            elif os.environ.get("CROWDSTRIKE_MOCK_ENDLESS", "").strip() == "1":
                # Same cursor forever: the client must cap rather than spin.
                self._send(200, envelope(ids[3:], {"offset": "page2", "total": 999999, "limit": 3}))
            elif offset == "page2":
                self._send(200, envelope(ids[3:], {"offset": "", "total": len(ids), "limit": 3}))
            else:
                self._send(200, envelope([], {"offset": "", "total": len(ids), "limit": 3}))
            return

        if path == "/spotlight/combined/vulnerabilities/v1":
            # Two pages, to exercise `after` cursor pagination.
            vulns = _vulnerabilities()
            after = (query.get("after") or [""])[0]
            if not after:
                self._send(200, envelope(vulns[:2], {"after": "cursor2", "total": len(vulns)}))
            elif after == "cursor2":
                self._send(200, envelope(vulns[2:], {"after": "", "total": len(vulns)}))
            else:
                self._send(200, envelope([], {"after": "", "total": len(vulns)}))
            return

        if path == "/alerts/queries/alerts/v2":
            ids = [a["composite_id"] for a in _alerts()]
            # Named apart from the scroll endpoint's `offset`, which is an
            # opaque *string* token. Two pagination styles, two types.
            start = int((query.get("offset") or ["0"])[0])
            self._send(200, envelope(ids[start:], {"offset": start, "limit": 500, "total": len(ids)}))
            return

        if path == "/policy/combined/prevention/v1":
            policies = _prevention_policies()
            start = int((query.get("offset") or ["0"])[0])
            self._send(
                200, envelope(policies[start:], {"offset": start, "limit": 100, "total": len(policies)})
            )
            return

        if path == "/zero-trust-assessment/entities/audit/v1":
            self._send(200, envelope(_zta_audit()))
            return

        if path == "/zero-trust-assessment/queries/assessments/v1":
            # Two pages, and the cursor comes back as `next` — this endpoint
            # answers with DomainSearchAfterPaging, not Spotlight's
            # DomainAPIQueryPagingV1. The mock said `after` and so did the
            # client, which is precisely why a one-page collection looked
            # correct to both of them.
            hosts = _host_assessments()
            after = (query.get("after") or [""])[0]
            if not after:
                self._send(200, envelope(hosts[:2], {"next": "page2", "total": len(hosts)}))
            elif after == "page2":
                self._send(200, envelope(hosts[2:], {"next": "", "total": len(hosts)}))
            else:
                self._send(200, envelope([], {"next": "", "total": len(hosts)}))
            return

        if path == "/filevantage/queries/changes/v3":
            # Two pages over an `after` cursor. FileVantage's own parameter
            # docs say an *empty* after token means the walk is finished, so
            # the last page returns "" rather than omitting the key — the
            # client must treat both the same way.
            changes = _filevantage_changes()
            after = (query.get("after") or [""])[0]
            ids = [c["id"] for c in changes]
            if not after:
                self._send(200, envelope(ids[:3], {"after": "fvpage2", "total": len(ids)}))
            elif after == "fvpage2":
                self._send(200, envelope(ids[3:], {"after": "", "total": len(ids)}))
            else:
                self._send(200, envelope([], {"after": "", "total": len(ids)}))
            return

        if path == "/filevantage/entities/changes/v2":
            # Unlike the host and alert entity lookups this is a GET taking its
            # IDs as repeated query parameters, so the batch arrives in `query`
            # rather than a JSON body.
            wanted = set(query.get("ids") or [])
            records = [c for c in _filevantage_changes() if c["id"] in wanted]
            self._send(200, envelope(records))
            return

        if path == "/policy/combined/firewall/v1":
            policies = _firewall_policies()
            start = int((query.get("offset") or ["0"])[0])
            self._send(
                200, envelope(policies[start:], {"offset": start, "limit": 100, "total": len(policies)})
            )
            return

        if path == "/fwmgr/queries/rule-groups/v1":
            # Single page. The interesting property here is that it returns the
            # orphaned group too — the fetcher deriving its group list from the
            # policy containers instead would never see it.
            ids = [g["id"] for g in _firewall_rule_groups()]
            after = (query.get("after") or [""])[0]
            if after:
                self._send(200, envelope([], {"after": "", "total": len(ids)}))
            else:
                self._send(200, envelope(ids, {"after": "", "total": len(ids)}))
            return

        if path == "/fwmgr/entities/policies/v1":
            wanted = set(query.get("ids") or [])
            records = [c for c in _firewall_containers() if c["policy_id"] in wanted]
            self._send(200, envelope(records))
            return

        if path == "/fwmgr/entities/rule-groups/v1":
            wanted = set(query.get("ids") or [])
            records = [g for g in _firewall_rule_groups() if g["id"] in wanted]
            self._send(200, envelope(records))
            return

        if path == "/fwmgr/entities/rules/v1":
            wanted = set(query.get("ids") or [])
            records = [r for r in _firewall_rules() if r["id"] in wanted]
            self._send(200, envelope(records))
            return

        self._error(404, f"no mock route for GET {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock CrowdStrike Falcon API for fetcher development")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    # ThreadingHTTPServer, not HTTPServer.
    #
    # HTTP/1.1 keep-alive holds a client's connection open after its response.
    # A single-threaded accept loop is then still blocked on that idle socket
    # when the next client arrives, so the second connection waits until
    # something times out. The test suite has always bound a threading server
    # for this reason; the standalone one did not, and running several fetchers
    # in sequence through `paramify run` hung two of them for 30 and 45 seconds
    # before failing with no evidence file at all.
    #
    # The symptom is indistinguishable from a broken fetcher, which is what
    # makes it worth a comment rather than a one-word change.
    server = ThreadingHTTPServer((args.host, args.port), FalconMockHandler)
    print(f"Mock Falcon API listening on http://{args.host}:{args.port}")
    print(f"  CROWDSTRIKE_API_BASE_URL=http://{args.host}:{args.port}")
    print(f"  CROWDSTRIKE_CLIENT_ID={VALID_CLIENT_ID}")
    print(f"  CROWDSTRIKE_CLIENT_SECRET={VALID_CLIENT_SECRET}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping mock Falcon API")
        server.server_close()


if __name__ == "__main__":
    main()
