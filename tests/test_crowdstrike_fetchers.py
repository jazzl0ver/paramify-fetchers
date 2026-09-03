"""Integration cover for the crowdstrike fetchers, against a local test double.

The CI notes say fetchers can't be integration-tested here because there are no
live tenants, and that the signal has to come from recorded fixtures. This is
that: ``tools/crowdstrike_mock.py`` serves the exact endpoints the crowdstrike
fetchers call, with response shapes taken from CrowdStrike's own SDK, so the
whole collect path — OAuth2 exchange, all three pagination styles, batched
entity lookup, summary maths, exit codes — runs in-process with no credentials
and no network.

What this suite can prove: the fetchers parse what Falcon's schema says Falcon
sends, and their summaries are arithmetically right. What it cannot prove: that
Falcon really sends that. Field-level fidelity still needs one run against a
real tenant.

The fixtures are deliberately awkward — a stale host, a sensor in reduced
functionality mode, an enabled-but-unassigned policy, a detection-only
anti-malware slider — because each one is a case that a happy-path fixture
would let through. Two live bugs were caught this way and both are pinned by
tests below (``test_reduced_functionality_mode_detected``,
``test_detection_only_slider_flagged``).

Run: ``pytest tests/test_crowdstrike_fetchers.py``
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "crowdstrike"
MOCK_PATH = REPO_ROOT / "tools" / "crowdstrike_mock.py"

FETCHERS = [
    "hosts",
    "spotlight_vulnerabilities",
    "detections",
    "prevention_policies",
    "zero_trust_assessment",
    "filevantage",
    "firewall_policies",
]


def _load_module(path: Path, name: str) -> Any:
    """Import a fetcher entry script by path; they are scripts, not a package."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mock_server() -> Iterator[str]:
    """Serve the Falcon double on an ephemeral port for the whole module."""
    mock = _load_module(MOCK_PATH, "crowdstrike_mock")

    # Port 0 lets the OS pick, so parallel runs never collide on 8787.
    server = HTTPServer(("127.0.0.1", 0), mock.FalconMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _run_fetcher(name: str, base_url: str, evidence_dir: Path, **extra: str) -> tuple:
    """Run one fetcher exactly as the runner does: a subprocess, env only."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONUNBUFFERED": "1",
        "EVIDENCE_DIR": str(evidence_dir),
        "CROWDSTRIKE_API_BASE_URL": base_url,
        "CROWDSTRIKE_CLIENT_ID": "mock-id",
        "CROWDSTRIKE_CLIENT_SECRET": "mock-secret",
        **extra,
    }
    result = subprocess.run(
        [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = evidence_dir / f"crowdstrike_{name}.json"
    payload = json.loads(output.read_text()) if output.exists() else None
    return result.returncode, payload


# --- every fetcher, end to end ------------------------------------------------


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_collects_successfully(name: str, mock_server: str, tmp_path: Path) -> None:
    code, payload = _run_fetcher(name, mock_server, tmp_path)

    assert code == 0, f"{name} exited {code}"
    assert payload is not None, f"{name} wrote no evidence file"
    assert payload["status"] == "success"
    assert payload["api_failures"] == []
    assert payload["retrieved_at"].endswith("Z")


@pytest.mark.parametrize("name", FETCHERS)
def test_fetcher_writes_evidence_even_when_auth_fails(
    name: str, mock_server: str, tmp_path: Path
) -> None:
    """
    The failure contract: exit non-zero, but still leave a readable file. A
    missing file is indistinguishable from a fetcher that never ran, which is
    the difference between "we have no evidence" and "we collected nothing".
    """
    code, payload = _run_fetcher(
        name, mock_server, tmp_path, CROWDSTRIKE_CLIENT_SECRET="wrong-secret"
    )

    assert code != 0, f"{name} reported success with bad credentials"
    assert payload is not None, f"{name} wrote no evidence file on failure"
    assert payload["status"] == "error"
    assert "401" in payload["message"] or "Unauthorized" in payload["message"]


# --- pagination ---------------------------------------------------------------


def test_scroll_pagination_collects_every_page(mock_server: str, tmp_path: Path) -> None:
    """The mock splits hosts 3/2 across two pages; a single-page read finds 3."""
    _, payload = _run_fetcher("hosts", mock_server, tmp_path)
    assert payload["analysis"]["total_hosts"] == 5


def test_after_cursor_pagination_collects_every_page(mock_server: str, tmp_path: Path) -> None:
    """Spotlight findings are split 2/1 across an `after` cursor."""
    _, payload = _run_fetcher("spotlight_vulnerabilities", mock_server, tmp_path)
    assert payload["analysis"]["total_findings"] == 3


# --- regressions: bugs the awkward fixtures caught ----------------------------


def test_reduced_functionality_mode_detected(mock_server: str, tmp_path: Path) -> None:
    """
    Falcon spells this "yes"/"no", not "true"/"false". Comparing against "true"
    reported zero degraded sensors while one host was degraded — a false clean
    bill of health, which is the worst failure mode for compliance evidence.
    """
    _, payload = _run_fetcher("hosts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["reduced_functionality_mode_count"] == 1
    assert analysis["reduced_functionality_mode_hosts"] == ["dev0000000000000000000000000003"]


def test_detection_only_slider_flagged(mock_server: str, tmp_path: Path) -> None:
    """
    An mlslider with prevention DISABLED detects but does not prevent. Counting
    it as an enabled protection overstates the posture, so it is reported
    separately with its levels preserved.
    """
    _, payload = _run_fetcher("prevention_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["policies_with_detection_only_settings"] == ["Workstations"]

    workstations = next(p for p in analysis["policies"] if p["name"] == "Workstations")
    assert workstations["detection_only_settings"] == ["Execution Blocking.Cloud Anti-malware"]
    assert workstations["slider_levels"]["Execution Blocking.Cloud Anti-malware"] == {
        "detection": "MODERATE",
        "prevention": "DISABLED",
    }


# --- summary correctness ------------------------------------------------------


def test_stale_hosts_identified(mock_server: str, tmp_path: Path) -> None:
    _, payload = _run_fetcher("hosts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["stale_host_count"] == 1
    assert analysis["stale_hosts"][0]["hostname"] == "laptop-decommissioned"
    assert analysis["distinct_sensor_versions"] == 2


def test_stale_threshold_is_configurable(mock_server: str, tmp_path: Path) -> None:
    """A 365-day window should stop counting the 95-day-old host as stale."""
    _, payload = _run_fetcher(
        "hosts", mock_server, tmp_path, CROWDSTRIKE_STALE_HOST_DAYS="365"
    )
    assert payload["analysis"]["stale_host_count"] == 0


def test_vulnerability_summary(mock_server: str, tmp_path: Path) -> None:
    _, payload = _run_fetcher("spotlight_vulnerabilities", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}
    assert analysis["by_exploit_status"] == {"known_exploit": 2, "no_known_exploit": 1}
    # One of the three fixtures has no remediation entities.
    assert analysis["findings_with_remediation_available"] == 2
    assert analysis["oldest_open_days"] >= 209
    assert analysis["distinct_cves"] == 3


def test_unassigned_policy_flagged(mock_server: str, tmp_path: Path) -> None:
    """Enabled but assigned to no host group enforces nothing in practice."""
    _, payload = _run_fetcher("prevention_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_policies"] == 3
    assert analysis["enabled_policies"] == 2
    assert analysis["enabled_but_unassigned_count"] == 1
    assert analysis["enabled_but_unassigned"][0]["name"] == "Workstations"


def test_zero_trust_audit_summary(mock_server: str, tmp_path: Path) -> None:
    _, payload = _run_fetcher("zero_trust_assessment", mock_server, tmp_path)
    audit = payload["analysis"]["audit"]

    assert audit["cid_count"] == 1
    cid = audit["by_cid"][0]
    assert cid["platform_names"] == ["Linux", "Mac", "Windows"]
    assert cid["num_aids"] == 5
    # Host assessments are opt-in and off by default.
    assert "host_assessments" not in payload["analysis"]


def test_zero_trust_audit_ranks_weakest_signals(mock_server: str, tmp_path: Path) -> None:
    """
    Regression: the audit `audit` field is a MAP of signal name to score, not a
    list of findings carrying a remediation flag. The first version of this
    fetcher read the latter, so it produced an empty analysis over a perfectly
    good response — a silent all-clear. Real shape confirmed against
    CrowdStrike's OpenAPI models (gofalcon CommonOSAudit).
    """
    _, payload = _run_fetcher("zero_trust_assessment", mock_server, tmp_path)
    audit = payload["analysis"]["audit"]

    assert audit["unrecognized_records"] == 0

    windows = next(p for p in audit["by_cid"][0]["platforms"] if p["name"] == "Windows")
    assert windows["signal_count"] == 6
    # Worst signal first, so a reader sees the weakest control immediately.
    assert windows["lowest_scoring_signals"][0] == {"signal": "firewall_policy", "score": 30.5}
    assert [s["score"] for s in windows["lowest_scoring_signals"]] == sorted(
        s["score"] for s in windows["lowest_scoring_signals"]
    )


def test_zero_trust_audit_flags_unrecognized_shape() -> None:
    """
    A schema change must not degrade into a clean empty result. Anything that
    is not the documented shape is counted rather than summarized as zeros.
    """
    zta = _load_module(FETCHER_ROOT / "zero_trust_assessment" / "fetcher.py", "cs_zta")

    summary = zta.summarize_audit([{"cid": "abc", "assessment_items": {"legacy": []}}])

    assert summary["unrecognized_records"] == 1
    assert summary["by_cid"] == []


def test_zero_trust_host_assessments_opt_in(mock_server: str, tmp_path: Path) -> None:
    _, payload = _run_fetcher(
        "zero_trust_assessment", mock_server, tmp_path, CROWDSTRIKE_ZTA_INCLUDE_HOSTS="true"
    )
    hosts = payload["analysis"]["host_assessments"]

    assert hosts["host_count"] == 4
    assert hosts["min_score"] == 54
    assert hosts["max_score"] == 91


# --- unit cover on the pure helpers ------------------------------------------


def test_resolution_excludes_reopened_alerts() -> None:
    """
    A reopened alert is open work again. Counting it as resolved overstated the
    resolved total and polluted the timing with the gap before it reopened.
    """
    detections = _load_module(FETCHER_ROOT / "detections" / "fetcher.py", "cs_detections")

    reopened = {
        "status": "reopened",
        "created_timestamp": "2026-01-01T00:00:00Z",
        "updated_timestamp": "2026-01-02T00:00:00Z",
    }
    closed = {
        "status": "closed",
        "created_timestamp": "2026-01-01T00:00:00Z",
        "updated_timestamp": "2026-01-01T06:00:00Z",
    }

    assert detections.resolution_hours(reopened) is None
    assert detections.resolution_hours(closed) == 6.0


@pytest.mark.parametrize(
    "raw,expected",
    [("yes", True), ("Yes", True), ("true", True), ("no", False), ("", False), (None, False)],
)
def test_reduced_functionality_mode_parsing(raw: Any, expected: bool) -> None:
    hosts = _load_module(FETCHER_ROOT / "hosts" / "fetcher.py", "cs_hosts")
    record = {} if raw is None else {"reduced_functionality_mode": raw}
    assert hosts.in_reduced_functionality_mode(record) is expected


@pytest.mark.parametrize(
    "value,expected_enabled",
    [
        ({"enabled": True}, True),
        ({"enabled": False}, False),
        ({"detection": "MODERATE", "prevention": "MODERATE"}, True),
        ({"detection": "MODERATE", "prevention": "DISABLED"}, True),
        ({"detection": "DISABLED", "prevention": "DISABLED"}, False),
    ],
)
def test_setting_classification(value: dict, expected_enabled: bool) -> None:
    policies = _load_module(
        FETCHER_ROOT / "prevention_policies" / "fetcher.py", "cs_prevention_policies"
    )
    is_enabled, _ = policies.classify_setting({"value": value})
    assert is_enabled is expected_enabled


def test_cloud_region_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    GovCloud's hostname is not derivable from the commercial one, and a wrong
    region surfaces as a 401 rather than a DNS error — so this mapping is worth
    pinning.
    """
    client = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_falcon_client")

    monkeypatch.delenv("CROWDSTRIKE_API_BASE_URL", raising=False)
    monkeypatch.setenv("CROWDSTRIKE_CLOUD_REGION", "us-gov-1")
    assert client.resolve_base_url() == "https://api.laggar.gcw.crowdstrike.com"

    # An explicit base URL always wins — this is how the mock is pointed at.
    monkeypatch.setenv("CROWDSTRIKE_API_BASE_URL", "http://127.0.0.1:8787/")
    assert client.resolve_base_url() == "http://127.0.0.1:8787"

    monkeypatch.delenv("CROWDSTRIKE_API_BASE_URL")
    monkeypatch.delenv("CROWDSTRIKE_CLOUD_REGION")
    assert client.resolve_base_url() == "https://api.crowdstrike.com"

    monkeypatch.setenv("CROWDSTRIKE_CLOUD_REGION", "not-a-cloud")
    with pytest.raises(RuntimeError, match="Unknown CROWDSTRIKE_CLOUD_REGION"):
        client.resolve_base_url()


def test_every_documented_cloud_is_routable() -> None:
    """
    The cloud table is checked against gofalcon's falcon/cloud.go, CrowdStrike's
    own list. us-3 was missing, which made a us-3 tenant unrunnable: the region
    is rejected outright rather than falling back, so there is no workaround
    short of hand-setting a base URL.
    """
    client = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_falcon_client")

    assert client.CLOUD_REGIONS == {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "us-3": "https://api.us-3.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
        "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
    }
    # GovCloud is the FedRAMP-relevant half and neither host is guessable.
    assert client.CLOUD_REGIONS["us-gov-2"].endswith(".mil")


@pytest.mark.parametrize(
    "given,expected",
    [
        ("us-gov-1", "us-gov-1"),
        ("usgov1", "us-gov-1"),
        ("US-GOV-1", "us-gov-1"),
        ("  us_gov_1 ", "us-gov-1"),
        ("gov1", "us-gov-1"),
        ("gov2", "us-gov-2"),
        ("us1", "us-1"),
    ],
)
def test_region_spellings_all_reach_the_same_cloud(given: str, expected: str) -> None:
    """
    The console, the docs and the SDKs each spell GovCloud differently. Every
    spelling gofalcon accepts must land on the same host here — a rejected
    spelling is recoverable, but silently defaulting to commercial us-1 while
    the operator believes they are on GovCloud is not.
    """
    client = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_falcon_client")
    assert client.normalize_region(given) == expected


class _FakeResponse:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers


def test_reported_region_is_taken_from_the_tenant_not_the_config(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    X-CS-Region is the tenant's own statement of which cloud answered. It is the
    only value in the evidence that is not just a restatement of the manifest,
    so a GovCloud claim can be checked against it. A mismatch warns rather than
    fails — the header is informational and must not stop a collection.
    """
    mod = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_falcon_client")
    client = mod.FalconClient(mod.CLOUD_REGIONS["us-gov-1"], "id", "secret")

    client._record_reported_region(_FakeResponse({"X-CS-Region": "us-gov-1"}))
    assert client.reported_region == "us-gov-1"

    with caplog.at_level("WARNING"):
        client._record_reported_region(_FakeResponse({"X-CS-Region": "us-1"}))
    assert client.reported_region == "us-1"
    assert "tenant reports us-1" in caplog.text

    # A header we do not recognize is kept verbatim, not dropped: an unknown
    # cloud is still evidence about where the data came from.
    client._record_reported_region(_FakeResponse({"X-CS-Region": "us-9"}))
    assert client.reported_region == "us-9"

    # Absent header leaves the last known value rather than inventing one.
    client._record_reported_region(_FakeResponse({}))
    assert client.reported_region == "us-9"


def test_cloud_provenance_records_configured_and_reported_separately() -> None:
    """
    Both halves matter to an assessor: what the manifest asked for, and what
    answered. A test double resolves to no known region, which must read as
    None rather than defaulting to a real cloud.
    """
    mod = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_falcon_client")

    # The two values must differ here, or reading the config in place of the
    # tenant would satisfy the assertion and prove nothing.
    client = mod.FalconClient(mod.CLOUD_REGIONS["us-gov-1"], "id", "secret")
    client.reported_region = "us-2"
    assert mod.cloud_provenance(client) == {
        "api_base_url": "https://api.laggar.gcw.crowdstrike.com",
        "cloud_region": "us-gov-1",
        "reported_cloud_region": "us-2",
    }

    double = mod.FalconClient("http://127.0.0.1:8787", "id", "secret")
    assert mod.cloud_provenance(double)["cloud_region"] is None


# --- vendor schema conformance ------------------------------------------------
#
# The tests above prove the fetchers agree with the test double. These prove the
# fetchers agree with CrowdStrike, which is a different and stronger claim: the
# double was hand-written from the same assumptions as the fetchers, so the two
# can be wrong together. Field names here are checked against a snapshot of
# CrowdStrike's own OpenAPI-generated models (see tools/crowdstrike_schema_check.py).

SCHEMA_SNAPSHOT = json.loads(
    (Path(__file__).resolve().parents[1] / "tools" / "crowdstrike_schema_snapshot.json").read_text()
)

# The response fields each fetcher's analysis actually depends on. Not every
# field it touches — the ones where a wrong name silently produces an empty or
# misleading summary rather than an error.
LOAD_BEARING_FIELDS = {
    "hosts": [
        "device_id", "hostname", "platform_name", "os_version", "agent_version",
        "last_seen", "status", "product_type_desc", "reduced_functionality_mode",
    ],
    "spotlight_vulnerabilities": [
        "id", "cve", "host_info", "remediation", "status", "created_timestamp",
        "severity", "exprt_rating", "exploit_status", "hostname", "aid", "entities",
    ],
    "detections": [
        "composite_id", "status", "severity_name", "tactic", "technique",
        "created_timestamp", "updated_timestamp", "device", "product",
    ],
    "prevention_policies": [
        "id", "name", "platform_name", "enabled", "groups", "prevention_settings",
        "settings", "value",
    ],
    "zero_trust_assessment": [
        "cid", "platforms", "name", "audit", "average_overall_score", "num_aids",
    ],
    # Split out from the audit above: `aid` and `score` belong to the per-host
    # score records, which are a different model on a different endpoint.
    # Listing them under the audit made two shapes look like one.
    "zero_trust_assessment_hosts": ["aid", "score"],
    "filevantage": [
        "id", "action_type", "entity_type", "entity_path", "action_timestamp",
        "severity", "is_suppressed", "host", "policy", "name",
    ],
    "firewall_policies": [
        "id", "name", "platform_name", "enabled", "groups",
    ],
    # The fields the enforcement verdict actually turns on live on the policy
    # container, a different model on a different API family. Kept separate so
    # a name drifting there cannot hide behind the policy's own field list.
    "firewall_policy_containers": [
        "policy_id", "enforce", "test_mode", "local_logging",
        "default_inbound", "default_outbound", "rule_group_ids",
    ],
    "firewall_rule_groups": [
        "id", "name", "enabled", "rule_ids", "policy_ids",
    ],
    "firewall_rules": [
        "id", "name", "enabled", "action", "direction", "protocol",
        "fqdn_enabled", "monitor",
    ],
}


@pytest.mark.parametrize("fetcher", sorted(LOAD_BEARING_FIELDS))
def test_fields_exist_in_vendor_schema(fetcher: str) -> None:
    """
    Every field the fetcher relies on must appear in CrowdStrike's published
    schema for the endpoints it calls.

    This is what caught the Zero Trust Assessment bug: the fetcher read
    `assessment_items`, `policy_rule`, `requires_remediation` and
    `sensor_config_status`, none of which exist anywhere in the ZTA models. The
    mock happily served them because it had been written to match the fetcher.
    """
    known: set = set()
    for fields in SCHEMA_SNAPSHOT[fetcher].values():
        known.update(fields)

    unknown = [f for f in LOAD_BEARING_FIELDS[fetcher] if f not in known]
    assert not unknown, (
        f"{fetcher} reads field(s) absent from CrowdStrike's schema: {unknown}. "
        "Either the name is wrong or the model list in "
        "tools/crowdstrike_schema_check.py needs the owning model added."
    )


# --- structural conformance to CrowdStrike's schema ---------------------------
#
# The strongest offline check available, and the only one that reaches
# prevention_policies and zero_trust_assessment — neither has any publicly
# recorded response to test against.
#
# Field names alone are not enough: the ZTA bug was a wrong *shape*, not a wrong
# name. These validate types, enum membership and nested object structure
# against models generated from CrowdStrike's own OpenAPI spec.


def _schema_module() -> Any:
    return _load_module(REPO_ROOT / "tools" / "crowdstrike_schema.py", "cs_schema")


@pytest.mark.parametrize("fetcher", sorted(LOAD_BEARING_FIELDS))
def test_mock_fixtures_conform_to_vendor_schema(fetcher: str) -> None:
    """
    Every fixture the test double serves must be a structurally legal instance
    of the model CrowdStrike says that endpoint returns.

    Without this, a fixture is only evidence that it agrees with the fetcher
    written beside it — which is how a wrong ZTA shape passed every test.
    """
    schema = _schema_module()
    mock = _load_module(MOCK_PATH, "crowdstrike_mock_schema_check")

    fixtures = {
        "hosts": mock._devices,
        "spotlight_vulnerabilities": mock._vulnerabilities,
        "detections": mock._alerts,
        "prevention_policies": mock._prevention_policies,
        "zero_trust_assessment": mock._zta_audit,
        # The Zero Trust fetcher consumes two different record shapes. Only the
        # audit was checked here; the host scores went unvalidated until the
        # audit bug prompted a look at what else had been missed.
        "zero_trust_assessment_hosts": mock._host_assessments,
        "filevantage": mock._filevantage_changes,
        "firewall_policies": mock._firewall_policies,
        "firewall_policy_containers": mock._firewall_containers,
        "firewall_rule_groups": mock._firewall_rule_groups,
        "firewall_rules": mock._firewall_rules,
    }

    models = schema.load_models()
    problems: list = []
    for index, record in enumerate(fixtures[fetcher]()):
        problems += schema.validate(record, schema.ROOT_MODELS[fetcher], models, f"[{index}]")

    assert not problems, f"{fetcher} fixtures violate CrowdStrike's schema:\n" + "\n".join(problems)


def test_prevention_setting_types_are_legal_enum_values() -> None:
    """
    CrowdStrike documents exactly two setting types — `toggle` and `mlslider` —
    and `classify_setting` branches on their value shapes. A third type would
    fall through to `bool(value)`, which is truthy for any non-empty dict and so
    would silently report an unknown setting as enabled.
    """
    schema = _schema_module()
    models = schema.load_models()

    setting_type = models["PreventionSettingRespV1"]["type"]
    assert setting_type["enum"] == ["toggle", "mlslider"]

    mock = _load_module(MOCK_PATH, "crowdstrike_mock_enum_check")
    seen = {
        setting.get("type")
        for policy in mock._prevention_policies()
        for category in policy.get("prevention_settings", [])
        for setting in category.get("settings", [])
    }
    assert seen <= {"toggle", "mlslider"}, f"fixture uses undocumented setting types: {seen}"
    assert seen == {"toggle", "mlslider"}, "fixtures should exercise both documented types"


def test_partial_success_is_not_reported_as_clean(mock_server: str, tmp_path: Path) -> None:
    """
    Falcon signals a partial result as HTTP 200 with a populated `errors[]`, not
    as a non-2xx status. `raise_for_status()` sees nothing wrong, so without an
    explicit check the fetcher reports success over evidence that is quietly
    short — fewer findings than the tenant has, presented as a clean result.

    Verified against CrowdStrike's own response models, where every response
    type carries `errors` alongside `resources`.
    """
    # The switch is read by the mock, which runs in *this* process — putting it
    # in the fetcher's environment would set it on the wrong side of the socket.
    os.environ["CROWDSTRIKE_MOCK_PARTIAL_ERRORS"] = "1"
    try:
        code, payload = _run_fetcher("hosts", mock_server, tmp_path)
    finally:
        os.environ.pop("CROWDSTRIKE_MOCK_PARTIAL_ERRORS", None)

    assert code != 0, "partial success exited 0 and looked like a clean run"
    assert payload["api_failures"], "partial errors were swallowed"
    assert any(f.get("partial") for f in payload["api_failures"])
    assert payload["api_failures"][0]["api_errors"][0]["code"] == 207


# --- pagination metadata, against the vendor's own paging models --------------


def test_pagination_field_names_match_vendor_models() -> None:
    """
    Each paginator reads `meta.pagination.<field>`, and a wrong name there does
    not raise — it ends the loop after page one, silently truncating evidence to
    the first few hundred records. On a small tenant that looks like success.

    Checked against the three paging models CrowdStrike actually returns:

      devices-scroll        DeviceapiDevicePagingV2  offset (string token)
      spotlight/combined    DomainAPIQueryPagingV1   after  (string cursor)
      alerts/queries        MsaPaging                offset (int) + total
    """
    schema = _schema_module()
    models = schema.load_models()

    expected = {
        "DeviceapiDevicePagingV2": "offset",
        "DomainAPIQueryPagingV1": "after",
        "MsaPaging": "offset",
    }
    for model, field in expected.items():
        assert model in models, f"{model} missing from the schema snapshot"
        assert field in models[model], f"{model} has no {field!r}; paginator would stall"

    # The scroll cursor is an opaque string, not an integer index. The client
    # passes it straight back, which is only correct because it never does
    # arithmetic on it.
    assert models["DeviceapiDevicePagingV2"]["offset"]["scalar"] == "string"
    assert models["MsaPaging"]["offset"]["scalar"] in ("int32", "int64", "int")
    assert models["MsaPaging"]["total"]["scalar"] in ("int32", "int64", "int")


def test_mock_envelope_is_a_legal_falcon_response() -> None:
    """
    The mock's envelope is the one part of a response the corpus cannot check —
    recorded captures are individual records, already unwrapped. So it is
    checked against MsaMetaInfo instead, which requires both `query_time` and
    `trace_id`.
    """
    schema = _schema_module()
    models = schema.load_models()
    mock = _load_module(MOCK_PATH, "crowdstrike_mock_envelope_check")

    body = mock.envelope([], pagination={"offset": "abc", "limit": 100, "total": 0})

    assert set(body) == {"meta", "errors", "resources"}
    for field, spec in models["MsaMetaInfo"].items():
        if spec["required"]:
            assert field in body["meta"], f"envelope meta missing required {field}"


def test_every_endpoint_exists_in_the_vendor_sdk() -> None:
    """
    Each path and HTTP verb a fetcher calls must be a real CrowdStrike
    operation.

    A wrong URL or verb cannot be caught by the test double — the double is
    written to answer whatever the fetcher asks. It surfaces only as a 404 or
    405 against a live tenant, which is precisely the feedback loop we do not
    have. Checked instead against the operation table in CrowdStrike's Go SDK.
    """
    schema = _schema_module()
    endpoints = schema.load_endpoints()
    assert endpoints, "endpoint table missing from the snapshot; run --refresh"

    used = {
        "GET /devices/queries/devices-scroll/v1": "hosts, id query",
        "POST /devices/entities/devices/v2": "hosts, entity lookup",
        "GET /spotlight/combined/vulnerabilities/v1": "spotlight",
        "GET /alerts/queries/alerts/v2": "detections, id query",
        "POST /alerts/entities/alerts/v2": "detections, entity lookup",
        "GET /policy/combined/prevention/v1": "prevention policies",
        "GET /zero-trust-assessment/entities/audit/v1": "zta, tenant audit",
        "GET /zero-trust-assessment/queries/assessments/v1": "zta, per-host scores",
    }

    missing = {call: why for call, why in used.items() if call not in endpoints}
    assert not missing, f"endpoints not present in CrowdStrike's SDK: {missing}"


def test_alerts_entity_lookup_uses_the_documented_body_key() -> None:
    """
    `POST /alerts/entities/alerts/v2` takes `composite_ids`, not `ids`. Alerts
    are keyed by composite ID (`<cid>:ind:<id>`) rather than the plain resource
    ID used elsewhere in Falcon, and the wrong key returns an empty result
    rather than an error — every alert would silently vanish from the evidence.

    Confirmed against DetectsapiPostEntitiesAlertsV2Request, where the field is
    `composite_ids` and required.
    """
    schema = _schema_module()
    models = schema.load_models()

    request_model = models.get("DetectsapiPostEntitiesAlertsV2Request")
    assert request_model, "request model missing from the snapshot"
    assert "composite_ids" in request_model
    assert request_model["composite_ids"]["required"] is True

    detections = _load_module(FETCHER_ROOT / "detections" / "fetcher.py", "cs_detections_body")
    assert detections.ENTITY_BODY_KEY == "composite_ids"


# --- filevantage summary ------------------------------------------------------


def test_filevantage_counts_elevated_changes(mock_server: str, tmp_path: Path) -> None:
    """
    A permissions or ownership change on a monitored file is the kind a reviewer
    looks at first; an ordinary content write is not. Counting every change
    equally buries the two that matter among the rest.

    The fixtures hold one PermissionsChange and one Deleted, both elevated, plus
    two ordinary writes.
    """
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["elevated_changes"] == 2
    assert analysis["changes_by_action_type"]["PermissionsChange"] == 1
    assert analysis["changes_by_action_type"]["Deleted"] == 1


def test_filevantage_reports_suppressed_changes_separately(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Falcon returns changes suppressed by a scheduled exclusion alongside the
    rest. Folding them into the headline count overstates what is actually being
    surfaced for review, and silently dropping them would hide that an exclusion
    is in force — which is itself worth an assessor's attention.
    """
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["suppressed_changes"] == 1
    # Still counted in the total: the record exists and was collected.
    assert analysis["total_changes"] == 5


def test_filevantage_counts_records_it_cannot_read(mock_server: str, tmp_path: Path) -> None:
    """
    A record that does not match the documented shape must increment a counter,
    not summarize as a zero. Zero Trust shipped an empty analysis over a valid
    response with `status: success` — a silent all-clear in a compliance tool —
    because nothing distinguished "nothing to report" from "could not read it".
    """
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["unrecognized_records"] == 1
    assert analysis["recorded_no_changes_in_window"] is False


def test_filevantage_walks_every_page(mock_server: str, tmp_path: Path) -> None:
    """
    The change query pages on an `after` cursor and the mock splits 3/2. A
    single-page read collects 3 and reports success, which is a truncated
    estate presented as a complete one.
    """
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)

    assert payload["queried_id_count"] == 5
    assert payload["record_count"] == 5


# --- firewall policy summary --------------------------------------------------


def test_firewall_enforcement_verdict_uses_the_container_not_the_policy(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `/policy/combined/firewall/v1` says a policy is enabled. It does not say
    whether it is enforced — `enforce`, `test_mode` and the default actions live
    on the policy container under `/fwmgr/`.

    Three of the four fixture policies are `enabled: true`. Only one of those is
    genuinely enforcing: the second is in test mode and the third has
    `enforce: false`. A fetcher that stopped at the first endpoint would report
    three enforcing policies over an estate restricting almost nothing.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["enabled_policies"] == 3
    assert analysis["fully_enforcing_policies"] == 1

    assert [p["name"] for p in analysis["policies_in_test_mode"]] == ["Mac Laptops - Test Mode"]
    assert [p["name"] for p in analysis["policies_not_enforcing"]] == ["Linux Build Hosts"]
    assert [p["name"] for p in analysis["enabled_but_unassigned"]] == ["Linux Build Hosts"]


def test_firewall_default_permit_is_flagged_in_both_directions(
    mock_server: str, tmp_path: Path
) -> None:
    """
    KSI-CNA-RNT is about limiting inbound *and* outbound traffic. A policy that
    denies inbound by default but permits all outbound satisfies half of it, and
    a single "default deny" boolean would score it as compliant.

    The fixtures separate the two: the Mac policy denies inbound and permits
    outbound, the Linux policy permits both.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    inbound = [p["name"] for p in analysis["policies_permissive_inbound"]]
    outbound = [p["name"] for p in analysis["policies_permissive_outbound"]]

    assert inbound == ["Linux Build Hosts"]
    assert outbound == ["Mac Laptops - Test Mode", "Linux Build Hosts"]


def test_firewall_policy_without_a_container_is_reported_not_assumed(
    mock_server: str, tmp_path: Path
) -> None:
    """
    The fourth fixture policy has no container in `/fwmgr/`, so whether it
    enforces anything is unknown. Unknown must not collapse into either answer:
    defaulting to enforcing overstates the estate, defaulting to not-enforcing
    invents a finding. It is named instead.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert [p["name"] for p in analysis["policies_missing_container"]] == ["Legacy Policy"]

    legacy = next(p for p in analysis["policies"] if p["name"] == "Legacy Policy")
    assert legacy["enforce"] is None
    assert legacy["test_mode"] is None
    # ...and it is not counted among the failures it cannot be shown to have.
    assert "Legacy Policy" not in [p["name"] for p in analysis["policies_not_enforcing"]]


def test_firewall_unknown_default_action_counts_as_permissive(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `default_inbound` is a free string in the schema, not an enum. An unfamiliar
    value must fail toward flagging it for a human rather than passing silently
    — the opposite convention would let a spelling change turn every policy
    compliant at once.
    """
    fetcher = _load_module(FETCHER_ROOT / "firewall_policies" / "fetcher.py", "cs_fw_defaults")

    assert fetcher.is_permissive("ALLOW") is True
    assert fetcher.is_permissive("SOMETHING_NEW") is True
    assert fetcher.is_permissive("") is True
    assert fetcher.is_permissive(None) is True
    assert fetcher.is_permissive("DENY") is False
    assert fetcher.is_permissive("deny") is False


def test_firewall_rule_groups_are_queried_not_derived_from_policies(
    mock_server: str, tmp_path: Path
) -> None:
    """
    A rule group attached to no policy is config sprawl worth naming, and it is
    structurally invisible if the group list is built from the policy
    containers' `rule_group_ids` — the orphan is, by definition, in none of
    them. The fetcher queries the tenant's full group list instead.

    The fixtures hold three groups, only two of which any container references.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_rule_groups"] == 3
    assert [g["name"] for g in analysis["rule_groups_not_attached_to_a_policy"]] == [
        "Retired DMZ rules"
    ]
    assert [g["name"] for g in analysis["disabled_rule_groups"]] == ["Retired DMZ rules"]


def test_firewall_rules_are_resolved_through_the_group_chain(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Rules are three hops from the policy: policy -> container -> rule group ->
    rule. Each hop is a separate endpoint, and stopping early yields a policy
    list with no evidence of what it actually permits.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_rules"] == 4
    assert analysis["rules_by_direction"] == {"IN": 2, "OUT": 2}
    assert analysis["rules_by_action"] == {"ALLOW": 3, "DENY": 1}
    assert analysis["disabled_rules"] == 1
    assert analysis["fqdn_rules"] == 1


def test_firewall_monitoring_is_read_from_the_rate_limit_not_the_objects_presence(
    mock_server: str, tmp_path: Path
) -> None:
    """
    `monitor` is not a boolean.

    gofalcon types it as FwmgrFirewallMonitoring — `{count, period_ms}`, both
    strings — and marks it `Required: true`. It is therefore present on every
    rule the API returns, whether or not match logging is switched on. Testing
    the object for truthiness counted all of them, so `monitored_rules` would
    equal `total_rules` on any real tenant regardless of the estate's actual
    configuration: a logging control reported as fully in place on the strength
    of a field that is always there.

    It passed here because the mock omitted `monitor` from three of its four
    rules — fixture and fetcher written from the same assumption, agreeing with
    each other and both disagreeing with the API. Same trap as the Zero Trust
    audit shape and the `next` cursor, reached a third way.

    The four fixtures are now: on, rate-limited to zero, on with a longer
    period, and an unparseable shape.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["total_rules"] == 4
    assert analysis["monitored_rules"] == 2
    # The unparseable one is neither monitored nor confirmed unmonitored.
    # Overstating a logging control is the dangerous direction, so it is
    # reported on its own rather than folded into either count.
    assert analysis["rules_with_unrecognized_monitor"] == 1


def test_firewall_orphan_groups_survive_a_container_that_did_not_load() -> None:
    """
    Attachment must not be derived only from the containers.

    `/fwmgr/entities/policies/v1` is a separate call with a separate scope, and
    it is allowed to fail — the fetcher already reports the case as
    `policies_missing_container`. When it did, every rule group attached to that
    policy was also reported as attached to nothing, because attachment was
    computed purely from the containers' `rule_group_ids`. A fabricated finding,
    fired by the fetcher's own already-detected failure.

    FwmgrAPIRuleGroupV1 carries `policy_ids`, the group's own back-reference.
    Here the container list is empty, so the container-derived set is empty too
    and only `policy_ids` can tell the two attached groups from the real orphan.
    """
    fw = _load_module(FETCHER_ROOT / "firewall_policies" / "fetcher.py", "cs_fw_summary")

    policies = [
        {"id": "p1", "name": "Windows", "enabled": True, "groups": [{"name": "g"}]},
        {"id": "p2", "name": "Mac", "enabled": True, "groups": [{"name": "g"}]},
    ]
    rule_groups = [
        {"id": "rgA", "name": "attached to p1", "enabled": True, "policy_ids": ["p1"]},
        {"id": "rgB", "name": "attached to p2", "enabled": True, "policy_ids": ["p2"]},
        {"id": "rgC", "name": "truly orphaned", "enabled": True, "policy_ids": []},
    ]

    analysis = fw.summarize(policies, [], rule_groups, [])

    assert [p["id"] for p in analysis["policies_missing_container"]] == ["p1", "p2"]
    assert [g["name"] for g in analysis["rule_groups_not_attached_to_a_policy"]] == [
        "truly orphaned"
    ]


def test_firewall_deleted_config_is_not_counted_as_posture() -> None:
    """
    `deleted` is Required on FwmgrAPIRuleGroupV1 and FwmgrFirewallRuleV1, so the
    API distinguishes removed config from live config and a caller that ignores
    the flag counts dead rules toward the estate. A deleted group also has no
    policies attached to it, so it would arrive as a spurious orphan on top.

    Counted rather than dropped: an evidence file that quietly discards records
    is its own problem.
    """
    fw = _load_module(FETCHER_ROOT / "firewall_policies" / "fetcher.py", "cs_fw_summary")

    rule_groups = [
        {"id": "rgA", "name": "live", "enabled": True, "policy_ids": ["p1"]},
        {"id": "rgB", "name": "removed", "enabled": True, "policy_ids": [], "deleted": True},
    ]
    rules = [
        {"id": "r1", "enabled": True, "action": "DENY", "direction": "IN", "protocol": "6"},
        {"id": "r2", "enabled": True, "action": "ALLOW", "direction": "IN",
         "protocol": "6", "deleted": True},
    ]

    analysis = fw.summarize([], [], rule_groups, rules)

    assert analysis["total_rule_groups"] == 1
    assert analysis["deleted_rule_groups"] == 1
    assert analysis["rule_groups_not_attached_to_a_policy"] == []
    assert analysis["total_rules"] == 1
    assert analysis["deleted_rules"] == 1
    assert analysis["rules_by_action"] == {"DENY": 1}


def test_no_fetcher_reads_a_nested_object_as_a_boolean() -> None:
    """
    A real field name used as the wrong kind of thing.

    The schema check answers "does this field exist?". It cannot answer "is a
    dict being read as a flag?", which is how `monitor` slipped through:
    FwmgrFirewallRuleV1.monitor is an object and `Required: true`, so testing it
    for truthiness marked every rule on a real tenant as monitored. A mock
    cannot catch that either — this one omitted the field from three of four
    fixtures, so it agreed with the fetcher and both disagreed with the API.

    The committed model dump is the independent source, and it is already in the
    repo, so this costs nothing and runs offline.
    """
    check = _load_module(REPO_ROOT / "tools" / "crowdstrike_usage_check.py", "cs_usage")
    nested = check.nested_object_fields()

    findings = []
    for path in sorted((FETCHER_ROOT).glob("*/fetcher.py")):
        for line, field, decls in check.scan(path, nested):
            findings.append(f"{path.parent.name}/fetcher.py:{line} reads {field!r} as a boolean ({', '.join(sorted(decls))})")

    assert findings == [], "\n".join(findings)


# --- boundaries and branches the mutation sweep found untested ----------------
#
# A sweep over the judgement functions scored 64%: 24 mutants survived. Several
# were not defaulting noise — they were threshold comparisons and branches that
# no fixture happened to land on. A band boundary that nothing asserts is a
# boundary that can move silently, and these bands decide what severity a real
# alert is filed under.


def test_severity_bands_at_their_exact_boundaries() -> None:
    """
    `score < ceiling` decides the band. Flipping it to `<=` moved every
    boundary value down one band and no test noticed — the mock even has an
    alert at exactly 70, the Medium/High edge, but nothing asserted the label it
    produced.

    This matters more than it looks: CrowdStrike populates `severity_name` on
    some alerts and only the numeric `severity` on others, and 64% of the real
    recorded alerts fall through to this banding. A boundary that shifts by one
    band reclassifies real findings.

    Bands are (20, Informational), (40, Low), (70, Medium), (90, High), else
    Critical — so a value equal to a ceiling belongs to the band ABOVE it.
    """
    detections = _load_module(FETCHER_ROOT / "detections" / "fetcher.py", "cs_sev_bands")
    label = lambda n: detections.severity_label({"severity": n})  # noqa: E731

    # Just below each ceiling, and exactly on it.
    assert label(0) == "Informational"
    assert label(19) == "Informational"
    assert label(20) == "Low", "a score equal to the ceiling belongs to the band above"
    assert label(39) == "Low"
    assert label(40) == "Medium"
    assert label(69) == "Medium"
    assert label(70) == "High", "70 is the Medium/High edge and the mock has an alert on it"
    assert label(89) == "High"
    assert label(90) == "Critical"
    assert label(100) == "Critical"

    # A supplied label always wins over the number, even when they disagree —
    # the recorded samples contain exactly that case.
    assert detections.severity_label({"severity": 10, "severity_name": "Critical"}) == "Critical"
    # Neither readable.
    assert detections.severity_label({}) == "unknown"
    # A bool is not a score. `True` would otherwise band as Informational.
    assert detections.severity_label({"severity": True}) == "unknown"


def test_is_monitored_distinguishes_absent_from_unrecognized() -> None:
    """
    Three outcomes, not two: monitored, not monitored, and unreadable.

    A rule with **no** `monitor` object is answerably not monitored (False). A
    rule whose monitor is a shape we do not recognize is unknown (None) — and
    the difference decides whether it lands in `monitored_rules` or in
    `rules_with_unrecognized_monitor`.

    Every mock rule carries a monitor object, so the absent branch had never
    run. A mutation swapping `is` for `is not` inverted the two and survived.
    """
    fw = _load_module(FETCHER_ROOT / "firewall_policies" / "fetcher.py", "cs_fw_monitor")

    # Absent entirely -> answerably not monitored.
    assert fw.is_monitored({}) is False
    assert fw.is_monitored({"monitor": None}) is False
    # A real monitor block, rate limit above zero -> monitored.
    assert fw.is_monitored({"monitor": {"count": "5", "period_ms": "60000"}}) is True
    # Rate-limited to nothing -> present, but logging nothing.
    assert fw.is_monitored({"monitor": {"count": "0", "period_ms": "0"}}) is False
    # Shapes we cannot read -> unknown, never guessed either way.
    assert fw.is_monitored({"monitor": {"count": "", "period_ms": ""}}) is None
    assert fw.is_monitored({"monitor": {}}) is None
    assert fw.is_monitored({"monitor": "yes"}) is None


def test_the_stale_host_threshold_is_honoured_on_both_sides() -> None:
    """
    A host either side of the configured threshold, and an unreadable timestamp.

    Note on the mutation sweep: flipping `last_seen < stale_cutoff` to `<=`
    survives this test and **cannot be killed**, because the two differ only
    when `last_seen` equals the cutoff to the microsecond — a measure-zero point
    on a wall clock that no test can land on deterministically. That is an
    equivalent mutant, not a gap, and chasing it would mean freezing time to
    assert behaviour nobody can observe.

    What is worth pinning is the threshold either side of that point, and that
    a host whose `last_seen` cannot be parsed is counted as unknown rather than
    quietly treated as fresh — a host reporting nothing is the one most worth
    looking at, and defaulting it to healthy is the dangerous direction.
    """
    hosts = _load_module(FETCHER_ROOT / "hosts" / "fetcher.py", "cs_hosts_cutoff")
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415

    now = datetime.now(timezone.utc)
    stamp = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731

    def summary(days_ago, threshold=30):
        record = {"device_id": "d1", "hostname": "h1", "last_seen": stamp(days_ago)}
        return hosts.summarize([record], threshold)

    assert [h["hostname"] for h in summary(31)["stale_hosts"]] == ["h1"]
    assert summary(29)["stale_hosts"] == []
    # The threshold is configurable, so it must actually be read.
    assert [h["hostname"] for h in summary(29, threshold=7)["stale_hosts"]] == ["h1"]
    assert summary(29, threshold=60)["stale_hosts"] == []

    # Unreadable timestamp: counted, not assumed fresh and not assumed stale.
    unreadable = hosts.summarize(
        [{"device_id": "d2", "hostname": "h2", "last_seen": "not-a-date"}], 30
    )
    assert unreadable["hosts_with_unknown_last_seen"] == 1
    assert unreadable["stale_hosts"] == []


# --- the grouping outputs nothing was asserting -------------------------------
#
# The mutation sweep's remaining survivors were almost all the same shape:
# `record.get(field) or "unknown"` inside a Counter, in an analysis field no
# test read. Mutating the `or` empties or relabels the whole grouping and every
# test passed. These are the breakdowns an assessor scans first, so they are
# exactly the wrong thing to leave unchecked.


def test_host_groupings_are_asserted(mock_server: str, tmp_path: Path) -> None:
    """Platform, status and product-type splits, plus the unreadable counter."""
    _, payload = _run_fetcher("hosts", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_platform"] == {"Linux": 3, "Windows": 1, "Mac": 1}
    assert analysis["by_status"] == {"normal": 5}
    assert analysis["by_product_type"] == {"Server": 3, "Workstation": 2}
    assert sum(analysis["by_platform"].values()) == analysis["total_hosts"]
    assert analysis["hosts_with_unknown_last_seen"] == 0


def test_detection_groupings_are_asserted(mock_server: str, tmp_path: Path) -> None:
    """
    Status, product, tactic and technique. The tactic and technique counters run
    through the spelling-normalising path that once reported
    "Credential Access" and "CredentialAccess" as two tactics at half the count
    each, so an assertion on them guards that fix as well.
    """
    _, payload = _run_fetcher("detections", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["by_status"] == {"closed": 1, "new": 1, "in_progress": 1}
    assert analysis["by_product"] == {"epp": 3}
    assert analysis["by_tactic"] == {"Defense Evasion": 1, "Execution": 1, "Discovery": 1}
    assert analysis["by_technique"] == {
        "Masquerading": 1,
        "Command and Scripting Interpreter": 1,
        "System Information Discovery": 1,
    }
    assert analysis["affected_host_count"] == 3
    assert sum(analysis["by_status"].values()) == analysis["total_detections"]


def test_policy_and_vulnerability_groupings_are_asserted(
    mock_server: str, tmp_path: Path
) -> None:
    _, prevention = _run_fetcher("prevention_policies", mock_server, tmp_path)
    assert prevention["analysis"]["by_platform"] == {"Linux": 1, "Windows": 2}

    _, spotlight = _run_fetcher("spotlight_vulnerabilities", mock_server, tmp_path)
    assert spotlight["analysis"]["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}


def test_filevantage_change_window_is_asserted(mock_server: str, tmp_path: Path) -> None:
    """
    The earliest and latest change bound the window this evidence covers, and
    both are derived through `if stamp is not None` — a mutation flipping that
    to `is None` survived, which would have compared `None` values and produced
    either a crash or a meaningless window.
    """
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["earliest_change"] == "2026-08-16T13:27:41+00:00"
    assert analysis["latest_change"] == "2026-08-18T06:40:55+00:00"
    assert analysis["earliest_change"] < analysis["latest_change"]


def test_firewall_rule_groupings_and_empty_policies_are_asserted(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Rule breakdowns, and `policies_without_rule_groups` — a policy that is
    enabled, assigned and enforcing but carries no rules at all restricts
    nothing, which is precisely the shape that looks healthy from every other
    field.
    """
    _, payload = _run_fetcher("firewall_policies", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["rules_by_action"] == {"ALLOW": 3, "DENY": 1}
    assert analysis["rules_by_direction"] == {"IN": 2, "OUT": 2}
    assert analysis["rules_by_protocol"] == {"6": 3, "ANY": 1}
    assert analysis["by_platform"] == {"Windows": 2, "Mac": 1, "Linux": 1}

    assert [p["name"] for p in analysis["policies_without_rule_groups"]] == [
        "Linux Build Hosts"
    ]


def test_filevantage_groupings_are_asserted(mock_server: str, tmp_path: Path) -> None:
    """The change breakdowns, and the top policy/host tallies."""
    _, payload = _run_fetcher("filevantage", mock_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis["changes_by_action_type"] == {
        "Written": 2, "PermissionsChange": 1, "Deleted": 1,
    }
    assert analysis["changes_by_entity_type"] == {"file": 3, "registry": 1}
    assert analysis["changes_by_severity"] == {"High": 2, "Medium": 1, "Critical": 1}
    assert analysis["top_policies"] == {"Linux Critical Config": 3, "Windows Baseline": 1}
    assert analysis["top_hosts"] == {"web-prod-01": 2, "win-app-02": 1, "db-prod-03": 1}
    # The breakdown deliberately does NOT sum to total_changes: a record whose
    # shape is not recognized is counted in `unrecognized_records` rather than
    # being filed under a type it might not have. The relationship is worth
    # pinning precisely, because "the numbers don't add up" is otherwise the
    # first thing a reviewer would query.
    assert analysis["unrecognized_records"] == 1
    assert (
        sum(analysis["changes_by_entity_type"].values())
        + analysis["unrecognized_records"]
        == analysis["total_changes"]
    )


def test_spotlight_and_host_version_groupings_are_asserted(
    mock_server: str, tmp_path: Path
) -> None:
    """
    Vulnerability rating/status/exploit splits, and the host OS and sensor
    version spread — the latter is how a reviewer sees an estate running mixed
    sensor builds, which no other field shows.
    """
    _, spotlight = _run_fetcher("spotlight_vulnerabilities", mock_server, tmp_path)
    sa = spotlight["analysis"]
    assert sa["by_exprt_rating"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1}
    assert sa["by_status"] == {"open": 2, "reopen": 1}
    assert sa["by_exploit_status"] == {"known_exploit": 2, "no_known_exploit": 1}

    _, hosts = _run_fetcher("hosts", mock_server, tmp_path)
    ha = hosts["analysis"]
    assert ha["by_os_version"] == {
        "Amazon Linux 2023": 2, "Ubuntu 22.04": 1, "Windows 11": 1, "Sequoia (15)": 1,
    }
    assert ha["by_sensor_version"] == {"7.16.18604.0": 3, "7.10.17604.0": 2}
    assert sum(ha["by_sensor_version"].values()) == ha["total_hosts"]


def test_a_group_referenced_only_by_its_container_is_not_an_orphan() -> None:
    """
    Attachment is the union of two signals, and this pins the second one.

    A rule group's own `policy_ids` is the primary source. The container's
    `rule_group_ids` is unioned in for the case where the group's own list is
    stale or empty but a policy demonstrably references it — the two signals can
    only ever add evidence of attachment, never remove it.

    Nothing exercised that fallback: every fixture group carried an accurate
    `policy_ids`, so a mutation emptying the container-derived set survived. A
    group here has an empty `policy_ids` and IS referenced by a container, so
    only the union keeps it off the orphan list.
    """
    fw = _load_module(FETCHER_ROOT / "firewall_policies" / "fetcher.py", "cs_fw_union")

    policies = [{"id": "p1", "name": "P1", "enabled": True, "groups": [{"name": "g"}]}]
    containers = [
        {"policy_id": "p1", "enforce": True, "test_mode": False,
         "default_inbound": "DENY", "default_outbound": "DENY",
         "rule_group_ids": ["rgStale"]},
    ]
    rule_groups = [
        # Says it belongs to nothing, but a container references it.
        {"id": "rgStale", "name": "stale back-reference", "enabled": True, "policy_ids": []},
        # Says nothing and nothing references it — a genuine orphan.
        {"id": "rgOrphan", "name": "real orphan", "enabled": True, "policy_ids": []},
    ]

    analysis = fw.summarize(policies, containers, rule_groups, [])

    assert [g["name"] for g in analysis["rule_groups_not_attached_to_a_policy"]] == [
        "real orphan"
    ]
