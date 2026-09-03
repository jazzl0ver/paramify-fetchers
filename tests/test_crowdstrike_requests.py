"""
Check the requests the fetchers actually put on the wire against CrowdStrike's
own parameter definitions.

Everything verified so far was about *responses* — what comes back and how it is
parsed. This is the other half: what goes out. It matters because Falcon's
handling of a bad request is mostly silent.

    a misspelled query parameter   -> ignored, so `limit` typo'd means the
                                      default page size and a wrong filter key
                                      means no filtering at all
    a `limit` over the maximum     -> 400, on first contact with a real tenant
    an illegal FQL field           -> 400, likewise

None of that is reachable through a mock, which answers whatever it is asked.
It is reachable through gofalcon's `*_parameters.go`, which lists the accepted
query parameters, the documented `limit` range and — for some endpoints — the
legal FQL filter fields.

The requests are not hardcoded here. A recording proxy sits in front of the mock
and captures every request each fetcher makes, so these tests check the traffic
the fetcher really produces rather than a second copy of my own assumptions.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "crowdstrike"
MOCK_PATH = REPO_ROOT / "tools" / "crowdstrike_mock.py"
SCHEMA_PATH = REPO_ROOT / "tools" / "crowdstrike_schema.py"

FETCHERS = [
    "hosts",
    "spotlight_vulnerabilities",
    "detections",
    "prevention_policies",
    "zero_trust_assessment",
    "filevantage",
    "firewall_policies",
]

# Optional code paths, switched on so their traffic is recorded too.
#
# The Zero Trust host-assessment query is opt-in, and leaving it off meant an
# entire endpoint went unexercised — which showed up as this file's page-size
# check passing against a deliberately broken page size, because the one
# endpoint with a low cap was never called. An opt-in path is still a shipped
# path.
FETCHER_ENV: Dict[str, Dict[str, str]] = {
    "zero_trust_assessment": {"CROWDSTRIKE_ZTA_INCLUDE_HOSTS": "true"},
}


def _load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


schema = _load_module(SCHEMA_PATH, "crowdstrike_schema_requests")
PARAMETERS: Dict[str, Any] = schema.load_parameters()
ENDPOINTS: Dict[str, str] = schema.load_endpoints()


# --- recording ----------------------------------------------------------------


class Recorder:
    """Requests captured across one fetcher run, as (method, path, query)."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Dict[str, List[str]]]] = []

    def record(self, method: str, raw_path: str) -> None:
        parsed = urlparse(raw_path)
        self.calls.append((method, parsed.path, parse_qs(parsed.query)))

    def api_calls(self) -> List[Tuple[str, str, Dict[str, List[str]]]]:
        """Everything except authentication, which is not a documented op."""
        return [c for c in self.calls if not c[1].startswith("/oauth2/")]


@pytest.fixture(scope="module")
def recorded() -> Dict[str, Recorder]:
    """Run every fetcher once against a recording mock; return the traffic.

    Module-scoped: five subprocess launches is the expensive part, and the
    assertions below are read-only over the result.
    """
    mock = _load_module(MOCK_PATH, "crowdstrike_mock_requests")
    recorder = Recorder()

    class RecordingHandler(mock.FalconMockHandler):  # type: ignore[misc,name-defined]
        def do_GET(self) -> None:  # noqa: N802
            recorder.record("GET", self.path)
            super().do_GET()

        def do_POST(self) -> None:  # noqa: N802
            recorder.record("POST", self.path)
            super().do_POST()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{httpd.server_address[1]}"

    results: Dict[str, Recorder] = {}
    try:
        import tempfile

        for name in FETCHERS:
            recorder.calls.clear()
            with tempfile.TemporaryDirectory() as evidence_dir:
                subprocess.run(
                    [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
                    env={
                        "PATH": os.environ.get("PATH", ""),
                        "HOME": os.environ.get("HOME", ""),
                        "EVIDENCE_DIR": evidence_dir,
                        "CROWDSTRIKE_API_BASE_URL": base_url,
                        "CROWDSTRIKE_CLIENT_ID": "mock-id",
                        "CROWDSTRIKE_CLIENT_SECRET": "mock-secret",
                        **FETCHER_ENV.get(name, {}),
                    },
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            captured = Recorder()
            captured.calls = list(recorder.calls)
            results[name] = captured
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)

    return results


# --- the requests are real ----------------------------------------------------


def test_every_fetcher_actually_called_the_api(recorded: Dict[str, Recorder]) -> None:
    """Guard against the whole suite passing vacuously.

    If a fetcher failed to start, or the recorder were wired up wrong, every
    assertion below would hold over an empty list and report success. This is
    the test that has to fail first if that happens.
    """
    for name in FETCHERS:
        assert recorded[name].api_calls(), f"{name} made no API calls — recording is broken"


# --- endpoints ----------------------------------------------------------------


@pytest.mark.parametrize("name", FETCHERS)
def test_requested_endpoints_exist_in_the_vendor_sdk(
    name: str, recorded: Dict[str, Recorder]
) -> None:
    """Every path+verb pair a fetcher uses is a real CrowdStrike operation.

    The earlier version of this check read the path constants out of the source.
    This one watches the socket, so a path assembled at runtime is covered too.
    """
    for method, path, _ in recorded[name].api_calls():
        assert f"{method} {path}" in ENDPOINTS, (
            f"{name} called {method} {path}, which is not a gofalcon operation"
        )


# --- query parameters ---------------------------------------------------------


@pytest.mark.parametrize("name", FETCHERS)
def test_query_parameters_are_accepted_by_the_endpoint(
    name: str, recorded: Dict[str, Recorder]
) -> None:
    """
    Every query parameter sent is one the endpoint accepts.

    This is the check with the least visible failure mode in production. Falcon
    does not reject an unknown query parameter — it ignores it. A fetcher
    sending `fitler=...` would collect the entire estate unfiltered and report
    success, and nothing short of reading the evidence by hand would show it.
    """
    for method, path, query in recorded[name].api_calls():
        endpoint = f"{method} {path}"
        spec = PARAMETERS.get(endpoint)
        if spec is None:
            pytest.skip(f"no parameter definition for {endpoint}")

        accepted = set(spec["query"])
        for param in query:
            assert param in accepted, (
                f"{name} sends {param!r} to {endpoint}, which accepts {sorted(accepted)}. "
                "Falcon ignores unknown query parameters rather than rejecting them."
            )


@pytest.mark.parametrize("name", FETCHERS)
def test_page_sizes_are_within_the_documented_maximum(
    name: str, recorded: Dict[str, Recorder]
) -> None:
    """
    `limit` is capped per endpoint and the caps differ — 10000 for the device
    scroll and the alerts query, 5000 for Spotlight and prevention policies, but
    only **1000** for the Zero Trust assessment query.

    The three paginators in the shared client each carry one default page size
    that is used for every endpoint of that pagination style, so raising a
    default to suit one endpoint can silently exceed another's cap. That is a
    400 on first contact with a live tenant, which is exactly the feedback this
    project does not have.
    """
    for method, path, query in recorded[name].api_calls():
        endpoint = f"{method} {path}"
        spec = PARAMETERS.get(endpoint)
        if spec is None or spec["limit_max"] is None or "limit" not in query:
            continue

        limit = int(query["limit"][0])
        assert limit <= spec["limit_max"], (
            f"{name} asks {endpoint} for {limit} records; the documented maximum "
            f"is {spec['limit_max']}"
        )
        assert limit >= 1, f"{name} sends a non-positive limit to {endpoint}"


# --- FQL ----------------------------------------------------------------------


# Field names are the bit before a colon, once quoted values are removed — those
# contain colons of their own (`created_timestamp:>'2026-01-01T00:00:00Z'`).
QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
FQL_FIELD = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*:")


def fql_fields(expression: str) -> List[str]:
    return FQL_FIELD.findall(QUOTED.sub("''", expression))


def test_the_fql_field_parser_is_not_fooled_by_timestamps() -> None:
    """The parser this file's real check depends on, checked itself.

    A naive split on ':' reads `2026-01-01T00` and `00` out of a timestamp and
    reports them as illegal fields — a failing test for a correct filter, which
    would most likely be resolved by weakening the check.
    """
    assert fql_fields("created_timestamp:>'2026-01-01T00:00:00Z'") == ["created_timestamp"]
    assert fql_fields("status:['open','reopen']") == ["status"]
    assert fql_fields("cve.id:'CVE-2024-1'+host_info.platform_name:'Windows'") == [
        "cve.id",
        "host_info.platform_name",
    ]


@pytest.mark.parametrize("name", FETCHERS)
def test_fql_filter_fields_are_legal_for_the_endpoint(
    name: str, recorded: Dict[str, Recorder]
) -> None:
    """
    Filters are typed as a bare string in the SDK, so nothing checks them at
    compile time and I had recorded them as unverifiable without a tenant. That
    was only half right: CrowdStrike documents the legal filter fields in the
    parameter comment, and where that list is complete it can be asserted
    against offline.

    Only Spotlight documents a complete list today. The alerts endpoint says the
    set is "extensive" and names a few examples, so its list is marked
    incomplete and skipped — asserting against a partial list would fail correct
    filters.
    """
    checked = 0
    for method, path, query in recorded[name].api_calls():
        spec = PARAMETERS.get(f"{method} {path}")
        if spec is None or not spec["filter_fields_are_complete"] or "filter" not in query:
            continue

        legal = set(spec["filter_fields"])
        for field in fql_fields(query["filter"][0]):
            assert field in legal, (
                f"{name} filters {method} {path} on {field!r}, which is not a "
                f"documented filter field. Legal fields: {sorted(legal)}"
            )
            checked += 1

    if not checked:
        pytest.skip(f"{name} sends no filter to an endpoint with a complete field list")


def test_spotlight_facets_are_documented_values() -> None:
    """
    Facets decide whether the CVE, host and remediation blocks come back at all.
    An unrecognised facet name yields a response missing that block, and the
    summary then reports zero of whatever it was counting — a wrong number
    rather than an error.
    """
    fetcher = _load_module(FETCHER_ROOT / "spotlight_vulnerabilities" / "fetcher.py", "cs_spot")
    documented = {"host_info", "remediation", "cve", "evaluation_logic"}

    assert set(fetcher.FACETS) <= documented, (
        f"undocumented facet(s): {set(fetcher.FACETS) - documented}"
    )


# --- request bodies -----------------------------------------------------------


def test_entity_lookups_use_a_body_where_the_endpoint_expects_one(
    recorded: Dict[str, Recorder]
) -> None:
    """
    Both entity lookups are POSTs that take their IDs in a JSON body. Sending
    them as a query string instead returns an empty result rather than an error,
    so every record would silently vanish from the evidence.
    """
    for name in ("hosts", "detections"):
        posts = [
            (method, path, query)
            for method, path, query in recorded[name].api_calls()
            if method == "POST"
        ]
        assert posts, f"{name} made no POST — the entity lookup did not run"

        for method, path, query in posts:
            spec = PARAMETERS.get(f"{method} {path}")
            assert spec is not None and spec["takes_body"], (
                f"{name} POSTs to {path}, which takes no request body"
            )
            assert "ids" not in query and "composite_ids" not in query, (
                f"{name} put IDs in the query string of {path} instead of the body"
            )


# --- least privilege ----------------------------------------------------------

# The Falcon scope a path belongs to, from falconpy's service-collection field.
# Console scope names follow the collection: hosts -> "Hosts", alerts ->
# "Alerts", and so on. Read is sufficient for all of them.
ENDPOINT_SCOPES = {
    "/devices/queries/devices-scroll/v1": "hosts",
    "/devices/entities/devices/v2": "hosts",
    "/alerts/queries/alerts/v2": "alerts",
    "/policy/combined/prevention/v1": "prevention_policies",
    "/alerts/entities/alerts/v2": "alerts",
    "/spotlight/combined/vulnerabilities/v1": "spotlight_vulnerabilities",
    "/zero-trust-assessment/entities/audit/v1": "zero_trust_assessment",
    "/zero-trust-assessment/queries/assessments/v1": "zero_trust_assessment",
    "/filevantage/queries/changes/v3": "filevantage",
    "/filevantage/entities/changes/v2": "filevantage",
    # Two scopes, not one: the policy list is served by Falcon's policy API and
    # everything that says whether the policy is enforced is served by the
    # firewall management API. An API client issued only the first reads the
    # policies and 403s on the fields the evidence turns on.
    "/policy/combined/firewall/v1": "firewall_policies",
    "/fwmgr/queries/rule-groups/v1": "firewall_management",
    "/fwmgr/entities/policies/v1": "firewall_management",
    "/fwmgr/entities/rule-groups/v1": "firewall_management",
    "/fwmgr/entities/rules/v1": "firewall_management",
}

# GET reads; POST here is only ever a batched entity lookup, whose IDs are too
# numerous for a query string. Falcon's mutating verbs on these same paths
# (PATCH /alerts/entities/alerts/v2 updates alert status) require a Write scope.
READ_ONLY_VERBS = {"GET", "POST"}


def test_no_fetcher_uses_a_mutating_verb(recorded: Dict[str, Recorder]) -> None:
    """
    An evidence collector must never write to the tenant it is measuring, and
    the API client it runs as should be issued Read scopes only. PATCH, PUT and
    DELETE all exist on paths these fetchers already call — PATCH on the alerts
    entity path is one character away in falconpy's own table — so this is a
    plausible slip, not a hypothetical one. It would also fail confusingly at
    runtime rather than obviously: a Read-scoped client gets a 403.
    """
    for name in FETCHERS:
        for method, path, _ in recorded[name].api_calls():
            assert method in READ_ONLY_VERBS, (
                f"{name} used {method} on {path}; evidence collection is read-only "
                "and the API client is scoped Read"
            )


def test_every_called_path_maps_to_a_known_scope(recorded: Dict[str, Recorder]) -> None:
    """
    The credential guide tells an operator exactly which scopes to tick when
    creating the API client, and a missing scope is a 403 at collection time —
    after the trial clock has started. If a fetcher reaches a path absent from
    that list, the documentation is now wrong.
    """
    for name in FETCHERS:
        for _, path, _ in recorded[name].api_calls():
            assert path in ENDPOINT_SCOPES, (
                f"{name} called {path}, which is not in the documented scope list"
            )
