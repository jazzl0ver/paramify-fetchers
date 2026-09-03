"""
Exercise the crowdstrike client's failure handling.

The shared client carries a retry loop with backoff, a page cap, a stalled-cursor
guard and structured failure reporting. All of it was written against
CrowdStrike's documented behaviour and **none of it had ever run**: a happy-path
test double never rate-limits, never revokes a token, and never returns a cursor
that fails to advance.

Untested error handling is the kind that fails when it is finally needed — on a
large estate, mid-collection, against a live tenant nobody can debug against. So
the mock grows fault injection and these tests drive each path.

Every test here asserts the *observable contract* the runner depends on: exit
code, `api_failures`, and that an evidence file is written either way.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "crowdstrike"
MOCK_PATH = REPO_ROOT / "tools" / "crowdstrike_mock.py"


def _load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def server() -> Iterator[Any]:
    """
    Function-scoped, unlike the other suites' module-scoped server.

    Fault injection is per-run state (the rate-limit budget is consumed), so a
    shared server would leak one test's faults into the next.
    """
    mock = _load_module(MOCK_PATH, "crowdstrike_mock_resilience")
    mock.FalconMockHandler._rate_limited = {}

    # Threading, not the plain HTTPServer the other suites use. Retries make the
    # client open a second connection while the first is still held open by
    # HTTP/1.1 keep-alive, and a single-threaded server blocks its accept loop
    # on the idle connection — the request never gets served and the test hangs.
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), mock.FalconMockHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def run(name: str, base_url: str, evidence_dir: Path, **extra: str) -> tuple:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "EVIDENCE_DIR": str(evidence_dir),
        "CROWDSTRIKE_API_BASE_URL": base_url,
        "CROWDSTRIKE_CLIENT_ID": "mock-id",
        "CROWDSTRIKE_CLIENT_SECRET": "mock-secret",
        **extra,
    }
    result = subprocess.run(
        [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
        env=env, capture_output=True, text=True, timeout=120,
    )
    output = evidence_dir / f"crowdstrike_{name}.json"
    payload = json.loads(output.read_text()) if output.exists() else None
    return result.returncode, payload


@pytest.fixture
def mock_env() -> Iterator[None]:
    """Fault switches are read by the mock, which runs in this process — so they
    go in this environment, not the fetcher subprocess's."""
    keys = (
        "CROWDSTRIKE_MOCK_RATE_LIMIT",
        "CROWDSTRIKE_MOCK_FORBID",
        "CROWDSTRIKE_MOCK_ENDLESS",
        "CROWDSTRIKE_MOCK_PARTIAL_ERRORS",
        "CROWDSTRIKE_MOCK_REGION",
    )
    try:
        yield
    finally:
        for key in keys:
            os.environ.pop(key, None)


# --- rate limiting ------------------------------------------------------------


def test_rate_limited_requests_are_retried_and_succeed(
    server: str, tmp_path: Path, mock_env: None
) -> None:
    """
    Falcon rate-limits per API client, and a large estate will hit it. The
    client retries 429 with backoff honouring `Retry-After`; without that a
    collection simply fails partway and reports an incomplete estate.

    Two 429s per path, then success — the run must come back clean, not merely
    not crash.
    """
    os.environ["CROWDSTRIKE_MOCK_RATE_LIMIT"] = "2"

    code, payload = run("hosts", server, tmp_path)

    assert code == 0, "retry did not recover from rate limiting"
    assert payload["status"] == "success"
    assert payload["api_failures"] == []
    assert payload["analysis"]["total_hosts"] == 5, "retry lost records"


def test_retry_gives_up_and_reports_rather_than_hanging(
    server: str, tmp_path: Path, mock_env: None
) -> None:
    """
    Retry is bounded. Past the budget the client must record a failure and exit
    non-zero — an unbounded retry against a persistently limited tenant would
    hang the whole run with no evidence written.
    """
    os.environ["CROWDSTRIKE_MOCK_RATE_LIMIT"] = "999"

    code, payload = run("hosts", server, tmp_path)

    assert code != 0
    assert payload is not None, "no evidence written on give-up"
    assert payload["api_failures"], "gave up without recording why"


# --- unlicensed modules -------------------------------------------------------


def test_unlicensed_module_fails_loudly(server: str, tmp_path: Path, mock_env: None) -> None:
    """
    Spotlight and Zero Trust Assessment are separately licensed. A tenant
    without the licence gets 403 even with the scope granted.

    This pins the deliberate design decision: **fail, do not degrade quietly.**
    An empty Spotlight result reads as "no vulnerabilities", which is the most
    dangerous possible misreport in a compliance tool. If that decision is ever
    reversed, this test should be the thing that argues with you.
    """
    os.environ["CROWDSTRIKE_MOCK_FORBID"] = "/spotlight/combined/vulnerabilities/v1"

    code, payload = run("spotlight_vulnerabilities", server, tmp_path)

    assert code != 0, "unlicensed module reported success"
    assert payload is not None, "no evidence written for a 403"
    assert payload["api_failures"], "403 was swallowed"

    blob = json.dumps(payload["api_failures"])
    assert "403" in blob, "the failure does not identify itself as a 403"

    # And critically: it must not look like a clean empty result.
    assert payload.get("analysis", {}).get("total_findings", 0) == 0
    assert payload["status"] != "success"


# --- pagination safety --------------------------------------------------------


def test_endless_cursor_is_capped_not_spun(server: str, tmp_path: Path, mock_env: None) -> None:
    """
    A cursor that never advances would loop forever. The client caps pages and
    records hitting the cap as a collection failure rather than silently
    truncating — truncated evidence that reports success is indistinguishable
    from a small estate.
    """
    os.environ["CROWDSTRIKE_MOCK_ENDLESS"] = "1"

    code, payload = run("hosts", server, tmp_path)

    assert payload is not None
    assert payload["api_failures"], "page cap hit without recording a failure"
    assert code != 0, "truncated collection reported success"


# --- token handling -----------------------------------------------------------


def test_expired_token_is_renewed_mid_collection(server: str, tmp_path: Path) -> None:
    """
    Falcon bearer tokens last ~30 minutes and the client renews a minute before
    expiry. Forcing the margin to exceed the lifetime makes every call re-auth,
    which proves the renewal path works rather than assuming it.
    """
    client = _load_module(FETCHER_ROOT / "_shared" / "falcon_client.py", "cs_client_renew")

    os.environ.update(
        CROWDSTRIKE_API_BASE_URL=server,
        CROWDSTRIKE_CLIENT_ID="mock-id",
        CROWDSTRIKE_CLIENT_SECRET="mock-secret",
    )
    try:
        falcon = client.build_client()
        falcon.authenticate()
        assert falcon._token, "no token after initial authentication"

        # Expire it by hand, exactly as the clock would.
        falcon._token_expires_at = 0.0
        body = falcon.request("GET", "/devices/queries/devices-scroll/v1")

        assert body is not None, "request failed after the token expired"
        assert falcon._token, "no token after renewal"
        assert falcon._token_expires_at > 0, "expiry was not refreshed"
        assert falcon.api_failures == [], "renewal recorded a failure"
    finally:
        for key in ("CROWDSTRIKE_API_BASE_URL", "CROWDSTRIKE_CLIENT_ID",
                    "CROWDSTRIKE_CLIENT_SECRET"):
            os.environ.pop(key, None)


# --- cloud provenance ---------------------------------------------------------


def test_govcloud_tenant_is_recorded_in_the_evidence(
    server: str, tmp_path: Path, mock_env: None
) -> None:
    """
    A FedRAMP package has to show its evidence came from GovCloud rather than
    the commercial cloud. The manifest's own region is a claim, not proof — the
    tenant states its cloud in X-CS-Region at auth, and that is what lands in
    the evidence. Driven end-to-end through a fetcher subprocess because this
    header is read during authentication, before any collection runs.
    """
    os.environ["CROWDSTRIKE_MOCK_REGION"] = "us-gov-1"

    code, payload = run("hosts", server, tmp_path)

    assert code == 0
    assert payload["cloud"]["reported_cloud_region"] == "us-gov-1"
    # The base URL here is a test double, so there is no configured region to
    # report — the two fields must not be conflated.
    assert payload["cloud"]["cloud_region"] is None
    assert payload["cloud"]["api_base_url"] == server


def test_unrecognized_reported_cloud_is_kept_not_dropped(
    server: str, tmp_path: Path, mock_env: None
) -> None:
    """
    A cloud this code has never heard of is still a fact about where the
    evidence came from. Silently dropping it would leave the field empty and
    indistinguishable from a server that never sent one.
    """
    os.environ["CROWDSTRIKE_MOCK_REGION"] = "us-4"

    code, payload = run("hosts", server, tmp_path)

    assert code == 0
    assert payload["cloud"]["reported_cloud_region"] == "us-4"
