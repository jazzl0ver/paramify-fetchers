"""
Run the crowdstrike fetchers over REAL recorded CrowdStrike responses.

The sibling suite (``test_crowdstrike_fetchers.py``) proves the fetchers are
self-consistent with a hand-written test double. That is a weaker claim than it
looks: the double was written from the same assumptions as the fetchers, so the
two can be — and were — wrong together. Two bugs shipped that way.

This suite closes that gap. ``tools/crowdstrike_corpus.py`` downloads response
captures committed by organisations that ship CrowdStrike integrations, and
these tests drive the fetchers over that data, end to end through the mock's
HTTP layer so pagination, batched entity lookup and the summary maths all run
against records CrowdStrike really produced.

Nothing is vendored: the corpus is gitignored and downloaded on demand. Without
it every test here **skips**, so CI stays offline.

    python tools/crowdstrike_corpus.py
    pytest tests/test_crowdstrike_real_responses.py -v
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import threading
from http.server import HTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FETCHER_ROOT = REPO_ROOT / "fetchers" / "crowdstrike"
CORPUS_DIR = REPO_ROOT / "tests" / "fixtures" / "crowdstrike_corpus"

# Fetchers with real recorded data available. Prevention policies and ZTA have
# no public capture, so they keep the built-in fixtures and are not asserted on
# here — an honest gap, not a silent one.
COVERED = ["hosts", "spotlight_vulnerabilities", "detections"]

pytestmark = pytest.mark.skipif(
    not CORPUS_DIR.exists() or not any(CORPUS_DIR.glob("*.ndjson")),
    reason="no response corpus; run: python tools/crowdstrike_corpus.py",
)


def corpus_records(fetcher: str) -> List[Dict[str, Any]]:
    """Every recorded record for one fetcher, across all its source files."""
    records: List[Dict[str, Any]] = []
    for path in sorted(CORPUS_DIR.glob("*.ndjson")):
        doc = json.loads(path.read_text())
        if doc.get("fetcher") == fetcher:
            records.extend(doc.get("records") or [])
    return records


@pytest.fixture(scope="module")
def corpus_server() -> Iterator[str]:
    """
    Serve the corpus over the mock's HTTP layer.

    The mock reads CROWDSTRIKE_MOCK_CORPUS lazily and caches per directory, so
    setting it here is enough — no reload, and no dependence on whether another
    test module imported the mock first.
    """
    os.environ["CROWDSTRIKE_MOCK_CORPUS"] = str(CORPUS_DIR)
    sys.path.insert(0, str(REPO_ROOT / "tools"))

    mock = importlib.import_module("crowdstrike_mock")
    assert mock.corpus(), "corpus present on disk but the mock loaded none"

    server = HTTPServer(("127.0.0.1", 0), mock.FalconMockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        os.environ.pop("CROWDSTRIKE_MOCK_CORPUS", None)


def run_fetcher(name: str, base_url: str, evidence_dir: Path) -> tuple:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "EVIDENCE_DIR": str(evidence_dir),
        "CROWDSTRIKE_API_BASE_URL": base_url,
        "CROWDSTRIKE_CLIENT_ID": "mock-id",
        "CROWDSTRIKE_CLIENT_SECRET": "mock-secret",
        # The corpus is historical, so a default "last 7 days" window would
        # filter everything out. The mock does not enforce FQL, but the fetcher
        # still computes the window, so widen it for realism.
        "CROWDSTRIKE_DETECTION_LOOKBACK_DAYS": "3650",
    }
    result = subprocess.run(
        [sys.executable, str(FETCHER_ROOT / name / "fetcher.py")],
        env=env, capture_output=True, text=True, timeout=120,
    )
    output = evidence_dir / f"crowdstrike_{name}.json"
    payload = json.loads(output.read_text()) if output.exists() else None
    return result.returncode, payload, result.stderr


# --- the corpus itself --------------------------------------------------------


def test_corpus_has_records_for_every_covered_fetcher() -> None:
    """A corpus that silently downloaded nothing would make every test below
    pass vacuously."""
    for fetcher in COVERED:
        assert corpus_records(fetcher), f"no recorded records for {fetcher}"


# --- end to end over real data ------------------------------------------------


@pytest.mark.parametrize("name", COVERED)
def test_fetcher_handles_real_responses(name: str, corpus_server: str, tmp_path: Path) -> None:
    code, payload, stderr = run_fetcher(name, corpus_server, tmp_path)

    assert code == 0, f"{name} exited {code} on real data:\n{stderr}"
    assert payload["status"] == "success"
    assert payload["api_failures"] == []
    assert payload["record_count"] == len(corpus_records(name))


@pytest.mark.parametrize("name", COVERED)
def test_analysis_is_not_silently_empty(name: str, corpus_server: str, tmp_path: Path) -> None:
    """
    The failure that matters is not a crash, it is a clean-looking empty
    result. A fetcher reading the wrong field names exits 0, reports success,
    and produces an analysis full of zeros — which reads as good news.
    """
    _, payload, _ = run_fetcher(name, corpus_server, tmp_path)
    analysis = payload["analysis"]

    assert analysis, f"{name} produced no analysis over {len(corpus_records(name))} real records"

    numeric = [v for v in analysis.values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
    assert any(v > 0 for v in numeric), f"{name} analysis is entirely zero over real records"


# --- field-level fidelity, checked rather than eyeballed ----------------------

# Fields whose absence would quietly distort the summary. Each must be present
# on at least one real record — a name that never appears is a wrong name.
EXPECTED_FIELDS = {
    "hosts": ["device_id", "hostname", "platform_name", "os_version", "agent_version",
              "last_seen", "status", "product_type_desc", "reduced_functionality_mode"],
    "spotlight_vulnerabilities": ["id", "cve", "host_info", "status", "created_timestamp"],
    "detections": ["composite_id", "status", "created_timestamp", "updated_timestamp", "product"],
}


@pytest.mark.parametrize("fetcher", sorted(EXPECTED_FIELDS))
def test_expected_fields_present_in_real_data(fetcher: str) -> None:
    records = corpus_records(fetcher)
    seen: set = set()
    for record in records:
        seen.update(record.keys())

    missing = [f for f in EXPECTED_FIELDS[fetcher] if f not in seen]
    assert not missing, (
        f"{fetcher} depends on {missing}, absent from all {len(records)} recorded responses. "
        "Either the field name is wrong or these captures predate it."
    )


def test_severity_is_resolved_for_most_real_alerts(corpus_server: str, tmp_path: Path) -> None:
    """
    Regression. Falcon populates `severity_name` on some alerts and only the
    numeric `severity` on others — every EPP alert in the captures has
    `severity: 30` and no name. Bucketing on the label alone filed the majority
    of a real tenant's alerts as "unknown", which is useless as evidence.

    Overwatch alerts genuinely carry no severity at all, so a residue of
    "unknown" is correct; it must not be the majority.
    """
    _, payload, _ = run_fetcher("detections", corpus_server, tmp_path)
    by_severity = payload["analysis"]["by_severity"]

    total = sum(by_severity.values())
    unknown = by_severity.get("unknown", 0)

    assert total > 0
    assert unknown < total / 2, (
        f"{unknown}/{total} real alerts have unresolved severity: {by_severity}"
    )


def test_tactic_spelling_variants_are_merged(corpus_server: str, tmp_path: Path) -> None:
    """
    Regression. Real data contains both "Credential Access" and
    "CredentialAccess" for one tactic. Counting raw strings reports two tactics
    and halves each count.
    """
    _, payload, _ = run_fetcher("detections", corpus_server, tmp_path)

    for field in ("by_tactic", "by_technique"):
        buckets = payload["analysis"][field]
        keys = [k.replace(" ", "").replace("-", "").casefold() for k in buckets]
        duplicates = {k for k in keys if keys.count(k) > 1}
        assert not duplicates, f"{field} splits one value across variants: {duplicates}"


def test_every_real_record_is_attributed_to_a_host(corpus_server: str, tmp_path: Path) -> None:
    """
    Host attribution is what ties a finding to an asset, and it is read from a
    different field per endpoint (`device_id` vs `aid` vs `device.device_id`).
    A wrong choice reports zero affected hosts while showing findings.
    """
    for name in ("spotlight_vulnerabilities", "detections"):
        _, payload, _ = run_fetcher(name, corpus_server, tmp_path)
        analysis = payload["analysis"]
        assert analysis["affected_host_count"] > 0, f"{name} attributed no findings to any host"


# --- real data vs the vendor's own schema -------------------------------------


def _schema():
    sys.path.insert(0, str(REPO_ROOT / "tools"))
    return importlib.import_module("crowdstrike_schema")


# Real captures that CrowdStrike's own spec gets wrong. Kept explicit rather
# than loosening the check: `evaluation_logic.logic[].id` is declared numeric
# and arrives as a string in every recorded response. Nothing here reads it —
# it sits under `apps[].evaluation_logic`, which the Spotlight fetcher does not
# touch — but silently widening the type would hide a real mismatch elsewhere.
KNOWN_SPEC_DISCREPANCIES = ("evaluation_logic",)


@pytest.mark.parametrize("name", COVERED)
def test_real_records_conform_to_vendor_schema(name: str) -> None:
    """
    Real responses must be structurally legal against CrowdStrike's own schema.

    This is as much a check on the *schema snapshot* as on the fetchers: if the
    two disagree, the snapshot is stale or wrong, and every offline conformance
    test built on it is worth less than it looks.
    """
    schema = _schema()
    models = schema.load_models()

    problems = []
    for index, record in enumerate(corpus_records(name)):
        problems += schema.validate(record, schema.ROOT_MODELS[name], models, f"[{index}]")

    unexplained = [p for p in problems if not any(k in p for k in KNOWN_SPEC_DISCREPANCIES)]
    assert not unexplained, (
        f"{name}: real recorded responses violate CrowdStrike's schema:\n"
        + "\n".join(unexplained[:20])
    )


def test_required_flags_are_unreliable_and_we_know_it() -> None:
    """
    Pins the calibration behind `enforce_required=False`.

    CrowdStrike's spec marks fields required that real responses routinely omit.
    Measured here rather than asserted in a comment, so that if CrowdStrike ever
    tightens its API to match its spec, this test fails and tells us the
    leniency is no longer needed.
    """
    schema = _schema()
    models = schema.load_models()
    records = corpus_records("detections")

    strict = []
    for record in records:
        strict += schema.validate(record, "DetectsAlert", models, "", enforce_required=True)

    missing = [p for p in strict if "required by" in p]
    assert missing, (
        "real responses now satisfy every 'required' field in CrowdStrike's spec; "
        "enforce_required can be turned on"
    )
