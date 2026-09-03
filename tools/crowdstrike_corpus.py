#!/usr/bin/env python3
"""
Download a corpus of real, recorded CrowdStrike API responses.

Why
---
These fetchers were built without a Falcon tenant. A hand-written test double
proves the code is self-consistent, not that it matches CrowdStrike — the
double and the fetcher are written from the same assumptions, so they agree
with each other while both disagree with the API. Two bugs got through exactly
that way.

Several organisations that ship CrowdStrike integrations commit **real captured
responses** as test data. Running our fetchers over that data is the closest
thing to a live tenant available without one, and it is what
``tests/test_crowdstrike_real_responses.py`` consumes.

Nothing is vendored into this repository. The corpus is downloaded on demand
into a gitignored directory, so third-party files stay under their own
licences and this repo carries only the URLs.

Usage
-----
    python tools/crowdstrike_corpus.py            # download
    python tools/crowdstrike_corpus.py --list     # show sources, download nothing

Then::

    pytest tests/test_crowdstrike_real_responses.py

Without the corpus those tests skip, so CI stays offline and green.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Dict, List, NamedTuple

CORPUS_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "crowdstrike_corpus"

EL = "https://raw.githubusercontent.com/elastic/integrations/main/packages/crowdstrike/data_stream"


class Source(NamedTuple):
    """One downloadable set of recorded responses."""

    name: str          # local filename
    fetcher: str       # which fetcher's records these are
    url: str
    fmt: str           # "ndjson" (one record per line) or "envelope" (API body with .resources)
    origin: str        # for attribution in --list
    licence: str


SOURCES: List[Source] = [
    Source(
        "hosts_elastic_test.ndjson", "hosts",
        f"{EL}/host/_dev/test/pipeline/test-host.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "hosts_elastic_benchmark.ndjson", "hosts",
        f"{EL}/host/_dev/benchmark/pipeline/test-host.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "spotlight_elastic_test.ndjson", "spotlight_vulnerabilities",
        f"{EL}/vulnerability/_dev/test/pipeline/test-vulnerability.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "spotlight_elastic_benchmark.ndjson", "spotlight_vulnerabilities",
        f"{EL}/vulnerability/_dev/benchmark/pipeline/test-vulnerability.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "detections_elastic_test.ndjson", "detections",
        f"{EL}/alert/_dev/test/pipeline/test-alert.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "detections_elastic_benchmark.ndjson", "detections",
        f"{EL}/alert/_dev/benchmark/pipeline/test-alert.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "detections_elastic_automated_lead.ndjson", "detections",
        f"{EL}/alert/_dev/test/pipeline/test-automated-lead.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
    Source(
        "detections_elastic_correlation.ndjson", "detections",
        f"{EL}/alert/_dev/test/pipeline/test-correlation-detection.log",
        "ndjson", "elastic/integrations", "Elastic License 2.0",
    ),
]


def download(source: Source, dest_dir: Path) -> int:
    """Fetch one source. Returns the record count, or -1 on failure."""
    try:
        with urllib.request.urlopen(source.url, timeout=60) as response:
            body = response.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001 - an unreachable source is data, not a crash
        print(f"  ! {source.name}: {e}", file=sys.stderr)
        return -1

    records = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # Some captures are a single pretty-printed body rather than ndjson.
            try:
                records = [json.loads(body)]
            except json.JSONDecodeError:
                print(f"  ! {source.name}: not JSON", file=sys.stderr)
                return -1
            break

    # Normalise an API envelope down to its resources, so every corpus file is
    # a flat list of the records a fetcher actually iterates.
    if len(records) == 1 and isinstance(records[0], dict) and "resources" in records[0]:
        resources = records[0].get("resources")
        if isinstance(resources, list):
            records = resources

    (dest_dir / source.name).write_text(
        json.dumps({"fetcher": source.fetcher, "origin": source.origin,
                    "url": source.url, "records": records}, indent=2) + "\n"
    )
    return len(records)


def main() -> int:
    parser = argparse.ArgumentParser(description="Download recorded CrowdStrike responses.")
    parser.add_argument("--list", action="store_true", help="list sources without downloading")
    args = parser.parse_args()

    if args.list:
        by_fetcher: Dict[str, List[Source]] = {}
        for s in SOURCES:
            by_fetcher.setdefault(s.fetcher, []).append(s)
        for fetcher in sorted(by_fetcher):
            print(f"\n{fetcher}:")
            for s in by_fetcher[fetcher]:
                print(f"  {s.origin:<24} {s.licence:<22} {s.url}")
        return 0

    CORPUS_DIR.mkdir(parents=True, exist_ok=True)
    total = 0
    failed = 0
    for source in SOURCES:
        count = download(source, CORPUS_DIR)
        if count < 0:
            failed += 1
            continue
        total += count
        print(f"  {source.name:<44} {count:>4} records  ({source.origin})")

    print(f"\n{total} records across {len(SOURCES) - failed} files in {CORPUS_DIR}")
    if failed:
        print(f"{failed} source(s) unavailable", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
