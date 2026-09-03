"""
Pagination at scale.

Every pagination test up to now ran against a fixture of three or four records
across two pages. That exercises the shape of the loop and almost nothing else:
a two-page walk cannot show a record dropped at a boundary, a batch remainder
mishandled, or a cursor followed one page too few.

A compliance fetcher that silently returns 90% of the estate is worse than one
that fails, because the number it reports looks perfectly plausible. So these
tests drive thousands of records through each of the three paginators and assert
the collection is **exact** — every record, once, in order.

What is still not covered: whether a real Falcon server paginates the way this
one does. These tests pin our client's behaviour against the documented
contract; only a live tenant can confirm the server keeps its side of it. That
distinction is the whole reason the numbers below are large — if the client is
wrong, it should be wrong loudly here rather than quietly on someone's estate.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List
from urllib.parse import parse_qs, urlparse

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CLIENT_PATH = REPO_ROOT / "fetchers" / "crowdstrike" / "_shared" / "falcon_client.py"


def _load_module(path: Path, name: str) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


client_module = _load_module(CLIENT_PATH, "cs_client_pagination")


# --- a server that pages properly ---------------------------------------------


class Config:
    """Per-test server behaviour."""

    total = 2500
    # Return fewer records than asked for on every page, while still handing
    # back a cursor. A client that treats a short page as the last page — a
    # common and very plausible shortcut — loses everything after page one.
    short_pages = False
    # Report a `total` lower than the truth, as a large estate's approximate
    # count can.
    understate_total: int | None = None
    # Repeat the final record of each page as the first of the next, which is
    # what a cursor over data being written underneath it does.
    overlap = False


class PagingHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: Any) -> None:  # silence
        pass

    def _send(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _slice(self, start: int, limit: int) -> List[str]:
        if Config.short_pages:
            limit = max(1, limit // 4)
        if Config.overlap and start > 0:
            start -= 1
        return [f"id-{i:06d}" for i in range(start, min(start + limit, Config.total))]

    def _reported_total(self) -> int:
        return Config.understate_total if Config.understate_total is not None else Config.total

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/oauth2/token":
            self._send({"access_token": "mock-token", "expires_in": 1800})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        ids = body.get("ids") or body.get("composite_ids") or []
        # Echo each requested ID back as a record, and record the batch size so
        # a test can check how the client split the work.
        BATCHES.append(len(ids))
        self._send({"resources": [{"device_id": i} for i in ids], "errors": []})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        limit = int((query.get("limit") or ["100"])[0])

        if parsed.path == "/scroll":
            token = (query.get("offset") or [""])[0]
            start = int(token) if token else 0
            records = self._slice(start, limit)
            nxt = start + len(records)
            # The scroll token is an opaque string, and is empty at the end.
            self._send({
                "resources": records,
                "meta": {"pagination": {
                    "offset": str(nxt) if nxt < Config.total else "",
                    "total": self._reported_total(),
                }},
                "errors": [],
            })
            return

        if parsed.path in ("/after", "/next"):
            cursor = (query.get("after") or [""])[0]
            start = int(cursor) if cursor else 0
            records = self._slice(start, limit)
            nxt = start + len(records)
            # /after answers like Spotlight, /next like Zero Trust. Both take
            # the cursor as `after` on the way in; only the way out differs.
            key = "after" if parsed.path == "/after" else "next"
            self._send({
                "resources": [{"id": r} for r in records],
                "meta": {"pagination": {
                    key: str(nxt) if nxt < Config.total else "",
                    "total": self._reported_total(),
                }},
                "errors": [],
            })
            return

        if parsed.path == "/offset":
            start = int((query.get("offset") or ["0"])[0])
            records = self._slice(start, limit)
            self._send({
                "resources": [{"id": r} for r in records],
                "meta": {"pagination": {
                    "offset": start,
                    "limit": limit,
                    "total": self._reported_total(),
                }},
                "errors": [],
            })
            return

        self._send({"resources": [], "errors": []})


BATCHES: List[int] = []


@pytest.fixture
def falcon() -> Iterator[Any]:
    Config.total = 2500
    Config.short_pages = False
    Config.understate_total = None
    Config.overlap = False
    BATCHES.clear()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), PagingHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        instance = client_module.FalconClient(
            base_url=f"http://127.0.0.1:{httpd.server_address[1]}",
            client_id="mock-id",
            client_secret="mock-secret",
            timeout=30,
        )
        instance.authenticate()
        yield instance
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def expected(total: int) -> List[str]:
    return [f"id-{i:06d}" for i in range(total)]


# --- exact collection ---------------------------------------------------------


@pytest.mark.parametrize("total", [0, 1, 99, 100, 101, 2500, 7001])
def test_scroll_collects_every_record_exactly_once(falcon: Any, total: int) -> None:
    """
    Sizes chosen around the page boundary rather than at random: one under, one
    on, and one over a round page, plus empty and single. Off-by-one errors in a
    paging loop live exactly there and nowhere else.
    """
    Config.total = total
    collected = falcon.paginate_scroll("/scroll", limit=100)

    assert collected == expected(total)
    assert len(collected) == len(set(collected)), "records duplicated across pages"
    assert falcon.api_failures == []


@pytest.mark.parametrize("total", [0, 1, 400, 401, 2500])
def test_after_cursor_collects_every_record_exactly_once(falcon: Any, total: int) -> None:
    Config.total = total
    collected = falcon.paginate_after("/after", limit=400)

    assert [r["id"] for r in collected] == expected(total)
    assert falcon.api_failures == []


@pytest.mark.parametrize("total", [0, 1, 400, 401, 2500])
def test_a_next_cursor_paginates_as_well_as_an_after_cursor(falcon: Any, total: int) -> None:
    """
    The cursor goes out as `after` on every endpoint but comes back under
    different names: `after` from Spotlight, **`next`** from Zero Trust.

    Reading only `after` meant the Zero Trust host query saw no cursor, stopped
    after its first page and reported success — a capped collection that looks
    exactly like a small estate. Found by reading the response models rather
    than in testing, because a mock written from the same assumption as the
    client agrees with it.
    """
    Config.total = total
    collected = falcon.paginate_after("/next", limit=400)

    assert [r["id"] for r in collected] == expected(total)
    assert falcon.api_failures == []


def test_an_integer_offset_is_not_mistaken_for_a_search_after_cursor(falcon: Any) -> None:
    """
    `offset` names two different things: an opaque string token on the search
    -after endpoints, and a number on the ones `paginate_offset` serves.

    Accepting a number here would feed `offset=0` back as a cursor and restart
    the walk from the beginning — an endless loop over page one, which the cap
    would eventually stop after collecting the same records a thousand times.
    """
    assert falcon._next_cursor({"meta": {"pagination": {"offset": 0}}}) is None
    assert falcon._next_cursor({"meta": {"pagination": {"offset": 500}}}) is None
    assert falcon._next_cursor({"meta": {"pagination": {"offset": "tok"}}}) == "tok"
    assert falcon._next_cursor({"meta": {"pagination": {"after": "", "next": "tok"}}}) == "tok"
    assert falcon._next_cursor({"meta": {}}) is None
    assert falcon._next_cursor({}) is None


@pytest.mark.parametrize("total", [0, 1, 500, 501, 2500])
def test_offset_pagination_collects_every_record_exactly_once(falcon: Any, total: int) -> None:
    Config.total = total
    collected = falcon.paginate_offset("/offset", limit=500)

    assert [r["id"] for r in collected] == expected(total)
    assert falcon.api_failures == []


# --- server behaviour that a naive loop gets wrong -----------------------------


def test_a_short_page_is_not_mistaken_for_the_last_page(falcon: Any) -> None:
    """
    Falcon may return fewer records than `limit` without being finished — the
    cursor, not the page size, says whether there is more.

    `len(page) < limit` is the obvious termination test and it is wrong. Here it
    would collect 25 of 2500 records and report success, so this is the single
    most valuable case in the file.
    """
    Config.short_pages = True
    collected = falcon.paginate_scroll("/scroll", limit=100)

    assert collected == expected(2500)
    assert falcon.api_failures == []


def test_offset_pagination_stops_when_total_understates_the_estate(falcon: Any) -> None:
    """
    Offset pagination has no cursor, so it must trust `total` — and on a large
    estate `total` is an estimate that can come back low.

    This documents a real limitation rather than asserting it away: the client
    trusts `total` and stops at the first page boundary at or past it — so an
    understated total truncates the collection, and reports success while doing
    it. Here 2500 records behind a claimed total of 1200 yields 1500: three
    pages of 500, because the stop is only checked between pages.

    The alternative, ignoring `total` and paging until an empty response, costs
    one extra request per collection and was not chosen. Recorded so the
    behaviour is a decision rather than a surprise, and flagged for a live
    tenant — whether Falcon's `total` is ever low in practice is the question
    that decides whether this needs changing.
    """
    Config.understate_total = 1200
    collected = falcon.paginate_offset("/offset", limit=500)

    assert len(collected) == 1500, "behaviour changed — re-read the docstring before editing"
    assert len(collected) < Config.total, "the truncation this test documents did not happen"


def test_duplicate_records_across_a_boundary_are_not_looked_up_twice(falcon: Any) -> None:
    """
    A cursor walking data that is being written underneath it can hand back the
    same record on two consecutive pages. Paying twice for the lookup also
    duplicates the record in the evidence, which inflates every count derived
    from it.
    """
    Config.overlap = True
    ids = falcon.paginate_scroll("/scroll", limit=100)

    assert len(ids) > len(set(ids)), "the server did not actually produce overlap"

    records = falcon.get_entities("/entities", ids)
    returned = [r["device_id"] for r in records]
    assert returned == sorted(set(ids)) or len(returned) == len(set(ids)), (
        "duplicate IDs were looked up more than once"
    )
    assert len(returned) == len(set(returned)), "duplicate records reached the evidence"


# --- batching -----------------------------------------------------------------


@pytest.mark.parametrize("count", [1, 99, 100, 101, 250, 1000, 1001])
def test_entity_lookups_batch_without_losing_the_remainder(falcon: Any, count: int) -> None:
    """
    IDs are resolved 100 at a time. A remainder shorter than a full batch is the
    classic thing to drop — and it drops silently, because a short final batch
    looks exactly like a complete collection.
    """
    ids = expected(count)
    records = falcon.get_entities("/entities", ids)

    assert [r["device_id"] for r in records] == ids
    assert sum(BATCHES) == count, "IDs were lost or duplicated between batches"
    assert all(size <= 100 for size in BATCHES), f"a batch exceeded 100: {BATCHES}"
    assert len(BATCHES) == (count + 99) // 100, f"unexpected batch count: {BATCHES}"


def test_no_request_is_made_for_an_empty_id_list(falcon: Any) -> None:
    """An estate with nothing to look up should cost nothing, and must not send
    a POST with an empty body that a real tenant would answer with a 400."""
    assert falcon.get_entities("/entities", []) == []
    assert BATCHES == []


# --- responses that omit what the client was leaning on ------------------------


class SparseMetaHandler(BaseHTTPRequestHandler):
    """
    A server whose responses are valid but thinner than the happy path.

    `meta.pagination` is `omitempty` on every endpoint these fetchers page, and
    `meta` itself is a Go pointer with no `omitempty` — so it serialises as JSON
    `null` when unset. Both shapes are things the spec permits and neither
    appeared in any fixture, which is why the client's behaviour on them had
    never been observed.
    """

    mode = "no_total"
    total = 250

    def log_message(self, *args: Any) -> None:  # silence
        pass

    def _send(self, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        self._send({"access_token": "mock-token", "expires_in": 1800})

    def do_GET(self) -> None:  # noqa: N802
        query = parse_qs(urlparse(self.path).query)
        limit = int((query.get("limit") or ["100"])[0])
        start = int((query.get("offset") or ["0"])[0])
        records = [
            {"id": f"id-{i:06d}"}
            for i in range(start, min(start + limit, SparseMetaHandler.total))
        ]

        if SparseMetaHandler.mode == "no_total":
            meta: Any = {"pagination": {"offset": start, "limit": limit}}
        elif SparseMetaHandler.mode == "no_pagination":
            meta = {"trace_id": "abc123", "query_time": 0.01}
        else:  # null_meta
            meta = None

        self._send({"resources": records, "meta": meta, "errors": []})


@pytest.fixture
def sparse_falcon() -> Iterator[Any]:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), SparseMetaHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        instance = client_module.FalconClient(
            base_url=f"http://127.0.0.1:{httpd.server_address[1]}",
            client_id="mock-id",
            client_secret="mock-secret",
            timeout=30,
        )
        instance.authenticate()
        yield instance
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("mode", ["no_total", "no_pagination"])
def test_offset_pagination_does_not_stop_because_total_is_missing(
    sparse_falcon: Any, mode: str
) -> None:
    """
    A missing `total` is not the end of the data.

    `paginate_offset` terminated on `total is None`, so a response without a
    pagination block returned page one and reported success — 100 of 250
    records, no `api_failures`, `status: success`. That is the failure this
    client keeps re-learning: a truncated collection is indistinguishable from a
    small estate, and it is the compliance error that does the most damage
    because the number looks entirely plausible.

    `meta.pagination` is `omitempty` on `MsaMetaInfo`, which is what all three
    endpoints `paginate_offset` serves return — alerts queries, prevention
    policies and firewall policies. So this is a documented response shape, not
    a hypothetical one.

    The empty page is now the only terminator when the count is unknown. A
    server that ignores `offset` walks into the page cap and is recorded as a
    failure, which is loud rather than quiet.
    """
    SparseMetaHandler.mode = mode
    SparseMetaHandler.total = 250

    collected = sparse_falcon.paginate_offset("/offset", limit=100)

    assert [r["id"] for r in collected] == expected(250)
    assert sparse_falcon.api_failures == []


def test_every_paginator_survives_a_null_meta(sparse_falcon: Any) -> None:
    """
    `meta` is a Go pointer with no `omitempty`, so an unset one is sent as JSON
    `null` rather than omitted. `_next_cursor` was hardened against that;
    `paginate_scroll` and `paginate_offset` were not, and both raised
    AttributeError on `None.get` — a traceback out of the middle of a
    collection instead of a recorded failure.
    """
    SparseMetaHandler.mode = "null_meta"
    SparseMetaHandler.total = 100

    assert len(sparse_falcon.paginate_offset("/offset", limit=100)) == 100
    assert len(sparse_falcon.paginate_scroll("/scroll", limit=100)) == 100
    assert len(sparse_falcon.paginate_after("/after", limit=100)) == 100
    assert sparse_falcon.api_failures == []
