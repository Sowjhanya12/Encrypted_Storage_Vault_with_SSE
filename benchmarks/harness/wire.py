"""
benchmarks/harness/wire.py -- counts the HTTP traffic the untrusted cloud
actually receives during a benchmarked operation.

Several Phase 7 claims are about the cloud's *view*, not the client's
speed: how many requests one upload causes (architecture Section 09's
static-rebuild leakage, demonstration D7), and the literal
`POST /search` -> `GET /documents/<doc_id>` sequence one search produces
(demonstration D3b, audit finding M4). Those are only worth reporting if
they are observed rather than derived from reading the code -- so this
module records the real calls, using the same non-invasive technique
tests/conftest.py's `wire_log` fixture uses: it wraps
`client/cloud_client.py`'s HTTP entry point for the duration of a block
and restores it afterwards. No application file is modified, and nothing
is simulated: if a request is in this log, it was sent.

Only the method and path are recorded, which is precisely what an
untrusted cloud reads from its own access log. Bodies are left alone --
Phase 6 already proved they contain nothing but ciphertext, and copying
them here would only bloat the raw record.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Dict, Iterator, List


class WireLog:
    """The requests observed inside one `record_wire()` block."""

    def __init__(self, base_url: str):
        self.base_url = base_url
        self.calls: "List[tuple]" = []          # (method, path)

    def add(self, method: str, url: str) -> None:
        self.calls.append((method.upper(), url.replace(self.base_url, "") or "/"))

    def __len__(self) -> int:
        return len(self.calls)

    @property
    def sequence(self) -> "List[str]":
        """The access pattern as a cloud operator would read it."""
        return [f"{method} {path}" for method, path in self.calls]

    def count(self, method: str, path_pattern: str) -> int:
        """How many calls matched, e.g. count("GET", r"/documents/[0-9a-f]+")."""
        rx = re.compile(f"^{path_pattern}$")
        return sum(1 for m, p in self.calls if m == method.upper() and rx.match(p))

    def summary(self) -> "Dict[str, int]":
        """Request counts collapsed by shape, with document ids replaced by a
        placeholder so repeated fetches group together."""
        out: "Dict[str, int]" = {}
        for method, path in self.calls:
            shape = re.sub(r"/documents/[0-9a-f]{8,}", "/documents/<doc_id>", path)
            out[f"{method} {shape}"] = out.get(f"{method} {shape}", 0) + 1
        return out


@contextmanager
def record_wire(base_url: str) -> "Iterator[WireLog]":
    """Record every HTTP call `client/cloud_client.py` makes inside the block.

    The wrapper adds one function call and a list append per request, which
    is negligible beside a loopback HTTP round trip -- but for that reason
    the timings reported in the benchmarks are taken OUTSIDE this context
    wherever possible, and wire counts are captured in separate,
    untimed passes.
    """
    import client.cloud_client as cloud_client

    log = WireLog(base_url)
    original = cloud_client.requests.request

    def capture(method, url, **kwargs):
        log.add(method, url)
        return original(method, url, **kwargs)

    cloud_client.requests.request = capture
    try:
        yield log
    finally:
        cloud_client.requests.request = original
