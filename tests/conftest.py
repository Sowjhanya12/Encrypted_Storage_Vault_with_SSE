"""
tests/conftest.py -- shared fixtures for the test suite (Phase 5's live
two-process harness, plus Phase 6's security/leakage demonstration
infrastructure).

client/client_app.py makes REAL HTTP calls to the cloud (via
client/cloud_client.py) rather than being tested against an in-process
Flask test client on both legs. Testing it faithfully therefore means
running an actual cloud/cloud_app.py on an actual TCP port, not just
importing its Flask app object -- otherwise the tests wouldn't be
exercising the real two-process topology Section 02 describes, only a
simulation of it.

Phase 6 adds `wire_log` and `evidence` on top of that same live
two-process harness: `wire_log` captures the literal HTTP traffic the
trusted client sends to the untrusted cloud (method, path, JSON body,
JSON response) during a test, which is the ground truth for every
"what can the cloud observe" claim in tests/test_security_demonstrations.py
-- not a narrated claim, a captured transcript. `evidence` lets those
tests record a structured, human-readable finding; pytest_sessionfinish
renders everything collected into docs/security_demo_report.html once
the whole run completes, so `pytest` alone reproduces the report.
"""

import itertools
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cloud.cloud_app import create_app as create_cloud_app  # noqa: E402

# Sequential port allocation to avoid collisions between tests in one
# session (this project's test suite runs sequentially, not in
# parallel, so a simple counter is sufficient).
_port_counter = itertools.count(15100)


def _wait_for_health(base_url: str, timeout: float = 5.0) -> None:
    """Poll /health instead of a fixed sleep -- faster and more
    reliable than guessing how long Werkzeug's dev server takes to
    bind its socket."""
    import urllib.error
    import urllib.request

    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{base_url}/health", timeout=0.5)
            return
        except (urllib.error.URLError, ConnectionError) as exc:
            last_error = exc
            time.sleep(0.02)
    raise RuntimeError(f"cloud service at {base_url} never became healthy: {last_error}")


@pytest.fixture
def live_cloud(tmp_path, monkeypatch):
    """Starts a REAL cloud_app.py Flask server on its own thread and
    port, backed by a fresh temp SQLite file, and points
    client/cloud_client.py's CLOUD_BASE_URL at it for the duration of
    the test. Yields the base_url.
    """
    port = next(_port_counter)
    base_url = f"http://127.0.0.1:{port}"
    db_path = tmp_path / "cloud_vault.sqlite3"

    app = create_cloud_app(db_path=str(db_path))
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False),
        daemon=True,
    )
    server_thread.start()
    _wait_for_health(base_url)

    import client.cloud_client as cloud_client

    monkeypatch.setattr(cloud_client, "CLOUD_BASE_URL", base_url)

    yield base_url
    # Daemon thread: no explicit shutdown needed for test purposes --
    # it is torn down with the test process. Werkzeug's dev server has
    # no clean programmatic stop API when run this way.


# ---------------------------------------------------------------------------
# Multi-user extension: client_app.py now requires a logged-in account
# (and a CSRF header on state-changing requests) before any vault route.
# This helper gives the pre-existing client tests exactly the session
# they assume -- one regular user with their own fresh, empty vault --
# so their bodies (and security assertions) run unchanged.
# ---------------------------------------------------------------------------

def make_client_app(tmp_path, **config):
    from client.client_app import create_app as create_client_app

    app = create_client_app({
        "ACCOUNTS_DB_PATH": str(tmp_path / "client_accounts.sqlite3"),
        "ADMIN_SETUP_TOKEN": "test-setup-token",
        **config,
    })
    app.config["TESTING"] = True
    return app


def login_test_client(client, username, password, register=True):
    """Register (optionally) + log in; installs the CSRF header on the
    test client so later requests carry it automatically. Returns the
    login response JSON."""
    if register:
        resp = client.post("/api/auth/register", json={"username": username, "password": password})
        assert resp.status_code == 201, resp.get_json()
    resp = client.post("/api/auth/login", json={"username": username, "password": password})
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    client.environ_base["HTTP_X_CSRF_TOKEN"] = data["csrf_token"]
    return data


@pytest.fixture
def user_app_client(live_cloud, tmp_path):
    app = make_client_app(tmp_path)
    with app.test_client() as c:
        login_test_client(c, "vault-owner", "owner-account-password")
        yield c


# ---------------------------------------------------------------------------
# Phase 6: security/leakage demonstration infrastructure
# ---------------------------------------------------------------------------

@pytest.fixture
def wire_log(monkeypatch, live_cloud):
    """Captures every HTTP request client/cloud_client.py sends to the
    live cloud during a test, in the exact form the untrusted cloud
    process actually receives it: method, path, JSON request body, and
    the cloud's JSON response. Every byte field in that JSON is already
    base64 text (cloud_client._b64 encodes before sending; cloud_app.py
    only ever jsonifies base64 text back), so a wire_log entry IS
    literally what a curious cloud operator sniffing its own inbound
    requests would see -- nothing is decoded or reconstructed after
    the fact.

    Depends on live_cloud (not just requesting it implicitly) so the
    fixture order is explicit: CLOUD_BASE_URL must already be pointed
    at the live test server before anything patches how requests reach
    it.
    """
    import client.cloud_client as cloud_client_module

    log = []
    real_request = cloud_client_module.requests.request

    def _capture(method, url, **kwargs):
        entry = {
            "method": method,
            "path": url.replace(live_cloud, ""),
            "request_json": kwargs.get("json"),
            # Multi-user extension: the vault id + access-token headers
            # are part of what an observer of the request sees, too.
            "request_headers": dict(kwargs.get("headers") or {}),
        }
        resp = real_request(method, url, **kwargs)
        try:
            entry["response_json"] = resp.json()
        except ValueError:
            entry["response_json"] = None
        entry["status_code"] = resp.status_code
        log.append(entry)
        return resp

    monkeypatch.setattr(cloud_client_module.requests, "request", _capture)
    return log


# Findings accumulate here across the whole test session; rendered once
# at the end by pytest_sessionfinish. Module-level (not a yielded
# fixture value) because the render has to happen after every test has
# run, not after any single test's fixture teardown.
_SECURITY_EVIDENCE = []


@pytest.fixture
def evidence():
    """tests/test_security_demonstrations.py appends one structured
    finding per demonstration here. Each finding is expected to carry:
    id, title, audit_ref, claim, cloud_can_see, client_can_see,
    remains_secret, intentional_limitation (or None), verdict, and
    optionally raw_evidence (a small JSON-safe dict of captured proof
    -- wire_log entries, hex snippets, counts -- backing the claim).
    See that module for the concrete shape.
    """
    return _SECURITY_EVIDENCE


def pytest_sessionfinish(session, exitstatus):
    """Renders docs/security_demo_report.html from whatever
    tests/test_security_demonstrations.py collected into `evidence`
    this run. A no-op if those tests didn't run (e.g. `pytest -k
    something_else`) -- never overwrites the report with an empty one.
    Runs regardless of exitstatus so a single failing demonstration
    still shows up in the report rather than silently disappearing.
    """
    if not _SECURITY_EVIDENCE:
        return
    out_path = os.path.join(os.path.dirname(__file__), "..", "docs", "security_demo_report.html")
    _render_security_demo_report(_SECURITY_EVIDENCE, out_path)


def _render_security_demo_report(evidence_list, out_path):
    import html
    import json as _json

    CATEGORY_META = {
        "cloud_can_see": ("Cloud can see", "#b45309", "#fffbeb"),
        "client_can_see": ("Trusted client can see", "#1d4ed8", "#eff6ff"),
        "remains_secret": ("Remains secret", "#15803d", "#f0fdf4"),
        "intentional_limitation": ("Intentional limitation", "#7c3aed", "#f5f3ff"),
    }
    VERDICT_META = {
        "SECURE": ("#15803d", "#f0fdf4", "confirmed secure"),
        "CONFIRMED-LEAKAGE": ("#b45309", "#fffbeb", "confirmed leakage (by design)"),
        "MITIGATED": ("#1d4ed8", "#eff6ff", "mitigated (security fix verified)"),
    }

    def esc(x):
        return html.escape(str(x)) if x is not None else ""

    def render_field(key, value):
        if value is None:
            return ""
        label, color, bg = CATEGORY_META[key]
        return f'''<div class="field" style="border-left-color:{color}">
          <div class="field-label" style="color:{color}">{label}</div>
          <div class="field-body">{esc(value)}</div>
        </div>'''

    cards = []
    for item in evidence_list:
        vcolor, vbg, vlabel = VERDICT_META.get(item.get("verdict"), ("#374151", "#f3f4f6", item.get("verdict", "")))
        raw = item.get("raw_evidence")
        raw_html = ""
        if raw:
            raw_html = f'''<details class="raw">
              <summary>Raw captured evidence (from this run)</summary>
              <pre>{esc(_json.dumps(raw, indent=2, default=str))}</pre>
            </details>'''
        fields_html = "".join(
            render_field(k, item.get(k))
            for k in ("cloud_can_see", "client_can_see", "remains_secret", "intentional_limitation")
        )
        cards.append(f'''
        <section class="card">
          <div class="card-head">
            <span class="card-id">{esc(item.get("id"))}</span>
            <h2>{esc(item.get("title"))}</h2>
            <span class="verdict" style="color:{vcolor};background:{vbg}">{esc(vlabel)}</span>
          </div>
          <p class="claim">{esc(item.get("claim"))}</p>
          <p class="audit-ref">Audit reference: {esc(item.get("audit_ref", "—"))}</p>
          <div class="fields">{fields_html}</div>
          {raw_html}
        </section>''')

    n = len(evidence_list)
    leakage_n = sum(1 for e in evidence_list if e.get("verdict") == "CONFIRMED-LEAKAGE")
    secure_n = sum(1 for e in evidence_list if e.get("verdict") == "SECURE")
    mitigated_n = sum(1 for e in evidence_list if e.get("verdict") == "MITIGATED")

    doc = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Encrypted Cloud Vault — Security &amp; Leakage Demonstration Report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root {{
    --bg: #ffffff; --fg: #111827; --muted: #6b7280; --border: #e5e7eb; --card-bg: #fafafa;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 0 0 4rem 0; background: var(--bg); color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.5;
  }}
  header {{
    padding: 2.5rem 1.5rem 1.5rem; max-width: 900px; margin: 0 auto;
  }}
  header h1 {{ font-size: 1.5rem; margin: 0 0 0.25rem; }}
  header .sub {{ color: var(--muted); font-size: 0.95rem; }}
  .summary {{ display: flex; gap: 0.75rem; margin-top: 1.25rem; flex-wrap: wrap; }}
  .stat {{
    border: 1px solid var(--border); border-radius: 10px; padding: 0.6rem 1rem;
    font-size: 0.85rem; color: var(--muted);
  }}
  .stat b {{ color: var(--fg); font-size: 1.1rem; display: block; }}
  .legend {{
    max-width: 900px; margin: 1.5rem auto 0; padding: 0 1.5rem;
    display: flex; flex-wrap: wrap; gap: 0.5rem; font-size: 0.8rem; color: var(--muted);
  }}
  .legend span {{ border-radius: 6px; padding: 0.15rem 0.55rem; }}
  main {{ max-width: 900px; margin: 0 auto; padding: 0 1.5rem; }}
  .card {{
    border: 1px solid var(--border); border-radius: 14px; background: var(--card-bg);
    padding: 1.25rem 1.5rem; margin-top: 1.25rem;
  }}
  .card-head {{ display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }}
  .card-id {{
    font-family: ui-monospace, Menlo, monospace; font-size: 0.75rem; color: var(--muted);
    border: 1px solid var(--border); border-radius: 6px; padding: 0.1rem 0.4rem;
  }}
  .card-head h2 {{ font-size: 1.05rem; margin: 0; flex: 1; }}
  .verdict {{ font-size: 0.75rem; font-weight: 600; border-radius: 999px; padding: 0.2rem 0.7rem; white-space: nowrap; }}
  .claim {{ margin: 0.75rem 0 0.25rem; font-size: 0.95rem; }}
  .audit-ref {{ margin: 0 0 0.75rem; font-size: 0.78rem; color: var(--muted); }}
  .fields {{ display: grid; gap: 0.6rem; }}
  .field {{ border-left: 3px solid; padding: 0.35rem 0 0.35rem 0.75rem; }}
  .field-label {{ font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }}
  .field-body {{ font-size: 0.9rem; margin-top: 0.15rem; }}
  details.raw {{ margin-top: 0.9rem; }}
  details.raw summary {{ cursor: pointer; font-size: 0.8rem; color: var(--muted); }}
  details.raw pre {{
    background: #0b1021; color: #d1d5db; border-radius: 10px; padding: 0.9rem;
    overflow-x: auto; font-size: 0.75rem; margin-top: 0.5rem;
  }}
  footer {{ max-width: 900px; margin: 2rem auto 0; padding: 0 1.5rem; color: var(--muted); font-size: 0.8rem; }}
</style>
</head>
<body>
<header>
  <h1>Encrypted Cloud Vault — Security &amp; Leakage Demonstration Report</h1>
  <div class="sub">Generated by <code>pytest</code> from tests/test_security_demonstrations.py, against the real two-process topology (a live cloud/cloud_app.py Flask server on its own port, driven by client/client_app.py making real HTTP calls). Every number and byte snippet below was captured during this specific run, not asserted from memory.</div>
  <div class="summary">
    <div class="stat"><b>{n}</b>demonstrations</div>
    <div class="stat"><b>{secure_n}</b>confirmed secure</div>
    <div class="stat"><b>{leakage_n}</b>confirmed leakage (by design)</div>
    <div class="stat"><b>{mitigated_n}</b>mitigated (fix verified live)</div>
  </div>
</header>
<div class="legend">
  <span style="background:#fffbeb;color:#b45309">Cloud can see</span>
  <span style="background:#eff6ff;color:#1d4ed8">Trusted client can see</span>
  <span style="background:#f0fdf4;color:#15803d">Remains secret</span>
  <span style="background:#f5f3ff;color:#7c3aed">Intentional limitation</span>
</div>
<main>
{"".join(cards)}
</main>
<footer>
  Encrypted Cloud Vault (SSE) — see docs/architecture.html (design) and docs/security_audit_opus_phase6_readiness.md (the audit these demonstrations answer). Full rationale for each demonstration lives in tests/test_security_demonstrations.py's docstrings. Regenerate this report at any time with: <code>python3 -m pytest tests/test_security_demonstrations.py</code>
</footer>
</body>
</html>'''

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
